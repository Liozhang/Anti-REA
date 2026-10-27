// 写入前的签名与校验和门控。
// 规则来自设计文档的“签名制品保护”边界：
//   检测到代码签名或校验和机制的制品默认跳过改写，并在输出中给出明确原因；
//   策略显式允许时才施加，施加后在输出中标记 requires_resign，由用户用自有签名身份重新签名。
//   PE 可选头 CheckSum 非零时默认等长重算，策略未允许重算时按签名制品同等对待。
//
// 门控判定不自己写一份：观察与决策一律走 src/signatures 的观察器，
// 本文件只把观察结果折算成 transforms 内部的“允许写入、是否需要重新签名、是否重算校验和”三件事。

import { detectContainer } from '../container/detect.mjs';
import { analyzeByContainer, computePeChecksum } from '../signatures/index.mjs';
import { readSignaturesPolicy } from '../signatures/policy.mjs';
import { parsePeStructure } from './parse.mjs';

/**
 * 对一段字节做门控评估。
 * @param {Buffer} buffer 待写入前的制品字节
 * @param {Record<string, unknown>} policy 策略
 * @returns {{
 *   container: string,
 *   allowed: boolean,
 *   requiresResign: boolean,
 *   recomputeChecksum: boolean,
 *   reason: string | null,
 *   observations: Array<Record<string, unknown>>,
 * }}
 */
export function evaluateSignatureGate(buffer, policy) {
  const container = detectContainer(buffer).type;
  const observations = analyzeByContainer(buffer, container, { policy });
  const gates = observations.map((observation) => observation.gate).filter((gate) => gate !== undefined && gate !== null);

  const blocking = gates.find((gate) => gate.action === 'skip-rewrite');
  if (blocking !== undefined) {
    return {
      container,
      allowed: false,
      requiresResign: blocking.requiresResign === true,
      recomputeChecksum: false,
      reason: blocking.reason ?? '签名或校验和观察器要求跳过改写',
      observations,
    };
  }

  const signaturesPolicy = readSignaturesPolicy(policy);
  const requiresResign = gates.some((gate) => gate.requiresResign === true);
  // CheckSum 重算条件：观察器明确给出 recompute-checksum，或校验和非零且策略允许重算。
  const recomputeChecksum =
    gates.some((gate) => gate.action === 'recompute-checksum') ||
    (container === 'pe' && signaturesPolicy.allowChecksumRecompute && peChecksumNonZero(buffer));
  return {
    container,
    allowed: true,
    requiresResign,
    recomputeChecksum,
    reason: null,
    observations,
  };
}

/**
 * 判断 PE 可选头 CheckSum 是否非零。解析失败时按零处理，由观察器与复审另行判定。
 * @param {Buffer} buffer
 * @returns {boolean}
 */
function peChecksumNonZero(buffer) {
  const pe = parsePeStructure(buffer);
  if (!pe.ok || pe.data.checksumFieldOffset === null) {
    return false;
  }
  const value = buffer.readUInt32LE(pe.data.checksumFieldOffset);
  return value !== 0;
}

/**
 * 等长重算 PE 可选头 CheckSum 并写回缓冲区（就地修改，调用方传入的必须是可写副本）。
 * 算法与字段位置一律取自 src/signatures/pe-checksum.mjs，不另写一份。
 * @param {Buffer} buffer 可写缓冲区
 * @returns {{before: number, after: number, fieldOffset: number} | null} 无法定位字段时返回 null
 */
export function recomputePeChecksumInPlace(buffer) {
  const pe = parsePeStructure(buffer);
  if (!pe.ok || pe.data.checksumFieldOffset === null) {
    return null;
  }
  const fieldOffset = pe.data.checksumFieldOffset;
  const before = buffer.readUInt32LE(fieldOffset);
  const after = computePeChecksum(buffer, fieldOffset);
  buffer.writeUInt32LE(after, fieldOffset);
  return { before, after, fieldOffset };
}
