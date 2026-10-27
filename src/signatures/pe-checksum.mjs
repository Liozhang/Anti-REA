// PE 安全目录与可选头 CheckSum 观察器，附带 CheckSum 重算函数。
// 只读：解析 DOS 头、PE 签名、COFF 头与可选头，读安全目录（数据目录索引 4）与 CheckSum 字段。
// 只观察不验证密码学信任：回答“制品是否带 Authenticode 签名或非零校验和”，不回答“签名是否可信”。
// 默认行为：安全目录存在时跳过改写；CheckSum 非零时默认等长重算，策略未允许重算时按签名制品同等对待。

import { readSignaturesPolicy } from './policy.mjs';

/** 数据目录中安全目录（证书表）的索引。 */
const SECURITY_DIRECTORY_INDEX = 4;
/** 可选头内 CheckSum 字段相对可选头起点的偏移，PE32 与 PE32+ 相同。 */
const CHECKSUM_FIELD_OFFSET = 64;

/**
 * 解析 PE 头部关键偏移。
 * @param {Buffer} buffer
 * @returns {{ok: true, optionalHeaderOffset: number, isPe32Plus: boolean, checksumFieldOffset: number, securityEntryOffset: number | null, numDataDirs: number} | {ok: false, reason: string}}
 */
function locatePe(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 0x40 || buffer[0] !== 0x4d || buffer[1] !== 0x5a) {
    return { ok: false, reason: '不是有效的 PE 文件（缺少 MZ 头）' };
  }
  const peOffset = buffer.readUInt32LE(0x3c);
  if (peOffset + 4 > buffer.length) {
    return { ok: false, reason: `e_lfanew 指向的 PE 签名偏移 ${peOffset} 越界` };
  }
  if (buffer.readUInt32LE(peOffset) !== 0x00004550) {
    return { ok: false, reason: '缺少 PE 签名（PE\\0\\0）' };
  }
  const coffOffset = peOffset + 4;
  if (coffOffset + 20 > buffer.length) {
    return { ok: false, reason: 'COFF 头越界' };
  }
  const sizeOfOptionalHeader = buffer.readUInt16LE(coffOffset + 16);
  const optionalHeaderOffset = coffOffset + 20;
  const checksumFieldOffset = optionalHeaderOffset + CHECKSUM_FIELD_OFFSET;

  if (sizeOfOptionalHeader === 0) {
    return {
      ok: true,
      optionalHeaderOffset,
      isPe32Plus: false,
      checksumFieldOffset,
      securityEntryOffset: null,
      numDataDirs: 0,
      hasOptionalHeader: false,
    };
  }
  if (optionalHeaderOffset + 2 > buffer.length) {
    return { ok: false, reason: '可选头越界' };
  }
  const magic = buffer.readUInt16LE(optionalHeaderOffset);
  const isPe32Plus = magic === 0x20b;
  const isPe32 = magic === 0x10b;
  if (!isPe32Plus && !isPe32) {
    return { ok: false, reason: `可选头魔数无法识别：0x${magic.toString(16)}` };
  }
  const numDataDirsOffset = optionalHeaderOffset + (isPe32Plus ? 108 : 92);
  const dataDirOffset = optionalHeaderOffset + (isPe32Plus ? 112 : 96);
  const numDataDirs = buffer.readUInt32LE(numDataDirsOffset);
  const securityEntryOffset =
    numDataDirs > SECURITY_DIRECTORY_INDEX ? dataDirOffset + SECURITY_DIRECTORY_INDEX * 8 : null;
  return {
    ok: true,
    optionalHeaderOffset,
    isPe32Plus,
    checksumFieldOffset,
    securityEntryOffset,
    numDataDirs,
    hasOptionalHeader: true,
  };
}

/**
 * 观察 PE：安全目录存在性与可选头 CheckSum 是否非零，并给出门控决策。
 * @param {Buffer} buffer 制品字节
 * @param {Record<string, unknown>} [policy] 策略
 * @returns {Record<string, unknown>} 观察结果
 */
export function analyzePe(buffer, policy = {}) {
  const signaturesPolicy = readSignaturesPolicy(policy);
  const base = {
    observer: 'pe-security-and-checksum',
    container: 'pe',
  };

  const located = locatePe(buffer);
  if (!located.ok) {
    return {
      ...base,
      parseable: false,
      limitation: located.reason,
      signatureDetected: false,
      checksumDetected: false,
      securityDirectory: { present: false, fileOffset: null, size: 0 },
      checksum: { value: 0, nonZero: false, fieldOffset: null },
      gate: { action: 'observe-only', requiresResign: false, reason: located.reason },
    };
  }

  let checksumValue = 0;
  if (located.hasOptionalHeader && located.checksumFieldOffset + 4 <= buffer.length) {
    checksumValue = buffer.readUInt32LE(located.checksumFieldOffset);
  }
  const checksumNonZero = checksumValue !== 0;

  let securityPresent = false;
  let securityFileOffset = null;
  let securitySize = 0;
  if (located.securityEntryOffset !== null && located.securityEntryOffset + 8 <= buffer.length) {
    securityFileOffset = buffer.readUInt32LE(located.securityEntryOffset);
    securitySize = buffer.readUInt32LE(located.securityEntryOffset + 4);
    securityPresent = securitySize > 0;
  }

  const gate = decidePeGate({
    securityPresent,
    checksumNonZero,
    signaturesPolicy,
  });

  return {
    ...base,
    parseable: true,
    limitation: located.hasOptionalHeader ? null : '对象文件无可选头，无 CheckSum 与安全目录可观察',
    signatureDetected: securityPresent,
    checksumDetected: checksumNonZero,
    securityDirectory: { present: securityPresent, fileOffset: securityFileOffset, size: securitySize },
    checksum: { value: checksumValue, nonZero: checksumNonZero, fieldOffset: located.checksumFieldOffset },
    gate,
  };
}

/**
 * 由安全目录与 CheckSum 观察结果叠加策略得出 PE 门控决策。
 * @param {{securityPresent: boolean, checksumNonZero: boolean, signaturesPolicy: {allowRewriteSigned: boolean, allowChecksumRecompute: boolean}}} input
 * @returns {{action: string, requiresResign: boolean, reason: string}}
 */
function decidePeGate({ securityPresent, checksumNonZero, signaturesPolicy }) {
  if (securityPresent) {
    if (signaturesPolicy.allowRewriteSigned) {
      return {
        action: 'allow',
        requiresResign: true,
        reason: '检测到 PE 安全目录（Authenticode 签名），策略显式允许改写，施加后须标记 requires_resign 由用户重新签名',
      };
    }
    return {
      action: 'skip-rewrite',
      requiresResign: true,
      reason: '检测到 PE 安全目录（Authenticode 签名），默认跳过改写',
    };
  }
  if (checksumNonZero) {
    if (signaturesPolicy.allowChecksumRecompute) {
      return {
        action: 'recompute-checksum',
        requiresResign: false,
        reason: '可选头 CheckSum 非零，策略允许等长重算',
      };
    }
    return {
      action: 'skip-rewrite',
      requiresResign: false,
      reason: '可选头 CheckSum 非零且策略未允许重算，按签名制品同等对待，默认跳过改写',
    };
  }
  return { action: 'allow', requiresResign: false, reason: '未检测到安全目录，CheckSum 为零' };
}

/**
 * 计算 PE 可选头 CheckSum。算法为把整份文件按 16 位字求和并折叠进位，
 * CheckSum 字段本身按零处理，最后加上文件总长度。
 * @param {Buffer} buffer 制品字节
 * @param {number} checksumFieldOffset CheckSum 字段在文件中的绝对偏移（analyzePe 的 checksum.fieldOffset）
 * @returns {number} 无符号 32 位校验和
 */
export function computePeChecksum(buffer, checksumFieldOffset) {
  const length = buffer.length;
  let sum = 0;
  for (let offset = 0; offset < length; offset += 2) {
    // CheckSum 字段占 4 字节，两个 16 位字都按零处理。
    if (offset === checksumFieldOffset || offset === checksumFieldOffset + 2) {
      continue;
    }
    const word = offset + 1 < length ? buffer.readUInt16LE(offset) : buffer[offset];
    sum += word;
    sum = (sum & 0xffff) + (sum >>> 16);
  }
  sum = (sum & 0xffff) + (sum >>> 16);
  sum = (sum + length) >>> 0;
  return sum >>> 0;
}

/** PE 安全目录与 CheckSum 观察器登记项。 */
export const PE_CHECKSUM_OBSERVER = Object.freeze({
  id: 'pe-security-and-checksum',
  containers: Object.freeze(['pe']),
  observes: 'PE 安全目录是否存在、可选头 CheckSum 是否非零',
  defaultBehavior: '默认跳过改写；CheckSum 非零时默认等长重算，无法重算时按签名制品同等对待',
  analyze: analyzePe,
  computeChecksum: computePeChecksum,
});
