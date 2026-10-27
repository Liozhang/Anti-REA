// 签名与校验和观察器。
// 只观察不验证密码学信任：回答“这个制品是否带签名或校验和机制”，不回答“签名是否可信”。
// 观察结果是写入型工具的安全门：命中签名或校验和机制的制品默认跳过改写。
//
// 读取全部在进程内完成：不启动目标、不附加进程、不发起网络请求，只用 Node.js 内置模块。
// 每个观察器对一个容器字节缓冲区做只读解析，返回统一的观察信封（见 policy.mjs 的 Observation）。

import { open } from 'node:fs/promises';

import { crc32 } from './crc32.mjs';
import { ZIP_CRC32_OBSERVER } from './zip-crc32.mjs';
import { PE_CHECKSUM_OBSERVER } from './pe-checksum.mjs';
import { MACHO_SIGNATURE_OBSERVER } from './mach-o-signature.mjs';
import { ELF_NOTE_OBSERVER } from './elf-note.mjs';

export { crc32 } from './crc32.mjs';
export { analyzeZip } from './zip-crc32.mjs';
export { analyzePe, computePeChecksum } from './pe-checksum.mjs';
export { analyzeMacho } from './mach-o-signature.mjs';
export { analyzeElf } from './elf-note.mjs';
export { readSignaturesPolicy } from './policy.mjs';

/** v1 的四个观察器。 */
export const SIGNATURE_OBSERVERS = Object.freeze([
  ZIP_CRC32_OBSERVER,
  PE_CHECKSUM_OBSERVER,
  MACHO_SIGNATURE_OBSERVER,
  ELF_NOTE_OBSERVER,
]);

/**
 * 按容器取观察器。
 * @param {string} containerType 容器标识
 * @returns {readonly Record<string, unknown>[]}
 */
export function observersForContainer(containerType) {
  return SIGNATURE_OBSERVERS.filter((observer) => observer.containers.includes(containerType));
}

/**
 * 对一段字节按容器分派观察器。未给容器时运行全部观察器，由各自自校验格式。
 * @param {Buffer} buffer 制品字节
 * @param {string} [containerType] 容器标识；省略时尝试全部观察器
 * @param {{policy?: Record<string, unknown>}} [options]
 * @returns {Array<Record<string, unknown>>} 观察结果列表
 */
export function analyzeByContainer(buffer, containerType, options = {}) {
  const policy = options.policy ?? {};
  const observers = containerType ? observersForContainer(containerType) : SIGNATURE_OBSERVERS;
  const results = [];
  for (const observer of observers) {
    try {
      results.push(observer.analyze(buffer, policy));
    } catch (error) {
      results.push({
        observer: observer.id,
        container: containerType ?? 'unknown',
        parseable: false,
        limitation: `观察器执行异常：${error instanceof Error ? error.message : String(error)}`,
        signatureDetected: false,
        checksumDetected: false,
        gate: { action: 'observe-only', requiresResign: false, reason: '观察器执行异常' },
      });
    }
  }
  return results;
}

/**
 * 读取制品文件并按容器分派观察器。读取量受单文件上限约束，超限时附限制说明而非失败。
 * @param {string} path 制品文件路径
 * @param {{container?: string, policy?: Record<string, unknown>, budgets?: {maxFileBytes?: number}, io?: {open: Function}}} [options]
 * @returns {Promise<{path: string, bytes: number, bytesRead: number, truncated: boolean, observations: Array<Record<string, unknown>>}>}
 */
export async function observeFile(path, options = {}) {
  const policy = options.policy ?? {};
  const budgets = options.budgets ?? policy.budgets ?? {};
  const maxFileBytes = budgets.maxFileBytes ?? Number.POSITIVE_INFINITY;
  const openFn = options.io?.open ?? open;

  const handle = await openFn(path, 'r');
  let bytes = 0;
  let bytesRead = 0;
  let used = Buffer.alloc(0);
  try {
    const info = await handle.stat();
    bytes = info.size;
    const wanted = Math.min(info.size, Math.max(maxFileBytes, 0));
    const buffer = Buffer.alloc(wanted);
    const read = wanted > 0 ? await handle.read(buffer, 0, wanted, 0) : { bytesRead: 0 };
    bytesRead = read.bytesRead;
    used = buffer.subarray(0, bytesRead);
  } finally {
    await handle.close();
  }

  const truncated = bytes > bytesRead;
  const observations = analyzeByContainer(used, options.container, { policy });
  if (truncated) {
    const note = `文件超过单文件上限，仅读取前 ${bytesRead} 字节（共 ${bytes} 字节）`;
    for (const observation of observations) {
      observation.limitation = observation.limitation ? `${observation.limitation}；${note}` : note;
    }
  }
  return { path, bytes, bytesRead, truncated, observations };
}

/** APK 签名方案的能力边界：不在 v1 范围内，明确写出而不是静默跳过。 */
export const APK_SIGNATURE_BOUNDARY = Object.freeze({
  id: 'apk-signature-scheme',
  label: 'APK 签名方案',
  reason: 'v1 签名观察器不含 APK v2 及以上签名块解析，带签名块的 ZIP 只能按普通 ZIP 条目处理',
  hint: 'APK 签名块验证需要独立的签名方案解析，属后续版本范围',
});
