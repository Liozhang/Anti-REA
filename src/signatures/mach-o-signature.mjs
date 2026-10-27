// Mach-O LC_CODE_SIGNATURE 观察器。
// 只读：解析 Mach-O 头与加载命令，查找 LC_CODE_SIGNATURE（0x1d）；胖二进制先解析 fat 头再逐分片检查。
// 只观察不验证密码学信任：回答“分片是否带代码签名加载命令”，不回答“签名是否可信”。
// 默认行为：命中后跳过改写；策略显式允许时施加并在输出中标记 requires_resign。

import { readSignaturesPolicy } from './policy.mjs';

/** LC_CODE_SIGNATURE 加载命令编号。 */
const LC_CODE_SIGNATURE = 0x1d;

/**
 * 按字节序读取 16 位无符号整数。
 * @param {Buffer} buffer
 * @param {number} offset
 * @param {boolean} swapped 是否字节交换
 * @returns {number}
 */
function readU16(buffer, offset, swapped) {
  return swapped ? buffer.readUInt16BE(offset) : buffer.readUInt16LE(offset);
}

/**
 * 按字节序读取 32 位无符号整数。
 * @param {Buffer} buffer
 * @param {number} offset
 * @param {boolean} swapped
 * @returns {number}
 */
function readU32(buffer, offset, swapped) {
  return swapped ? buffer.readUInt32BE(offset) : buffer.readUInt32LE(offset);
}

/**
 * 识别 Mach-O 魔数，判定位数与字节序。
 * @param {Buffer} buffer
 * @returns {{fat: true} | {fat: false, bits: 32 | 64, swapped: boolean} | null}
 */
function readMagic(buffer) {
  if (buffer.length < 4) {
    return null;
  }
  const le = buffer.readUInt32LE(0);
  if (le === 0xfeedface) {
    return { fat: false, bits: 32, swapped: false };
  }
  if (le === 0xcefaedfe) {
    return { fat: false, bits: 32, swapped: true };
  }
  if (le === 0xfeedfacf) {
    return { fat: false, bits: 64, swapped: false };
  }
  if (le === 0xcffaedfe) {
    return { fat: false, bits: 64, swapped: true };
  }
  // 胖二进制头按大端存储；以小端读出为 0xbebafeca。
  if (le === 0xbebafeca) {
    return { fat: true };
  }
  return null;
}

/**
 * 解析单个瘦 Mach-O 分片的加载命令，查找 LC_CODE_SIGNATURE。
 * @param {Buffer} buffer 整个制品字节
 * @param {number} sliceOffset 分片起点
 * @param {{bits: 32 | 64, swapped: boolean}} layout
 * @returns {{hasCodeSignature: boolean, codeSignature: {dataoff: number, datasize: number} | null, limitation: string | null}}
 */
function analyzeSlice(buffer, sliceOffset, layout) {
  const headerSize = layout.bits === 64 ? 32 : 28;
  if (sliceOffset + headerSize > buffer.length) {
    return { hasCodeSignature: false, codeSignature: null, limitation: '分片头越界' };
  }
  const ncmds = readU32(buffer, sliceOffset + 16, layout.swapped);
  let position = sliceOffset + headerSize;
  let hasCodeSignature = false;
  let codeSignature = null;
  let limitation = null;

  for (let index = 0; index < ncmds; index += 1) {
    if (position + 8 > buffer.length) {
      limitation = `第 ${index + 1} 个加载命令头越界，停止枚举`;
      break;
    }
    const cmd = readU32(buffer, position, layout.swapped);
    const cmdsize = readU32(buffer, position + 4, layout.swapped);
    if (cmdsize < 8 || position + cmdsize > buffer.length) {
      limitation = `第 ${index + 1} 个加载命令尺寸 ${cmdsize} 非法或越界，停止枚举`;
      break;
    }
    if (cmd === LC_CODE_SIGNATURE) {
      hasCodeSignature = true;
      codeSignature = {
        dataoff: readU32(buffer, position + 8, layout.swapped),
        datasize: readU32(buffer, position + 12, layout.swapped),
      };
    }
    position += cmdsize;
  }
  return { hasCodeSignature, codeSignature, limitation };
}

/**
 * 观察 Mach-O（瘦或胖）是否带 LC_CODE_SIGNATURE，并给出门控决策。
 * @param {Buffer} buffer 制品字节
 * @param {Record<string, unknown>} [policy] 策略
 * @returns {Record<string, unknown>} 观察结果
 */
export function analyzeMacho(buffer, policy = {}) {
  const signaturesPolicy = readSignaturesPolicy(policy);
  const base = {
    observer: 'mach-o-code-signature',
    container: 'mach-o',
  };

  const magic = readMagic(buffer);
  if (magic === null) {
    return {
      ...base,
      parseable: false,
      limitation: '魔数不是 Mach-O 或胖二进制',
      signatureDetected: false,
      isFat: false,
      slices: [],
      gate: { action: 'observe-only', requiresResign: false, reason: '无法解析 Mach-O 结构' },
    };
  }

  const limitations = [];
  let slices = [];
  let isFat = false;

  if (magic.fat) {
    isFat = true;
    if (buffer.length < 8) {
      return {
        ...base,
        container: 'mach-o-fat',
        parseable: false,
        limitation: '胖二进制头越界',
        signatureDetected: false,
        isFat: true,
        slices: [],
        gate: { action: 'observe-only', requiresResign: false, reason: '胖二进制头越界' },
      };
    }
    const nfat = buffer.readUInt32BE(4);
    let archPosition = 8;
    for (let index = 0; index < nfat; index += 1) {
      if (archPosition + 20 > buffer.length) {
        limitations.push(`第 ${index + 1} 个 fat_arch 越界，停止枚举`);
        break;
      }
      const sliceOffset = buffer.readUInt32BE(archPosition + 8);
      const sliceSize = buffer.readUInt32BE(archPosition + 12);
      const sliceMagic = readMagic(buffer.subarray(sliceOffset, sliceOffset + sliceSize));
      let sliceResult;
      if (sliceMagic === null || sliceMagic.fat) {
        sliceResult = { hasCodeSignature: false, codeSignature: null, limitation: '分片魔数无法识别' };
      } else {
        sliceResult = analyzeSlice(buffer, sliceOffset, sliceMagic);
      }
      slices.push({ offset: sliceOffset, size: sliceSize, ...sliceResult });
      if (sliceResult.limitation !== null) {
        limitations.push(sliceResult.limitation);
      }
      archPosition += 20;
    }
  } else {
    const sliceResult = analyzeSlice(buffer, 0, magic);
    slices = [{ offset: 0, size: buffer.length, ...sliceResult }];
    if (sliceResult.limitation !== null) {
      limitations.push(sliceResult.limitation);
    }
  }

  const hasCodeSignature = slices.some((slice) => slice.hasCodeSignature);
  const gate = decideMachoGate({ hasCodeSignature, signaturesPolicy });

  return {
    ...base,
    container: isFat ? 'mach-o-fat' : 'mach-o',
    parseable: true,
    limitation: limitations.length > 0 ? limitations.join('；') : null,
    signatureDetected: hasCodeSignature,
    checksumDetected: false,
    isFat,
    slices,
    gate,
  };
}

/**
 * 由 LC_CODE_SIGNATURE 观察结果叠加策略得出 Mach-O 门控决策。
 * @param {{hasCodeSignature: boolean, signaturesPolicy: {allowRewriteSigned: boolean, allowChecksumRecompute: boolean}}} input
 * @returns {{action: string, requiresResign: boolean, reason: string}}
 */
function decideMachoGate({ hasCodeSignature, signaturesPolicy }) {
  if (hasCodeSignature) {
    if (signaturesPolicy.allowRewriteSigned) {
      return {
        action: 'allow',
        requiresResign: true,
        reason: '检测到 LC_CODE_SIGNATURE，策略显式允许改写，施加后须标记 requires_resign 由用户重新签名',
      };
    }
    return { action: 'skip-rewrite', requiresResign: true, reason: '检测到 LC_CODE_SIGNATURE，默认跳过改写' };
  }
  return { action: 'allow', requiresResign: false, reason: '未检测到 LC_CODE_SIGNATURE' };
}

/** Mach-O LC_CODE_SIGNATURE 观察器登记项。 */
export const MACHO_SIGNATURE_OBSERVER = Object.freeze({
  id: 'mach-o-code-signature',
  containers: Object.freeze(['mach-o', 'mach-o-fat']),
  observes: 'LC_CODE_SIGNATURE 加载命令是否存在',
  defaultBehavior: '默认跳过改写；策略显式允许时施加并在输出中标记 requires_resign',
  analyze: analyzeMacho,
});
