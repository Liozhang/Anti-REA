// ZIP 条目 CRC32 与中央目录一致性观察器。
// 只读：解析本地文件头、中央目录与结尾记录，逐条目比对 CRC32，不修改任何字节。
// deflate 条目用 node:zlib 的 inflateRawSync 解压后计算 CRC32；解压失败或超出预算时退回原始字节并附限制说明。
// 观察结果是写入型工具的门：条目改写后必须同帧重算 CRC32，否则复审判定不通过。

import { inflateRawSync } from 'node:zlib';

import { crc32 } from './crc32.mjs';

/** 本地文件头签名 PK\x03\x04。 */
const LOCAL_FILE_HEADER_SIG = 0x04034b50;
/** 中央目录文件头签名 PK\x01\x02。 */
const CENTRAL_DIR_SIG = 0x02014b50;
/** 结尾记录签名 PK\x05\x06。 */
const EOCD_SIG = 0x06054b50;
/** 通用目的标志位第 3 位：CRC 与尺寸写在数据描述符里。 */
const FLAG_DATA_DESCRIPTOR = 0x0008;

/** 压缩方法编号到名称。 */
const METHOD_NAMES = Object.freeze({ 0: 'stored', 8: 'deflate' });

/**
 * 从缓冲区末尾向前定位结尾记录（EOCD），容忍注释字节。
 * @param {Buffer} buffer
 * @returns {number} EOCD 起始偏移，未找到返回 -1
 */
function findEocd(buffer) {
  const minEocd = 22;
  if (buffer.length < minEocd) {
    return -1;
  }
  const maxComment = 0xffff;
  const scanFloor = Math.max(0, buffer.length - minEocd - maxComment);
  for (let offset = buffer.length - minEocd; offset >= scanFloor; offset -= 1) {
    if (buffer.readUInt32LE(offset) !== EOCD_SIG) {
      continue;
    }
    const commentLength = buffer.readUInt16LE(offset + 20);
    if (offset + minEocd + commentLength === buffer.length) {
      return offset;
    }
  }
  return -1;
}

/**
 * 观察 ZIP：逐条目比对 CRC32 与中央目录记录。
 * @param {Buffer} buffer 制品字节
 * @param {Record<string, unknown>} [policy] 策略
 * @returns {Record<string, unknown>} 观察结果
 */
export function analyzeZip(buffer, policy = {}) {
  const base = {
    observer: 'zip-entry-crc32',
    container: 'zip',
    signatureDetected: false,
    checksumDetected: false,
  };

  if (!Buffer.isBuffer(buffer) || buffer.length < 22) {
    return { ...base, parseable: false, limitation: '缓冲区过小，不构成 ZIP', gate: allowGate(), entries: [], hasCentralDirectory: false, allCrcConsistent: null, inconsistentEntryCount: 0 };
  }

  const eocd = findEocd(buffer);
  if (eocd < 0) {
    return {
      ...base,
      parseable: false,
      limitation: '未找到结尾记录（PK\\x05\\x06），无法定位中央目录',
      gate: allowGate(),
      entries: [],
      hasCentralDirectory: false,
      allCrcConsistent: null,
      inconsistentEntryCount: 0,
    };
  }

  const totalEntries = buffer.readUInt16LE(eocd + 10);
  const centralDirOffset = buffer.readUInt32LE(eocd + 16);
  const centralDirSize = buffer.readUInt32LE(eocd + 12);

  if (centralDirOffset > buffer.length) {
    return {
      ...base,
      parseable: false,
      limitation: `中央目录偏移 ${centralDirOffset} 超出文件长度 ${buffer.length}`,
      gate: allowGate(),
      entries: [],
      hasCentralDirectory: true,
      allCrcConsistent: null,
      inconsistentEntryCount: 0,
    };
  }

  const entries = [];
  const limitations = [];
  let inconsistent = 0;
  let position = centralDirOffset;
  const centralDirEnd = Math.min(buffer.length, centralDirOffset + centralDirSize);

  for (let index = 0; index < totalEntries; index += 1) {
    if (position + 46 > centralDirEnd || buffer.readUInt32LE(position) !== CENTRAL_DIR_SIG) {
      limitations.push(`第 ${index + 1} 个中央目录项签名不符或越界，停止枚举`);
      break;
    }
    const flags = buffer.readUInt16LE(position + 8);
    const method = buffer.readUInt16LE(position + 10);
    const crcCentral = buffer.readUInt32LE(position + 16);
    const compressedSize = buffer.readUInt32LE(position + 20);
    const uncompressedSize = buffer.readUInt32LE(position + 24);
    const nameLength = buffer.readUInt16LE(position + 28);
    const extraLength = buffer.readUInt16LE(position + 30);
    const commentLength = buffer.readUInt16LE(position + 32);
    const localOffset = buffer.readUInt32LE(position + 42);
    const nameStart = position + 46;
    const name = buffer.toString('utf8', nameStart, nameStart + nameLength);

    const entry = {
      name,
      method,
      methodName: METHOD_NAMES[method] ?? `method-${method}`,
      crcCentralDirectory: crcCentral,
      crcLocalHeader: null,
      crcComputed: null,
      scanMode: 'raw-bytes',
      contentAvailable: false,
      declaredConsistent: null,
      computedConsistent: null,
      consistent: null,
      usesDataDescriptor: (flags & FLAG_DATA_DESCRIPTOR) !== 0,
      compressedSize,
      uncompressedSize,
    };

    if (localOffset + 30 > buffer.length || buffer.readUInt32LE(localOffset) !== LOCAL_FILE_HEADER_SIG) {
      entry.consistent = false;
      entry.declaredConsistent = false;
      entry.limitation = '本地文件头缺失或越界，无法比对';
      inconsistent += 1;
    } else {
      entry.crcLocalHeader = buffer.readUInt32LE(localOffset + 14);
      const localNameLength = buffer.readUInt16LE(localOffset + 26);
      const localExtraLength = buffer.readUInt16LE(localOffset + 28);
      const dataStart = localOffset + 30 + localNameLength + localExtraLength;
      const dataEnd = dataStart + compressedSize;

      // 计算内容 CRC32：存储条目直接对原始字节计算，deflate 条目先解压再计算。
      if (dataEnd <= buffer.length) {
        const rawData = buffer.subarray(dataStart, dataEnd);
        if (method === 0) {
          entry.crcComputed = crc32(rawData);
          entry.scanMode = 'raw-bytes';
          entry.contentAvailable = true;
        } else if (method === 8) {
          try {
            const inflated = inflateRawSync(rawData);
            entry.crcComputed = crc32(inflated);
            entry.scanMode = 'decompressed';
            entry.contentAvailable = true;
          } catch {
            entry.scanMode = 'raw-bytes';
            entry.contentAvailable = false;
            entry.limitation = 'deflate 条目解压失败，仅按原始字节扫描';
          }
        } else {
          entry.limitation = `压缩方法 ${method} 不在已支持范围，仅按原始字节扫描`;
        }
      } else {
        entry.limitation = '条目数据越界，无法读取内容';
      }

      entry.declaredConsistent = entry.usesDataDescriptor ? null : entry.crcLocalHeader === crcCentral;
      entry.computedConsistent = entry.crcComputed === null ? null : entry.crcComputed === crcCentral;
      const declaredOk = entry.declaredConsistent !== false;
      const computedOk = entry.computedConsistent !== false;
      entry.consistent = declaredOk && computedOk;
      if (!entry.consistent) {
        inconsistent += 1;
      }
    }

    entries.push(entry);
    position += 46 + nameLength + extraLength + commentLength;
  }

  return {
    ...base,
    parseable: true,
    limitation: limitations.length > 0 ? limitations.join('；') : null,
    checksumDetected: entries.length > 0,
    hasCentralDirectory: true,
    entries,
    allCrcConsistent: inconsistent === 0,
    inconsistentEntryCount: inconsistent,
    gate: {
      action: 'allow',
      requiresResign: false,
      reason:
        entries.length > 0
          ? 'ZIP 条目可改写，但改写后必须同帧重算 CRC32，否则复审判定不通过'
          : '没有可枚举的 ZIP 条目',
    },
  };
}

/**
 * ZIP 观察器不涉及代码签名，改写不触发重新签名；CRC32 一致性由复审校验。
 * @returns {{action: string, requiresResign: boolean, reason: string | null}}
 */
function allowGate() {
  return { action: 'allow', requiresResign: false, reason: null };
}

/** ZIP 条目 CRC32 观察器登记项。 */
export const ZIP_CRC32_OBSERVER = Object.freeze({
  id: 'zip-entry-crc32',
  containers: Object.freeze(['zip']),
  observes: 'ZIP 条目 CRC32 与中央目录记录是否一致',
  defaultBehavior: '条目改写后必须同帧重算 CRC32，否则判定复审不通过',
  analyze: analyzeZip,
});
