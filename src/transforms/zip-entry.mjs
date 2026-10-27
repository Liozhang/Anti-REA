// ZIP 条目定位与同帧 CRC32 重算。
// 规则来自设计文档：ZIP 条目改写必须同帧重算 CRC32，
// 即本地文件头与中央目录两处记录在同一遍写入里一起更新，避免出现“内容已改、记录未改”的半帧状态。
// 本文件只做定位与重算，不解压、不执行制品内代码。

import { readUIntLE } from '../readers/common.mjs';
import { crc32 } from '../signatures/crc32.mjs';

/** ZIP 签名。 */
const SIGNATURES = Object.freeze({
  local: Buffer.from('PK\x03\x04', 'latin1'),
  central: Buffer.from('PK\x01\x02', 'latin1'),
  eocd: Buffer.from('PK\x05\x06', 'latin1'),
  descriptor: Buffer.from('PK\x07\x08', 'latin1'),
});

/** 本地文件头里 CRC32 字段相对本地头起点的偏移。 */
const LOCAL_CRC_OFFSET = 14;
/** 中央目录项里 CRC32 字段相对中央目录项起点的偏移。 */
const CENTRAL_CRC_OFFSET = 16;
/** 通用目的标志位第 3 位：数据描述符承载 CRC32 与大小。 */
const FLAG_DATA_DESCRIPTOR = 0x08;

/**
 * 在字节区间内查找子序列，返回全部命中偏移。
 * @param {Buffer} bytes
 * @param {Buffer} needle
 * @param {{from?: number}} [range]
 * @returns {number[]}
 */
function findAll(bytes, needle, range = {}) {
  const hits = [];
  const from = Math.max(0, range.from ?? 0);
  let position = from;
  while (position + needle.length <= bytes.length) {
    const found = bytes.indexOf(needle, position);
    if (found < 0) {
      break;
    }
    hits.push(found);
    position = found + 1;
  }
  return hits;
}

/**
 * 定位 ZIP 的中央目录与逐条目本地文件头，返回每个条目的数据区间。
 * 解析失败返回 {ok: false, reason}，由调用方转成跳过原因。
 * @param {Buffer} bytes 整个 ZIP 文件字节
 * @returns {{ok: true, entries: Array<Record<string, unknown>>} | {ok: false, reason: string}}
 */
export function locateZipEntries(bytes) {
  const eocdHits = findAll(bytes, SIGNATURES.eocd, { from: Math.max(0, bytes.length - 65557) });
  let eocd = null;
  // 从后向前取：中央目录紧挨在结尾记录之前，注释里可能出现签名字节。
  for (let index = eocdHits.length - 1; index >= 0; index -= 1) {
    const offset = eocdHits[index];
    if (offset + 22 > bytes.length) {
      continue;
    }
    const cdOffset = readUIntLE(bytes, offset + 16, 4);
    const cdSize = readUIntLE(bytes, offset + 12, 4);
    if (cdOffset === undefined || cdSize === undefined) {
      continue;
    }
    if (cdOffset + cdSize <= offset) {
      eocd = { offset, cdOffset, cdSize };
      break;
    }
  }
  if (eocd === null) {
    return { ok: false, reason: '文件尾部找不到中央目录结尾记录，无法定位条目' };
  }

  const entries = [];
  const end = Math.min(bytes.length, eocd.cdOffset + eocd.cdSize);
  let position = eocd.cdOffset;
  while (position + 46 <= end) {
    if (!bytes.subarray(position, position + 4).equals(SIGNATURES.central)) {
      return { ok: false, reason: `中央目录偏移 ${position} 处不是中央目录文件头签名` };
    }
    const flags = readUIntLE(bytes, position + 8, 2);
    const method = readUIntLE(bytes, position + 10, 2);
    const crc32Recorded = readUIntLE(bytes, position + 16, 4);
    const compressedSize = readUIntLE(bytes, position + 20, 4);
    const nameLength = readUIntLE(bytes, position + 28, 2);
    const extraLength = readUIntLE(bytes, position + 30, 2);
    const commentLength = readUIntLE(bytes, position + 32, 2);
    const localOffset = readUIntLE(bytes, position + 42, 4);
    if ([flags, method, crc32Recorded, compressedSize, nameLength, extraLength, commentLength, localOffset].some((value) => value === undefined)) {
      return { ok: false, reason: `中央目录偏移 ${position} 处的条目字段读取越界` };
    }
    const nameEnd = position + 46 + nameLength;
    if (nameEnd > end) {
      return { ok: false, reason: `中央目录偏移 ${position} 处的条目名超出范围` };
    }
    entries.push({
      name: bytes.subarray(position + 46, nameEnd).toString('latin1'),
      flags,
      method,
      crc32: crc32Recorded,
      compressedSize,
      centralOffset: position,
      localOffset,
    });
    position = nameEnd + extraLength + commentLength;
  }
  if (entries.length === 0) {
    return { ok: false, reason: '中央目录里没有解析到条目' };
  }

  for (const entry of entries) {
    const base = entry.localOffset;
    if (base + 30 > bytes.length || !bytes.subarray(base, base + 4).equals(SIGNATURES.local)) {
      entry.localReadable = false;
      continue;
    }
    const nameLength = readUIntLE(bytes, base + 26, 2);
    const extraLength = readUIntLE(bytes, base + 28, 2);
    if (nameLength === undefined || extraLength === undefined) {
      entry.localReadable = false;
      continue;
    }
    entry.localReadable = true;
    entry.localBase = base;
    entry.dataStart = base + 30 + nameLength + extraLength;
    entry.dataEnd = entry.dataStart + entry.compressedSize;
    entry.hasDataDescriptor = (entry.flags & FLAG_DATA_DESCRIPTOR) !== 0;
  }
  return { ok: true, entries };
}

/**
 * 找出数据区间覆盖指定偏移的存储条目（压缩方法 0）。压缩条目不能等长覆写，不参与查找。
 * @param {Array<Record<string, unknown>>} entries locateZipEntries 的条目
 * @param {number} offset 文件内偏移
 * @returns {Record<string, unknown> | null}
 */
export function findStoredEntryAt(entries, offset) {
  for (const entry of entries) {
    if (entry.method !== 0 || entry.localReadable !== true) {
      continue;
    }
    if (offset >= entry.dataStart && offset < entry.dataEnd) {
      return entry;
    }
  }
  return null;
}

/**
 * 同帧重算条目 CRC32：按改写后的条目数据重算，并写回本地文件头、中央目录项，
 * 以及通用目的标志位第 3 位置位时的数据描述符。就地修改，调用方传入可写缓冲区。
 * @param {Buffer} bytes 可写缓冲区
 * @param {Record<string, unknown>} entry locateZipEntries 给出的条目
 * @returns {{before: number, after: number} | null} 条目数据不可读时返回 null
 */
export function patchEntryCrc32(bytes, entry) {
  if (entry.localReadable !== true || entry.dataEnd > bytes.length) {
    return null;
  }
  const before = bytes.readUInt32LE(entry.localBase + LOCAL_CRC_OFFSET);
  const after = crc32(bytes.subarray(entry.dataStart, entry.dataEnd));
  bytes.writeUInt32LE(after, entry.localBase + LOCAL_CRC_OFFSET);
  bytes.writeUInt32LE(after, entry.centralOffset + CENTRAL_CRC_OFFSET);
  if (entry.hasDataDescriptor) {
    // 数据描述符：可选四字节签名 PK\x07\x08，之后依次是 CRC32、压缩大小、未压缩大小。
    const descriptor = entry.dataEnd;
    const crcField = bytes.subarray(descriptor, descriptor + 4).equals(SIGNATURES.descriptor) ? descriptor + 4 : descriptor;
    if (crcField + 4 <= bytes.length) {
      bytes.writeUInt32LE(after, crcField);
    }
  }
  return { before, after };
}
