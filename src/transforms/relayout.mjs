// 重布局写入类缓解措施：模型层真实信号。
// 与等长覆写的根本区别：这类写入改变文件长度与全部数据偏移，因此必须
//   1. 整体重新序列化（头区按新长度重写，数据区整体后移，一个字节都不改写内容）
//   2. 按原对齐规则重排（GGUF 按原 alignment 向上取整，safetensors 按 8 字节长度前缀语义）
//   3. 重跑全部格式校验（无越界、无间隙、无重叠、无未索引尾部），校验不过就不写出
// 各张量声明的相对偏移保持原值不变：safetensors 的 data_offsets 相对数据区起点，
// GGUF 的 data_offset 相对 tensor_data_offset，两者都不随重布局改写，只重算派生偏移。

import { inspectLegalFields } from '../notice/index.mjs';
import { readUIntLE } from '../readers/common.mjs';

/** safetensors 长度前缀字节数。 */
const SAFETENSORS_PREFIX_BYTES = 8;
/** GGUF 魔数。 */
const GGUF_MAGIC = Buffer.from('GGUF', 'latin1');
/** GGUF 元数据值类型编号。 */
const GGUF_VALUE_TYPES = Object.freeze({ 0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 8: null, 9: null, 10: 8, 11: 8, 12: 8 });
/** GGUF 张量数据类型编号到元素字节数；量化类型的块结构不在 v1 范围内。 */
const GGUF_TENSOR_TYPES = Object.freeze({ 0: 4, 1: 2, 24: 1, 25: 2, 26: 4, 27: 8, 28: 8, 29: 2 });
/** GGUF 默认对齐值，文件未声明 general.alignment 时使用。 */
const GGUF_DEFAULT_ALIGNMENT = 32;
/** 法律字段缺失时不得写入任何元数据：内容不真实即构成伪造。 */
const MODEL_METADATA_REFUSAL = '模型层元数据只能写真实法律字段，字段不齐全时拒写';

/**
 * 按对齐值向上取整。
 * @param {number} value
 * @param {number} alignment
 * @returns {number}
 */
function alignUp(value, alignment) {
  if (!Number.isSafeInteger(alignment) || alignment <= 1) {
    return value;
  }
  return Math.ceil(value / alignment) * alignment;
}

/**
 * 构造 safetensors 八字节小端长度前缀。
 * @param {number} headerLength 头部 JSON 字节数
 * @returns {Buffer}
 */
function safetensorsPrefix(headerLength) {
  const prefix = Buffer.alloc(SAFETENSORS_PREFIX_BYTES);
  prefix.writeBigUInt64LE(BigInt(headerLength));
  return prefix;
}

/**
 * 从策略法律字段派生模型元数据内容。字段不齐全时返回拒否原因，由调用方折成跳过或拒否。
 * @param {Record<string, unknown>} policy 策略
 * @returns {{ok: true, metadata: Record<string, string>} | {ok: false, omittedReason: string[]}}
 */
export function modelMetadataFromPolicy(policy) {
  const inspection = inspectLegalFields(policy ?? {});
  if (!inspection.complete) {
    return { ok: false, omittedReason: inspection.omittedReason };
  }
  const legal = policy.legal ?? {};
  return {
    ok: true,
    metadata: {
      'license.subject': String(legal.subject),
      'license.contact': String(legal.contact),
      'license.jurisdiction': String(legal.jurisdiction),
      'license.id': String(legal.licenseId),
      'license.text-source': String(legal.licenseTextSource),
      'license.prohibited-acts': (legal.prohibitedActs ?? []).map((act) => String(act)).join('；'),
      'license.consequences': (legal.consequences ?? [])
        .map((item) => `${String(item?.statement ?? '')}（法条摘录：${String(item?.statuteExcerpt ?? '')}）`)
        .join('；'),
    },
  };
}

/**
 * 校验调用方直接给出的元数据内容：必须是非空对象，键值只能是字符串或字符串数组，
 * 且不得改写 GGUF 的对齐值声明。
 * @param {unknown} metadata
 * @returns {{ok: true, metadata: Record<string, string | string[]>} | {ok: false, reason: string}}
 */
function normalizeMetadata(metadata) {
  if (metadata === null || typeof metadata !== 'object' || Array.isArray(metadata)) {
    return { ok: false, reason: '元数据必须是对象，键为槽位名，值为字符串或字符串数组' };
  }
  const entries = Object.entries(metadata);
  if (entries.length === 0) {
    return { ok: false, reason: '元数据对象为空，没有可写入的真实信号' };
  }
  for (const [key, value] of entries) {
    if (typeof key !== 'string' || key === '') {
      return { ok: false, reason: '元数据键必须是非空字符串' };
    }
    if (key === 'general.alignment') {
      return { ok: false, reason: 'general.alignment 由文件自身声明，不通过元数据写入改写对齐值' };
    }
    if (typeof value === 'string') {
      continue;
    }
    if (Array.isArray(value) && value.every((item) => typeof item === 'string')) {
      continue;
    }
    return { ok: false, reason: `元数据键 ${key} 的值只能是字符串或字符串数组` };
  }
  return { ok: true, metadata: Object.fromEntries(entries) };
}

// ---- safetensors ----

/**
 * safetensors 重布局写入：把 __metadata__ 写进头部 JSON，数据区整体后移。
 * @param {Buffer} buffer 制品字节
 * @param {{metadata?: Record<string, string | string[]>, policy?: Record<string, unknown>}} options
 * @returns {{ok: true, buffer: Buffer, ranges: Array<[number, number]>, notes: string[], relayout: Record<string, unknown>} | {ok: false, reason: string, omittedReason?: string[]}}
 */
export function writeSafetensorsMetadata(buffer, options = {}) {
  const parsed = parseSafetensors(buffer);
  if (!parsed.ok) {
    return { ok: false, reason: parsed.reason };
  }
  const resolved = resolveMetadata(options);
  if (!resolved.ok) {
    return { ok: false, reason: MODEL_METADATA_REFUSAL, omittedReason: resolved.omittedReason };
  }

  const newHeader = { ...parsed.header, __metadata__: resolved.metadata };
  const headerJson = Buffer.from(JSON.stringify(newHeader), 'utf8');
  const newBuffer = Buffer.concat([safetensorsPrefix(headerJson.length), headerJson, buffer.subarray(parsed.tensorDataOffset)]);

  const validation = validateSafetensors(newBuffer);
  if (!validation.ok) {
    return { ok: false, reason: `重布局后格式校验未通过：${validation.problems.join('；')}` };
  }
  return {
    ok: true,
    buffer: newBuffer,
    ranges: [[0, SAFETENSORS_PREFIX_BYTES + headerJson.length]],
    notes: [
      '重布局写入整体重新序列化：只重写长度前缀与 JSON 头，张量数据整体后移且内容不改写',
      '各张量 data_offsets 是相对数据区起点的相对偏移，保持原值不变',
    ],
    relayout: {
      kind: 'relayout-write',
      headerLengthBefore: parsed.headerLength,
      headerLengthAfter: headerJson.length,
      tensorDataOffsetBefore: parsed.tensorDataOffset,
      tensorDataOffsetAfter: SAFETENSORS_PREFIX_BYTES + headerJson.length,
      tensorCount: parsed.tensors.length,
      dataOffsetsUnchanged: true,
    },
  };
}

/**
 * 解析 safetensors：长度前缀、JSON 头与张量索引。
 * @param {Buffer} buffer
 * @returns {{ok: true, header: Record<string, unknown>, headerLength: number, tensorDataOffset: number, tensors: Array<Record<string, unknown>>, dataLength: number} | {ok: false, reason: string}}
 */
export function parseSafetensors(buffer) {
  if (buffer.length < 16) {
    return { ok: false, reason: '文件不足 16 字节，读不到八字节长度前缀加完整 JSON 头' };
  }
  const headerLength = Number(readUIntLE(buffer, 0, 8));
  if (!Number.isSafeInteger(headerLength) || headerLength <= 0 || SAFETENSORS_PREFIX_BYTES + headerLength > buffer.length) {
    return { ok: false, reason: `八字节长度前缀声明的头部长度 ${String(headerLength)} 不可用：头部区间超出文件范围` };
  }
  let header;
  try {
    header = JSON.parse(buffer.toString('utf8', SAFETENSORS_PREFIX_BYTES, SAFETENSORS_PREFIX_BYTES + headerLength));
  } catch (error) {
    return { ok: false, reason: `头部 JSON 解析失败：${String(error?.message ?? error)}` };
  }
  if (header === null || typeof header !== 'object' || Array.isArray(header)) {
    return { ok: false, reason: '头部 JSON 不是对象' };
  }
  const tensors = [];
  for (const [name, value] of Object.entries(header)) {
    if (name === '__metadata__') {
      continue;
    }
    const offsets = value?.data_offsets;
    if (!Array.isArray(offsets) || offsets.length !== 2 || !offsets.every((offset) => Number.isSafeInteger(offset))) {
      return { ok: false, reason: `张量 ${name} 的 data_offsets 不是两个安全整数` };
    }
    tensors.push({ name, start: offsets[0], end: offsets[1] });
  }
  return {
    ok: true,
    header,
    headerLength,
    tensorDataOffset: SAFETENSORS_PREFIX_BYTES + headerLength,
    tensors,
    dataLength: buffer.length - (SAFETENSORS_PREFIX_BYTES + headerLength),
  };
}

/**
 * 重跑 safetensors 全部格式校验：无越界、无间隙、无重叠、无未索引尾部。
 * @param {Buffer} buffer
 * @returns {{ok: true, problems: string[]} | {ok: false, problems: string[]}}
 */
export function validateSafetensors(buffer) {
  const parsed = parseSafetensors(buffer);
  if (!parsed.ok) {
    return { ok: false, problems: [parsed.reason] };
  }
  const problems = [];
  const sorted = [...parsed.tensors].sort((left, right) => left.start - right.start);
  let cursor = 0;
  for (const tensor of sorted) {
    if (tensor.end < tensor.start) {
      problems.push(`张量 ${tensor.name} 的区间起止颠倒`);
      continue;
    }
    if (tensor.end > parsed.dataLength) {
      problems.push(`张量 ${tensor.name} 的区间终点 ${tensor.end} 超出数据区长度 ${parsed.dataLength}`);
      continue;
    }
    if (tensor.start > cursor) {
      problems.push(`数据区相对偏移 ${cursor} 到 ${tensor.start} 之间存在间隙`);
    }
    if (tensor.start < cursor) {
      problems.push(`张量 ${tensor.name} 的区间与已索引区间重叠`);
    }
    cursor = Math.max(cursor, tensor.end);
  }
  if (cursor < parsed.dataLength) {
    problems.push(`数据区末尾 ${parsed.dataLength - cursor} 字节没有被任何张量索引覆盖，存在未索引尾部`);
  }
  return problems.length === 0 ? { ok: true, problems } : { ok: false, problems };
}

// ---- GGUF ----

/**
 * GGUF 重布局写入：把元数据键值写进元数据区，张量索引原样保留，
 * 按原 alignment 重新对齐后重算 tensor_data_offset，张量数据整体后移。
 * 同一键已存在且内容逐字节相同时不重复写入；内容不同时旧条目整条弃用、
 * 按本次声明更新为该键的值，不在元数据区留下重复键。
 * @param {Buffer} buffer 制品字节
 * @param {{metadata?: Record<string, string | string[]>, policy?: Record<string, unknown>}} options
 * @returns {{ok: true, buffer: Buffer, ranges: Array<[number, number]>, notes: string[], relayout: Record<string, unknown>} | {ok: false, reason: string, omittedReason?: string[]}}
 */
export function writeGgufMetadata(buffer, options = {}) {
  const parsed = parseGguf(buffer);
  if (!parsed.ok) {
    return { ok: false, reason: parsed.reason };
  }
  const resolved = resolveMetadata(options);
  if (!resolved.ok) {
    return { ok: false, reason: MODEL_METADATA_REFUSAL, omittedReason: resolved.omittedReason };
  }

  // 已存在且内容逐字节相同的键不重复写入；已存在且内容不同的键按本次声明整条替换：
  // 重布局契约就是写入本次策略的声明，留着旧值会让读取方先读到过期内容。
  const existing = new Map();
  for (const item of parsed.metadata) {
    existing.set(item.key, item.valueBytes);
  }
  const pending = {};
  const replacedKeys = new Set();
  for (const [key, value] of Object.entries(resolved.metadata)) {
    const encoded = encodeGgufValue(value);
    const current = existing.get(key);
    if (current !== undefined && current.equals(encoded)) {
      continue;
    }
    pending[key] = value;
    if (current !== undefined) {
      replacedKeys.add(key);
    }
  }
  const pendingKeys = Object.keys(pending);
  if (pendingKeys.length === 0) {
    return {
      ok: true,
      buffer,
      ranges: [],
      notes: ['元数据键值已存在且内容一致，本次没有重复写入'],
      relayout: {
        kind: 'relayout-write',
        addedKeys: [],
        alignment: parsed.alignment,
        tensorDataOffsetBefore: parsed.tensorDataOffset,
        tensorDataOffsetAfter: parsed.tensorDataOffset,
        tensorCount: parsed.tensors.length,
        dataOffsetsUnchanged: true,
      },
    };
  }

  // 未改动的条目按原字节原序保留，被替换的旧条目整条弃用，本次值追加在后。
  const kept = parsed.metadata.filter((item) => !replacedKeys.has(item.key));
  const keptBytes = Buffer.concat(kept.map((item) => item.entryBytes));
  const added = encodeGgufMetadata(pending);
  const metadataStart = parsed.metadataEnd;
  const tensorInfoEnd = parsed.position;
  const headerEnd = 24 + keptBytes.length + added.length + (tensorInfoEnd - metadataStart);
  const newTensorDataOffset = alignUp(headerEnd, parsed.alignment);
  const padding = newTensorDataOffset - headerEnd;

  // 变更区间起点：第一个被替换条目之前的内容逐字节不变，之后整体重排。
  let changeStart = metadataStart;
  let keptPrefix = 0;
  for (const item of parsed.metadata) {
    if (replacedKeys.has(item.key)) {
      changeStart = 24 + keptPrefix;
      break;
    }
    keptPrefix += item.entryBytes.length;
  }

  // 整体重新序列化：未改动条目按原字节拼接，本次值追加，张量索引原样保留，
  // 再按原 alignment 补对齐填充，最后接上原封不动的张量数据区。
  const newBuffer = Buffer.concat([
    buffer.subarray(0, 24),
    keptBytes,
    added,
    buffer.subarray(metadataStart, tensorInfoEnd),
    Buffer.alloc(padding),
    buffer.subarray(parsed.tensorDataOffset),
  ]);
  // 元数据键数按实际留存数加本次新增数重写：被替换的键不增减计数，全新键才递增。
  newBuffer.writeBigUInt64LE(BigInt(kept.length + pendingKeys.length), 16);

  const validation = validateGguf(newBuffer);
  if (!validation.ok) {
    return { ok: false, reason: `重布局后格式校验未通过：${validation.problems.join('；')}` };
  }
  const notes = [
    '重布局写入整体重新序列化：只重写元数据区与对齐填充，张量索引与张量数据原样保留',
    '各张量 data_offset 保持原值不变，tensor_data_offset 按原 alignment 重新对齐后重算',
  ];
  if (replacedKeys.size > 0) {
    notes.push(`同一键已存在且内容不同，按本次声明更新为本次值：${[...replacedKeys].join('、')}`);
  }
  return {
    ok: true,
    buffer: newBuffer,
    ranges: [[changeStart, newTensorDataOffset]],
    notes,
    relayout: {
      kind: 'relayout-write',
      addedKeys: pendingKeys,
      updatedKeys: [...replacedKeys],
      alignment: parsed.alignment,
      tensorDataOffsetBefore: parsed.tensorDataOffset,
      tensorDataOffsetAfter: newTensorDataOffset,
      tensorCount: parsed.tensors.length,
      dataOffsetsUnchanged: true,
    },
  };
}

/**
 * 解析 GGUF：头部、元数据键值区结束位置、张量索引与按原对齐规则推算的数据区起点。
 * @param {Buffer} buffer
 * @returns {{ok: true, version: number, tensorCount: number, metadataCount: number, position: number, tensorDataOffset: number, alignment: number, tensors: Array<Record<string, unknown>>} | {ok: false, reason: string}}
 */
export function parseGguf(buffer) {
  if (buffer.length < 24 || !buffer.subarray(0, 4).equals(GGUF_MAGIC)) {
    return { ok: false, reason: '文件头不是 GGUF 魔数' };
  }
  const version = readUIntLE(buffer, 4, 4);
  const tensorCount = Number(readUIntLE(buffer, 8, 8));
  const metadataCount = Number(readUIntLE(buffer, 16, 8));
  if (version === undefined || !Number.isSafeInteger(tensorCount) || !Number.isSafeInteger(metadataCount)) {
    return { ok: false, reason: 'GGUF 头字段读取越界' };
  }
  let position = 24;
  let alignment = GGUF_DEFAULT_ALIGNMENT;
  const metadata = [];
  for (let index = 0; index < metadataCount; index += 1) {
    // entryStart 记整条键值的起点：键覆盖时要按原字节重排未改动的条目，一个字节都不改写内容。
    const entryStart = position;
    const key = readGgufString(buffer, position);
    if (key === undefined) {
      return { ok: false, reason: `第 ${index} 个元数据键读取失败` };
    }
    const typeId = readUIntLE(buffer, key.next, 4);
    if (typeId === undefined) {
      return { ok: false, reason: `元数据键 ${key.value} 的值类型读取失败` };
    }
    const value = skipGgufValue(buffer, key.next + 4, typeId);
    if (value === undefined) {
      return { ok: false, reason: `元数据键 ${key.value} 的值解析失败` };
    }
    if (key.value === 'general.alignment' && typeof value.value === 'number' && value.value > 0) {
      alignment = value.value;
    }
    metadata.push({
      key: key.value,
      typeId,
      valueStart: key.next + 4,
      valueBytes: buffer.subarray(key.next + 4, value.next),
      entryBytes: buffer.subarray(entryStart, value.next),
    });
    position = value.next;
  }
  // 元数据区结束位置：新键值追加在这里，张量索引整体后移。
  const metadataEnd = position;

  const tensors = [];
  for (let index = 0; index < tensorCount; index += 1) {
    const name = readGgufString(buffer, position);
    if (name === undefined) {
      return { ok: false, reason: `第 ${index} 个张量名读取失败` };
    }
    const dimensions = readUIntLE(buffer, name.next, 4);
    if (dimensions === undefined || dimensions > 8) {
      return { ok: false, reason: `张量 ${name.value} 的维度数读取失败或超出合理范围` };
    }
    let cursor = name.next + 4;
    const shape = [];
    for (let dimension = 0; dimension < dimensions; dimension += 1) {
      const size = readUIntLE(buffer, cursor, 8);
      if (size === undefined) {
        return { ok: false, reason: `张量 ${name.value} 的维度读取失败` };
      }
      shape.push(Number(size));
      cursor += 8;
    }
    const typeId = readUIntLE(buffer, cursor, 4);
    const dataOffset = readUIntLE(buffer, cursor + 4, 8);
    if (typeId === undefined || dataOffset === undefined) {
      return { ok: false, reason: `张量 ${name.value} 的类型或偏移读取失败` };
    }
    const elementSize = GGUF_TENSOR_TYPES[typeId] ?? null;
    tensors.push({
      name: name.value,
      shape,
      typeId,
      elementSize,
      dataOffset: Number(dataOffset),
      byteLength: elementSize === null ? null : shape.reduce((total, size) => total * size, 1) * elementSize,
    });
    position = cursor + 12;
  }

  return {
    ok: true,
    version,
    tensorCount,
    metadataCount,
    metadata,
    metadataEnd,
    position,
    tensorDataOffset: alignUp(position, alignment),
    alignment,
    tensors,
  };
}

/**
 * 重跑 GGUF 全部格式校验：头部可解析、张量索引可解析、数据区起点按原对齐规则、张量区间无越界。
 * @param {Buffer} buffer
 * @returns {{ok: true, problems: string[]} | {ok: false, problems: string[]}}
 */
export function validateGguf(buffer) {
  const parsed = parseGguf(buffer);
  if (!parsed.ok) {
    return { ok: false, problems: [parsed.reason] };
  }
  const problems = [];
  if (parsed.tensorDataOffset > buffer.length) {
    problems.push(`张量数据区起点 ${parsed.tensorDataOffset} 超出文件范围 ${buffer.length}`);
  }
  for (const tensor of parsed.tensors) {
    if (tensor.byteLength === null) {
      continue;
    }
    const start = parsed.tensorDataOffset + tensor.dataOffset;
    const end = start + tensor.byteLength;
    if (start < parsed.tensorDataOffset || end > buffer.length) {
      problems.push(`张量 ${tensor.name} 的数据区间 [${start}, ${end}) 超出文件范围 ${buffer.length}`);
    }
  }
  return problems.length === 0 ? { ok: true, problems } : { ok: false, problems };
}

/**
 * 读取 GGUF 字符串：八字节小端长度前缀加字节内容。
 * @param {Buffer} buffer
 * @param {number} offset
 * @returns {{value: string, next: number} | undefined}
 */
function readGgufString(buffer, offset) {
  const length = readUIntLE(buffer, offset, 8);
  if (length === undefined || !Number.isSafeInteger(Number(length))) {
    return undefined;
  }
  const size = Number(length);
  const start = offset + 8;
  if (start + size > buffer.length) {
    return undefined;
  }
  return { value: buffer.toString('latin1', start, start + size), next: start + size };
}

/**
 * 跳过一个 GGUF 元数据值，只求结束位置。数组逐项递归，深度上限一层。
 * @param {Buffer} buffer
 * @param {number} offset
 * @param {number} typeId
 * @returns {{value: unknown, next: number} | undefined}
 */
function skipGgufValue(buffer, offset, typeId) {
  const size = GGUF_VALUE_TYPES[typeId];
  if (size === undefined) {
    return undefined;
  }
  if (size !== null) {
    if (offset + size > buffer.length) {
      return undefined;
    }
    return { value: readUIntLE(buffer, offset, size), next: offset + size };
  }
  if (typeId === 8) {
    return readGgufString(buffer, offset);
  }
  // 数组：四字节元素类型加八字节元素数量，之后逐项递归。
  const elementType = readUIntLE(buffer, offset, 4);
  const count = readUIntLE(buffer, offset + 4, 8);
  if (elementType === undefined || count === undefined) {
    return undefined;
  }
  let position = offset + 12;
  for (let index = 0; index < Number(count); index += 1) {
    const element = skipGgufValue(buffer, position, elementType);
    if (element === undefined) {
      return undefined;
    }
    position = element.next;
  }
  return { value: Number(count), next: position };
}

/**
 * 编码单个元数据值：字符串按类型 8 的值字节，字符串数组按类型 9 的值字节。
 * @param {string | string[]} value
 * @returns {Buffer}
 */
function encodeGgufValue(value) {
  if (typeof value === 'string') {
    return encodeGgufString(value);
  }
  const parts = [uint32(8), uint64(BigInt(value.length))];
  for (const item of value) {
    parts.push(encodeGgufString(item));
  }
  return Buffer.concat(parts);
}

/**
 * 把元数据对象编码成 GGUF 元数据键值字节序列。
 * 每个键值由键字符串、值类型编号与值字节组成。
 * @param {Record<string, string | string[]>} metadata
 * @returns {Buffer}
 */
function encodeGgufMetadata(metadata) {
  const parts = [];
  for (const [key, value] of Object.entries(metadata)) {
    parts.push(encodeGgufString(key));
    if (typeof value === 'string') {
      parts.push(uint32(8));
      parts.push(encodeGgufString(value));
      continue;
    }
    parts.push(uint32(9));
    parts.push(encodeGgufValue(value));
  }
  return Buffer.concat(parts);
}

/**
 * 编码 GGUF 字符串：八字节小端长度前缀加字节内容。
 * @param {string} value
 * @returns {Buffer}
 */
function encodeGgufString(value) {
  const bytes = Buffer.from(value, 'utf8');
  return Buffer.concat([uint64(BigInt(bytes.length)), bytes]);
}

/** @returns {Buffer} 四字节小端无符号整数 */
function uint32(value) {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32LE(value >>> 0);
  return buffer;
}

/** @returns {Buffer} 八字节小端无符号整数 */
function uint64(value) {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64LE(BigInt(value));
  return buffer;
}

/**
 * 解析元数据来源：优先调用方直接给出的内容，缺失时从策略法律字段派生。
 * @param {{metadata?: unknown, policy?: Record<string, unknown>}} options
 * @returns {{ok: true, metadata: Record<string, string | string[]>} | {ok: false, reason?: string, omittedReason?: string[]}}
 */
function resolveMetadata(options) {
  if (options?.metadata !== undefined) {
    return normalizeMetadata(options.metadata);
  }
  const derived = modelMetadataFromPolicy(options?.policy ?? {});
  if (!derived.ok) {
    return { ok: false, omittedReason: derived.omittedReason };
  }
  return { ok: true, metadata: derived.metadata };
}
