// GGUF 读取器：头部、元数据键值与张量偏移的事实提取。
// 只读：按 GGUF 规范的类型编号逐个解析元数据键值与张量信息，按原对齐规则推算张量数据区起点。
// 每条发现都附读取器自身限制；解析不到的部分转成限制说明，不让审计失败。

import { createFinding } from '../audit/finding.mjs';
import { defineReader, isPrintableAscii, limitation, readEntryBytes, readUIntLE, sanitizeExcerpt, truncationLimitation } from './common.mjs';
import { appendTokenScan } from './scan.mjs';

/** GGUF 魔数。 */
const GGUF_MAGIC = Buffer.from('GGUF', 'latin1');

/** 元数据值类型编号。 */
const VALUE_TYPES = Object.freeze({
  0: { name: 'u8', size: 1 },
  1: { name: 'i8', size: 1 },
  2: { name: 'u16', size: 2 },
  3: { name: 'i16', size: 2 },
  4: { name: 'u32', size: 4 },
  5: { name: 'i32', size: 4 },
  6: { name: 'f32', size: 4 },
  7: { name: 'bool', size: 1 },
  8: { name: 'string', size: null },
  9: { name: 'array', size: null },
  10: { name: 'u64', size: 8 },
  11: { name: 'i64', size: 8 },
  12: { name: 'f64', size: 8 },
});

/**
 * 张量数据类型编号到类型名与元素字节数。量化类型的块结构不在 v1 范围内，只登记名称。
 * 复审与写入侧都从这里取，避免三处各写一份 approximations 互相漂移。
 */
export const GGUF_TENSOR_TYPES = Object.freeze({
  0: { name: 'F32', size: 4 },
  1: { name: 'F16', size: 2 },
  6: { name: 'Q5_0', size: null },
  7: { name: 'Q5_1', size: null },
  8: { name: 'Q8_0', size: null },
  10: { name: 'Q2_K', size: null },
  11: { name: 'Q3_K', size: null },
  12: { name: 'Q4_K', size: null },
  13: { name: 'Q5_K', size: null },
  14: { name: 'Q6_K', size: null },
  24: { name: 'I8', size: 1 },
  25: { name: 'I16', size: 2 },
  26: { name: 'I32', size: 4 },
  27: { name: 'I64', size: 8 },
  28: { name: 'F64', size: 8 },
  29: { name: 'BF16', size: 2 },
});

/** 单个文件最多登记的元数据键数，超出部分在限制说明里声明。 */
const METADATA_KEY_LIMIT = 128;

/** 单个文件最多登记的张量数，超出部分在限制说明里声明。 */
const TENSOR_LIMIT = 4096;

/**
 * 按对齐值向上取整。
 * @param {number} value
 * @param {number} alignment
 * @returns {number}
 */
function alignUp(value, alignment) {
  if (alignment <= 1) {
    return value;
  }
  return Math.ceil(value / alignment) * alignment;
}

/**
 * 读取 GGUF 字符串：八字节小端长度前缀加字节内容。
 * @param {Buffer} bytes
 * @param {number} offset
 * @returns {{value: string, next: number} | undefined}
 */
function readString(bytes, offset) {
  const length = readUIntLE(bytes, offset, 8);
  if (length === undefined || length > bytes.length) {
    return undefined;
  }
  const start = offset + 8;
  const end = start + length;
  if (end > bytes.length) {
    return undefined;
  }
  const raw = bytes.subarray(start, end);
  return { value: isPrintableAscii(raw) ? raw.toString('latin1') : sanitizeExcerpt(raw, 64), next: end, raw };
}

/**
 * 解析一个元数据值。数组逐项递归，深度上限一层，避免畸形结构造成超长循环。
 * @param {Buffer} bytes
 * @param {number} offset
 * @param {number} typeId
 * @returns {{value: unknown, next: number} | undefined}
 */
function readValue(bytes, offset, typeId) {
  const type = VALUE_TYPES[typeId];
  if (type === undefined) {
    return undefined;
  }
  if (type.name === 'string') {
    return readString(bytes, offset);
  }
  if (type.name === 'array') {
    const elementType = readUIntLE(bytes, offset, 4);
    const count = readUIntLE(bytes, offset + 4, 8);
    if (elementType === undefined || count === undefined || count > 1_000_000) {
      return undefined;
    }
    let position = offset + 12;
    for (let index = 0; index < count; index += 1) {
      const element = readValue(bytes, position, elementType);
      if (element === undefined) {
        return undefined;
      }
      position = element.next;
    }
    return { value: `${count} 项 ${VALUE_TYPES[elementType]?.name ?? elementType} 数组`, next: position };
  }
  if (offset + type.size > bytes.length) {
    return undefined;
  }
  const value = readUIntLE(bytes, offset, type.size);
  if (value === undefined) {
    return undefined;
  }
  return { value: type.name === 'bool' ? value !== 0 : value, next: offset + type.size };
}

/**
 * GGUF 读取器入口。
 * @param {{entry: Record<string, unknown>, policy: Record<string, unknown>, budgets: Record<string, number>}} context
 * @returns {Promise<{findings: Array<Record<string, unknown>>, limitations: Array<Record<string, unknown>>}>}
 */
async function readGguf(context) {
  const entry = context.entry;
  const budgets = context.budgets ?? {};
  const read = await readEntryBytes(entry, budgets);
  const bytes = read.bytes;
  const findings = [];
  const limitations = [];
  const path = entry.relativePath;

  if (!read.complete) {
    limitations.push(truncationLimitation(read));
  }

  if (bytes.length < 4 || !bytes.subarray(0, 4).equals(GGUF_MAGIC)) {
    limitations.push(limitation('gguf-magic-missing', '文件头不是 GGUF 魔数。该条目不等于没有暴露，只是本次没有提取到事实'));
    return { findings, limitations };
  }
  // 元数据键值里可能带凭据：格式已确认，扫全部已读字节。
  appendTokenScan(bytes, findings, limitations, { path, reader: 'gguf' });
  if (bytes.length < 24) {
    limitations.push(limitation('gguf-header-unparsable', `文件头只有 ${bytes.length} 字节，读不到完整的版本、张量数与元数据键数`));
    return { findings, limitations };
  }
  const version = readUIntLE(bytes, 4, 4);
  const tensorCount = readUIntLE(bytes, 8, 8);
  const metadataCount = readUIntLE(bytes, 16, 8);
  if (version === undefined || tensorCount === undefined || metadataCount === undefined) {
    limitations.push(limitation('gguf-header-unparsable', 'GGUF 头字段读取越界，版本、张量数与元数据键数未取出'));
    return { findings, limitations };
  }

  let position = 24;
  const metadata = [];
  let alignment = 32;
  for (let index = 0; index < metadataCount; index += 1) {
    const key = readString(bytes, position);
    if (key === undefined) {
      limitations.push(limitation('gguf-metadata-key-unparsable', `第 ${index} 个元数据键读取失败，该键及其后的键没有解析`));
      break;
    }
    const typeId = readUIntLE(bytes, key.next, 4);
    if (typeId === undefined) {
      limitations.push(limitation('gguf-metadata-type-unparsable', `元数据键 ${key.value} 的值类型读取失败，该键及其后的键没有解析`));
      break;
    }
    const value = readValue(bytes, key.next + 4, typeId);
    if (value === undefined) {
      limitations.push(limitation('gguf-metadata-value-unparsable', `元数据键 ${key.value} 的值解析失败（类型 ${VALUE_TYPES[typeId]?.name ?? typeId}），该键及其后的键没有解析`));
      break;
    }
    metadata.push({ key: key.value, type: VALUE_TYPES[typeId]?.name ?? String(typeId), value: value.value });
    position = value.next;
    if (key.value === 'general.alignment' && typeof value.value === 'number' && value.value > 0 && Number.isSafeInteger(value.value)) {
      alignment = value.value;
    }
    if (metadata.length >= METADATA_KEY_LIMIT) {
      limitations.push(limitation('gguf-metadata-key-limit', `元数据键数达到登记上限 ${METADATA_KEY_LIMIT}，其余键本次没有登记`));
      break;
    }
  }

  const tensors = [];
  for (let index = 0; index < tensorCount; index += 1) {
    const name = readString(bytes, position);
    if (name === undefined) {
      limitations.push(limitation('gguf-tensor-name-unparsable', `第 ${index} 个张量名读取失败，该张量及其后的张量没有解析`));
      break;
    }
    const dimensions = readUIntLE(bytes, name.next, 4);
    if (dimensions === undefined || dimensions > 8) {
      limitations.push(limitation('gguf-tensor-dims-unparsable', `张量 ${name.value} 的维度数读取失败或超出合理范围，该张量及其后的张量没有解析`));
      break;
    }
    let cursor = name.next + 4;
    const shape = [];
    for (let dimension = 0; dimension < dimensions; dimension += 1) {
      const size = readUIntLE(bytes, cursor, 8);
      if (size === undefined) {
        break;
      }
      shape.push(size);
      cursor += 8;
    }
    const typeId = readUIntLE(bytes, cursor, 4);
    const dataOffset = readUIntLE(bytes, cursor + 4, 8);
    if (typeId === undefined || dataOffset === undefined) {
      limitations.push(limitation('gguf-tensor-fields-unparsable', `张量 ${name.value} 的类型或偏移读取失败，该张量及其后的张量没有解析`));
      break;
    }
    const elementCount = shape.reduce((total, size) => total * size, 1);
    const elementSize = GGUF_TENSOR_TYPES[typeId]?.size ?? null;
    tensors.push({
      name: name.value,
      shape,
      type: GGUF_TENSOR_TYPES[typeId]?.name ?? String(typeId),
      elementSize,
      dataOffset,
      byteLength: elementSize === null ? null : elementCount * elementSize,
    });
    position = cursor + 12;
    if (tensors.length >= TENSOR_LIMIT) {
      limitations.push(limitation('gguf-tensor-limit', `张量数达到登记上限 ${TENSOR_LIMIT}，其余张量本次没有登记`));
      break;
    }
  }

  const tensorDataOffset = alignUp(position, alignment);

  findings.push(
    createFinding({
      layer: 'model-truthful-signals',
      severity: 'info',
      title: 'GGUF 头部声明的格式事实',
      category: 'gguf-header',
      evidence: { path, byteRange: [0, position], excerpt: `版本 ${version}，${tensorCount} 个张量，${metadataCount} 个元数据键` },
      reader: 'gguf',
      readerLimitation: '只解析头部、元数据键值与张量信息，不加载权重、不推理；元数据键值是文件自述事实，读取方不验证其真实性',
      mitigation: null,
      detail: { version, tensorCount: tensors.length, metadataCount: metadata.length, alignment, tensorDataOffset },
    }),
  );

  if (metadata.length > 0) {
    findings.push(
      createFinding({
        layer: 'model-truthful-signals',
        severity: 'medium',
        title: 'GGUF 元数据键值',
        category: 'gguf-metadata',
        evidence: {
          path,
          byteRange: [24, position],
          excerpt: metadata.slice(0, 8).map((item) => `${item.key}=${sanitizeExcerpt(Buffer.from(String(item.value), 'latin1'), 24)}`).join('、'),
        },
        reader: 'gguf',
        readerLimitation: '元数据键值按声明逐条登记，只报告键名与值的文本形态；键值可被再次改写，不构成技术屏障',
        mitigation: 'model.gguf-metadata-relayout',
        detail: { keys: metadata },
      }),
    );
  }

  if (tensors.length > 0) {
    findings.push(
      createFinding({
        layer: 'model-truthful-signals',
        severity: 'info',
        title: 'GGUF 张量索引',
        category: 'gguf-tensors',
        evidence: {
          path,
          byteRange: [position, tensorDataOffset],
          excerpt: tensors.slice(0, 6).map((tensor) => `${tensor.name}[${tensor.shape.join('x')}]`).join('、'),
        },
        reader: 'gguf',
        readerLimitation:
          '张量偏移按原对齐规则推算：张量数据区起点等于张量信息结束位置按 alignment 向上取整，各张量文件偏移等于该起点加声明的 data_offset；量化类型的元素字节数未登记，长度校验只覆盖非量化类型',
        mitigation: 'model.gguf-metadata-relayout',
        detail: {
          tensorDataOffset,
          tensors: tensors.slice(0, 64).map((tensor) => ({ ...tensor, fileOffset: tensorDataOffset + tensor.dataOffset })),
          registeredTensors: tensors.length,
        },
      }),
    );
  }

  // 张量区间越界检查：只对元素字节数已知的类型做。
  for (const tensor of tensors) {
    if (tensor.byteLength === null) {
      continue;
    }
    const start = tensorDataOffset + tensor.dataOffset;
    const end = start + tensor.byteLength;
    if (end > read.fileSize) {
      limitations.push(
        limitation(
          'gguf-tensor-out-of-range',
          `张量 ${tensor.name} 的数据区间 [${start}, ${end}) 超出文件范围（${read.fileSize} 字节），该张量的长度校验不通过`,
        ),
      );
    }
  }

  return { findings, limitations };
}

export const ggufReader = defineReader({
  id: 'gguf',
  formats: ['gguf'],
  layers: ['model-truthful-signals'],
  purpose: 'GGUF 头部、元数据键值与张量偏移的事实提取',
  read: readGguf,
});
