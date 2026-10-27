// safetensors 读取器：头部 JSON、__metadata__ 与张量 data_offsets 的事实提取。
// 只读：八字节小端头部长度前缀加一段 JSON；各 data_offsets 是相对数据区起点的相对偏移。
// 读取器同时核对索引是否覆盖整个数据区（无越界、无间隙、无重叠、无未索引尾部），为复审提供事实。

import { createFinding } from '../audit/finding.mjs';
import { defineReader, limitation, readEntryBytes, readUIntLE, sanitizeExcerpt, truncationLimitation } from './common.mjs';
import { appendTokenScan } from './scan.mjs';

/** safetensors 数据类型到元素字节数。 */
const DTYPES = Object.freeze({
  BOOL: 1,
  U8: 1,
  I8: 1,
  F8_E4M3: 1,
  F8_E5M2: 1,
  I16: 2,
  U16: 2,
  F16: 2,
  BF16: 2,
  I32: 4,
  U32: 4,
  F32: 4,
  I64: 8,
  U64: 8,
  F64: 8,
});

/** 单个头部最多登记的张量数，超出部分在限制说明里声明。 */
const TENSOR_LIMIT = 4096;

/**
 * safetensors 读取器入口。
 * @param {{entry: Record<string, unknown>, policy: Record<string, unknown>, budgets: Record<string, number>}} context
 * @returns {Promise<{findings: Array<Record<string, unknown>>, limitations: Array<Record<string, unknown>>}>}
 */
async function readSafetensors(context) {
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

  if (bytes.length < 16) {
    limitations.push(limitation('safetensors-prefix-missing', '文件不足 16 字节，读不到八字节长度前缀加完整 JSON 头。该条目不等于没有暴露，只是本次没有提取到事实'));
    return { findings, limitations };
  }
  const headerLength = readUIntLE(bytes, 0, 8);
  if (headerLength === undefined || headerLength <= 0 || 8 + headerLength > bytes.length) {
    limitations.push(
      limitation(
        'safetensors-header-unreadable',
        `八字节长度前缀声明的头部长度 ${headerLength} 不可用：头部区间超出已读取字节范围（${bytes.length} 字节），JSON 头没有解析`,
      ),
    );
    return { findings, limitations };
  }

  let header;
  try {
    header = JSON.parse(bytes.toString('utf8', 8, 8 + headerLength));
  } catch (error) {
    limitations.push(limitation('safetensors-header-not-json', `头部 JSON 解析失败：${String(error.message)}。JSON 头没有解析，张量索引与元数据事实本次没有覆盖`));
    return { findings, limitations };
  }
  if (header === null || typeof header !== 'object' || Array.isArray(header)) {
    limitations.push(limitation('safetensors-header-not-object', '头部 JSON 不是对象，张量索引与元数据事实本次没有覆盖'));
    return { findings, limitations };
  }
  // __metadata__ 是自由文本键值，可能带凭据：头部已确认是 JSON 对象，扫全部已读字节。
  appendTokenScan(bytes, findings, limitations, { path, reader: 'safetensors' });

  const tensorDataOffset = 8 + headerLength;
  const metadata = header.__metadata__;
  const tensors = [];
  for (const [name, value] of Object.entries(header)) {
    if (name === '__metadata__') {
      continue;
    }
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      limitations.push(limitation('safetensors-tensor-entry-invalid', `头部条目 ${name} 不是张量描述对象，该条目按未解析处理`));
      continue;
    }
    const offsets = value.data_offsets;
    if (!Array.isArray(offsets) || offsets.length !== 2 || offsets.some((offset) => typeof offset !== 'number' || !Number.isSafeInteger(offset))) {
      limitations.push(limitation('safetensors-tensor-offsets-invalid', `张量 ${name} 的 data_offsets 不是两个安全整数，该张量的区间校验不通过`));
      continue;
    }
    tensors.push({ name, dtype: typeof value.dtype === 'string' ? value.dtype : String(value.dtype), shape: Array.isArray(value.shape) ? value.shape : [], start: offsets[0], end: offsets[1] });
    if (tensors.length >= TENSOR_LIMIT) {
      limitations.push(limitation('safetensors-tensor-limit', `张量数达到登记上限 ${TENSOR_LIMIT}，其余张量本次没有登记`));
      break;
    }
  }

  findings.push(
    createFinding({
      layer: 'model-truthful-signals',
      severity: 'info',
      title: 'safetensors 头部声明的格式事实',
      category: 'safetensors-header',
      evidence: {
        path,
        byteRange: [0, tensorDataOffset],
        excerpt: `头部 ${headerLength} 字节，${tensors.length} 个张量，数据区起点 ${tensorDataOffset}`,
      },
      reader: 'safetensors',
      readerLimitation: '只解析八字节长度前缀与 JSON 头，不加载张量数据、不推理；头里的 dtype 与 shape 是文件自述事实，读取方不验证其真实性',
      mitigation: null,
      detail: { headerLength, tensorDataOffset, tensorCount: tensors.length, fileSize: read.fileSize },
    }),
  );

  if (metadata !== null && typeof metadata === 'object' && !Array.isArray(metadata)) {
    findings.push(
      createFinding({
        layer: 'model-truthful-signals',
        severity: 'medium',
        title: 'safetensors __metadata__ 元数据槽位',
        category: 'safetensors-metadata',
        evidence: {
          path,
          byteRange: [8, tensorDataOffset],
          excerpt: Object.keys(metadata).map((key) => `${key}=${sanitizeExcerpt(Buffer.from(String(metadata[key]), 'utf8'), 24)}`).join('、'),
        },
        reader: 'safetensors',
        readerLimitation: '元数据槽位内容按声明逐条登记；元数据只是声明，可被再次剥离，不构成技术屏障',
        mitigation: 'model.safetensors-metadata-relayout',
        detail: { metadata },
      }),
    );
  }

  if (tensors.length > 0) {
    findings.push(
      createFinding({
        layer: 'model-truthful-signals',
        severity: 'info',
        title: 'safetensors 张量索引',
        category: 'safetensors-tensors',
        evidence: {
          path,
          byteRange: [tensorDataOffset, read.fileSize],
          excerpt: tensors.slice(0, 6).map((tensor) => `${tensor.name}:${tensor.dtype}`).join('、'),
        },
        reader: 'safetensors',
        readerLimitation:
          '各 data_offsets 是相对数据区起点的相对偏移，文件偏移等于 tensor_data_offset 加该值；本读取器核对索引是否覆盖整个数据区，间隙与重叠逐条登记',
        mitigation: 'model.safetensors-metadata-relayout',
        detail: {
          tensorDataOffset,
          tensors: tensors.slice(0, 64).map((tensor) => ({ ...tensor, fileStart: tensorDataOffset + tensor.start, fileEnd: tensorDataOffset + tensor.end })),
          registeredTensors: tensors.length,
        },
      }),
    );
  }

  // 索引覆盖检查：越界、重叠、间隙、未索引尾部。
  const sorted = [...tensors].sort((left, right) => left.start - right.start);
  let cursor = 0;
  for (const tensor of sorted) {
    if (tensor.end < tensor.start) {
      limitations.push(limitation('safetensors-interval-inverted', `张量 ${tensor.name} 的区间 [${tensor.start}, ${tensor.end}) 起止颠倒，该区间校验不通过`));
      continue;
    }
    if (tensor.end > read.fileSize - tensorDataOffset) {
      limitations.push(
        limitation(
          'safetensors-interval-out-of-range',
          `张量 ${tensor.name} 的区间终点 ${tensor.end} 超出数据区长度（${read.fileSize - tensorDataOffset} 字节），该区间校验不通过`,
        ),
      );
      continue;
    }
    if (tensor.start > cursor) {
      limitations.push(
        limitation('safetensors-interval-gap', `数据区相对偏移 ${cursor} 到 ${tensor.start} 之间没有被任何张量索引覆盖，存在间隙`),
      );
    }
    if (tensor.start < cursor) {
      limitations.push(
        limitation('safetensors-interval-overlap', `张量 ${tensor.name} 的区间 [${tensor.start}, ${tensor.end}) 与已索引区间重叠，重叠起点为相对偏移 ${cursor}`),
      );
    }
    cursor = Math.max(cursor, tensor.end);
  }
  const dataRegionLength = read.fileSize - tensorDataOffset;
  if (cursor < dataRegionLength) {
    limitations.push(
      limitation('safetensors-unindexed-tail', `数据区末尾 ${dataRegionLength - cursor} 字节没有被任何张量索引覆盖，存在未索引尾部`),
    );
  }

  return { findings, limitations };
}

export const safetensorsReader = defineReader({
  id: 'safetensors',
  formats: ['safetensors'],
  layers: ['model-truthful-signals'],
  purpose: 'safetensors 头部 JSON、__metadata__ 与张量 data_offsets 的事实提取',
  read: readSafetensors,
});
