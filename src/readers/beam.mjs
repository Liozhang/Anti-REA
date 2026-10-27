// BEAM 读取器：块结构与已编译模块名的事实提取。
// 只读：BEAM 是 IFF 风格容器，FOR1 之后是 BEAM 标记，再往后是四字节块标识加四字节大端长度（偶数对齐）。
// 模块名在 AtU8 块里按长度前缀逐一存放，本读取器对长度前缀宽度做多种解释并取第一种自洽的，解释方式写进限制说明。

import { createFinding } from '../audit/finding.mjs';
import { defineReader, isPrintableAscii, limitation, readEntryBytes, readUIntBE, truncationLimitation } from './common.mjs';
import { appendTokenScan } from './scan.mjs';

/** 单个文件最多登记的块数，超出部分在限制说明里声明。 */
const CHUNK_LIMIT = 512;

/** 单个 AtU8 块最多登记的原子数。 */
const ATOM_LIMIT = 512;

/**
 * 按一种长度前缀宽度解释 AtU8 块，返回原子列表；解释不自洽时返回 null。
 * 自洽的判定：读出的原子恰好耗尽整个块。
 * @param {Buffer} content 块内容
 * @param {number} width 长度前缀宽度，2 或 4
 * @param {boolean} withCount 是否带两字节原子计数前缀
 * @returns {{atoms: string[], consumed: number} | null}
 */
function decodeAtoms(content, width, withCount) {
  const atoms = [];
  let position = withCount ? 2 : 0;
  const count = withCount ? readUIntBE(content, 0, 2) : null;
  if (count !== null && count > ATOM_LIMIT) {
    return null;
  }
  const target = count ?? ATOM_LIMIT;
  for (let index = 0; index < target; index += 1) {
    if (position + width > content.length) {
      break;
    }
    const length = readUIntBE(content, position, width);
    if (length === undefined) {
      break;
    }
    position += width;
    if (position + length > content.length) {
      return null;
    }
    const raw = content.subarray(position, position + length);
    position += length;
    if (!isPrintableAscii(raw)) {
      return null;
    }
    atoms.push(raw.toString('latin1'));
  }
  if (position !== content.length || atoms.length === 0) {
    return null;
  }
  if (count !== null && count !== atoms.length) {
    return null;
  }
  return { atoms, consumed: position };
}

/**
 * 解析 AtU8 块，取出原子表。多种解释按优先级尝试，第一种自洽解释即采用。
 * @param {Buffer} content 块内容
 * @returns {{atoms: string[], interpretation: string} | null}
 */
function parseAtomChunk(content) {
  const attempts = [
    { width: 2, withCount: false, label: '两字节长度前缀，无计数' },
    { width: 2, withCount: true, label: '两字节计数加两字节长度前缀' },
    { width: 4, withCount: false, label: '四字节长度前缀，无计数' },
  ];
  for (const attempt of attempts) {
    const decoded = decodeAtoms(content, attempt.width, attempt.withCount);
    if (decoded !== null) {
      return { atoms: decoded.atoms, interpretation: attempt.label };
    }
  }
  return null;
}

/**
 * BEAM 读取器入口。
 * @param {{entry: Record<string, unknown>, policy: Record<string, unknown>, budgets: Record<string, number>}} context
 * @returns {Promise<{findings: Array<Record<string, unknown>>, limitations: Array<Record<string, unknown>>}>}
 */
async function readBeam(context) {
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

  if (bytes.length < 12 || bytes.toString('latin1', 0, 4) !== 'FOR1' || bytes.toString('latin1', 8, 12) !== 'BEAM') {
    limitations.push(
      limitation('beam-container-missing', '文件不是 FOR1 加 BEAM 的容器结构。该条目不等于没有暴露，只是本次没有提取到事实'),
    );
    return { findings, limitations };
  }
  // 原子表与代码块里可能带凭据：容器结构已确认，扫全部已读字节。
  appendTokenScan(bytes, findings, limitations, { path, reader: 'beam' });

  const declaredSize = readUIntBE(bytes, 4, 4);
  const chunks = [];
  let position = 12;
  while (position + 8 <= bytes.length && chunks.length < CHUNK_LIMIT) {
    const id = bytes.toString('latin1', position, position + 4);
    const length = readUIntBE(bytes, position + 4, 4);
    if (length === undefined) {
      limitations.push(limitation('beam-chunk-length-unreadable', `偏移 ${position} 处的块长度读取越界，该块及其后的块没有解析`));
      break;
    }
    if (position + 8 + length > bytes.length) {
      limitations.push(
        limitation('beam-chunk-out-of-range', `块 ${id} 声明的长度 ${length} 超出已读取字节范围（${bytes.length} 字节），该块及其后的块没有解析`),
      );
      break;
    }
    chunks.push({ id, offset: position, length, contentOffset: position + 8 });
    position += 8 + length + (length % 2);
  }
  if (chunks.length >= CHUNK_LIMIT) {
    limitations.push(limitation('beam-chunk-limit', `块数达到登记上限 ${CHUNK_LIMIT}，其余块本次没有登记`));
  }
  if (declaredSize !== undefined && 8 + declaredSize > bytes.length) {
    limitations.push(
      limitation('beam-declared-size-mismatch', `FOR1 声明的容器长度 ${declaredSize} 超出已读取字节范围（${bytes.length} 字节），容器可能被截断`),
    );
  }

  const atomChunk = chunks.find((chunk) => chunk.id === 'AtU8') ?? chunks.find((chunk) => chunk.id === 'Atom');
  let atoms = [];
  let interpretation = null;
  if (atomChunk === undefined) {
    limitations.push(
      limitation('beam-atom-chunk-missing', '容器里没有 AtU8 或 Atom 块，模块名不可恢复；块清单照常登记，模块名事实本次没有覆盖'),
    );
  } else {
    const content = bytes.subarray(atomChunk.contentOffset, atomChunk.contentOffset + atomChunk.length);
    const parsed = parseAtomChunk(content);
    if (parsed === null) {
      limitations.push(
        limitation(
          'beam-atom-decode-failed',
          `${atomChunk.id} 块的长度前缀结构无法用已登记的三种解释自洽解出，模块名不可恢复；块清单照常登记，模块名事实本次没有覆盖`,
        ),
      );
    } else {
      atoms = parsed.atoms;
      interpretation = parsed.interpretation;
    }
  }

  findings.push(
    createFinding({
      layer: 'metadata-hygiene',
      severity: 'info',
      title: 'BEAM 块结构',
      category: 'beam-chunks',
      evidence: {
        path,
        byteRange: [12, position],
        excerpt: chunks.map((chunk) => chunk.id).join('、'),
      },
      reader: 'beam',
      readerLimitation:
        '块清单按四字节标识加四字节大端长度逐一登记，不解析块内指令；导出表、导入表与字符串块的逐项内容不在 v1 范围内',
      mitigation: null,
      detail: {
        declaredSize: declaredSize ?? null,
        chunkCount: chunks.length,
        chunks: chunks.map((chunk) => ({ id: chunk.id, offset: chunk.offset, length: chunk.length })),
      },
    }),
  );

  if (atoms.length > 0) {
    findings.push(
      createFinding({
        layer: 'metadata-hygiene',
        severity: 'low',
        title: 'BEAM 已编译模块名',
        category: 'beam-module-name',
        evidence: {
          path,
          byteRange: [atomChunk.contentOffset, atomChunk.contentOffset + atomChunk.length],
          excerpt: atoms.slice(0, 8).join('、'),
        },
        reader: 'beam',
        readerLimitation: `模块名取 ${atomChunk.id} 块的首个原子，长度前缀解释为${interpretation}；原子编码宽度未在文件内声明，解释不唯一，其余原子只作登记`,
        mitigation: null,
        detail: { moduleName: atoms[0], atomCount: atoms.length, sampleAtoms: atoms.slice(0, 32), interpretation },
      }),
    );
  }

  return { findings, limitations };
}

export const beamReader = defineReader({
  id: 'beam',
  formats: ['beam'],
  layers: ['metadata-hygiene'],
  purpose: 'BEAM 块结构与已编译模块名的事实提取',
  read: readBeam,
});
