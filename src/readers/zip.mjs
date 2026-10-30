// ZIP 读取器：中央目录、本地文件头一致性与逐条目覆盖标记的事实提取。
// 存储条目按原始字节扫描，deflate 条目用 node:zlib 解压后扫描；不可解压条目只按原始字节扫描并附限制说明。
// 条目改写后必须同帧重算 CRC32，本读取器逐条目核对 CRC32 与中央目录记录是否一致，为复审提供事实。

import { inflateRawSync } from 'node:zlib';

import { createFinding } from '../audit/finding.mjs';
import { defineReader, findAll, limitation, readEntryBytes, readUIntLE, sanitizeExcerpt, truncationLimitation } from './common.mjs';
import { parseDex } from './dex.mjs';
import { scanTokens, tokenFindings, tokenScanLimitation } from './scan.mjs';

/** ZIP 签名。 */
const SIGNATURES = Object.freeze({
  local: Buffer.from('PK\x03\x04', 'latin1'),
  central: Buffer.from('PK\x01\x02', 'latin1'),
  eocd: Buffer.from('PK\x05\x06', 'latin1'),
});

/** APK 签名块魔数。 */
const APK_SIG_BLOCK_MAGIC = Buffer.from('APK Sig Block 42', 'latin1');

/** 压缩方法名。 */
const METHODS = Object.freeze({ 0: 'stored', 8: 'deflate', 9: 'deflate64', 12: 'bzip2', 14: 'lzma', 93: 'zstd', 95: 'xz' });

/** 搜索中央目录结尾记录时回溯的最大字节数：注释最长 65535 字节加 22 字节记录本身。 */
const EOCD_SEARCH_BYTES = 65557;

/** 嵌套容器魔数表，用于识别“ZIP 里还有容器”的情况。 */
const NESTED_MAGICS = Object.freeze([
  { type: 'zip', magic: Buffer.from('PK\x03\x04', 'latin1') },
  { type: 'elf', magic: Buffer.from('\x7fELF', 'latin1') },
  { type: 'pe', magic: Buffer.from('MZ', 'latin1') },
  { type: 'mach-o', magic: Buffer.from('\xcf\xfa\xed\xfe', 'latin1') },
  { type: 'gguf', magic: Buffer.from('GGUF', 'latin1') },
  // DEX 只认前四个字节 dex\n，版本号由 DEX 读取器自己校验；
  // 这里先按四字节命中，认不出来的交给读取器转成限制说明。
  { type: 'dex', magic: Buffer.from('dex\n', 'latin1') },
]);

/**
 * 单个 ZIP 内最多递归解析的 DEX 条目数。
 * 多 dex 应用的 classes2.dex、classes3.dex 通常只有个位数，
 * 上限用来防住刻意构造的条目堆叠把审计拖住。
 */
const NESTED_DEX_ENTRY_LIMIT = 8;

/** 单个 ZIP 内递归解析 DEX 的累计字节上限，防止解压后总体积失控。 */
const NESTED_DEX_BYTES_LIMIT = 32 * 1024 * 1024;

/** CRC32 查找表，多项式 0xEDB88320 的反射形式。 */
const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = (value & 1) !== 0 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[index] = value >>> 0;
  }
  return table;
})();

/**
 * 计算 CRC32（IEEE 802.3，与 ZIP 中央目录记录同算法）。
 * @param {Buffer} bytes
 * @returns {number}
 */
export function crc32Of(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc = CRC32_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * 从文件尾部搜索中央目录结尾记录。
 * @param {Buffer} bytes
 * @returns {{offset: number, totalEntries: number, cdSize: number, cdOffset: number} | null}
 */
function findEocd(bytes) {
  const searchFrom = Math.max(0, bytes.length - EOCD_SEARCH_BYTES);
  const hits = findAll(bytes, SIGNATURES.eocd, { from: searchFrom });
  for (let index = hits.length - 1; index >= 0; index -= 1) {
    const offset = hits[index];
    if (offset + 22 > bytes.length) {
      continue;
    }
    const totalEntries = readUIntLE(bytes, offset + 10, 2);
    const cdSize = readUIntLE(bytes, offset + 12, 4);
    const cdOffset = readUIntLE(bytes, offset + 16, 4);
    if (totalEntries === undefined || cdSize === undefined || cdOffset === undefined) {
      continue;
    }
    // 从后向前取：中央目录紧挨在结尾记录之前，注释里可能出现签名字节，倒序取才符合 ZIP 书写顺序。
    if (cdOffset + cdSize <= offset) {
      return { offset, totalEntries, cdSize, cdOffset };
    }
  }
  return null;
}

/**
 * 解析中央目录。
 * @param {Buffer} bytes
 * @param {{cdOffset: number, cdSize: number}} eocd
 * @returns {{entries: Array<Record<string, unknown>>, limitations: Array<Record<string, unknown>>}}
 */
function parseCentralDirectory(bytes, eocd) {
  const entries = [];
  const limitations = [];
  const end = Math.min(bytes.length, eocd.cdOffset + eocd.cdSize);
  let position = eocd.cdOffset;
  while (position + 46 <= end) {
    if (bytes[position] !== 0x50 || bytes[position + 1] !== 0x4b || bytes[position + 2] !== 0x01 || bytes[position + 3] !== 0x02) {
      limitations.push(limitation('zip-central-entry-signature-mismatch', `中央目录偏移 ${position} 处不是中央目录文件头签名，该处及其后的条目没有解析`));
      break;
    }
    const flags = readUIntLE(bytes, position + 8, 2);
    const method = readUIntLE(bytes, position + 10, 2);
    const crc32 = readUIntLE(bytes, position + 16, 4);
    const compressedSize = readUIntLE(bytes, position + 20, 4);
    const uncompressedSize = readUIntLE(bytes, position + 24, 4);
    const nameLength = readUIntLE(bytes, position + 28, 2);
    const extraLength = readUIntLE(bytes, position + 30, 2);
    const commentLength = readUIntLE(bytes, position + 32, 2);
    const localOffset = readUIntLE(bytes, position + 42, 4);
    if ([flags, method, crc32, compressedSize, uncompressedSize, nameLength, extraLength, commentLength, localOffset].some((value) => value === undefined)) {
      limitations.push(limitation('zip-central-entry-field-missing', `中央目录偏移 ${position} 处的条目字段读取越界，该条目按未解析处理`));
      break;
    }
    const nameEnd = position + 46 + nameLength;
    if (nameEnd > end) {
      limitations.push(limitation('zip-central-entry-name-out-of-range', `中央目录偏移 ${position} 处的条目名超出已读取范围，该条目及其后的条目没有解析`));
      break;
    }
    entries.push({
      name: sanitizeExcerpt(bytes.subarray(position + 46, nameEnd), 200),
      flags,
      method,
      crc32,
      compressedSize,
      uncompressedSize,
      localOffset,
      centralOffset: position,
    });
    position = nameEnd + extraLength + commentLength;
  }
  return { entries, limitations };
}

/**
 * 核对本地文件头与中央目录记录，并取出条目原始字节。
 * @param {Buffer} bytes 整个文件字节
 * @param {Record<string, unknown>} entry 中央目录条目
 * @returns {{ok: true, localHeader: Record<string, unknown>, raw: Buffer} | {ok: false, reason: string}}
 */
function readLocalEntry(bytes, entry) {
  const base = entry.localOffset;
  if (base + 30 > bytes.length) {
    return { ok: false, reason: `本地文件头偏移 ${base} 超出已读取字节范围` };
  }
  if (bytes[base] !== 0x50 || bytes[base + 1] !== 0x4b || bytes[base + 2] !== 0x03 || bytes[base + 3] !== 0x04) {
    return { ok: false, reason: `本地文件头偏移 ${base} 处不是本地文件头签名` };
  }
  const nameLength = readUIntLE(bytes, base + 26, 2);
  const extraLength = readUIntLE(bytes, base + 28, 2);
  if (nameLength === undefined || extraLength === undefined) {
    return { ok: false, reason: '本地文件头的名称与附加字段长度读取越界' };
  }
  const dataStart = base + 30 + nameLength + extraLength;
  const dataEnd = dataStart + entry.compressedSize;
  if (dataEnd > bytes.length) {
    return { ok: false, reason: `条目数据区间 [${dataStart}, ${dataEnd}) 超出已读取字节范围` };
  }
  return {
    ok: true,
    localHeader: { base, nameLength, extraLength, dataStart, method: readUIntLE(bytes, base + 8, 2) },
    raw: bytes.subarray(dataStart, dataEnd),
  };
}

/**
 * 判断一段内容是否以已知容器魔数开头。
 * @param {Buffer} bytes
 * @returns {string | null}
 */
function nestedContainerOf(bytes) {
  for (const candidate of NESTED_MAGICS) {
    if (bytes.length >= candidate.magic.length && bytes.subarray(0, candidate.magic.length).equals(candidate.magic)) {
      return candidate.type;
    }
  }
  return null;
}

/**
 * ZIP 读取器入口。
 * @param {{entry: Record<string, unknown>, policy: Record<string, unknown>, budgets: Record<string, number>}} context
 * @returns {Promise<{findings: Array<Record<string, unknown>>, limitations: Array<Record<string, unknown>>}>}
 */
async function readZip(context) {
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

  const eocd = findEocd(bytes);
  if (eocd === null) {
    limitations.push(
      limitation(
        'zip-eocd-missing',
        '文件尾部找不到中央目录结尾记录，中央目录无法定位；该条目不等于没有暴露，只是本次没有提取到事实',
      ),
    );
    return { findings, limitations };
  }

  const { entries, limitations: directoryLimitations } = parseCentralDirectory(bytes, eocd);
  limitations.push(...directoryLimitations);

  // APK 特征：条目名带 AndroidManifest.xml 或 classes.dex，或文件里存在 APK 签名块魔数。
  const apkByEntries = entries.some((candidate) => candidate.name === 'AndroidManifest.xml' || candidate.name === 'classes.dex');
  const apkBySigningBlock = findAll(bytes, APK_SIG_BLOCK_MAGIC).length > 0;
  if (apkByEntries || apkBySigningBlock) {
    limitations.push(
      limitation(
        'apk-signature-scheme',
        '该制品带 APK 特征（AndroidManifest.xml、classes.dex 或 APK 签名块魔数）；APK v2 及以上签名方案解析不在 v1 范围内，本次只能按普通 ZIP 条目处理，签名块本身没有解析',
      ),
    );
  }

  const entryReports = [];
  const nestedContainers = [];
  // DEX 条目的内容缓存：APK 的 classes.dex 要交给 DEX 读取器解析，
  // 但存储条目与 deflate 条目拿到内容的时机不同，先收集再统一处理。
  const dexCandidates = [];
  let scannedEntryCount = 0;
  let rawOnlyCount = 0;
  // 已按条目原始字节报告过的令牌命中，键为“模式标识加文件偏移”，避免整文件扫描重复报告同一次命中。
  const reportedRawHits = new Set();

  for (const zipEntry of entries) {
    const report = {
      name: zipEntry.name,
      method: METHODS[zipEntry.method] ?? String(zipEntry.method),
      methodCode: zipEntry.method,
      compressedSize: zipEntry.compressedSize,
      uncompressedSize: zipEntry.uncompressedSize,
      coverage: 'not-scanned',
      crc32Recorded: zipEntry.crc32,
      crc32Computed: null,
      crcMatch: null,
      nestedContainer: null,
      reason: null,
    };
    const local = readLocalEntry(bytes, zipEntry);
    if (!local.ok) {
      report.reason = local.reason;
      report.coverage = 'not-scanned';
      rawOnlyCount += 1;
      limitations.push(limitation('zip-local-entry-unreadable', `条目 ${zipEntry.name} 的本地文件头不可用：${local.reason}。该条目只按中央目录记录登记，内容没有扫描`));
      entryReports.push(report);
      continue;
    }

    if (zipEntry.method === 0) {
      // 存储条目：原始字节即内容，直接算 CRC32 并扫描。
      const crc = crc32Of(local.raw);
      report.coverage = 'raw-bytes-scanned';
      report.crc32Computed = crc;
      report.crcMatch = crc === zipEntry.crc32;
      scannedEntryCount += 1;
      if (!report.crcMatch) {
        limitations.push(
          limitation(
            'zip-entry-crc-mismatch',
            `条目 ${zipEntry.name} 的原始字节 CRC32 为 0x${crc.toString(16)}，与中央目录记录的 0x${zipEntry.crc32.toString(16)} 不一致；条目内容可能已被改动，或本地文件头与中央目录不同帧`,
          ),
        );
      }
      report.nestedContainer = nestedContainerOf(local.raw);
      if (report.nestedContainer === 'dex') {
        dexCandidates.push({ name: zipEntry.name, content: local.raw, compressed: false });
      }
      const scan = scanTokens(local.raw);
      for (const hit of scan.hits) {
        reportedRawHits.add(`${hit.id}:${local.localHeader.dataStart + hit.offset}`);
      }
      findings.push(...tokenFindings(scan, { path, reader: 'zip', baseOffset: local.localHeader.dataStart, source: 'stored-entry-raw-bytes' }));
      const scanLimitation = tokenScanLimitation(scan, `条目 ${zipEntry.name} 的原始字节`);
      if (scanLimitation !== null) {
        limitations.push(scanLimitation);
      }
    } else if (zipEntry.method === 8) {
      // deflate 条目：解压后扫描，并用解压结果核对 CRC32。
      let inflated = null;
      try {
        inflated = inflateRawSync(local.raw);
      } catch {
        inflated = null;
      }
      if (inflated === null) {
        report.coverage = 'raw-bytes-only';
        report.reason = 'node:zlib 无法解压该 deflate 条目，只按原始压缩字节扫描，覆盖缺口在此声明';
        rawOnlyCount += 1;
        limitations.push(
          limitation(
            'zip-entry-inflate-failed',
            `条目 ${zipEntry.name} 用 node:zlib 解压失败，只按原始压缩字节扫描；压缩内容里的可提取事实本次没有覆盖，不等于不存在`,
          ),
        );
        const scan = scanTokens(local.raw);
        findings.push(...tokenFindings(scan, { path, reader: 'zip', baseOffset: local.localHeader.dataStart, source: 'deflate-entry-compressed-bytes' }));
      } else {
        const crc = crc32Of(inflated);
        report.coverage = 'decompressed-scanned';
        report.crc32Computed = crc;
        report.crcMatch = crc === zipEntry.crc32;
        report.nestedContainer = nestedContainerOf(inflated);
        if (report.nestedContainer === 'dex') {
          dexCandidates.push({ name: zipEntry.name, content: inflated, compressed: true });
        }
        scannedEntryCount += 1;
        if (!report.crcMatch) {
          limitations.push(
            limitation(
              'zip-entry-crc-mismatch',
              `条目 ${zipEntry.name} 解压后 CRC32 为 0x${crc.toString(16)}，与中央目录记录的 0x${zipEntry.crc32.toString(16)} 不一致；条目内容可能已被改动`,
            ),
          );
        }
        if (inflated.length !== zipEntry.uncompressedSize) {
          limitations.push(
            limitation(
              'zip-entry-size-mismatch',
              `条目 ${zipEntry.name} 解压后 ${inflated.length} 字节，与中央目录记录的未压缩大小 ${zipEntry.uncompressedSize} 不一致`,
            ),
          );
        }
        const scan = scanTokens(inflated);
        findings.push(...tokenFindings(scan, { path, reader: 'zip', source: 'deflate-entry-decompressed-bytes' }));
        const scanLimitation = tokenScanLimitation(scan, `条目 ${zipEntry.name} 的解压内容`);
        if (scanLimitation !== null) {
          limitations.push(scanLimitation);
        }
      }
    } else {
      report.coverage = 'raw-bytes-only';
      report.reason = `压缩方法 ${METHODS[zipEntry.method] ?? zipEntry.method} 不在 v1 解压范围内，只按原始压缩字节扫描`;
      rawOnlyCount += 1;
      limitations.push(
        limitation(
          'zip-entry-method-unsupported',
          `条目 ${zipEntry.name} 的压缩方法为 ${METHODS[zipEntry.method] ?? zipEntry.method}，v1 只用 node:zlib 处理存储与 deflate 两类；该条目内容本次没有覆盖，不等于不存在`,
        ),
      );
      const scan = scanTokens(local.raw);
      for (const hit of scan.hits) {
        reportedRawHits.add(`${hit.id}:${local.localHeader.dataStart + hit.offset}`);
      }
      findings.push(...tokenFindings(scan, { path, reader: 'zip', baseOffset: local.localHeader.dataStart, source: 'unsupported-method-raw-bytes' }));
    }
    if (report.nestedContainer !== null) {
      nestedContainers.push({ name: zipEntry.name, container: report.nestedContainer });
    }
    entryReports.push(report);
  }

  // DEX 条目单独递归解析，其余嵌套容器仍不跟进：只做 DEX 是因为
  // APK 的 classes.dex 是最常见也最暴露的嵌套层，其余容器没有同等的现实需求。
  const dexFindings = [];
  const dexLimitations = [];
  const dexNames = [];
  let dexBytes = 0;
  for (const candidate of dexCandidates) {
    if (dexNames.length >= NESTED_DEX_ENTRY_LIMIT) {
      dexLimitations.push(
        limitation(
          'zip-nested-dex-entry-limit',
          `DEX 条目数达到递归上限 ${NESTED_DEX_ENTRY_LIMIT}，条目 ${candidate.name} 及其后的 DEX 条目本次没有解析；这些条目不等于没有暴露，只是本次没有提取到事实`,
        ),
      );
      break;
    }
    if (dexBytes + candidate.content.length > NESTED_DEX_BYTES_LIMIT) {
      dexLimitations.push(
        limitation(
          'zip-nested-dex-bytes-limit',
          `DEX 条目累计字节数达到上限 ${NESTED_DEX_BYTES_LIMIT}，条目 ${candidate.name} 及其后的 DEX 条目本次没有解析；这些条目不等于没有暴露，只是本次没有提取到事实`,
        ),
      );
      break;
    }
    dexBytes += candidate.content.length;
    dexNames.push(candidate.name);
    // 证据路径用“外层条目!内层条目”，让报告能指到 APK 内的具体 classes.dex。
    const nested = parseDex(candidate.content, `${path}!${candidate.name}`);
    dexFindings.push(...nested.findings);
    for (const note of nested.limitations) {
      dexLimitations.push({
        ...note,
        message: `条目 ${candidate.name}：${note.message}`,
      });
    }
  }
  findings.push(...dexFindings);
  limitations.push(...dexLimitations);

  // 未递归的嵌套容器排除 DEX：DEX 已经解析，再报一条“没有跟进”会自相矛盾。
  const unfollowed = nestedContainers.filter((nested) => nested.container !== 'dex');
  if (unfollowed.length > 0) {
    limitations.push(
      limitation(
        'zip-nested-container-not-followed',
        `条目 ${unfollowed.map((nested) => `${nested.name}（${nested.container}）`).join('、')} 的内容本身是容器；v1 只递归解析 DEX 一类，其余嵌套层内的事实本次没有覆盖`,
      ),
    );
  }
  if (dexNames.length > 0) {
    limitations.push(
      limitation(
        'zip-nested-dex-parsed',
        `条目 ${dexNames.join('、')} 识别为 DEX，已按 DEX 读取器解析类型描述符、方法名与字符串常量；DEX 内的指令流与方法体不在解析范围内`,
      ),
    );
  }

  const nameExcerpt = entries.slice(0, 8).map((candidate) => candidate.name).join('、');
  findings.push(
    createFinding({
      layer: 'metadata-hygiene',
      severity: 'info',
      title: 'ZIP 中央目录与逐条目覆盖标记',
      category: 'zip-entries',
      evidence: {
        path,
        byteRange: [eocd.cdOffset, eocd.cdOffset + eocd.cdSize],
        excerpt: entries.length > 0 ? nameExcerpt : '中央目录为空',
      },
      reader: 'zip',
      readerLimitation:
        '条目清单来自中央目录，逐条目标记已解压扫描或仅原始字节；不可解压与超预算条目的内容没有覆盖，覆盖缺口以限制说明逐条声明，不等于不存在',
      mitigation: null,
      detail: {
        eocdOffset: eocd.offset,
        centralDirectoryOffset: eocd.cdOffset,
        centralDirectorySize: eocd.cdSize,
        totalEntries: eocd.totalEntries,
        parsedEntries: entries.length,
        scannedEntryCount,
        rawOnlyCount,
        entries: entryReports,
      },
    }),
  );

  // 令牌扫描按整文件做一次，覆盖中央目录之外的散落字节；已按条目报告过的命中不重复登记。
  const scan = scanTokens(bytes);
  const freshHits = scan.hits.filter((hit) => !reportedRawHits.has(`${hit.id}:${hit.offset}`));
  findings.push(...tokenFindings({ ...scan, hits: freshHits }, { path, reader: 'zip', source: 'container-raw-bytes' }));
  const scanLimitation = tokenScanLimitation(scan, '制品字节');
  if (scanLimitation !== null) {
    limitations.push(scanLimitation);
  }

  return { findings, limitations };
}

export const zipReader = defineReader({
  id: 'zip',
  formats: ['zip'],
  layers: ['metadata-hygiene', 'secret-minimization'],
  purpose: 'ZIP 中央目录与条目的事实提取，deflate 条目用 node:zlib 解压后扫描',
  read: readZip,
});
