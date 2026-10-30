// Mach-O 读取器：加载命令、节表、LC_CODE_SIGNATURE、Go 构建信息与 __DATA,.dep-v0 的事实提取。
// 只读：按魔数判定字节序，逐个加载命令解析，节名取节内的固定长字段。
// 胖二进制按分片表逐个解析分片；每条发现都附读取器自身限制。

import { createFinding } from '../audit/finding.mjs';
import { defineReader, findAll, isPrintableAscii, limitation, readEntryBytes, readUIntBE, readUIntLE, sanitizeExcerpt, truncationLimitation } from './common.mjs';
import { GO_BUILDINFO_MAGIC, goBuildinfoDetail, inspectDepV0, inspectGoBuildinfo } from './native-shared.mjs';
import { scanTokens, tokenFindings, tokenScanLimitation } from './scan.mjs';

/** Mach-O 魔数。 */
const MACHO_MAGICS = Object.freeze({
  0xfeedface: { bits: 32, big: false, label: 'Mach-O 32 位' },
  0xcefaedfe: { bits: 32, big: true, label: 'Mach-O 32 位（大端）' },
  0xfeedfacf: { bits: 64, big: false, label: 'Mach-O 64 位' },
  0xcffaedfe: { bits: 64, big: true, label: 'Mach-O 64 位（大端）' },
});

/** 胖二进制魔数，按大端解释。 */
const FAT_MAGICS = Object.freeze({
  0xcafebabe: { bits: 32, label: '胖二进制' },
  0xcafebabf: { bits: 64, label: '胖二进制（64 位）' },
});

/** Mach-O 中央处理器类型。 */
const CPU_TYPES = Object.freeze({ 7: 'x86', 0x01000007: 'x86-64', 12: 'ARM', 0x0100000c: 'ARM64' });

/** Mach-O 文件类型。 */
const FILE_TYPES = Object.freeze({ 1: '目标文件', 2: '可执行文件', 4: '核心转储', 6: '动态库', 8: '捆绑包', 9: '动态链接编辑器', 10: '预载可执行文件' });

/** 加载命令标识，只登记 v1 会报告的类型。 */
const LOAD_COMMANDS = Object.freeze({
  0x1: 'LC_SEGMENT',
  0x2: 'LC_SYMTAB',
  0x5: 'LC_UNIXTHREAD',
  0xb: 'LC_DYSYMTAB',
  0xc: 'LC_LOAD_DYLIB',
  0xd: 'LC_ID_DYLIB',
  0x19: 'LC_SEGMENT_64',
  0x1b: 'LC_UUID',
  0x1d: 'LC_CODE_SIGNATURE',
  0x80000018: 'LC_LOAD_WEAK_DYLIB',
  0x80000028: 'LC_MAIN',
  0x8000001f: 'LC_REEXPORT_DYLIB',
  0x32: 'LC_BUILD_VERSION',
});

/** VM 保护位。 */
const VM_PROT_WRITE = 0x2;

/** 单个分片最多解析的加载命令数，防止畸形 cmdsize 造成超长循环。 */
const MAX_LOAD_COMMANDS = 4096;

/**
 * 读取定长节名或段名字段：取首个空字符前的可打印内容。
 * @param {Buffer} bytes
 * @param {number} offset
 * @param {number} length
 * @returns {string}
 */
function readFixedName(bytes, offset, length) {
  const raw = bytes.subarray(offset, offset + length);
  let end = 0;
  while (end < raw.length && raw[end] !== 0) {
    end += 1;
  }
  const name = raw.subarray(0, end);
  return isPrintableAscii(name) ? name.toString('latin1') : sanitizeExcerpt(raw, length);
}

/**
 * 解析一个 Mach-O 分片。
 * @param {Buffer} bytes 整个文件字节
 * @param {number} base 分片起始偏移
 * @param {string} sliceLabel 分片说明，用于报告
 * @returns {{ok: true, data: Record<string, unknown>} | {ok: false, reason: string}}
 */
function parseSlice(bytes, base, sliceLabel) {
  if (base + 28 > bytes.length) {
    return { ok: false, reason: `${sliceLabel}起始偏移 ${base} 之后读不到完整 Mach-O 头` };
  }
  const magic = readUIntLE(bytes, base, 4);
  const spec = MACHO_MAGICS[magic];
  if (spec === undefined) {
    return { ok: false, reason: `${sliceLabel}起始偏移 ${base} 处的魔数 0x${magic?.toString(16)} 不是 Mach-O 魔数` };
  }
  const read = (offset, size) => (spec.big ? readUIntBE(bytes, offset, size) : readUIntLE(bytes, offset, size));
  const headerSize = spec.bits === 64 ? 32 : 28;
  if (base + headerSize > bytes.length) {
    return { ok: false, reason: `${sliceLabel}头超出已读取字节范围` };
  }
  const data = {
    base,
    sliceLabel,
    bits: spec.bits,
    big: spec.big,
    cputype: read(base + 4, 4),
    cpusubtype: read(base + 8, 4),
    filetype: read(base + 12, 4),
    ncmds: read(base + 16, 4),
    sizeofcmds: read(base + 20, 4),
    flags: read(base + 24, 4),
    sections: [],
    segments: [],
    dylibs: [],
    codeSignature: null,
    uuid: null,
    entryPoint: null,
    loadCommandKinds: [],
    // 解析过程中攒下的说明，由读取器入口转成限制说明。挂在 data 上而不是改返回形状：
    // parseFat 只取 parsed.data，改形状会漏掉胖二进制分片那一支。
    problems: [],
  };
  if (data.cputype === undefined || data.ncmds === undefined || data.sizeofcmds === undefined) {
    return { ok: false, reason: `${sliceLabel}头字段读取越界` };
  }
  const commandBase = base + headerSize;
  const commandEnd = Math.min(bytes.length, commandBase + data.sizeofcmds);
  let position = commandBase;
  const declaredOverCap = data.ncmds > MAX_LOAD_COMMANDS;
  for (let index = 0; index < Math.min(data.ncmds, MAX_LOAD_COMMANDS); index += 1) {
    if (position + 8 > commandEnd) {
      break;
    }
    const cmd = read(position, 4);
    const cmdsize = read(position + 4, 4);
    if (cmd === undefined || cmdsize === undefined || cmdsize < 8 || position + cmdsize > commandEnd) {
      break;
    }
    const kind = LOAD_COMMANDS[cmd];
    data.loadCommandKinds.push({ cmd, name: kind ?? `0x${cmd.toString(16)}`, offset: position, size: cmdsize });
    if (cmd === 0x19 || cmd === 0x1) {
      const is64 = cmd === 0x19;
      const segmentHeaderSize = is64 ? 72 : 56;
      const sectionSize = is64 ? 80 : 68;
      if (position + segmentHeaderSize <= commandEnd) {
        const segname = readFixedName(bytes, position + 8, 16);
        const nsects = read(position + (is64 ? 64 : 48), 4);
        const segment = {
          name: segname,
          fileoff: read(position + (is64 ? 40 : 32), is64 ? 8 : 4),
          filesize: read(position + (is64 ? 48 : 40), is64 ? 8 : 4),
          initprot: read(position + (is64 ? 60 : 44), 4),
          nsects: nsects ?? 0,
        };
        data.segments.push(segment);
        const sectionBase = position + segmentHeaderSize;
        for (let sectionIndex = 0; sectionIndex < (nsects ?? 0); sectionIndex += 1) {
          const offset = sectionBase + sectionIndex * sectionSize;
          if (offset + sectionSize > commandEnd) {
            break;
          }
          data.sections.push({
            segment: segname,
            name: readFixedName(bytes, offset, 16),
            addr: read(offset + 32, is64 ? 8 : 4),
            size: read(offset + (is64 ? 40 : 36), is64 ? 8 : 4),
            offset: read(offset + (is64 ? 48 : 40), 4),
          });
        }
      }
    } else if (cmd === 0x1d) {
      const dataoff = read(position + 8, 4);
      const datasize = read(position + 12, 4);
      if (dataoff !== undefined && datasize !== undefined) {
        data.codeSignature = { offset: base + dataoff, size: datasize };
      }
    } else if (cmd === 0x1b) {
      data.uuid = sanitizeExcerpt(bytes.subarray(position + 8, position + 24), 32);
    } else if (cmd === 0xc || cmd === 0xd || cmd === 0x80000018 || cmd === 0x8000001f) {
      const nameOffset = read(position + 8, 4);
      if (nameOffset !== undefined && nameOffset > 0 && position + nameOffset < position + cmdsize) {
        const raw = bytes.subarray(position + nameOffset, position + cmdsize);
        let end = 0;
        while (end < raw.length && raw[end] !== 0) {
          end += 1;
        }
        if (isPrintableAscii(raw.subarray(0, end))) {
          data.dylibs.push(raw.subarray(0, end).toString('latin1'));
        }
      }
    } else if (cmd === 0x80000028) {
      data.entryPoint = read(position + 8, 8);
    }
    position += cmdsize;
  }
  // 命令数按登记上限截断，截断必须留声：一个声明 42 亿条命令的文件和一个声明
  // 4096 条的文件，解析结果完全相同，不说的话报告分辨不出这两者。
  // 报实际解析条数而不是上限本身：命令区提前读完时解析条数会少于上限，
  // 写成"只解析前 4096 条"就成了假话。
  if (declaredOverCap) {
    data.problems.push(
      `加载命令数声明 ${data.ncmds} 条，超过登记上限 ${MAX_LOAD_COMMANDS}，本次解析 ${data.loadCommandKinds.length} 条，其余命令没有解析`,
    );
  }
  return { ok: true, data };
}

/**
 * 解析胖二进制分片表并逐个解析分片。
 * 分片项布局按位数区分：32 位 fat_arch 为 20 字节，offset 与 size 各 4 字节；
 * 64 位 fat_arch_64 为 32 字节，offset 与 size 各 8 字节。
 * @param {Buffer} bytes
 * @returns {{ok: true, slices: Array<Record<string, unknown>>, fat: true} | {ok: false, reason: string}}
 */
function parseFat(bytes) {
  const magic = readUIntBE(bytes, 0, 4);
  const spec = FAT_MAGICS[magic];
  if (spec === undefined) {
    return { ok: false, reason: '魔数不是胖二进制魔数' };
  }
  const count = readUIntBE(bytes, 4, 4);
  if (count === undefined || count > 64) {
    return { ok: false, reason: '胖二进制分片数读取失败或超出合理范围' };
  }
  const is64 = spec.bits === 64;
  const entrySize = is64 ? 32 : 20;
  const slices = [];
  for (let index = 0; index < count; index += 1) {
    const base = 8 + index * entrySize;
    if (base + entrySize > bytes.length) {
      break;
    }
    // 偏移字段宽度随位数：64 位按 8 字节读，按 4 字节读会取到高 4 字节，
    // 对 offset 大于 4 GiB 的分片恒为零，把所有分片都送到文件头去解析。
    const offset = readUIntBE(bytes, base + 8, is64 ? 8 : 4);
    if (offset === undefined) {
      continue;
    }
    const parsed = parseSlice(bytes, offset, `第 ${index} 号分片`);
    slices.push(parsed.ok ? parsed.data : { base: offset, sliceLabel: `第 ${index} 号分片`, unparsable: parsed.reason });
  }
  return { ok: true, slices, fat: true };
}

/**
 * Mach-O 读取器入口。
 * @param {{entry: Record<string, unknown>, policy: Record<string, unknown>, budgets: Record<string, number>}} context
 * @returns {Promise<{findings: Array<Record<string, unknown>>, limitations: Array<Record<string, unknown>>}>}
 */
async function readMachO(context) {
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

  let slices = [];
  let isFat = false;
  // 胖二进制魔数按大端读：字节序列 CA FE BA BE，小端读会得到另一个值。
  const firstMagic = readUIntBE(bytes, 0, 4);
  if (FAT_MAGICS[firstMagic] !== undefined) {
    const fat = parseFat(bytes);
    if (!fat.ok) {
      limitations.push(limitation('macho-fat-unparsable', `胖二进制解析失败：${fat.reason}。该条目不等于没有暴露，只是本次没有提取到事实`));
      return { findings, limitations };
    }
    slices = fat.slices;
    isFat = true;
    const sliceLabels = slices.map((slice) => `${slice.sliceLabel}：${CPU_TYPES[slice.cputype] ?? slice.cputype ?? '未解析'}`);
    findings.push(
      createFinding({
        layer: 'metadata-hygiene',
        severity: 'info',
        title: 'Mach-O 胖二进制分片表',
        category: 'macho-fat-header',
        evidence: { path, byteRange: [0, 8], excerpt: sliceLabels.join('；') },
        reader: 'mach-o',
        readerLimitation: '胖二进制只按分片表逐个解析分片头与加载命令，不反汇编、不恢复源码；分片数上限 64，超出部分没有解析',
        mitigation: null,
        detail: { fat: true, sliceCount: slices.length, slices: slices.map((slice) => ({ cputype: slice.cputype ?? null, unparsable: slice.unparsable ?? null })) },
      }),
    );
  } else {
    const parsed = parseSlice(bytes, 0, 'Mach-O');
    if (!parsed.ok) {
      limitations.push(limitation('macho-unparsable', `Mach-O 解析失败：${parsed.reason}。该条目不等于没有暴露，只是本次没有提取到事实`));
      return { findings, limitations };
    }
    slices = [parsed.data];
  }

  for (const slice of slices) {
    if (slice.unparsable !== undefined) {
      limitations.push(limitation('macho-slice-unparsable', `${slice.sliceLabel}解析失败：${slice.unparsable}`));
      continue;
    }
    for (const problem of slice.problems ?? []) {
      limitations.push(limitation('macho-load-command-limit', `${slice.sliceLabel}${problem}`));
    }
    const cpuLabel = CPU_TYPES[slice.cputype] ?? String(slice.cputype);
    const filetypeLabel = FILE_TYPES[slice.filetype] ?? String(slice.filetype);
    findings.push(
      createFinding({
        layer: 'metadata-hygiene',
        severity: 'info',
        title: 'Mach-O 头声明的格式事实',
        category: 'macho-header',
        evidence: {
          path,
          byteRange: [slice.base, slice.base + (slice.bits === 64 ? 32 : 28)],
          excerpt: `${slice.bits} 位 ${cpuLabel} ${filetypeLabel} ${slice.ncmds} 条加载命令`,
        },
        reader: 'mach-o',
        readerLimitation:
          '只解析 Mach-O 头与加载命令声明的字段，不反汇编、不恢复源码；头字段可被伪造，声明与真实行为未必一致；加载命令数上限 4096 条，超出部分没有解析',
        mitigation: null,
        detail: {
          fat: isFat,
          slice: slice.sliceLabel,
          bits: slice.bits,
          cputype: cpuLabel,
          filetype: filetypeLabel,
          loadCommandCount: slice.ncmds,
          loadCommandKinds: slice.loadCommandKinds.map((command) => command.name),
        },
      }),
    );

    if (slice.uuid !== null) {
      findings.push(
        createFinding({
          layer: 'metadata-hygiene',
          severity: 'low',
          title: 'Mach-O LC_UUID 构建标识',
          category: 'macho-uuid',
          evidence: { path, byteRange: [slice.base, slice.base + 24], excerpt: slice.uuid },
          reader: 'mach-o',
          readerLimitation: '只登记 LC_UUID 的十六进制字节，不据此判断制品来源；标识可被改写，改写后需走必需集豁免',
          mitigation: null,
          detail: { uuid: slice.uuid },
        }),
      );
    }

    if (slice.codeSignature !== null) {
      findings.push(
        createFinding({
          layer: 'metadata-hygiene',
          severity: 'medium',
          title: 'Mach-O LC_CODE_SIGNATURE 代码签名',
          category: 'macho-code-signature',
          evidence: { path, byteRange: [slice.codeSignature.offset, slice.codeSignature.offset + slice.codeSignature.size], excerpt: `签名数据 ${slice.codeSignature.size} 字节` },
          reader: 'mach-o',
          readerLimitation: '只登记 LC_CODE_SIGNATURE 存在与大小，不验证密码学信任、不解码签名者身份；签名是否有效不在 v1 判定范围',
          mitigation: null,
          detail: { offset: slice.codeSignature.offset, size: slice.codeSignature.size },
        }),
      );
    }

    if (slice.dylibs.length > 0) {
      findings.push(
        createFinding({
          layer: 'metadata-hygiene',
          severity: 'medium',
          title: 'Mach-O 链接的动态库',
          category: 'macho-dylibs',
          evidence: { path, byteRange: [slice.base, slice.base + slice.sizeofcmds], excerpt: slice.dylibs.slice(0, 12).join('、') },
          reader: 'mach-o',
          readerLimitation: '动态库名按加载命令逐个取出，只登记链接关系，不解析符号导入清单',
          mitigation: null,
          detail: { dylibs: slice.dylibs },
        }),
      );
    }

    // Rust 依赖节 __DATA,.dep-v0。
    for (const section of slice.sections) {
      if (!(section.segment === '__DATA' && section.name === '.dep-v0')) {
        continue;
      }
      const content = bytes.subarray(section.offset, Math.min(bytes.length, section.offset + section.size));
      const dep = inspectDepV0(content);
      findings.push(
        createFinding({
          layer: 'metadata-hygiene',
          severity: 'medium',
          title: 'Rust 依赖清单节 __DATA,.dep-v0',
          category: 'rust-dep-v0',
          evidence: {
            path,
            byteRange: [section.offset, section.offset + section.size],
            excerpt: dep.method === 'none' ? `压缩载荷 ${section.size} 字节，未能解压` : dep.entries.slice(0, 6).join('、'),
          },
          reader: 'mach-o',
          readerLimitation:
            dep.method === 'none'
              ? `${dep.error}；依赖清单只能按节名命中，载荷内容未解出，未解出部分不等于不存在`
              : `依赖清单来自解压后的载荷，解压方式为${dep.method}；节名覆写后载荷字节仍可能被裸检索原样提取，读取器未发现不等于不存在`,
          mitigation: 'metadata.rust-dep-section-overwrite',
          detail: { segment: section.segment, section: section.name, size: section.size, decompressMethod: dep.method, dependencies: dep.method === 'none' ? [] : dep.entries.slice(0, 32) },
        }),
      );
    }

    // Go 构建信息：命中魔数后看是否落在首个可写映射内。
    const magicHits = findAll(bytes, GO_BUILDINFO_MAGIC);
    for (const magicOffset of magicHits) {
      const info = inspectGoBuildinfo(bytes, magicOffset);
      const writableSegment = slice.segments.find((segment) => (segment.initprot & VM_PROT_WRITE) !== 0);
      const inWritableSegment =
        writableSegment !== undefined && magicOffset >= writableSegment.fileoff && magicOffset < writableSegment.fileoff + writableSegment.filesize;
      findings.push(
        createFinding({
          layer: 'metadata-hygiene',
          severity: 'high',
          title: 'Go 构建信息',
          category: 'go-buildinfo',
          evidence: {
            path,
            byteRange: [magicOffset, magicOffset + 32],
            excerpt: info.version ? `${info.encoding} 编码，版本串 ${info.version}` : `${info.encoding} 编码，版本串未解出`,
          },
          reader: 'mach-o',
          readerLimitation:
            info.encoding === 'unresolved'
              ? '魔数之后的编码既不符合 inline 也不符合 pointer 的已识别布局，只报告存在；未解出的版本串不等于不存在'
              : '只提取魔数附近的版本串，模块信息载荷是否完整未经解析；覆写只覆盖已识别布局，其余字节仍可被裸检索',
          mitigation: 'metadata.go-buildinfo-macho-rw-overwrite',
          detail: { writableSegment: writableSegment?.name ?? null, inWritableSegment, ...goBuildinfoDetail(info) },
        }),
      );
    }
  }

  // 令牌扫描按整文件做一次，不随分片重复。
  const scan = scanTokens(bytes);
  findings.push(...tokenFindings(scan, { path, reader: 'mach-o', source: 'raw-bytes' }));
  const scanLimitation = tokenScanLimitation(scan, '制品字节');
  if (scanLimitation !== null) {
    limitations.push(scanLimitation);
  }

  return { findings, limitations };
}

export const machoReader = defineReader({
  id: 'mach-o',
  formats: ['mach-o', 'mach-o-fat'],
  layers: ['metadata-hygiene', 'secret-minimization'],
  purpose: 'Mach-O 加载命令、节表与 LC_CODE_SIGNATURE 的事实提取',
  read: readMachO,
});
