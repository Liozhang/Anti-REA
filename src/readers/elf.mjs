// ELF 读取器：节表、符号表、note、Go 构建信息与 .dep-v0 的事实提取。
// 只读：按 e_ident 判定字节序与字长，逐节解析节头，符号名经字符串表间接取出。
// 每条发现都附读取器自身限制；解析不到的部分转成限制说明，不让审计失败。

import { createFinding } from '../audit/finding.mjs';
import {
  defineReader,
  findAll,
  isPrintableAscii,
  limitation,
  readEntryBytes,
  readUIntBE,
  readUIntLE,
  sanitizeExcerpt,
  truncationLimitation,
} from './common.mjs';
import { GO_BUILDINFO_MAGIC, goBuildinfoDetail, inspectDepV0, inspectGoBuildinfo } from './native-shared.mjs';
import { scanTokens, tokenFindings, tokenScanLimitation } from './scan.mjs';

/** ELF 文件类型。 */
const ELF_TYPES = Object.freeze({ 0: 'ET_NONE', 1: 'ET_REL', 2: 'ET_EXEC', 3: 'ET_DYN', 4: 'ET_CORE' });

/** ELF 机器类型，只登记常见值。 */
const ELF_MACHINES = Object.freeze({
  3: 'x86',
  8: 'MIPS',
  20: 'PowerPC',
  21: 'PowerPC64',
  40: 'ARM',
  62: 'x86-64',
  183: 'AArch64',
  243: 'RISC-V',
});

/** 节类型名。 */
const SHT_NAMES = Object.freeze({ 1: 'PROGBITS', 2: 'SYMTAB', 3: 'STRTAB', 4: 'RELA', 5: 'HASH', 6: 'DYNAMIC', 7: 'NOTE', 8: 'NOBITS', 9: 'REL', 11: 'DYNSYM', 14: 'INIT_ARRAY', 15: 'FINI_ARRAY' });

/** 程序头类型名。 */
const PT_NAMES = Object.freeze({ 1: 'PT_LOAD', 2: 'PT_DYNAMIC', 3: 'PT_INTERP', 4: 'PT_NOTE', 5: 'PT_SHLIB', 6: 'PT_PHDR', 7: 'PT_TLS' });

/** 摘录里最多列出的符号名数量。 */
const SYMBOL_NAME_LIMIT = 12;

/** 头发现里最多登记的节名数量。 */
const SECTION_NAME_LIMIT = 64;

/** 头发现里最多登记的程序头数量。 */
const PROGRAM_HEADER_LIMIT = 32;

/**
 * 解析 ELF 头。
 * @param {Buffer} bytes
 * @returns {{ok: true, data: Record<string, number>} | {ok: false, reason: string}}
 */
function parseHeader(bytes) {
  if (bytes.length < 16) {
    return { ok: false, reason: '文件不足 16 字节，读不到完整的 e_ident' };
  }
  if (bytes[0] !== 0x7f || bytes[1] !== 0x45 || bytes[2] !== 0x4c || bytes[3] !== 0x46) {
    return { ok: false, reason: '文件头不是 ELF 魔数' };
  }
  const elfClass = bytes[4];
  const elfData = bytes[5];
  if (elfClass !== 1 && elfClass !== 2) {
    return { ok: false, reason: `e_ident 的 EI_CLASS 取值 ${elfClass} 不是 1（32 位）或 2（64 位）` };
  }
  if (elfData !== 1 && elfData !== 2) {
    return { ok: false, reason: `e_ident 的 EI_DATA 取值 ${elfData} 不是 1（小端）或 2（大端）` };
  }
  const is64 = elfClass === 2;
  const big = elfData === 2;
  const read = (offset, size) => (big ? readUIntBE(bytes, offset, size) : readUIntLE(bytes, offset, size));
  const headerSize = is64 ? 64 : 52;
  if (bytes.length < headerSize) {
    return { ok: false, reason: `文件头不足 ${headerSize} 字节，只读到 ${bytes.length} 字节` };
  }
  const header = {
    is64,
    big,
    headerSize,
    type: read(16, 2),
    machine: read(18, 2),
    version: read(20, 4),
    entry: is64 ? read(24, 8) : read(24, 4),
    phoff: is64 ? read(32, 8) : read(28, 4),
    shoff: is64 ? read(40, 8) : read(32, 4),
    flags: is64 ? read(48, 4) : read(36, 4),
    ehsize: read(is64 ? 52 : 40, 2),
    phentsize: read(is64 ? 54 : 42, 2),
    phnum: read(is64 ? 56 : 44, 2),
    shentsize: read(is64 ? 58 : 46, 2),
    shnum: read(is64 ? 60 : 48, 2),
    shstrndx: read(is64 ? 62 : 50, 2),
  };
  for (const [key, value] of Object.entries(header)) {
    if (value === undefined) {
      return { ok: false, reason: `ELF 头字段 ${key} 读取越界` };
    }
  }
  return { ok: true, data: header };
}

/**
 * 解析节表。节头解析失败不抛出，按已解析到的节继续，缺的部分进限制说明。
 * @param {Buffer} bytes
 * @param {ReturnType<typeof parseHeader>} header
 * @returns {{sections: Array<Record<string, unknown>>, limitations: Array<Record<string, unknown>>}}
 */
function parseSections(bytes, header) {
  const sections = [];
  const limitations = [];
  const { data } = header;
  if (data.shoff === 0 || data.shnum === 0) {
    limitations.push(limitation('elf-no-section-table', 'ELF 头声明 shoff 为 0 或节数为 0，没有节表可解析；节名扫描与符号表事实不覆盖该制品'));
    return { sections, limitations };
  }
  const entrySize = data.shentsize >= (data.is64 ? 64 : 40) ? data.shentsize : data.is64 ? 64 : 40;
  const tableEnd = data.shoff + entrySize * data.shnum;
  if (data.shoff > bytes.length || tableEnd > bytes.length) {
    limitations.push(
      limitation('elf-section-table-out-of-range', `节表区间 [${data.shoff}, ${tableEnd}) 超出已读取字节范围（${bytes.length} 字节），节名扫描不完整`),
    );
  }
  const read = (offset, size) => (data.big ? readUIntBE(bytes, offset, size) : readUIntLE(bytes, offset, size));
  for (let index = 0; index < data.shnum; index += 1) {
    const base = data.shoff + index * entrySize;
    if (base + (data.is64 ? 64 : 40) > bytes.length) {
      limitations.push(limitation('elf-section-entry-out-of-range', `第 ${index} 号节头超出已读取字节范围，该节及其后的节没有解析`));
      break;
    }
    const section = data.is64
      ? {
          index,
          nameOffset: read(base, 4),
          type: read(base + 4, 4),
          flags: read(base + 8, 8),
          addr: read(base + 16, 8),
          offset: read(base + 24, 8),
          size: read(base + 32, 8),
          link: read(base + 40, 4),
          info: read(base + 44, 4),
          entsize: read(base + 56, 8),
        }
      : {
          index,
          nameOffset: read(base, 4),
          type: read(base + 4, 4),
          flags: read(base + 8, 4),
          addr: read(base + 12, 4),
          offset: read(base + 16, 4),
          size: read(base + 20, 4),
          link: read(base + 24, 4),
          info: read(base + 28, 4),
          entsize: read(base + 32, 4),
        };
    for (const [key, value] of Object.entries(section)) {
      if (value === undefined) {
        limitations.push(limitation('elf-section-field-out-of-range', `第 ${index} 号节头的字段 ${key} 读取越界，该节按未解析处理`));
        section.broken = true;
        break;
      }
    }
    if (section.broken !== true) {
      sections.push(section);
    }
  }

  // 节名经节头字符串表（shstrndx 指向的节）解析。
  const stringTable = sections[data.shstrndx];
  if (stringTable === undefined) {
    limitations.push(limitation('elf-no-section-name-table', `shstrndx 指向的第 ${data.shstrndx} 号节不在已解析区间内，节名无法解析，节名扫描只覆盖可直接识别的内容`));
  } else {
    const names = bytes.subarray(stringTable.offset, Math.min(bytes.length, stringTable.offset + stringTable.size));
    for (const section of sections) {
      const name = readCStringFrom(names, section.nameOffset);
      section.name = name ?? `(${section.nameOffset})`;
    }
  }
  return { sections, limitations };
}

/**
 * 从节头字符串表里取空字符结尾的节名。
 * @param {Buffer} names 字符串表字节
 * @param {number} offset
 * @returns {string | undefined}
 */
function readCStringFrom(names, offset) {
  if (offset >= names.length) {
    return undefined;
  }
  let end = offset;
  while (end < names.length && names[end] !== 0) {
    end += 1;
  }
  const raw = names.subarray(offset, end);
  if (!isPrintableAscii(raw)) {
    return undefined;
  }
  return raw.toString('latin1');
}

/**
 * 解析程序头，返回 PT_LOAD 与 PT_NOTE 两类段。
 * @param {Buffer} bytes
 * @param {ReturnType<typeof parseHeader>} header
 * @returns {{loads: Array<Record<string, number>>, notes: Array<Record<string, number>>, limitations: Array<Record<string, unknown>>}}
 */
function parseSegments(bytes, header) {
  const loads = [];
  const notes = [];
  const limitations = [];
  const { data } = header;
  if (data.phoff === 0 || data.phnum === 0) {
    return { loads, notes, limitations };
  }
  const entrySize = data.phentsize >= (data.is64 ? 56 : 32) ? data.phentsize : data.is64 ? 56 : 32;
  const read = (offset, size) => (data.big ? readUIntBE(bytes, offset, size) : readUIntLE(bytes, offset, size));
  for (let index = 0; index < data.phnum; index += 1) {
    const base = data.phoff + index * entrySize;
    if (base + (data.is64 ? 56 : 32) > bytes.length) {
      limitations.push(limitation('elf-program-header-out-of-range', `第 ${index} 号程序头超出已读取字节范围，该段及其后的段没有解析`));
      break;
    }
    const segment = data.is64
      ? { type: read(base, 4), flags: read(base + 4, 4), offset: read(base + 8, 8), vaddr: read(base + 16, 8), filesz: read(base + 32, 8) }
      : { type: read(base, 4), offset: read(base + 4, 4), vaddr: read(base + 8, 4), filesz: read(base + 16, 4), flags: read(base + 24, 4) };
    if (segment.type === undefined || segment.offset === undefined || segment.filesz === undefined) {
      limitations.push(limitation('elf-program-header-field-out-of-range', `第 ${index} 号程序头字段读取越界，该段按未解析处理`));
      continue;
    }
    if (segment.type === 1) {
      loads.push(segment);
    } else if (segment.type === 4) {
      notes.push(segment);
    }
  }
  return { loads, notes, limitations };
}

/**
 * 解析 note 区段，返回 note 列表。note 结构为 namesz、descsz、type 三个四字节字段加名称与描述，各自四字节对齐。
 * @param {Buffer} bytes
 * @param {number} offset
 * @param {number} size
 * @param {boolean} big
 * @returns {Array<{name: string, type: number, descOffset: number, descSize: number}>}
 */
/**
 * 判断一段字节是否全部为零。用于区分“构建标识还在”与“已被等长清零”。
 * @param {Buffer} bytes
 * @param {number} offset
 * @param {number} size
 * @returns {boolean}
 */
function isAllZero(bytes, offset, size) {
  if (offset < 0 || size <= 0 || offset + size > bytes.length) {
    return false;
  }
  for (let index = offset; index < offset + size; index += 1) {
    if (bytes[index] !== 0) {
      return false;
    }
  }
  return true;
}

function parseNotes(bytes, offset, size, big) {
  const read = (position, width) => (big ? readUIntBE(bytes, position, width) : readUIntLE(bytes, position, width));
  const notes = [];
  let position = offset;
  const end = Math.min(bytes.length, offset + size);
  while (position + 12 <= end) {
    const nameSize = read(position, 4);
    const descSize = read(position + 4, 4);
    const type = read(position + 8, 4);
    if (nameSize === undefined || descSize === undefined || type === undefined) {
      break;
    }
    const nameStart = position + 12;
    const nameEnd = nameStart + nameSize;
    const descStart = nameEnd + ((4 - (nameSize % 4)) % 4);
    const descEnd = descStart + descSize;
    if (descEnd > end) {
      break;
    }
    const name = bytes.subarray(nameStart, nameEnd).toString('latin1').replace(/\0+$/, '');
    notes.push({ name, type, descOffset: descStart, descSize });
    position = descEnd + ((4 - (descSize % 4)) % 4);
  }
  return notes;
}

/**
 * 解析符号表。
 * @param {Buffer} bytes
 * @param {Record<string, unknown>} section 符号表节
 * @param {Array<Record<string, unknown>>} sections 全部节，用于取字符串表
 * @param {boolean} big
 * @param {boolean} is64
 * @returns {{count: number, names: string[], limitations: Array<Record<string, unknown>>}}
 */
function parseSymbols(bytes, section, sections, big, is64) {
  const names = [];
  const limitations = [];
  const recordSize = section.entsize > 0 ? section.entsize : is64 ? 24 : 16;
  const count = section.size > 0 ? Math.floor(section.size / recordSize) : 0;
  const stringTable = sections[section.link];
  if (stringTable === undefined) {
    limitations.push(limitation('elf-no-symbol-string-table', `符号表节 ${section.name} 的 sh_link 指向的字符串表不在已解析区间内，符号名无法取出，只报告符号数量`));
    return { count, names, limitations };
  }
  const strings = bytes.subarray(stringTable.offset, Math.min(bytes.length, stringTable.offset + stringTable.size));
  const read = (offset, size) => (big ? readUIntBE(bytes, offset, size) : readUIntLE(bytes, offset, size));
  for (let index = 0; index < count; index += 1) {
    const base = section.offset + index * recordSize;
    if (base + (is64 ? 24 : 16) > bytes.length) {
      limitations.push(limitation('elf-symbol-out-of-range', `第 ${index} 号符号超出已读取字节范围，该符号及其后的符号没有解析`));
      break;
    }
    const nameOffset = read(base, 4);
    if (nameOffset === undefined) {
      continue;
    }
    if (names.length < SYMBOL_NAME_LIMIT && nameOffset > 0 && nameOffset < strings.length) {
      let end = nameOffset;
      while (end < strings.length && strings[end] !== 0) {
        end += 1;
      }
      const name = strings.subarray(nameOffset, end);
      if (isPrintableAscii(name)) {
        names.push(name.toString('latin1'));
      }
    }
  }
  return { count, names, limitations };
}


/**
 * ELF 读取器入口。
 * @param {{entry: Record<string, unknown>, policy: Record<string, unknown>, budgets: Record<string, number>}} context
 * @returns {Promise<{findings: Array<Record<string, unknown>>, limitations: Array<Record<string, unknown>>}>}
 */
async function readElf(context) {
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

  const header = parseHeader(bytes);
  if (!header.ok) {
    limitations.push(limitation('elf-header-unparsable', `ELF 头解析失败：${header.reason}。该条目不等于没有暴露，只是本次没有提取到事实`));
    return { findings, limitations };
  }

  const classLabel = header.data.is64 ? '64 位' : '32 位';
  const dataLabel = header.data.big ? '大端' : '小端';
  const typeLabel = ELF_TYPES[header.data.type] ?? String(header.data.type);
  const machineLabel = ELF_MACHINES[header.data.machine] ?? String(header.data.machine);
  const headerFinding = createFinding({
    layer: 'metadata-hygiene',
    severity: 'info',
    title: 'ELF 头声明的格式事实',
    category: 'elf-header',
    evidence: { path, byteRange: [0, header.data.headerSize], excerpt: `ELF ${classLabel}${dataLabel} ${typeLabel} ${machineLabel}` },
    reader: 'elf',
    readerLimitation: '只解析 ELF 头与节表声明的字段，不反汇编、不恢复源码；头字段可被伪造，声明与真实行为未必一致',
    mitigation: null,
    detail: {
      class: header.data.is64 ? 'ELFCLASS64' : 'ELFCLASS32',
      data: header.data.big ? 'ELFDATA2MSB' : 'ELFDATA2LSB',
      type: typeLabel,
      machine: machineLabel,
      entry: header.data.entry,
    },
  });
  findings.push(headerFinding);

  const { sections, limitations: sectionLimitations } = parseSections(bytes, header);
  limitations.push(...sectionLimitations);
  const { loads, notes: noteSegments, limitations: segmentLimitations } = parseSegments(bytes, header);
  limitations.push(...segmentLimitations);

  // 节名扫描：节表里的节名逐条登记，供覆写类措施与必需集校验引用。
  const sectionNames = sections.filter((section) => section.index > 0).map((section) => section.name);
  const programHeaderFacts = noteSegments.map((segment) => ({ type: PT_NAMES[segment.type] ?? String(segment.type), offset: segment.offset, filesz: segment.filesz }));
  headerFinding.detail.sectionNames = sectionNames.slice(0, SECTION_NAME_LIMIT);
  headerFinding.detail.sectionCount = sectionNames.length;
  headerFinding.detail.programHeaders = programHeaderFacts.slice(0, PROGRAM_HEADER_LIMIT);
  if (sectionNames.length > SECTION_NAME_LIMIT) {
    limitations.push(limitation('elf-section-name-limit', `节数 ${sectionNames.length} 超过登记上限 ${SECTION_NAME_LIMIT}，节名清单只登记前 ${SECTION_NAME_LIMIT} 个`));
  }

  // note：段内与节内各扫一遍，按名称与类型登记。
  const noteRegions = [
    ...noteSegments.map((segment) => ({ offset: segment.offset, size: segment.filesz })),
    ...sections.filter((section) => section.type === 7).map((section) => ({ offset: section.offset, size: section.size })),
  ];
  const noteList = [];
  for (const region of noteRegions) {
    noteList.push(...parseNotes(bytes, region.offset, region.size, header.data.big));
  }
  // 描述符已全部为零的构建标识 note 不按“携带构建标识”登记：那是加固后的状态，
  // 报成携带会让用户以为标识还在。结构仍由下面的 note 段存在发现覆盖。
  const buildIdNote = noteList.find((note) => note.name === 'GNU' && note.type === 3 && !isAllZero(bytes, note.descOffset, note.descSize));
  if (buildIdNote !== undefined) {
    findings.push(
      createFinding({
        layer: 'metadata-hygiene',
        severity: 'low',
        title: 'ELF note 携带构建标识',
        category: 'elf-build-id',
        evidence: {
          path,
          byteRange: [buildIdNote.descOffset, buildIdNote.descOffset + buildIdNote.descSize],
          excerpt: sanitizeExcerpt(bytes.subarray(buildIdNote.descOffset, buildIdNote.descOffset + buildIdNote.descSize), 40),
        },
        reader: 'elf',
        readerLimitation: '构建标识只登记存在与字节，不据此判断制品来源；描述符字节可被等长清零，清零后按标识匹配调试信息的机制失效',
        mitigation: 'metadata.elf-build-id-note-overwrite',
        detail: { noteName: buildIdNote.name, noteType: buildIdNote.type, descSize: buildIdNote.descSize },
      }),
    );
  }
  if (noteList.length > 0 && buildIdNote === undefined) {
    findings.push(
      createFinding({
        layer: 'metadata-hygiene',
        severity: 'low',
        title: 'ELF note 段存在',
        category: 'elf-note',
        evidence: { path, byteRange: [noteRegions[0].offset, noteRegions[0].offset + noteRegions[0].size], excerpt: noteList.map((note) => `${note.name}/${note.type}`).join('、') },
        reader: 'elf',
        readerLimitation: 'note 名称与类型逐条登记，note 载荷是否含签名性内容不在 v1 判定范围',
        mitigation: null,
        detail: { notes: noteList.map((note) => ({ name: note.name, type: note.type, descSize: note.descSize })) },
      }),
    );
  }

  // 符号表。
  for (const section of sections) {
    if (section.type !== 2 && section.type !== 11) {
      continue;
    }
    const symbols = parseSymbols(bytes, section, sections, header.data.big, header.data.is64);
    limitations.push(...symbols.limitations);
    findings.push(
      createFinding({
        layer: 'metadata-hygiene',
        severity: 'medium',
        title: section.type === 11 ? 'ELF 动态符号表' : 'ELF 符号表',
        category: 'elf-symtab',
        evidence: {
          path,
          byteRange: [section.offset, section.offset + section.size],
          excerpt: symbols.names.length > 0 ? symbols.names.join('、') : `共 ${symbols.count} 个符号，符号名未取出`,
        },
        reader: 'elf',
        readerLimitation:
          '符号名按字符串表逐条取出，只列前若干个；剥离符号只让按名检索失败，地址级枚举仍可用，运行期动态符号不在覆写范围',
        mitigation: 'metadata.elf-symtab-clear',
        detail: {
          section: section.name,
          sectionType: SHT_NAMES[section.type] ?? String(section.type),
          symbolCount: symbols.count,
          sampleNames: symbols.names,
          stringTableSection: sections[section.link]?.name ?? null,
        },
      }),
    );
  }

  // Rust 依赖节 .dep-v0。
  for (const section of sections) {
    if (section.name !== '.dep-v0') {
      continue;
    }
    const content = bytes.subarray(section.offset, Math.min(bytes.length, section.offset + section.size));
    const dep = inspectDepV0(content);
    findings.push(
      createFinding({
        layer: 'metadata-hygiene',
        severity: 'medium',
        title: 'Rust 依赖清单节 .dep-v0',
        category: 'rust-dep-v0',
        evidence: {
          path,
          byteRange: [section.offset, section.offset + section.size],
          excerpt: dep.method === 'none' ? `压缩载荷 ${section.size} 字节，未能解压` : dep.entries.slice(0, 6).join('、'),
        },
        reader: 'elf',
        readerLimitation:
          dep.method === 'none'
            ? `${dep.error}；依赖清单只能按节名命中，载荷内容未解出，未解出部分不等于不存在`
            : '依赖清单来自解压后的载荷，解压方式为' +
              dep.method +
              '；节名与节类型覆写后载荷字节仍可能被裸检索原样提取，读取器未发现不等于不存在',
        mitigation: 'metadata.rust-dep-section-overwrite',
        detail: {
          section: section.name,
          sectionType: SHT_NAMES[section.type] ?? String(section.type),
          size: section.size,
          decompressMethod: dep.method,
          dependencies: dep.method === 'none' ? [] : dep.entries.slice(0, 32),
        },
      }),
    );
  }

  // Go 构建信息。
  const magicHits = findAll(bytes, GO_BUILDINFO_MAGIC);
  for (const magicOffset of magicHits) {
    const info = inspectGoBuildinfo(bytes, magicOffset);
    const containingSection = sections.find((section) => magicOffset >= section.offset && magicOffset < section.offset + section.size);
    const inWritableLoad = loads.some((load) => {
      const writable = (load.flags & 0x2) !== 0;
      const executable = (load.flags & 0x1) !== 0;
      return writable && !executable && magicOffset >= load.offset && magicOffset < load.offset + load.filesz;
    });
    let mitigation = 'metadata.go-buildinfo-pointer-overwrite';
    if (info.encoding === 'inline') {
      mitigation = 'metadata.go-buildinfo-inline-overwrite';
    } else if (info.encoding === 'pointer' && inWritableLoad) {
      mitigation = 'metadata.go-buildinfo-writable-region-overwrite';
    }
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
        reader: 'elf',
        readerLimitation:
          info.encoding === 'unresolved'
            ? '魔数之后的编码既不符合 inline 也不符合 pointer 的已识别布局，只报告存在；未解出的版本串不等于不存在'
            : '只提取魔数附近的版本串，模块信息载荷是否完整未经解析；覆写只覆盖已识别布局，其余字节仍可被裸检索',
        mitigation,
        detail: {
          section: containingSection?.name ?? null,
          inWritableNonExecutableLoad: inWritableLoad,
          ...goBuildinfoDetail(info),
        },
      }),
    );
  }

  // 令牌扫描。
  const scan = scanTokens(bytes);
  findings.push(...tokenFindings(scan, { path, reader: 'elf', source: 'raw-bytes' }));
  const scanLimitation = tokenScanLimitation(scan, '制品字节');
  if (scanLimitation !== null) {
    limitations.push(scanLimitation);
  }

  return { findings, limitations };
}

export const elfReader = defineReader({
  id: 'elf',
  formats: ['elf'],
  layers: ['metadata-hygiene', 'secret-minimization'],
  purpose: 'ELF 节表、符号表、note 与 Go 构建信息的事实提取',
  read: readElf,
});
