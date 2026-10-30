// 等长覆写类缓解措施。
// 共同性质：保持文件长度与全部偏移不变，只把目标字节清零，结构性安全。
// 每一项都先按当前字节重新定位目标（不轻信审计报告里的偏移），定位不到就返回跳过原因，
// 绝不“找不到也照写”——那会把无关字节清零，伤害合法用户。

import { findAll, readUvarint } from '../readers/common.mjs';
import { GO_BUILDINFO_MAGIC, inspectGoBuildinfo } from '../readers/native-shared.mjs';
import { scanTokens, TOKEN_PATTERNS } from '../readers/scan.mjs';
import { parseElfStructure, parseMachOStructure, parsePeStructure, locateElfBuildIdNotes, locatePeDebugPaths } from './parse.mjs';
import { findStoredEntryAt, locateZipEntries, patchEntryCrc32 } from './zip-entry.mjs';

/** 令牌扫描窗口，与读取器保持一致，保证重新扫描命中同一批偏移。 */
const TOKEN_SCAN_WINDOW_BYTES = 8 * 1024 * 1024;

/** ELF 静态符号表节类型。 */
const SHT_SYMTAB = 2;
/** ELF 动态符号表节类型，运行期必需，默认拒改。 */
const SHT_DYNSYM = 11;
/** ELF 字符串表节类型。 */
const SHT_STRTAB = 3;
/** Rust 依赖节名。 */
const RUST_DEP_SECTION = '.dep-v0';
/** pyc hash_based 标志位。 */
const PYC_FLAG_HASH_BASED = 0b01;
/** pyc check_source 标志位。 */
const PYC_FLAG_CHECK_SOURCE = 0b10;
/** pyc source_hash 字段偏移与长度。 */
const PYC_SOURCE_HASH_OFFSET = 8;
const PYC_SOURCE_HASH_LENGTH = 8;

/**
 * 把缓冲区的一段字节清零，返回实际清零的区间；区间为空时返回 null。
 * @param {Buffer} buffer 可写缓冲区
 * @param {number} start
 * @param {number} end
 * @returns {[number, number] | null}
 */
function zeroRange(buffer, start, end) {
  const from = Math.max(0, Math.min(Math.floor(start), buffer.length));
  const to = Math.max(from, Math.min(Math.floor(end), buffer.length));
  if (to <= from) {
    return null;
  }
  buffer.fill(0, from, to);
  return [from, to];
}

/**
 * 从发现里取 Go 构建信息魔数偏移：优先 detail.magicOffset，再退到证据字节区间起点，
 * 两处都对不上魔数时取缓冲区里第一个魔数命中。都找不到时返回 null。
 * @param {Buffer} buffer
 * @param {Record<string, unknown>} finding
 * @returns {number | null}
 */
export function goBuildinfoMagicOffset(buffer, finding) {
  const hits = findAll(buffer, GO_BUILDINFO_MAGIC);
  if (hits.length === 0) {
    return null;
  }
  const candidates = [finding?.detail?.magicOffset, finding?.evidence?.byteRange?.[0]];
  for (const candidate of candidates) {
    if (Number.isSafeInteger(candidate) && hits.includes(candidate)) {
      return candidate;
    }
  }
  return hits[0];
}

/**
 * Go 构建信息等长覆写：ELF、Mach-O 与 PE 三类容器共用同一套字节行为。
 * inline 编码覆写魔数、版本串与模块信息载荷；pointer 编码覆写魔数、两个指针变长值及其目标串；
 * 编码未识别时只覆写魔数本身，并把残留风险写进 notes。
 * @param {Buffer} buffer 制品字节（不会被修改）
 * @param {Record<string, unknown>} finding 审计发现
 * @returns {{ok: true, buffer: Buffer, ranges: Array<[number, number]>, notes: string[]} | {ok: false, reason: string}}
 */
export function overwriteGoBuildinfo(buffer, finding) {
  const magicOffset = goBuildinfoMagicOffset(buffer, finding);
  if (magicOffset === null) {
    return { ok: false, reason: '当前字节里找不到 Go 构建信息魔数，可能已被覆写或审计结果已过期' };
  }
  const out = Buffer.from(buffer);
  const ranges = [];
  const notes = [];
  const push = (range) => {
    if (range !== null) {
      ranges.push(range);
    }
  };

  push(zeroRange(out, magicOffset, magicOffset + GO_BUILDINFO_MAGIC.length));
  const info = inspectGoBuildinfo(out, magicOffset);
  const after = magicOffset + GO_BUILDINFO_MAGIC.length;

  if (info.encoding === 'inline') {
    const versionOffset = info.detail.versionOffset;
    const versionLength = info.detail.versionLength;
    if (Number.isSafeInteger(versionOffset) && Number.isSafeInteger(versionLength)) {
      push(zeroRange(out, versionOffset, versionOffset + versionLength));
      // 版本串之后的模块信息：变长长度加载荷，只有读取器确认存在时才覆写。
      if (info.moduleInfo === true) {
        const moduleInfo = readUvarint(out, versionOffset + versionLength);
        if (moduleInfo !== undefined && moduleInfo.value <= 8 * 1024 * 1024) {
          push(zeroRange(out, versionOffset + versionLength, moduleInfo.next + moduleInfo.value));
        }
      }
    }
  } else if (info.encoding === 'pointer') {
    const first = readUvarint(out, after);
    if (first !== undefined) {
      push(zeroRange(out, after, first.next));
      const second = readUvarint(out, first.next);
      const pointerEnd = second === undefined ? first.next : second.next;
      push(zeroRange(out, first.next, pointerEnd));
      // 指针目标区的版本串与模块信息串按变长长度定位后覆写。
      for (const pointer of [first, second]) {
        if (pointer === undefined) {
          continue;
        }
        const target = readUvarint(out, pointer.value);
        if (target !== undefined && target.value <= 8 * 1024 * 1024) {
          push(zeroRange(out, target.next, target.next + target.value));
        }
      }
    }
  } else {
    notes.push('魔数之后的编码既不符合 inline 也不符合 pointer 的已识别布局，本次只覆写魔数本身；其余字节仍可被裸字符串检索原样提取');
  }

  if (ranges.length === 0) {
    return { ok: false, reason: '定位到的覆写区间为空，未改动任何字节' };
  }
  return { ok: true, buffer: out, ranges, notes };
}

/**
 * Rust 依赖节等长覆写：ELF 覆写节头里的节名偏移与节类型，Mach-O 覆写节内的定长节名字段。
 * 只改节头标识，不动载荷字节：压缩载荷仍可能被裸检索，这一残留风险在 notes 里写明。
 * @param {Buffer} buffer 制品字节
 * @param {Record<string, unknown>} finding 审计发现
 * @param {string} containerType 容器标识
 * @returns {{ok: true, buffer: Buffer, ranges: Array<[number, number]>, notes: string[]} | {ok: false, reason: string}}
 */
export function overwriteRustDepSection(buffer, finding, containerType) {
  const out = Buffer.from(buffer);
  const ranges = [];
  const notes = ['节名与节类型覆写后，载荷字节仍可能被裸字符串检索原样提取；读取器未发现不等于不存在'];

  if (containerType === 'elf') {
    const elf = parseElfStructure(buffer);
    if (!elf.ok) {
      return { ok: false, reason: `ELF 节表解析失败：${elf.reason}` };
    }
    const targets = elf.data.sections.filter((section) => section.name === RUST_DEP_SECTION);
    if (targets.length === 0) {
      return { ok: false, reason: '当前节表里找不到 .dep-v0 节，可能已被覆写或审计结果已过期' };
    }
    for (const section of targets) {
      // 节名偏移清零：指向节头字符串表首部的空字符串，节变成无名节。
      out.writeUInt32LE(0, section.headerOffset);
      ranges.push([section.headerOffset, section.headerOffset + 4]);
      // 节类型改写为 PROGBITS：节表仍可解析，只是不再被识别为依赖清单节。
      out.writeUInt32LE(1, section.headerOffset + 4);
      ranges.push([section.headerOffset + 4, section.headerOffset + 8]);
    }
    return { ok: true, buffer: out, ranges, notes };
  }

  if (containerType === 'mach-o' || containerType === 'mach-o-fat') {
    const macho = parseMachOStructure(buffer);
    if (!macho.ok) {
      return { ok: false, reason: `Mach-O 结构解析失败：${macho.reason}` };
    }
    let touched = 0;
    for (const slice of macho.data.slices) {
      for (const section of slice.sections) {
        if (section.name !== RUST_DEP_SECTION) {
          continue;
        }
        // 定长节名字段共 16 字节，整段清零后节名为空，节表仍可解析。
        const range = zeroRange(out, section.sectionHeaderOffset, section.sectionHeaderOffset + 16);
        if (range !== null) {
          ranges.push(range);
          touched += 1;
        }
      }
    }
    if (touched === 0) {
      return { ok: false, reason: '当前 Mach-O 分片里找不到 __DATA,.dep-v0 节，可能已被覆写或审计结果已过期' };
    }
    return { ok: true, buffer: out, ranges, notes };
  }

  return { ok: false, reason: `Rust 依赖节覆写只适用于 ELF 与 Mach-O，当前容器为 ${containerType}` };
}

/**
 * ELF 静态符号表清零：清零 .symtab 节头条目，覆写符号表载荷与其字符串表载荷。
 * 动态符号表（.dynsym）是运行期必需数据，一律拒改，命中时返回跳过原因。
 * @param {Buffer} buffer 制品字节
 * @param {Record<string, unknown>} finding 审计发现
 * @returns {{ok: true, buffer: Buffer, ranges: Array<[number, number]>, notes: string[]} | {ok: false, reason: string}}
 */
export function clearElfSymtab(buffer, finding) {
  const elf = parseElfStructure(buffer);
  if (!elf.ok) {
    return { ok: false, reason: `ELF 节表解析失败：${elf.reason}` };
  }
  const out = Buffer.from(buffer);
  const ranges = [];
  const notes = [
    '清零只让按名检索失败，地址级枚举仍可用；运行期动态符号不在覆写范围',
    '符号表载荷与字符串表载荷已一并覆写，未覆写字节仍可被裸检索',
  ];
  const staticSymtabs = elf.data.sections.filter((section) => section.type === SHT_SYMTAB);
  const findingSection = typeof finding?.detail?.section === 'string' && finding.detail.section !== '' ? finding.detail.section : null;
  if (findingSection !== null && !staticSymtabs.some((section) => section.name === findingSection)) {
    // 发现指向的不是静态符号表：动态符号表是运行期重定位的必需数据，一律拒改。
    const dynamic = elf.data.sections.find((section) => section.type === SHT_DYNSYM && section.name === findingSection);
    if (dynamic !== undefined) {
      return { ok: false, reason: `发现指向动态符号表 ${dynamic.name}，动态符号是运行期重定位的必需数据，默认拒改` };
    }
    return { ok: false, reason: `当前节表里找不到名为 ${findingSection} 的静态符号表节，可能已被清零或审计结果已过期` };
  }
  const targets = findingSection === null ? staticSymtabs : staticSymtabs.filter((section) => section.name === findingSection);
  if (targets.length === 0) {
    return { ok: false, reason: '当前节表里找不到静态符号表节，可能已被清零或审计结果已过期' };
  }

  const cleared = [];
  for (const section of targets) {
    // 清零整条节头：节类型归零后该条目不再被当作符号表，节表本身仍可逐条解析。
    const header = zeroRange(out, section.headerOffset, section.headerOffset + section.headerSize);
    if (header !== null) {
      ranges.push(header);
    }
    // 覆写符号表载荷。
    const symbols = zeroRange(out, section.offset, section.offset + section.size);
    if (symbols !== null) {
      ranges.push(symbols);
    }
    // 覆写 sh_link 指向的字符串表载荷；跳过字符串表头自身，避免其余节名一起失效。
    const strings = elf.data.sections[section.link];
    if (strings !== undefined && strings.type === SHT_STRTAB && strings.index !== elf.data.shstrndx) {
      const payload = zeroRange(out, strings.offset, strings.offset + strings.size);
      if (payload !== null) {
        ranges.push(payload);
      }
    }
    cleared.push(section.name === '' ? `第 ${section.index} 号节` : section.name);
  }
  if (ranges.length === 0) {
    return { ok: false, reason: '定位到的覆写区间为空，未改动任何字节' };
  }
  notes.push(`已清零的静态符号表：${cleared.join('、')}`);
  return { ok: true, buffer: out, ranges, notes };
}

/**
 * ELF 构建标识 note 覆写：把全部 GNU 构建标识的描述符字节等长清零。
 * 段内与节内各定位一遍并按区间去重：只清一处会让另一处原样暴露。
 * 只清零描述符，note 的名称、类型与长度字段不动，note 结构、节表与段表仍可按原样解析。
 * @param {Buffer} buffer 制品字节
 * @returns {{ok: true, buffer: Buffer, ranges: Array<[number, number]>, notes: string[]} | {ok: false, reason: string}}
 */
export function clearElfBuildIdNotes(buffer) {
  const located = locateElfBuildIdNotes(buffer);
  if (!located.ok) {
    return { ok: false, reason: `ELF 构建标识定位失败：${located.reason}` };
  }
  if (located.notes.length === 0) {
    return { ok: false, reason: '当前字节里找不到 GNU 构建标识 note，可能已被覆写或审计结果已过期' };
  }
  const out = Buffer.from(buffer);
  const ranges = [];
  const pending = located.notes.filter((note) => {
    const descriptor = out.subarray(note.descOffset, note.descOffset + note.descSize);
    return descriptor.some((byte) => byte !== 0);
  });
  if (pending.length === 0) {
    return { ok: false, reason: '构建标识描述符已全部为零，无需重复覆写' };
  }
  for (const note of pending) {
    const range = zeroRange(out, note.descOffset, note.descOffset + note.descSize);
    if (range !== null) {
      ranges.push(range);
    }
  }
  if (ranges.length === 0) {
    return { ok: false, reason: '定位到的覆写区间为空，未改动任何字节' };
  }
  return {
    ok: true,
    buffer: out,
    ranges,
    notes: [
      `本次清零 ${pending.length} 处构建标识描述符，段内与节内按区间去重`,
      '只清零描述符字节，note 的名称、类型与长度字段未动，note 结构与段表、节表仍可按原样解析',
      '清零后按构建标识匹配调试信息、符号服务器与核心转储的机制失效，不等于制品不可分析',
    ],
  };
}

/**
 * PE 调试目录符号文件路径覆写：把 CODEVIEW 记录里的路径字节（含结尾空字符）清零。
 * 只改路径字符串，不动调试目录结构与数据目录项，PE 仍可按原结构解析。
 * @param {Buffer} buffer 制品字节
 * @returns {{ok: true, buffer: Buffer, ranges: Array<[number, number]>, notes: string[]} | {ok: false, reason: string}}
 */
export function overwritePeDebugDirectoryPaths(buffer) {
  const pe = parsePeStructure(buffer);
  if (!pe.ok) {
    return { ok: false, reason: `PE 解析失败：${pe.reason}` };
  }
  const located = locatePeDebugPaths(buffer, pe.data);
  if (!located.ok) {
    return { ok: false, reason: located.reason };
  }
  const out = Buffer.from(buffer);
  const ranges = [];
  for (const path of located.paths) {
    // 连结尾空字符一起清零：路径整体不可读，记录结构保持完整。
    const range = zeroRange(out, path.pathOffset, path.pathOffset + path.pathLength + 1);
    if (range !== null) {
      ranges.push(range);
    }
  }
  if (ranges.length === 0) {
    return { ok: false, reason: '定位到的覆写区间为空，未改动任何字节' };
  }
  return {
    ok: true,
    buffer: out,
    ranges,
    notes: ['只覆写符号文件路径字节，调试目录项与数据目录未改动；路径指向的符号文件本身是否随制品分发不在本措施范围内'],
  };
}

/**
 * pyc 源文件摘要清零：清零 source_hash，并一并清除 check_source 标志，
 * 否则标志位与哈希状态不一致，运行期核对会直接失败。
 * @param {Buffer} buffer 制品字节
 * @returns {{ok: true, buffer: Buffer, ranges: Array<[number, number]>, notes: string[]} | {ok: false, reason: string}}
 */
export function clearPycSourceHash(buffer) {
  if (buffer.length < 16) {
    return { ok: false, reason: '文件不足十六字节，读不到标志位与源文件摘要，无法施加' };
  }
  if (buffer[2] !== 0x0d || buffer[3] !== 0x0a) {
    return { ok: false, reason: '字节 2 至 3 不是 0D 0A，不符合 pyc 魔数之后的固定标记，按非 pyc 处理' };
  }
  const flags = buffer.readUInt32LE(4);
  if ((flags & PYC_FLAG_HASH_BASED) === 0) {
    return { ok: false, reason: '标志位未声明 hash_based，没有源文件摘要可清零' };
  }
  const out = Buffer.from(buffer);
  const ranges = [];
  const notes = [];
  const hash = zeroRange(out, PYC_SOURCE_HASH_OFFSET, PYC_SOURCE_HASH_OFFSET + PYC_SOURCE_HASH_LENGTH);
  if (hash !== null) {
    ranges.push(hash);
  }
  if ((flags & PYC_FLAG_CHECK_SOURCE) !== 0) {
    out.writeUInt32LE(flags & ~PYC_FLAG_CHECK_SOURCE, 4);
    ranges.push([4, 8]);
    notes.push('check_source 标志已一并清除，否则标志位与清零后的哈希状态不一致');
  }
  if (ranges.length === 0) {
    return { ok: false, reason: '定位到的覆写区间为空，未改动任何字节' };
  }
  notes.push('清零后按名核对源文件的机制失效，不等于字节码不可分析');
  return { ok: true, buffer: out, ranges, notes };
}

/**
 * 疑似凭据等长占位覆写：按发现给出的模式标识与偏移重新扫描当前字节，
 * 命中后以等长零字节占位，偏移不变。ZIP 只处理存储条目，并同帧重算该条目 CRC32。
 * @param {Buffer} buffer 制品字节
 * @param {Record<string, unknown>} finding 审计发现
 * @param {string} containerType 容器标识
 * @returns {{ok: true, buffer: Buffer, ranges: Array<[number, number]>, notes: string[], zip?: Record<string, unknown>} | {ok: false, reason: string}}
 */
export function overwriteTokenPlaceholder(buffer, finding, containerType) {
  const patternId = finding?.detail?.patternId;
  if (typeof patternId !== 'string' || patternId === '') {
    return { ok: false, reason: '发现没有给出令牌模式标识，无法定位要覆写的字节' };
  }
  const pattern = TOKEN_PATTERNS.find((candidate) => candidate.id === patternId);
  if (pattern === undefined) {
    return { ok: false, reason: `令牌模式 ${patternId} 不在已登记模式表内，拒绝按未登记模式改写字节` };
  }
  const expectedOffset = Number.isSafeInteger(finding?.detail?.fileOffset)
    ? finding.detail.fileOffset
    : finding?.evidence?.byteRange?.[0];
  if (!Number.isSafeInteger(expectedOffset)) {
    return { ok: false, reason: '发现没有给出可信的文件偏移，无法定位要覆写的字节' };
  }
  const byteSource = typeof finding?.detail?.byteSource === 'string' ? finding.detail.byteSource : 'raw-bytes';

  if (containerType === 'zip') {
    // ZIP 内只有存储条目的原始字节可以等长覆写；压缩与不可解压条目的内容不在文件偏移上。
    // 这项判定先于重新扫描：压缩条目按解压后偏移在原始字节里找不到命中，原因会写成
    // “扫描不到”，把覆盖缺口说成意外，掩盖真实原因。
    if (byteSource !== 'stored-entry-raw-bytes' && byteSource !== 'container-raw-bytes') {
      return { ok: false, reason: `令牌来自${byteSource}，压缩或不可解压条目的内容无法等长覆写，本次跳过` };
    }
  }

  const scan = scanTokens(buffer);
  const hit = scan.hits.find((candidate) => candidate.id === patternId && candidate.offset === expectedOffset);
  if (hit === undefined) {
    return { ok: false, reason: `按模式 ${patternId} 在偏移 ${expectedOffset} 处重新扫描不到该令牌，可能已被覆写或审计结果已过期` };
  }
  // 重新执行模式取真实匹配长度：摘录超长时会被截断，按摘录长度覆写会留下残余字节。
  const window = Math.min(buffer.length, TOKEN_SCAN_WINDOW_BYTES);
  pattern.pattern.lastIndex = hit.offset;
  const match = pattern.pattern.exec(buffer.toString('latin1', 0, window));
  const matchLength = match !== null && match.index === hit.offset ? match[0].length : hit.excerpt.length;

  const out = Buffer.from(buffer);

  if (containerType === 'zip') {
    const located = locateZipEntries(buffer);
    if (!located.ok) {
      return { ok: false, reason: `ZIP 结构定位失败：${located.reason}` };
    }
    const entry = findStoredEntryAt(located.entries, expectedOffset);
    if (entry === null) {
      return { ok: false, reason: '该偏移不在任何存储条目的数据区内，覆写会破坏归档结构，本次跳过' };
    }
    const range = zeroRange(out, hit.offset, hit.offset + matchLength);
    if (range === null) {
      return { ok: false, reason: '定位到的覆写区间为空，未改动任何字节' };
    }
    // 同帧重算：本地文件头、中央目录项与数据描述符里的 CRC32 一起更新。
    const patched = patchEntryCrc32(out, entry);
    if (patched === null) {
      return { ok: false, reason: `条目 ${entry.name} 的 CRC32 无法重算，放弃覆写以保持同帧一致` };
    }
    return {
      ok: true,
      buffer: out,
      ranges: [range],
      notes: [`条目 ${entry.name} 的 CRC32 已同帧重算：0x${patched.before.toString(16)} 改为 0x${patched.after.toString(16)}`],
      zip: { entry: entry.name, crc32Before: patched.before, crc32After: patched.after },
    };
  }

  const range = zeroRange(out, hit.offset, hit.offset + matchLength);
  if (range === null) {
    return { ok: false, reason: '定位到的覆写区间为空，未改动任何字节' };
  }
  return {
    ok: true,
    buffer: out,
    ranges: [range],
    notes: ['占位为零字节，长度与偏移不变；检索为空不证明制品里没有秘密，改写与否需用户逐条确认'],
  };
}

/**
 * 内容保护层的通用等长覆写：按发现给出的证据字节区间清零。
 * 没有字节区间的发现无法定位，返回跳过原因而不是猜一个范围。
 * @param {Buffer} buffer 制品字节
 * @param {Record<string, unknown>} finding 审计发现
 * @returns {{ok: true, buffer: Buffer, ranges: Array<[number, number]>, notes: string[]} | {ok: false, reason: string}}
 */
export function overwriteDataSegmentRange(buffer, finding) {
  const range = finding?.evidence?.byteRange;
  if (!Array.isArray(range) || range.length !== 2 || !range.every((value) => Number.isFinite(value) && value >= 0)) {
    return { ok: false, reason: '发现没有给出可用的证据字节区间，无法等长覆写' };
  }
  const out = Buffer.from(buffer);
  const zeroed = zeroRange(out, range[0], range[1]);
  if (zeroed === null) {
    return { ok: false, reason: '证据字节区间落在文件范围之外或为空，未改动任何字节' };
  }
  const notes = ['等长覆写保持文件长度与全部偏移不变；熵不能证明加密，未纳入改写范围的字节仍可被直接检索'];
  if (zeroed[0] !== Math.floor(range[0]) || zeroed[1] !== Math.floor(range[1])) {
    notes.push('证据字节区间部分超出文件范围，只覆写了落在文件内的部分');
  }
  return { ok: true, buffer: out, ranges: [zeroed], notes };
}
