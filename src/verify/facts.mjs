// 复审引擎的结构事实提取：从制品字节读出必需集每一项是否可解析。
// 与读取器的分工：读取器回答“暴露了什么”，本模块回答“结构是否仍然健全”。
// 与 tests/required-sets/extract-facts.mjs 的分工：那份是必需集模块的测试替身，
// 本文件是复审引擎的运行时事实来源，键与 src/required-sets/sets.mjs 的必需项编号一一对应。
//
// 三条约束贯穿全文件：
//   1. 只读。全部解析只检查字节，不执行制品内代码、不发起网络请求、不写入任何文件。
//   2. 畸形输入不抛异常。解析到哪里、缺什么，都以可判定的失败原因返回；
//      返回空结果冒充“结构良好”是比崩溃更严重的错误。
//   3. 缺席与损坏分开。制品本来不含某结构（静态制品没有 PT_INTERP、
//      非 Go 制品没有构建信息节）按不适用处理；声明了却越界、对不上才算失败。
//      依据是 src/required-sets/sets.mjs 各必需项的 requirement 文本。

import { inflateRawSync } from 'node:zlib';

import { crc32 } from '../signatures/crc32.mjs';
import { GGUF_TENSOR_TYPES } from '../readers/gguf.mjs';

/** marshal 类型码集合，用于判断 pyc 载荷是否存在且形状合理。 */
const MARSHAL_TYPE_CODES = new Set([0x28, 0x30, 0x3e, 0x5b, 0x7a, 0x63, 0x69, 0x73, 0x4e, 0x54, 0x46, 0x4c]);

/** 节缺席时的统一事实形状：按不适用处理，附原因。 */
function absent(reason) {
  return { absent: true, reason };
}

/** 节损坏时的统一事实形状。 */
function broken(reason) {
  return { parsed: false, reason };
}

/** 结构可解析时的统一事实形状。 */
function ok(reason) {
  return { parsed: true, reason };
}

/**
 * 按字节序读取无符号整数。越界返回 undefined，由调用方转成失败原因，不抛异常。
 * @param {Buffer} bytes 缓冲区
 * @param {number} offset 起始偏移
 * @param {number} size 字节数
 * @param {boolean} big 是否大端
 * @returns {number | undefined}
 */
function readUInt(bytes, offset, size, big) {
  if (offset < 0 || offset + size > bytes.length) {
    return undefined;
  }
  let value = 0;
  if (big) {
    for (let index = 0; index < size; index += 1) {
      value = value * 256 + bytes[offset + index];
    }
  } else {
    for (let index = size - 1; index >= 0; index -= 1) {
      value = value * 256 + bytes[offset + index];
    }
  }
  return value;
}

/**
 * 读取以空字符结尾的字符串。上界收敛到缓冲区长度，畸形制品不得让读取无限进行。
 * @param {Buffer} bytes 缓冲区
 * @param {number} offset 起始偏移
 * @param {number} end 可用上界
 * @returns {string}
 */
function readCString(bytes, offset, end) {
  const limit = Math.min(end, bytes.length);
  const start = Math.max(offset, 0);
  let stop = start;
  while (stop < limit && bytes[stop] !== 0) {
    stop += 1;
  }
  return bytes.toString('latin1', start, stop);
}

/**
 * 构造检查结果信封。
 * @param {string} container 容器标识
 * @param {{parseable: boolean, reason?: string, structures: string[]}} parse 容器级解析结论
 * @param {Record<string, unknown>} facts 必需项事实表
 * @param {Record<string, unknown> | null} [flagState] 格式专属状态（pyc 用）
 * @returns {Record<string, unknown>}
 */
function envelope(container, parse, facts, flagState = null) {
  return { container, parse, facts, flagState };
}

// ---------------------------------------------------------------------------
// ELF：32 与 64 位、小端与大端
// ---------------------------------------------------------------------------

/** ELF 节类型。 */
const SHT = Object.freeze({ PROGBITS: 1, SYMTAB: 2, STRTAB: 3, RELA: 4, DYNAMIC: 6, NOTE: 7, DYNSYM: 11, INIT_ARRAY: 14 });
/** ELF 程序头类型。 */
const PT = Object.freeze({ LOAD: 1, DYNAMIC: 2, INTERP: 3 });

/**
 * 提取 ELF 夹具的结构事实。
 * @param {Buffer} bytes 制品字节
 * @returns {Record<string, unknown>}
 */
function inspectElf(bytes) {
  const facts = {};
  const structures = [];
  const fail = (reason) => envelope('elf', { parseable: false, reason, structures }, facts);

  if (bytes.length < 16 || bytes[0] !== 0x7f || bytes[1] !== 0x45 || bytes[2] !== 0x4c || bytes[3] !== 0x46) {
    return fail('文件不足 16 字节或缺少 ELF 魔数');
  }
  const elfClass = bytes[4];
  const elfData = bytes[5];
  if (elfClass !== 1 && elfClass !== 2) {
    return fail(`e_ident 的 EI_CLASS 取值 ${elfClass} 不是 1（32 位）或 2（64 位）`);
  }
  if (elfData !== 1 && elfData !== 2) {
    return fail(`e_ident 的 EI_DATA 取值 ${elfData} 不是 1（小端）或 2（大端）`);
  }
  const is64 = elfClass === 2;
  const big = elfData === 2;
  const headerSize = is64 ? 64 : 52;
  if (bytes.length < headerSize) {
    return fail(`文件头不足 ${headerSize} 字节，只读到 ${bytes.length} 字节`);
  }
  const read = (offset, size) => readUInt(bytes, offset, size, big);
  const header = {
    entry: is64 ? read(24, 8) : read(24, 4),
    phoff: is64 ? read(32, 8) : read(28, 4),
    shoff: is64 ? read(40, 8) : read(32, 4),
    phentsize: read(is64 ? 54 : 42, 2),
    phnum: read(is64 ? 56 : 44, 2),
    shentsize: read(is64 ? 58 : 46, 2),
    shnum: read(is64 ? 60 : 48, 2),
    shstrndx: read(is64 ? 62 : 50, 2),
  };
  for (const [key, value] of Object.entries(header)) {
    if (value === undefined) {
      return fail(`ELF 头字段 ${key} 读取越界`);
    }
  }
  facts['elf.elf-header'] = ok(`ELF 头魔数与基本字段可读（${is64 ? 64 : 32} 位${big ? '大端' : '小端'}）`);
  structures.push('ELF 头');

  // 程序头表。
  const phdrSize = is64 ? 56 : 32;
  const programHeadersOk =
    header.phoff > 0 && header.phnum > 0 && header.phentsize >= phdrSize && header.phoff + header.phnum * header.phentsize <= bytes.length;
  facts['elf.program-headers'] = programHeadersOk
    ? ok(`程序头表位于 ${header.phoff}，共 ${header.phnum} 条`)
    : broken(`程序头表偏移 ${header.phoff} 或条目数 ${header.phnum} 越界`);

  let hasInterpSegment = false;
  let hasDynamicSegment = false;
  if (programHeadersOk) {
    structures.push(`程序头表（${header.phnum} 条）`);
    let loadCoversEntry = false;
    for (let index = 0; index < header.phnum; index += 1) {
      const base = header.phoff + index * header.phentsize;
      const type = read(base, 4);
      const offset = is64 ? read(base + 8, 8) : read(base + 4, 4);
      const virtualAddress = is64 ? read(base + 16, 8) : read(base + 8, 4);
      const fileSize = is64 ? read(base + 32, 8) : read(base + 16, 4);
      if (type === undefined || offset === undefined || virtualAddress === undefined || fileSize === undefined) {
        continue;
      }
      if (offset + fileSize > bytes.length) {
        continue;
      }
      if (type === PT.LOAD && virtualAddress <= header.entry && header.entry < virtualAddress + fileSize) {
        loadCoversEntry = true;
      }
      if (type === PT.DYNAMIC) {
        hasDynamicSegment = true;
      }
      if (type === PT.INTERP) {
        hasInterpSegment = true;
      }
    }
    facts['elf.segment-load'] = loadCoversEntry
      ? ok('入口地址落在某个 PT_LOAD 内')
      : broken('没有覆盖入口地址的 PT_LOAD 段');
    // 静态制品没有 PT_INTERP 与 PT_DYNAMIC 属格式允许，按不适用处理（必需项 requirement 文本明示）。
    facts['elf.segment-dynamic'] = hasDynamicSegment ? ok('存在 PT_DYNAMIC 且范围在文件内') : absent('该制品没有 PT_DYNAMIC 段，按静态制品处理');
    facts['elf.segment-interp'] = hasInterpSegment ? ok('存在 PT_INTERP 且范围在文件内') : absent('该制品没有 PT_INTERP 段，按静态制品处理');
  }

  // 节表。
  const sectionTableOk =
    header.shoff > 0 && header.shnum > 0 && header.shentsize >= (is64 ? 64 : 40) && header.shstrndx < header.shnum && header.shoff + header.shnum * header.shentsize <= bytes.length;
  facts['elf.section-table'] = sectionTableOk
    ? ok(`节表位于 ${header.shoff}，共 ${header.shnum} 节`)
    : header.shoff === 0 || header.shnum === 0
      ? absent('ELF 头声明 shoff 为 0 或节数为 0，该制品没有节表，按节检索的事实不适用')
      : broken(`节表偏移 ${header.shoff} 或条目数 ${header.shnum} 越界`);

  const sections = new Map();
  if (sectionTableOk) {
    structures.push(`节表（${header.shnum} 节）`);
    const shstrtabOffset = read(header.shoff + header.shstrndx * header.shentsize + 24, is64 ? 8 : 4);
    const shstrtabSize = read(header.shoff + header.shstrndx * header.shentsize + (is64 ? 32 : 20), is64 ? 8 : 4);
    for (let index = 0; index < header.shnum; index += 1) {
      const base = header.shoff + index * header.shentsize;
      const nameOffset = read(base, 4);
      const type = read(base + 4, 4);
      const offset = is64 ? read(base + 24, 8) : read(base + 16, 4);
      const size = is64 ? read(base + 32, 8) : read(base + 20, 4);
      if (nameOffset === undefined || type === undefined || offset === undefined || size === undefined) {
        continue;
      }
      const name = shstrtabOffset === undefined || shstrtabSize === undefined ? '' : readCString(bytes, shstrtabOffset + nameOffset, shstrtabOffset + shstrtabSize);
      if (name !== '' && !sections.has(name)) {
        sections.set(name, { index, type, offset, size });
      }
    }
  }

  // 逐节事实。节缺席按不适用处理；节在位但范围越界才算失败。
  const sectionFacts = {
    'elf.section.interp': ['.interp'],
    'elf.section.note': ['.note.gnu.build-id', '.note'],
    'elf.section.dynamic': ['.dynamic'],
    'elf.section.dynsym': ['.dynsym'],
    'elf.section.dynstr': ['.dynstr'],
    'elf.section.reloc': ['.rela.dyn', '.rela.plt'],
    'elf.section.got': ['.got', '.got.plt'],
    'elf.section.init-array': ['.init_array', '.fini_array'],
    'elf.section.text': ['.text'],
    'elf.section.symtab': ['.symtab'],
    'elf.section.strtab': ['.strtab'],
    'elf.section.go-buildinfo': ['.go.buildinfo'],
    'elf.section.dep-v0': ['.dep-v0'],
  };
  for (const [itemId, names] of Object.entries(sectionFacts)) {
    const found = names.map((name) => sections.get(name)).find((section) => section !== undefined);
    if (found === undefined) {
      facts[itemId] = absent(`节表里没有 ${names[0]} 节，该制品不含此结构`);
      continue;
    }
    facts[itemId] =
      found.offset + found.size <= bytes.length
        ? ok(`${names[0]} 位于 ${found.offset}，长 ${found.size} 字节`)
        : broken(`${names[0]} 声明范围 [${found.offset}, ${found.offset + found.size}) 超出文件长度 ${bytes.length}`);
  }

  const parseable = facts['elf.elf-header'].parsed === true && facts['elf.program-headers'].parsed === true && facts['elf.section-table'].parsed !== false;
  return envelope(
    'elf',
    parseable
      ? { parseable: true, structures }
      : { parseable: false, reason: firstFailure(facts) ?? 'ELF 头部结构解析失败', structures },
    facts,
  );
}

/**
 * 从事实表里取第一条失败原因，供容器级结论引用。
 * @param {Record<string, {parsed?: boolean, absent?: boolean, reason?: string}>} facts 事实表
 * @returns {string | null}
 */
function firstFailure(facts) {
  for (const fact of Object.values(facts)) {
    if (fact.parsed === false && typeof fact.reason === 'string') {
      return fact.reason;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// PE：PE32 与 PE32+
// ---------------------------------------------------------------------------

/**
 * 提取 PE 夹具的结构事实。
 * @param {Buffer} bytes 制品字节
 * @returns {Record<string, unknown>}
 */
function inspectPe(bytes) {
  const facts = {};
  const structures = [];
  const fail = (reason) => envelope('pe', { parseable: false, reason, structures }, facts);

  const dosOk = bytes.length >= 0x40 && bytes[0] === 0x4d && bytes[1] === 0x5a;
  facts['pe.dos-header'] = dosOk ? ok('MZ 签名与 e_lfanew 可读') : broken('文件不足 64 字节或缺少 MZ 签名');
  if (!dosOk) {
    return fail('DOS 头不可解析');
  }
  structures.push('DOS 头');
  const peOffset = bytes.readUInt32LE(0x3c);
  const signatureOk = peOffset + 4 <= bytes.length && bytes.toString('latin1', peOffset, peOffset + 4) === 'PE\0\0';
  facts['pe.pe-signature'] = signatureOk ? ok(`PE\\0\\0 签名位于 ${peOffset}`) : broken(`偏移 ${peOffset} 处不是 PE\\0\\0 签名`);
  if (!signatureOk) {
    return fail('PE 签名缺失');
  }
  structures.push('PE 签名');
  const coffOffset = peOffset + 4;
  if (coffOffset + 20 > bytes.length) {
    return fail('COFF 头越界');
  }
  const numberOfSections = bytes.readUInt16LE(coffOffset + 2);
  const sizeOfOptionalHeader = bytes.readUInt16LE(coffOffset + 16);
  const optionalOffset = coffOffset + 20;
  const coffOk = numberOfSections > 0 && sizeOfOptionalHeader >= 96;
  facts['pe.coff-header'] = coffOk ? ok(`节数 ${numberOfSections}，可选头 ${sizeOfOptionalHeader} 字节`) : broken(`节数 ${numberOfSections} 或可选头大小 ${sizeOfOptionalHeader} 不合理`);
  if (optionalOffset + 2 > bytes.length) {
    return fail('可选头越界');
  }
  const magic = bytes.readUInt16LE(optionalOffset);
  const isPe32Plus = magic === 0x20b;
  const isPe32 = magic === 0x10b;
  facts['pe.optional-header'] = isPe32Plus || isPe32 ? ok(`${isPe32Plus ? 'PE32+' : 'PE32'} 魔数`) : broken(`可选头魔数无法识别：0x${magic.toString(16)}`);
  if (!isPe32Plus && !isPe32) {
    return fail('可选头魔数无法识别');
  }
  structures.push(isPe32Plus ? '可选头（PE32+）' : '可选头（PE32）');
  facts['pe.optional-header.checksum'] =
    optionalOffset + 68 <= bytes.length ? ok('CheckSum 字段可读，取值一致性由校验和一致性检查族复验') : broken('可选头不足 68 字节，读不到 CheckSum 字段');

  // 节表。
  const sectionTableOffset = optionalOffset + sizeOfOptionalHeader;
  const sections = [];
  for (let index = 0; index < numberOfSections; index += 1) {
    const base = sectionTableOffset + index * 40;
    if (base + 40 > bytes.length) {
      break;
    }
    sections.push({
      name: readCString(bytes, base, base + 8),
      virtualAddress: bytes.readUInt32LE(base + 12),
      rawSize: bytes.readUInt32LE(base + 16),
      rawPointer: bytes.readUInt32LE(base + 20),
      characteristics: bytes.readUInt32LE(base + 36),
    });
  }
  facts['pe.section-table'] =
    sections.length === numberOfSections ? ok(`节表含 ${sections.length} 节`) : broken(`节表只解析出 ${sections.length} 节，声明 ${numberOfSections} 节`);
  if (sections.length !== numberOfSections) {
    return fail('节表不完整');
  }
  structures.push(`节表（${sections.length} 节）`);

  const rvaToOffset = (rva) => {
    for (const section of sections) {
      if (section.virtualAddress <= rva && rva < section.virtualAddress + Math.max(section.rawSize, 1)) {
        return section.rawPointer + (rva - section.virtualAddress);
      }
    }
    return null;
  };
  const entryRva = optionalOffset + 16 + 4 <= bytes.length ? bytes.readUInt32LE(optionalOffset + 16) : null;
  facts['pe.entry-point'] =
    entryRva !== null && rvaToOffset(entryRva) !== null ? ok(`入口 RVA ${entryRva} 落在某个已映射节内`) : broken(`入口 RVA ${entryRva} 不落在任何已映射节内`);

  const dataDirectory = (index) => {
    const base = optionalOffset + (isPe32Plus ? 112 : 96) + index * 8;
    if (base + 8 > bytes.length) {
      return null;
    }
    return { rva: bytes.readUInt32LE(base), size: bytes.readUInt32LE(base + 4) };
  };
  const importDirectory = dataDirectory(1);
  facts['pe.import-directory'] =
    importDirectory === null
      ? broken('读不到导入表数据目录')
      : importDirectory.rva === 0
        ? absent('该制品未声明导入表')
        : rvaToOffset(importDirectory.rva) !== null
          ? ok('导入描述符表可定位')
          : broken('导入表数据目录声明的 RVA 不落在任何已映射节内');
  const exportDirectory = dataDirectory(0);
  facts['pe.export-directory'] =
    exportDirectory === null
      ? broken('读不到导出表数据目录')
      : exportDirectory.rva === 0
        ? absent('该制品未声明导出表')
        : rvaToOffset(exportDirectory.rva) !== null
          ? ok('导出表可定位')
          : broken('导出表数据目录声明的 RVA 不落在任何已映射节内');
  const relocDirectory = dataDirectory(5);
  facts['pe.reloc-directory'] =
    relocDirectory === null
      ? broken('读不到重定位表数据目录')
      : relocDirectory.rva === 0
        ? absent('该制品未声明重定位表')
        : rvaToOffset(relocDirectory.rva) !== null
          ? ok('重定位表可定位')
          : broken('重定位表数据目录声明的 RVA 不落在任何已映射节内');
  const debugDirectory = dataDirectory(6);
  facts['pe.debug-directory'] =
    debugDirectory === null
      ? broken('读不到调试目录')
      : debugDirectory.rva === 0
        ? absent('该制品未声明调试目录')
        : rvaToOffset(debugDirectory.rva) !== null
          ? ok('调试目录可定位')
          : broken('调试目录声明的 RVA 不落在任何已映射节内');
  // 安全目录的“RVA”实为文件偏移，范围判定直接用文件长度。
  const securityDirectory = dataDirectory(4);
  facts['pe.security-directory'] =
    securityDirectory === null
      ? broken('读不到安全目录')
      : securityDirectory.rva === 0
        ? absent('该制品未声明安全目录')
        : securityDirectory.rva + securityDirectory.size <= bytes.length
          ? ok(`证书表范围 [${securityDirectory.rva}, ${securityDirectory.rva + securityDirectory.size}) 在文件内`)
          : broken(`证书表范围 [${securityDirectory.rva}, ${securityDirectory.rva + securityDirectory.size}) 超出文件长度 ${bytes.length}`);
  // Go 构建信息所在节按特征位 0xc0000040 识别，与缓解措施的判定方式一致。
  facts['pe.section.go-buildinfo'] = sections.some((section) => (section.characteristics & 0xc0000040) === 0xc0000040)
    ? ok('存在特征位为 0xc0000040 的节，即 Go 构建信息所在节')
    : absent('该制品没有特征位为 0xc0000040 的节');

  const parseable = Object.values(facts).every((fact) => fact.parsed !== false);
  return envelope(
    'pe',
    parseable ? { parseable: true, structures } : { parseable: false, reason: firstFailure(facts) ?? 'PE 头部结构解析失败', structures },
    facts,
  );
}

// ---------------------------------------------------------------------------
// Mach-O：瘦二进制（32 与 64 位、两种字节序）与胖二进制
// ---------------------------------------------------------------------------

/** 加载命令编号。 */
const LC = Object.freeze({
  SEGMENT: 0x1,
  SEGMENT_64: 0x19,
  UUID: 0x1b,
  CODE_SIGNATURE: 0x1d,
  LOAD_DYLINKER: 0xc,
  LOAD_WEAK_DYLINKER: 0x18,
  DYLD_INFO: 0x1e,
  DYLD_INFO_ONLY: 0x22,
});

/**
 * 识别 Mach-O 魔数。
 * @param {Buffer} bytes 缓冲区
 * @param {number} offset 魔数偏移
 * @returns {{bits: 32 | 64, swapped: boolean} | null}
 */
function machoMagic(bytes, offset) {
  if (offset + 4 > bytes.length) {
    return null;
  }
  const le = bytes.readUInt32LE(offset);
  if (le === 0xfeedface) {
    return { bits: 32, swapped: false };
  }
  if (le === 0xcefaedfe) {
    return { bits: 32, swapped: true };
  }
  if (le === 0xfeedfacf) {
    return { bits: 64, swapped: false };
  }
  if (le === 0xcffaedfe) {
    return { bits: 64, swapped: true };
  }
  return null;
}

/**
 * 解析单个瘦 Mach-O 分片。
 * @param {Buffer} bytes 整个制品字节
 * @param {number} sliceOffset 分片起点
 * @returns {Record<string, unknown>} 含 commands、sectionNames、limitation
 */
function inspectMachoSide(bytes, sliceOffset) {
  const magic = machoMagic(bytes, sliceOffset);
  const headerSize = magic === null || magic.bits === 64 ? 32 : 28;
  const result = { commands: [], sectionNames: new Set(), limitation: null, codeSignature: null };
  if (magic === null) {
    result.limitation = '分片魔数不是 Mach-O';
    return result;
  }
  if (sliceOffset + headerSize > bytes.length) {
    result.limitation = '分片头越界';
    return result;
  }
  const read = (offset, size) => readUInt(bytes, offset, size, magic.swapped);
  const ncmds = read(sliceOffset + 16, 4);
  const sizeofcmds = read(sliceOffset + 20, 4);
  if (ncmds === undefined || sizeofcmds === undefined) {
    result.limitation = '分片头的命令数字段读取越界';
    return result;
  }
  let position = sliceOffset + headerSize;
  const commandsEnd = Math.min(bytes.length, sliceOffset + headerSize + sizeofcmds);
  for (let index = 0; index < ncmds; index += 1) {
    if (position + 8 > commandsEnd) {
      result.limitation = `第 ${index + 1} 个加载命令头越界，停止枚举`;
      break;
    }
    const cmd = read(position, 4);
    const cmdsize = read(position + 4, 4);
    if (cmd === undefined || cmdsize === undefined || cmdsize < 8 || position + cmdsize > commandsEnd) {
      result.limitation = `第 ${index + 1} 个加载命令尺寸 ${cmdsize} 非法或越界，停止枚举`;
      break;
    }
    result.commands.push({ cmd, offset: position });
    if (cmd === LC.CODE_SIGNATURE) {
      result.codeSignature = { dataoff: read(position + 8, 4) ?? 0, datasize: read(position + 12, 4) ?? 0 };
    }
    if (cmd === LC.SEGMENT || cmd === LC.SEGMENT_64) {
      const nsects = read(position + 64, 4);
      if (nsects !== undefined) {
        for (let sectionIndex = 0; sectionIndex < nsects; sectionIndex += 1) {
          const base = position + (cmd === LC.SEGMENT_64 ? 72 : 56) + sectionIndex * (cmd === LC.SEGMENT_64 ? 80 : 68);
          if (base + 16 > bytes.length) {
            break;
          }
          result.sectionNames.add(readCString(bytes, base, base + 16));
        }
      }
    }
    position += cmdsize;
  }
  return result;
}

/**
 * 提取瘦 Mach-O 的结构事实。
 * @param {Buffer} bytes 制品字节
 * @returns {Record<string, unknown>}
 */
function inspectMachoThin(bytes) {
  const facts = {};
  const structures = [];
  const slice = inspectMachoSide(bytes, 0);
  if (slice.limitation !== null && slice.commands.length === 0) {
    return envelope('mach-o', { parseable: false, reason: slice.limitation, structures }, facts);
  }
  facts['mach-o.header'] = ok('Mach-O 头魔数与命令数字段可读');
  structures.push('Mach-O 头');
  const commandsOk = slice.limitation === null;
  facts['mach-o.load-commands'] = commandsOk
    ? ok(`加载命令区共 ${slice.commands.length} 条，全部可遍历`)
    : broken(`加载命令区遍历中断：${slice.limitation}`);
  if (commandsOk) {
    structures.push(`加载命令（${slice.commands.length} 条）`);
  }
  const has = (cmd) => slice.commands.some((command) => command.cmd === cmd);
  facts['mach-o.load-command.segment'] = has(LC.SEGMENT_64) || has(LC.SEGMENT) ? ok('存在 LC_SEGMENT_64 或 LC_SEGMENT') : broken('没有段加载命令');
  facts['mach-o.load-command.dyld-info'] =
    has(LC.DYLD_INFO_ONLY) || has(LC.DYLD_INFO) ? ok('存在动态链接信息加载命令') : absent('该制品没有动态链接信息加载命令');
  facts['mach-o.load-command.dylinker'] =
    has(LC.LOAD_DYLINKER) || has(LC.LOAD_WEAK_DYLINKER) ? ok('存在动态链接器路径加载命令') : absent('该制品没有动态链接器路径加载命令');
  facts['mach-o.load-command.uuid'] = has(LC.UUID) ? ok('存在 LC_UUID') : absent('该制品没有 LC_UUID 加载命令');
  facts['mach-o.load-command.code-signature'] = has(LC.CODE_SIGNATURE) ? ok('存在 LC_CODE_SIGNATURE') : absent('该制品没有 LC_CODE_SIGNATURE 加载命令');
  facts['mach-o.sections'] =
    slice.sectionNames.size > 0 ? ok(`段内节：${[...slice.sectionNames].join('、')}`) : absent('各段都没有声明节');
  facts['mach-o.section.go-buildinfo'] = slice.sectionNames.has('__go_buildinfo')
    ? ok('__go_buildinfo 节存在')
    : absent('该制品没有 __go_buildinfo 节');
  facts['mach-o.section.dep-v0'] = slice.sectionNames.has(',dep-v0') ? ok('__DATA 段的 ,dep-v0 节存在') : absent('该制品没有 ,dep-v0 节');

  const parseable = facts['mach-o.header'].parsed === true && facts['mach-o.load-commands'].parsed === true;
  return envelope('mach-o', parseable ? { parseable: true, structures } : { parseable: false, reason: firstFailure(facts) ?? 'Mach-O 结构解析失败', structures }, facts);
}

/**
 * 提取胖 Mach-O 的结构事实。
 * @param {Buffer} bytes 制品字节
 * @returns {Record<string, unknown>}
 */
function inspectMachoFat(bytes) {
  const facts = {};
  const structures = [];
  if (bytes.length < 8) {
    return envelope('mach-o-fat', { parseable: false, reason: '胖二进制头越界', structures }, facts);
  }
  // 胖二进制头按大端存储；以小端读出为 0xbebafeca。64 位魔数 CAFEBABF 读出为
  // 0xbfbafeca，分片项布局随位数区分：offset 与 size 各八字节。
  const fatMagic = bytes.readUInt32LE(0);
  const is64 = fatMagic === 0xbfbafeca;
  if (fatMagic !== 0xbebafeca && !is64 && fatMagic !== 0xcafebabe) {
    return envelope('mach-o-fat', { parseable: false, reason: '魔数不是 Mach-O 胖二进制', structures }, facts);
  }
  facts['mach-o-fat.fat-header'] = ok('胖二进制头魔数与 nfat_arch 可读');
  structures.push('胖二进制头');
  const nfat = bytes.readUInt32BE(4);
  const archBytes = is64 ? 32 : 20;
  const slices = [];
  let archTableOk = nfat > 0;
  for (let index = 0; index < nfat; index += 1) {
    const base = 8 + index * archBytes;
    if (base + archBytes > bytes.length) {
      archTableOk = false;
      break;
    }
    slices.push({
      offset: is64 ? Number(bytes.readBigUInt64BE(base + 8)) : bytes.readUInt32BE(base + 8),
      size: is64 ? Number(bytes.readBigUInt64BE(base + 16)) : bytes.readUInt32BE(base + 12),
    });
  }
  facts['mach-o-fat.arch-table'] = archTableOk ? ok(`分片表共 ${nfat} 条，全部可读`) : broken(`分片表第 ${nfat} 条越界或条目数为 0`);
  if (!archTableOk) {
    return envelope('mach-o-fat', { parseable: false, reason: firstFailure(facts), structures }, facts);
  }
  structures.push(`分片表（${nfat} 条）`);

  const sliceResults = slices.map((slice) => ({ ...slice, ...inspectMachoSide(bytes, slice.offset) }));
  const anyHeaderOk = sliceResults.some((slice) => slice.limitation === null || slice.commands.length > 0);
  facts['mach-o-fat.slice-header'] = anyHeaderOk ? ok('全部构成分片的 Mach-O 头可解析') : broken('没有可分片的 Mach-O 头');
  const commandsOk = sliceResults.every((slice) => slice.limitation === null);
  facts['mach-o-fat.slice-load-commands'] = commandsOk
    ? ok('各分片加载命令区全部可遍历')
    : broken(`分片加载命令区遍历中断：${sliceResults.find((slice) => slice.limitation !== null).limitation}`);
  facts['mach-o-fat.slice-code-signature'] = sliceResults.some((slice) => slice.codeSignature !== null)
    ? ok('存在带 LC_CODE_SIGNATURE 的分片')
    : absent('各分片都没有 LC_CODE_SIGNATURE');
  const allSections = new Set(sliceResults.flatMap((slice) => [...slice.sectionNames]));
  facts['mach-o-fat.slice-go-buildinfo'] = allSections.has('__go_buildinfo') ? ok('分片含 __go_buildinfo 节') : absent('各分片都没有 __go_buildinfo 节');
  facts['mach-o-fat.slice-dep-v0'] = allSections.has(',dep-v0') ? ok('分片含 ,dep-v0 节') : absent('各分片都没有 ,dep-v0 节');

  const parseable = facts['mach-o-fat.fat-header'].parsed === true && facts['mach-o-fat.arch-table'].parsed === true && facts['mach-o-fat.slice-load-commands'].parsed === true;
  return envelope('mach-o-fat', parseable ? { parseable: true, structures } : { parseable: false, reason: firstFailure(facts) ?? '胖二进制结构解析失败', structures }, facts);
}

/**
 * 按容器提取 Mach-O 结构事实。
 * @param {Buffer} bytes 制品字节
 * @returns {Record<string, unknown>}
 */
function inspectMacho(bytes) {
  if (bytes.length >= 4 && (bytes.readUInt32LE(0) === 0xbebafeca || bytes.readUInt32LE(0) === 0xcafebabe)) {
    return inspectMachoFat(bytes);
  }
  return inspectMachoThin(bytes);
}

// ---------------------------------------------------------------------------
// ZIP：本地文件头、中央目录与结尾记录
// ---------------------------------------------------------------------------

/**
 * 从缓冲区末尾向前定位结尾记录（EOCD），容忍注释字节。
 * @param {Buffer} bytes 缓冲区
 * @returns {number} EOCD 起始偏移，未找到返回 -1
 */
function findEocd(bytes) {
  if (bytes.length < 22) {
    return -1;
  }
  const scanFloor = Math.max(0, bytes.length - 22 - 0xffff);
  for (let offset = bytes.length - 22; offset >= scanFloor; offset -= 1) {
    if (bytes.readUInt32LE(offset) === 0x06054b50) {
      const commentLength = bytes.readUInt16LE(offset + 20);
      if (offset + 22 + commentLength === bytes.length) {
        return offset;
      }
    }
  }
  return -1;
}

/**
 * 提取 ZIP 夹具的结构事实。
 * @param {Buffer} bytes 制品字节
 * @returns {Record<string, unknown>}
 */
function inspectZip(bytes) {
  const facts = {};
  const structures = [];
  const eocd = findEocd(bytes);
  facts['zip.end-of-central-directory'] = eocd >= 0 ? ok(`结束记录位于 ${eocd}`) : broken('找不到结尾记录（PK\\x05\\x06）');
  if (eocd < 0) {
    return envelope('zip', { parseable: false, reason: '找不到中央目录结束记录', structures }, facts);
  }
  structures.push('结尾记录');
  const entryCount = bytes.readUInt16LE(eocd + 10);
  const centralSize = bytes.readUInt32LE(eocd + 12);
  const centralOffset = bytes.readUInt32LE(eocd + 16);
  if (entryCount === 0) {
    // 空归档：没有条目可检，全部条目级事实按不适用处理。
    for (const itemId of ['zip.central-directory', 'zip.entry-table', 'zip.local-file-headers', 'zip.entry-crc32', 'zip.entry-data']) {
      facts[itemId] = absent('该归档没有条目');
    }
    return envelope('zip', { parseable: true, structures }, facts);
  }
  facts['zip.central-directory'] =
    centralOffset + centralSize <= bytes.length ? ok(`中央目录位于 ${centralOffset}，共 ${entryCount} 条`) : broken(`中央目录范围 [${centralOffset}, ${centralOffset + centralSize}) 超出文件长度 ${bytes.length}`);

  const entries = [];
  let position = centralOffset;
  let tableOk = true;
  for (let index = 0; index < entryCount; index += 1) {
    if (position + 46 > bytes.length || bytes.readUInt32LE(position) !== 0x02014b50) {
      tableOk = false;
      break;
    }
    entries.push({
      name: readCString(bytes, position + 46, position + 46 + bytes.readUInt16LE(position + 28)),
      method: bytes.readUInt16LE(position + 10),
      checksum: bytes.readUInt32LE(position + 16),
      compressedSize: bytes.readUInt32LE(position + 20),
      uncompressedSize: bytes.readUInt32LE(position + 24),
      localOffset: bytes.readUInt32LE(position + 42),
    });
    position += 46 + bytes.readUInt16LE(position + 28) + bytes.readUInt16LE(position + 30) + bytes.readUInt16LE(position + 32);
  }
  facts['zip.entry-table'] = tableOk && entries.length === entryCount ? ok(`解析出 ${entries.length} 条目录项`) : broken(`中央目录只解析出 ${entries.length} 条，声明 ${entryCount} 条`);
  if (!tableOk || entries.length !== entryCount) {
    return envelope('zip', { parseable: false, reason: firstFailure(facts), structures }, facts);
  }
  structures.push(`中央目录（${entryCount} 条）`);

  let localsMatch = true;
  let crcMatches = true;
  let dataReadable = true;
  const coverage = [];
  const problems = [];
  for (const entry of entries) {
    if (entry.localOffset + 30 > bytes.length || bytes.readUInt32LE(entry.localOffset) !== 0x04034b50) {
      localsMatch = false;
      problems.push(`${entry.name}：本地文件头缺失或越界`);
      continue;
    }
    const dataStart = entry.localOffset + 30 + bytes.readUInt16LE(entry.localOffset + 26) + bytes.readUInt16LE(entry.localOffset + 28);
    const dataEnd = dataStart + entry.compressedSize;
    if (dataEnd > bytes.length) {
      dataReadable = false;
      problems.push(`${entry.name}：条目数据越界`);
      continue;
    }
    const stored = bytes.subarray(dataStart, dataEnd);
    let plain;
    try {
      plain = entry.method === 8 ? inflateRawSync(stored) : stored;
    } catch {
      dataReadable = false;
      coverage.push(`${entry.name}（压缩方法 ${entry.method}，不可解压）`);
      continue;
    }
    if (plain.length !== entry.uncompressedSize || crc32(plain) !== entry.checksum) {
      crcMatches = false;
      problems.push(`${entry.name}：CRC32 或解压后长度与中央目录项不符`);
    }
    coverage.push(`${entry.name}（${entry.method === 8 ? '已解压扫描' : '仅原始字节'}）`);
  }
  facts['zip.local-file-headers'] = localsMatch ? ok('本地文件头与中央目录项逐条对齐') : broken(problems.filter((line) => line.includes('本地文件头')).join('；'));
  facts['zip.entry-crc32'] = crcMatches ? ok('逐条目 CRC32 与数据重算值一致') : broken(problems.filter((line) => line.includes('CRC32')).join('；'));
  facts['zip.entry-data'] = dataReadable ? ok(`条目覆盖：${coverage.join('、')}`) : broken(problems.filter((line) => !line.includes('CRC32')).join('；'));

  const parseable = localsMatch && tableOk && dataReadable;
  return envelope('zip', parseable ? { parseable: true, structures } : { parseable: false, reason: firstFailure(facts) ?? 'ZIP 结构解析失败', structures }, facts);
}

// ---------------------------------------------------------------------------
// GGUF：头部、元数据键值、张量索引、对齐与数据区
// ---------------------------------------------------------------------------

/** GGUF 默认对齐值。general.alignment 元数据未声明或声明不可用时使用。 */
const GGUF_DEFAULT_ALIGNMENT = 32;

/** GGUF 元数据标量值类型编号到字节数；字符串（8）与数组（9）不在表内，由专门分支解析。 */
const GGUF_VALUE_SIZES = Object.freeze({ 0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8 });

/**
 * 越界安全的小端无符号整数读取。越界返回 undefined，由调用方转成失败原因，不抛异常。
 * @param {Buffer} bytes 缓冲区
 * @param {number} offset 起始偏移
 * @param {number} size 字节数
 * @returns {number | undefined}
 */
function readLE(bytes, offset, size) {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset + size > bytes.length) {
    return undefined;
  }
  let value = 0;
  for (let index = size - 1; index >= 0; index -= 1) {
    value = value * 256 + bytes[offset + index];
  }
  return value;
}

/**
 * 提取 GGUF 夹具的结构事实。
 * @param {Buffer} bytes 制品字节
 * @returns {Record<string, unknown>}
 */
function inspectGguf(bytes) {
  const facts = {};
  const structures = [];
  if (bytes.length < 24) {
    facts['gguf.header'] = broken('文件不足 24 字节，GGUF 头不完整');
    return envelope('gguf', { parseable: false, reason: 'GGUF 头不完整', structures }, facts);
  }
  facts['gguf.header'] =
    bytes.toString('latin1', 0, 4) === 'GGUF' && bytes.readUInt32LE(4) === 3
      ? ok(`魔数与版本 ${bytes.readUInt32LE(4)}`)
      : broken(`魔数或版本无法识别：${bytes.toString('latin1', 0, 4)} 版本 ${bytes.readUInt32LE(4)}`);
  if (facts['gguf.header'].parsed !== true) {
    return envelope('gguf', { parseable: false, reason: firstFailure(facts), structures }, facts);
  }
  structures.push('GGUF 头');
  const tensorCount = Number(bytes.readBigUInt64LE(8));
  const metadataCount = Number(bytes.readBigUInt64LE(16));
  let position = 24;
  let metadataOk = true;
  // general.alignment 覆盖：与 src/transforms/relayout.mjs 的 parseGguf 同一口径，
  // 文件未声明时缺省三十二字节，两边算出的 tensor_data_offset 必须一致。
  let alignment = GGUF_DEFAULT_ALIGNMENT;
  for (let index = 0; index < metadataCount && metadataOk; index += 1) {
    const keyLength = readLE(bytes, position, 8);
    position += 8;
    if (keyLength === undefined || position + keyLength > bytes.length) {
      metadataOk = false;
      break;
    }
    const key = bytes.toString('latin1', position, position + keyLength);
    position += keyLength;
    const valueType = readLE(bytes, position, 4);
    position += 4;
    if (valueType === undefined) {
      metadataOk = false;
      break;
    }
    const valueStart = position;
    if (valueType === 8) {
      const length = readLE(bytes, position, 8);
      position += 8;
      if (length === undefined || position + length > bytes.length) {
        metadataOk = false;
        break;
      }
      position += length;
    } else if (valueType === 9) {
      const elementType = readLE(bytes, position, 4);
      const count = readLE(bytes, position + 4, 8);
      position += 12;
      if (elementType === undefined || count === undefined) {
        metadataOk = false;
        break;
      }
      const elementSize = GGUF_VALUE_SIZES[elementType];
      if (elementSize !== undefined) {
        // 定长元素：按元素字节数整体跳过。
        if (position + count * elementSize > bytes.length) {
          metadataOk = false;
          break;
        }
        position += count * elementSize;
      } else if (elementType === 8) {
        // 字符串数组（如词表类元数据）：逐项读长度前缀；按四字节近似会算错结束位置。
        for (let element = 0; element < count; element += 1) {
          const length = readLE(bytes, position, 8);
          position += 8;
          if (length === undefined || position + length > bytes.length) {
            metadataOk = false;
            break;
          }
          position += length;
        }
        if (!metadataOk) {
          break;
        }
      } else {
        // 数组的数组或词表外元素类型：本模块不展开，记失败而不是猜位置。
        metadataOk = false;
        break;
      }
    } else {
      const size = GGUF_VALUE_SIZES[valueType];
      if (size === undefined || position + size > bytes.length) {
        metadataOk = false;
        break;
      }
      position += size;
    }
    if (key === 'general.alignment') {
      const size = GGUF_VALUE_SIZES[valueType];
      if (size !== undefined) {
        const declared = readLE(bytes, valueStart, size);
        if (declared !== undefined && declared > 0 && Number.isSafeInteger(declared)) {
          alignment = declared;
        }
      }
    }
  }
  facts['gguf.metadata-kv'] = metadataOk ? ok(`元数据键值共 ${metadataCount} 条`) : broken(`元数据键值表在第 ${metadataCount} 条内越界`);

  let indexOk = metadataOk;
  let maxEnd = 0;
  for (let index = 0; index < tensorCount && indexOk; index += 1) {
    const nameLength = readLE(bytes, position, 8);
    position += 8;
    if (nameLength === undefined || position + nameLength > bytes.length) {
      indexOk = false;
      break;
    }
    position += nameLength;
    const dimensions = readLE(bytes, position, 4);
    position += 4;
    if (dimensions === undefined || dimensions > 8) {
      indexOk = false;
      break;
    }
    let elements = 1;
    let shapeOk = true;
    for (let dimension = 0; dimension < dimensions; dimension += 1) {
      const size = readLE(bytes, position, 8);
      position += 8;
      if (size === undefined) {
        shapeOk = false;
        break;
      }
      elements *= size;
    }
    if (!shapeOk) {
      indexOk = false;
      break;
    }
    const tensorType = readLE(bytes, position, 4);
    const offset = readLE(bytes, position + 4, 8);
    position += 12;
    if (tensorType === undefined || offset === undefined) {
      indexOk = false;
      break;
    }
    // 元素字节数取自读取器登记的同一张表。曾经这里硬编码“类型 0 算 4 字节、其余一律
    // 2 字节”：F64 的需求被算成一半（漏报越界），I8 被算成两倍（误报数据区不足）。
    // 未登记类型与量化类型都不猜字节数，按索引越界处理。
    const tensorSpec = GGUF_TENSOR_TYPES[tensorType];
    if (tensorSpec === undefined || tensorSpec.size === null) {
      indexOk = false;
      break;
    }
    maxEnd = Math.max(maxEnd, offset + elements * tensorSpec.size);
  }
  facts['gguf.tensor-index'] = indexOk ? ok(`张量索引共 ${tensorCount} 条`) : broken('张量索引越界');
  const dataStart = Math.ceil(position / alignment) * alignment;
  facts['gguf.alignment'] = dataStart <= bytes.length ? ok(`按 ${alignment} 字节对齐后数据区起点 ${dataStart}`) : broken(`按对齐计算的数据区起点 ${dataStart} 超出文件长度 ${bytes.length}`);
  facts['gguf.tensor-data'] =
    dataStart + maxEnd <= bytes.length ? ok(`张量数据需 ${maxEnd} 字节，数据区可用 ${bytes.length - dataStart} 字节`) : broken(`张量数据需 ${maxEnd} 字节，数据区只有 ${bytes.length - dataStart} 字节`);

  const parseable = Object.values(facts).every((fact) => fact.parsed !== false);
  return envelope('gguf', parseable ? { parseable: true, structures } : { parseable: false, reason: firstFailure(facts) ?? 'GGUF 结构解析失败', structures }, facts);
}

// ---------------------------------------------------------------------------
// safetensors：长度前缀、头部 JSON、张量索引与数据区边界
// ---------------------------------------------------------------------------

/**
 * 提取 safetensors 夹具的结构事实。
 * @param {Buffer} bytes 制品字节
 * @returns {Record<string, unknown>}
 */
function inspectSafetensors(bytes) {
  const facts = {};
  const structures = [];
  if (bytes.length < 16) {
    facts['safetensors.header-length-prefix'] = broken('文件不足 16 字节，长度前缀不完整');
    return envelope('safetensors', { parseable: false, reason: '长度前缀不完整', structures }, facts);
  }
  const headerLength = Number(bytes.readBigUInt64LE(0));
  facts['safetensors.header-length-prefix'] =
    headerLength > 0 && 8 + headerLength <= bytes.length ? ok(`头部长度前缀为 ${headerLength}`) : broken(`头部长度前缀 ${headerLength} 越界`);
  if (facts['safetensors.header-length-prefix'].parsed !== true) {
    return envelope('safetensors', { parseable: false, reason: firstFailure(facts), structures }, facts);
  }
  structures.push('长度前缀');
  let header = null;
  try {
    header = JSON.parse(bytes.toString('utf8', 8, 8 + headerLength));
  } catch {
    header = null;
  }
  facts['safetensors.header-json'] = header !== null && typeof header === 'object' && !Array.isArray(header) ? ok('头部 JSON 可解析') : broken('头部 JSON 无法解析');
  if (facts['safetensors.header-json'].parsed !== true) {
    return envelope('safetensors', { parseable: false, reason: firstFailure(facts), structures }, facts);
  }
  structures.push('头部 JSON');
  const tensors = Object.entries(header).filter(([key, value]) => key !== '__metadata__' && value !== null && typeof value === 'object');
  const intervals = tensors.map(([name, value]) => ({ name, start: value.data_offsets?.[0], end: value.data_offsets?.[1] }));
  const sorted = [...intervals].sort((left, right) => left.start - right.start);
  let noGap = true;
  let noOverlap = true;
  for (let index = 1; index < sorted.length; index += 1) {
    if (sorted[index].start < sorted[index - 1].end) {
      noOverlap = false;
    }
    if (sorted[index].start > sorted[index - 1].end) {
      noGap = false;
    }
  }
  const dataStart = 8 + headerLength;
  const withinBounds = sorted.every((interval) => Number.isFinite(interval.start) && Number.isFinite(interval.end) && interval.start >= 0 && interval.end <= bytes.length - dataStart);
  const noTail = sorted.length === 0 || sorted[sorted.length - 1].end === bytes.length - dataStart;
  facts['safetensors.tensor-index'] =
    tensors.length > 0 && tensors.every(([, value]) => Array.isArray(value.data_offsets) && value.data_offsets.length === 2)
      ? ok(`张量索引共 ${tensors.length} 条`)
      : tensors.length === 0
        ? absent('头部没有张量条目')
        : broken('存在 data_offsets 形状不正确的张量条目');
  facts['safetensors.data-bounds'] =
    withinBounds && noGap && noOverlap && noTail
      ? ok('无越界、无间隙、无重叠、无未索引尾部')
      : broken(`越界=${!withinBounds} 间隙=${!noGap} 重叠=${!noOverlap} 未索引尾部=${!noTail}`);
  facts['safetensors.metadata'] = Object.hasOwn(header, '__metadata__') ? ok('__metadata__ 槽位存在') : absent('该制品没有 __metadata__ 槽位');

  const parseable = Object.values(facts).every((fact) => fact.parsed !== false);
  return envelope('safetensors', parseable ? { parseable: true, structures } : { parseable: false, reason: firstFailure(facts) ?? 'safetensors 结构解析失败', structures }, facts);
}

// ---------------------------------------------------------------------------
// pyc：魔数、标志位、源哈希与码对象载荷
// ---------------------------------------------------------------------------

/**
 * 提取 pyc 夹具的结构事实与标志状态。
 * flagState 供 pyc 标志与哈希状态一致性检查族消费。
 * @param {Buffer} bytes 制品字节
 * @returns {Record<string, unknown>}
 */
function inspectPyc(bytes) {
  const facts = {};
  const structures = [];
  if (bytes.length < 16) {
    facts['pyc.magic'] = broken('文件不足 16 字节，pyc 头不完整');
    return envelope('pyc', { parseable: false, reason: 'pyc 头不完整', structures }, facts, { readable: false });
  }
  facts['pyc.magic'] = bytes[2] === 0x0d && bytes[3] === 0x0a ? ok('魔数之后的 0D 0A 固定标记') : broken('字节 2 至 3 不是 0D 0A，不符合 pyc 魔数之后的固定标记');
  structures.push('魔数');
  const flags = bytes.readUInt32LE(4);
  const hashBased = (flags & 0b01) === 0b01;
  const checkSource = (flags & 0b10) === 0b10;
  facts['pyc.header-flags'] = ok(`标志位 ${flags}（hash_based=${hashBased}，check_source=${checkSource}）`);
  structures.push('标志位');
  facts['pyc.source-hash'] = hashBased ? ok('hash_based 制品带 8 字节源哈希') : absent('该制品不是 hash_based，没有源哈希字段');
  facts['pyc.check-source-flag'] = checkSource ? ok('check_source 标志已置位') : absent('check_source 标志未置位');
  const sourceHash = bytes.subarray(8, 16);
  const sourceHashZero = sourceHash.every((byte) => byte === 0);
  const payload = bytes.subarray(16);
  // marshal 的 FLAG_REF 位（0x80）与类型码共存：真实 pyc 的码对象载荷首字节常带这一位
  // （实测 Python 3.13 编译的模块首字节为 0xe3，即 FLAG_REF 加 TYPE_CODE），
  // 掩掉之后按剩余位查表，否则每个真实 pyc 都会被误判成结构损坏。
  const firstByte = payload[0];
  const firstType = firstByte === undefined ? undefined : firstByte & ~0x80;
  const refFlag = firstByte !== undefined && (firstByte & 0x80) !== 0;
  facts['pyc.code-object'] =
    payload.length > 0 && MARSHAL_TYPE_CODES.has(firstType)
      ? ok(`载荷 ${payload.length} 字节，首字节 0x${firstByte.toString(16)}${refFlag ? '（FLAG_REF 置位）' : ''}`)
      : broken(`载荷首字节 0x${firstByte?.toString(16) ?? '--'} 掩去 FLAG_REF 后不是已登记的 marshal 类型码`);
  structures.push('码对象载荷');

  const parseable = facts['pyc.magic'].parsed === true && facts['pyc.code-object'].parsed === true;
  return envelope(
    'pyc',
    parseable ? { parseable: true, structures } : { parseable: false, reason: firstFailure(facts) ?? 'pyc 结构解析失败', structures },
    facts,
    { readable: true, hashBased, checkSource, sourceHashZero },
  );
}

// ---------------------------------------------------------------------------
// BEAM：FOR1 外层块与内部块表
// ---------------------------------------------------------------------------

/**
 * 提取 BEAM 夹具的结构事实。
 * @param {Buffer} bytes 制品字节
 * @returns {Record<string, unknown>}
 */
function inspectBeam(bytes) {
  const facts = {};
  const structures = [];
  if (bytes.length < 12) {
    facts['beam.for1-chunk'] = broken('文件不足 12 字节，IFF 外层块不完整');
    return envelope('beam', { parseable: false, reason: 'IFF 外层块不完整', structures }, facts);
  }
  facts['beam.for1-chunk'] = bytes.toString('latin1', 0, 4) === 'FOR1' ? ok('FOR1 外层块魔数') : broken('缺少 FOR1 外层块魔数');
  facts['beam.beam-chunk'] = bytes.toString('latin1', 8, 12) === 'BEAM' ? ok('BEAM 类型标记') : broken('FOR1 之内不是 BEAM 类型标记');
  const formLength = bytes.readUInt32BE(4);
  facts['beam.chunk-table'] = formLength + 8 <= bytes.length ? ok(`外层块声明长度 ${formLength}`) : broken(`外层块声明长度 ${formLength} 超出文件长度 ${bytes.length}`);
  const chunkIds = new Set();
  let position = 12;
  while (position + 8 <= Math.min(bytes.length, 8 + formLength)) {
    const id = bytes.toString('latin1', position, position + 4);
    const size = bytes.readUInt32BE(position + 4);
    chunkIds.add(id);
    position += 8 + size;
  }
  facts['beam.chunk.atom'] = chunkIds.has('Atom') ? ok('Atom 块存在') : absent('该制品没有 Atom 块');
  facts['beam.chunk.code'] = chunkIds.has('Code') ? ok('Code 块存在') : absent('该制品没有 Code 块');

  const parseable = Object.values(facts).every((fact) => fact.parsed !== false);
  return envelope('beam', parseable ? { parseable: true, structures } : { parseable: false, reason: firstFailure(facts) ?? 'BEAM 结构解析失败', structures }, facts);
}

// ---------------------------------------------------------------------------
// DEX：头部、字节序标记与三张索引表
// ---------------------------------------------------------------------------

/** DEX 头部固定长度。 */
const DEX_HEADER_BYTES = 112;

/** DEX 字节序标记的合法值。 */
const DEX_ENDIAN_TAG = 0x12345678;

/**
 * 检查 DEX 结构事实。
 * 判据与 required-sets 的 requirement 对应：头部可读、字节序标记正确、
 * 字符串、类型、方法三张索引表的区间落在文件内且计数自洽。
 * @param {Buffer} bytes 制品字节
 * @returns {Record<string, unknown>}
 */
function inspectDex(bytes) {
  const facts = {};
  const structures = [];
  if (bytes.length < 8 || bytes.toString('latin1', 0, 4) !== 'dex\n') {
    facts['dex.header'] = broken('缺少 dex 加换行的魔数');
    return envelope('dex', { parseable: false, reason: '缺少 DEX 魔数', structures }, facts);
  }
  if (bytes.length < DEX_HEADER_BYTES) {
    facts['dex.header'] = broken(`文件仅 ${bytes.length} 字节，不足 DEX 头部固定的 ${DEX_HEADER_BYTES} 字节`);
    return envelope('dex', { parseable: false, reason: 'DEX 头部不完整', structures }, facts);
  }
  facts['dex.header'] = ok('魔数、版本与各表偏移计数均可读');
  const endianTag = readUInt(bytes, 40, 4, false);
  facts['dex.endian-tag'] = endianTag === DEX_ENDIAN_TAG ? ok(`字节序标记 0x${endianTag.toString(16)}`) : broken(`字节序标记为 0x${(endianTag ?? 0).toString(16)}，不是 0x${DEX_ENDIAN_TAG.toString(16)}`);

  // 三张索引表的区间检查：任一张越界即判失败，因为它的条目根本读不到。
  const tables = [
    { id: 'dex.string-ids', label: '字符串索引表', sizeField: 56, offField: 60, itemBytes: 4 },
    { id: 'dex.type-ids', label: '类型索引表', sizeField: 64, offField: 68, itemBytes: 4 },
    { id: 'dex.method-ids', label: '方法索引表', sizeField: 88, offField: 92, itemBytes: 8 },
  ];
  for (const table of tables) {
    const size = readUInt(bytes, table.sizeField, 4, false);
    const off = readUInt(bytes, table.offField, 4, false);
    if (size === undefined || off === undefined) {
      facts[table.id] = broken(`${table.label}的大小或偏移字段读取越界`);
      continue;
    }
    if (size === 0) {
      // 空表按不适用：制品可以合法地不含类型或方法，但不能含越界的表。
      facts[table.id] = absent(`${table.label}声明 0 项`);
      continue;
    }
    const end = off + size * table.itemBytes;
    facts[table.id] = end <= bytes.length ? ok(`${table.label}声明 ${size} 项，区间 [${off}, ${end}) 落在文件内`) : broken(`${table.label}声明 ${size} 项，区间终点 ${end} 超出文件长度 ${bytes.length}`);
  }

  const parseable = Object.values(facts).every((fact) => fact.parsed !== false);
  return envelope('dex', parseable ? { parseable: true, structures } : { parseable: false, reason: firstFailure(facts) ?? 'DEX 结构解析失败', structures }, facts);
}

// ---------------------------------------------------------------------------
// 分派
// ---------------------------------------------------------------------------

/** 容器标识到检查函数的映射。 */
const INSPECTORS = Object.freeze({
  elf: inspectElf,
  pe: inspectPe,
  'mach-o': inspectMacho,
  'mach-o-fat': inspectMachoFat,
  zip: inspectZip,
  gguf: inspectGguf,
  safetensors: inspectSafetensors,
  pyc: inspectPyc,
  beam: inspectBeam,
  dex: inspectDex,
});

/**
 * 按容器检查结构事实。容器不在 v1 格式集内时返回 null，由调用方判不适用。
 * @param {string} containerType 容器标识
 * @param {Buffer} bytes 制品字节
 * @returns {Record<string, unknown> | null}
 */
export function inspectContainer(containerType, bytes) {
  const inspector = INSPECTORS[containerType];
  if (inspector === undefined || !Buffer.isBuffer(bytes)) {
    return null;
  }
  return inspector(bytes);
}
