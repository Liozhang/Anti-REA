// required-sets 模块自用的结构事实提取。
// 这里做的是“读取器替身”：从真实字节里读出必需集每一项是否可解析，
// 键与 src/required-sets/sets.mjs 的必需项编号一一对应。
// 深度事实提取（例如完整的 marshal 反序列化、ZIP 嵌套层）属 readers 模块职责，
// 这里只检验必需集真正依赖的那些结构，检不出的项不出现在事实表里，交由必需集判 unverified。

import { inflateRawSync } from 'node:zlib';

import { crc32 } from './build-fixtures.mjs';

/** marshal 类型码集合，用于判断 pyc 载荷是否存在且形状合理。 */
const MARSHAL_TYPE_CODES = new Set([0x28, 0x30, 0x3e, 0x5b, 0x7a, 0x63, 0x69, 0x73, 0x4e, 0x54, 0x46, 0x4c]);

/**
 * 读取以 NUL 结尾的字符串。上界收敛到缓冲区长度，畸形制品不得让读取无限进行。
 * @param {Buffer} buffer 缓冲区
 * @param {number} offset 起始偏移
 * @param {number} end 可用上界
 * @returns {string}
 */
function readCString(buffer, offset, end) {
  const limit = Math.min(end, buffer.length);
  const start = Math.max(offset, 0);
  let stop = start;
  while (stop < limit && buffer[stop] !== 0) {
    stop += 1;
  }
  return buffer.toString('latin1', start, stop);
}

/**
 * 提取 ELF 夹具的结构事实。
 * @param {Buffer} buffer 制品字节
 * @returns {Record<string, unknown>}
 */
function extractElfFacts(buffer) {
  const facts = {};
  if (buffer.length < 64) {
    facts['elf.elf-header'] = { parsed: false, reason: '文件不足 64 字节，ELF 头不完整' };
    return facts;
  }
  facts['elf.elf-header'] = { parsed: buffer.readUInt32LE(0) === 0x464c457f, reason: 'ELF 头魔数与基本长度' };
  const entry = Number(buffer.readBigUInt64LE(24));
  const phoff = Number(buffer.readBigUInt64LE(32));
  const shoff = Number(buffer.readBigUInt64LE(40));
  const phentsize = buffer.readUInt16LE(54);
  const phnum = buffer.readUInt16LE(56);
  const shentsize = buffer.readUInt16LE(58);
  const shnum = buffer.readUInt16LE(60);
  const shstrndx = buffer.readUInt16LE(62);

  const programHeadersParseable = phoff > 0 && phnum > 0 && phentsize >= 56 && phoff + phnum * phentsize <= buffer.length;
  facts['elf.program-headers'] = programHeadersParseable
    ? { parsed: true, reason: `程序头表位于 ${phoff}，共 ${phnum} 条` }
    : { parsed: false, reason: `程序头表偏移 ${phoff} 或条目数 ${phnum} 越界` };

  if (programHeadersParseable) {
    let loadCoversEntry = false;
    let hasDynamic = false;
    let hasInterp = false;
    for (let index = 0; index < phnum; index += 1) {
      const base = phoff + index * phentsize;
      const type = buffer.readUInt32LE(base);
      const offset = Number(buffer.readBigUInt64LE(base + 8));
      const virtualAddress = Number(buffer.readBigUInt64LE(base + 16));
      const fileSize = Number(buffer.readBigUInt64LE(base + 32));
      const memorySize = Number(buffer.readBigUInt64LE(base + 40));
      if (type === 1 && virtualAddress <= entry && entry < virtualAddress + memorySize && offset + fileSize <= buffer.length) {
        loadCoversEntry = true;
      }
      if (type === 2 && offset + fileSize <= buffer.length) {
        hasDynamic = true;
      }
      if (type === 3 && offset + fileSize <= buffer.length) {
        hasInterp = true;
      }
    }
    facts['elf.segment-load'] = { parsed: loadCoversEntry, reason: '入口地址落在某个 PT_LOAD 内' };
    facts['elf.segment-dynamic'] = { parsed: hasDynamic, reason: '存在 PT_DYNAMIC 且范围在文件内' };
    facts['elf.segment-interp'] = { parsed: hasInterp, reason: '存在 PT_INTERP 且范围在文件内' };
  }

  const sectionTableParseable =
    shoff > 0 && shnum > 0 && shentsize >= 64 && shstrndx < shnum && shoff + shnum * shentsize <= buffer.length;
  facts['elf.section-table'] = sectionTableParseable
    ? { parsed: true, reason: `节表位于 ${shoff}，共 ${shnum} 节` }
    : { parsed: false, reason: `节表偏移 ${shoff} 或条目数 ${shnum} 越界` };
  if (!sectionTableParseable) {
    return facts;
  }

  const shstrtabOffset = Number(buffer.readBigUInt64LE(shoff + shstrndx * shentsize + 24));
  const shstrtabSize = Number(buffer.readBigUInt64LE(shoff + shstrndx * shentsize + 32));
  const names = new Map();
  for (let index = 0; index < shnum; index += 1) {
    const base = shoff + index * shentsize;
    const nameOffset = buffer.readUInt32LE(base);
    names.set(readCString(buffer, shstrtabOffset + nameOffset, shstrtabOffset + shstrtabSize), {
      type: buffer.readUInt32LE(base + 4),
      offset: Number(buffer.readBigUInt64LE(base + 24)),
      size: Number(buffer.readBigUInt64LE(base + 32)),
    });
  }
  const sectionFacts = {
    'elf.section.interp': '.interp',
    'elf.section.note': '.note.gnu.build-id',
    'elf.section.dynamic': '.dynamic',
    'elf.section.dynsym': '.dynsym',
    'elf.section.dynstr': '.dynstr',
    'elf.section.reloc': '.rela.dyn',
    'elf.section.got': '.got',
    'elf.section.init-array': '.init_array',
    'elf.section.text': '.text',
    'elf.section.symtab': '.symtab',
    'elf.section.strtab': '.strtab',
    'elf.section.go-buildinfo': '.go.buildinfo',
    'elf.section.dep-v0': '.dep-v0',
  };
  for (const [itemId, sectionName] of Object.entries(sectionFacts)) {
    const section = names.get(sectionName);
    facts[itemId] =
      section === undefined
        ? { parsed: false, reason: `节表里没有 ${sectionName}` }
        : { parsed: true, reason: `${sectionName} 位于 ${section.offset}，长 ${section.size} 字节` };
  }
  return facts;
}

/**
 * 提取 PE 夹具的结构事实。
 * @param {Buffer} buffer 制品字节
 * @returns {Record<string, unknown>}
 */
function extractPeFacts(buffer) {
  const facts = {};
  const dosParseable = buffer.length >= 0x40 && buffer[0] === 0x4d && buffer[1] === 0x5a;
  facts['pe.dos-header'] = { parsed: dosParseable, reason: 'MZ 签名与 e_lfanew 可读' };
  if (!dosParseable) {
    return facts;
  }
  const peOffset = buffer.readUInt32LE(0x3c);
  facts['pe.pe-signature'] = {
    parsed: peOffset + 4 <= buffer.length && buffer.toString('latin1', peOffset, peOffset + 4) === 'PE\0\0',
    reason: 'PE\\0\\0 签名',
  };
  if (peOffset + 24 + 240 > buffer.length) {
    return facts;
  }
  const coffOffset = peOffset + 4;
  const numberOfSections = buffer.readUInt16LE(coffOffset + 2);
  const sizeOfOptionalHeader = buffer.readUInt16LE(coffOffset + 16);
  const optionalOffset = coffOffset + 20;
  facts['pe.coff-header'] = { parsed: numberOfSections > 0 && sizeOfOptionalHeader >= 240, reason: '节数与可选头大小' };
  facts['pe.optional-header'] = { parsed: buffer.readUInt16LE(optionalOffset) === 0x20b, reason: 'PE32+ 魔数' };
  facts['pe.optional-header.checksum'] = { parsed: true, reason: 'CheckSum 字段可读，取值一致性由校验和一致性检查族复验' };

  const sectionTableOffset = optionalOffset + sizeOfOptionalHeader;
  const sections = [];
  for (let index = 0; index < numberOfSections; index += 1) {
    const base = sectionTableOffset + index * 40;
    if (base + 40 > buffer.length) {
      break;
    }
    sections.push({
      name: readCString(buffer, base, base + 8),
      virtualAddress: buffer.readUInt32LE(base + 12),
      rawSize: buffer.readUInt32LE(base + 16),
      rawPointer: buffer.readUInt32LE(base + 20),
      characteristics: buffer.readUInt32LE(base + 36),
    });
  }
  facts['pe.section-table'] = { parsed: sections.length === numberOfSections, reason: `节表含 ${sections.length} 节` };

  const entryRva = buffer.readUInt32LE(optionalOffset + 16);
  const rvaToOffset = (rva) => {
    for (const section of sections) {
      if (section.virtualAddress <= rva && rva < section.virtualAddress + Math.max(section.rawSize, 1)) {
        return section.rawPointer + (rva - section.virtualAddress);
      }
    }
    return null;
  };
  facts['pe.entry-point'] = { parsed: rvaToOffset(entryRva) !== null, reason: '入口 RVA 落在某个已映射节内' };

  const dataDirectory = (index) => {
    const base = optionalOffset + 112 + index * 8;
    return { rva: buffer.readUInt32LE(base), size: buffer.readUInt32LE(base + 4) };
  };
  const importDirectory = dataDirectory(1);
  facts['pe.import-directory'] =
    importDirectory.rva === 0
      ? { absent: true, reason: '该制品未声明导入表' }
      : { parsed: rvaToOffset(importDirectory.rva) !== null, reason: '导入描述符表可定位' };
  const exportDirectory = dataDirectory(0);
  facts['pe.export-directory'] =
    exportDirectory.rva === 0 ? { absent: true, reason: '该制品未声明导出表' } : { parsed: true, reason: '导出表可定位' };
  const relocDirectory = dataDirectory(5);
  facts['pe.reloc-directory'] =
    relocDirectory.rva === 0 ? { absent: true, reason: '该制品未声明重定位表' } : { parsed: true, reason: '重定位表可定位' };
  const debugDirectory = dataDirectory(6);
  facts['pe.debug-directory'] =
    debugDirectory.rva === 0
      ? { absent: true, reason: '该制品未声明调试目录' }
      : { parsed: rvaToOffset(debugDirectory.rva) !== null, reason: '调试目录可定位' };
  const securityDirectory = dataDirectory(4);
  facts['pe.security-directory'] =
    securityDirectory.rva === 0
      ? { absent: true, reason: '该制品未声明安全目录' }
      : { parsed: securityDirectory.rva + securityDirectory.size <= buffer.length, reason: '证书表范围在文件内' };
  // Go 构建信息所在节按特征位 0xc0000040 识别，与缓解措施的判定方式一致。
  // 位运算结果按无符号回填，避免与超过 2^31 的字面量比较时符号不一致。
  const hasGoBuildinfoCharacteristics = sections.some(
    (section) => ((section.characteristics & 0xc0000040) >>> 0) === 0xc0000040,
  );
  facts['pe.section.go-buildinfo'] = hasGoBuildinfoCharacteristics
    ? { parsed: true, reason: '存在特征位为 0xc0000040 的节，即 Go 构建信息所在节' }
    : { absent: true, reason: '该制品没有特征位为 0xc0000040 的节' };
  return facts;
}

/**
 * 提取 Mach-O 夹具的结构事实。
 * @param {Buffer} buffer 制品字节
 * @returns {Record<string, unknown>}
 */
function extractMachoFacts(buffer) {
  const facts = {};
  if (buffer.length < 32) {
    facts['mach-o.header'] = { parsed: false, reason: '文件不足 32 字节，Mach-O 头不完整' };
    return facts;
  }
  facts['mach-o.header'] = { parsed: buffer.readUInt32LE(0) === 0xfeedfacf, reason: '64 位小端魔数' };
  const ncmds = buffer.readUInt32LE(16);
  const sizeofcmds = buffer.readUInt32LE(20);

  const commands = [];
  let position = 32;
  let parseable = position + sizeofcmds <= buffer.length;
  while (parseable && position < 32 + sizeofcmds) {
    const cmd = buffer.readUInt32LE(position);
    const cmdsize = buffer.readUInt32LE(position + 4);
    if (cmdsize < 8 || position + cmdsize > 32 + sizeofcmds) {
      parseable = false;
      break;
    }
    commands.push({ cmd, cmdsize, offset: position });
    position += cmdsize;
  }
  facts['mach-o.load-commands'] = {
    parsed: parseable && commands.length === ncmds,
    reason: `加载命令区共 ${commands.length} 条，头部声明 ${ncmds} 条`,
  };

  const has = (cmd) => commands.some((command) => command.cmd === cmd);
  facts['mach-o.load-command.segment'] = { parsed: has(0x19), reason: '存在 LC_SEGMENT_64' };
  facts['mach-o.load-command.dyld-info'] = has(0x22)
    ? { parsed: true, reason: '存在 LC_DYLD_INFO_ONLY' }
    : { absent: true, reason: '该制品没有动态链接信息加载命令' };
  facts['mach-o.load-command.dylinker'] = { parsed: has(0x0c), reason: '存在 LC_LOAD_DYLINKER' };
  facts['mach-o.load-command.uuid'] = { parsed: has(0x1b), reason: '存在 LC_UUID' };
  facts['mach-o.load-command.code-signature'] = { parsed: has(0x1d), reason: '存在 LC_CODE_SIGNATURE' };

  const sectionNames = new Set();
  for (const command of commands) {
    if (command.cmd !== 0x19) {
      continue;
    }
    const nsects = buffer.readUInt32LE(command.offset + 64);
    for (let index = 0; index < nsects; index += 1) {
      const base = command.offset + 72 + index * 80;
      if (base + 80 > buffer.length) {
        break;
      }
      sectionNames.add(readCString(buffer, base, base + 16));
    }
  }
  facts['mach-o.sections'] = { parsed: sectionNames.size > 0, reason: `段内节：${[...sectionNames].join('、')}` };
  facts['mach-o.section.go-buildinfo'] = sectionNames.has('__go_buildinfo')
    ? { parsed: true, reason: '__go_buildinfo 节存在' }
    : { absent: true, reason: '该制品没有 __go_buildinfo 节' };
  facts['mach-o.section.dep-v0'] = sectionNames.has(',dep-v0')
    ? { parsed: true, reason: '__DATA 段的 ,dep-v0 节存在' }
    : { absent: true, reason: '该制品没有 ,dep-v0 节' };
  return facts;
}

/**
 * 提取 ZIP 夹具的结构事实。
 * @param {Buffer} buffer 制品字节
 * @returns {Record<string, unknown>}
 */
function extractZipFacts(buffer) {
  const facts = {};
  let eocd = -1;
  for (let index = buffer.length - 22; index >= 0 && index >= buffer.length - 22 - 65536; index -= 1) {
    if (buffer.readUInt32LE(index) === 0x06054b50) {
      eocd = index;
      break;
    }
  }
  facts['zip.end-of-central-directory'] = { parsed: eocd >= 0, reason: eocd >= 0 ? `结束记录位于 ${eocd}` : '找不到结束记录' };
  if (eocd < 0) {
    return facts;
  }
  const entryCount = buffer.readUInt16LE(eocd + 10);
  const centralSize = buffer.readUInt32LE(eocd + 12);
  const centralOffset = buffer.readUInt32LE(eocd + 16);
  facts['zip.central-directory'] = {
    parsed: centralOffset + centralSize <= buffer.length && entryCount > 0,
    reason: `中央目录位于 ${centralOffset}，共 ${entryCount} 条`,
  };

  let position = centralOffset;
  const entries = [];
  let parseable = true;
  for (let index = 0; index < entryCount; index += 1) {
    if (position + 46 > buffer.length || buffer.readUInt32LE(position) !== 0x02014b50) {
      parseable = false;
      break;
    }
    entries.push({
      method: buffer.readUInt16LE(position + 10),
      checksum: buffer.readUInt32LE(position + 16),
      compressedSize: buffer.readUInt32LE(position + 20),
      uncompressedSize: buffer.readUInt32LE(position + 24),
      nameLength: buffer.readUInt16LE(position + 28),
      localOffset: buffer.readUInt32LE(position + 42),
      name: readCString(buffer, position + 46, position + 46 + buffer.readUInt16LE(position + 28)),
    });
    position += 46 + buffer.readUInt16LE(position + 28) + buffer.readUInt16LE(position + 30) + buffer.readUInt16LE(position + 32);
  }
  facts['zip.entry-table'] = { parsed: parseable && entries.length === entryCount, reason: `解析出 ${entries.length} 条目录项` };

  let localsMatch = true;
  let crcMatches = true;
  let dataReadable = true;
  const coverage = [];
  for (const entry of entries) {
    if (entry.localOffset + 30 > buffer.length || buffer.readUInt32LE(entry.localOffset) !== 0x04034b50) {
      localsMatch = false;
      continue;
    }
    const localNameLength = buffer.readUInt16LE(entry.localOffset + 26);
    const localExtraLength = buffer.readUInt16LE(entry.localOffset + 28);
    const dataStart = entry.localOffset + 30 + localNameLength + localExtraLength;
    const dataEnd = dataStart + entry.compressedSize;
    if (dataEnd > buffer.length) {
      dataReadable = false;
      continue;
    }
    const stored = buffer.subarray(dataStart, dataEnd);
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
    }
    coverage.push(`${entry.name}（${entry.method === 8 ? '已解压扫描' : '仅原始字节'}）`);
  }
  facts['zip.local-file-headers'] = { parsed: localsMatch, reason: '本地文件头与中央目录项逐条对齐' };
  facts['zip.entry-crc32'] = { parsed: crcMatches, reason: '逐条目 CRC32 与数据重算值一致' };
  facts['zip.entry-data'] = { parsed: dataReadable, reason: `条目覆盖：${coverage.join('、')}` };
  return facts;
}

/**
 * 提取 GGUF 夹具的结构事实。
 * @param {Buffer} buffer 制品字节
 * @returns {Record<string, unknown>}
 */
function extractGgufFacts(buffer) {
  const facts = {};
  if (buffer.length < 24) {
    facts['gguf.header'] = { parsed: false, reason: '文件不足 24 字节，GGUF 头不完整' };
    return facts;
  }
  facts['gguf.header'] = {
    parsed: buffer.toString('latin1', 0, 4) === 'GGUF' && buffer.readUInt32LE(4) === 3,
    reason: `魔数与版本 ${buffer.readUInt32LE(4)}`,
  };
  const tensorCount = Number(buffer.readBigUInt64LE(8));
  const metadataCount = Number(buffer.readBigUInt64LE(16));
  let position = 24;
  let parseable = true;
  for (let index = 0; index < metadataCount && parseable; index += 1) {
    if (position + 8 > buffer.length) {
      parseable = false;
      break;
    }
    const keyLength = Number(buffer.readBigUInt64LE(position));
    position += 8 + keyLength;
    if (position + 4 > buffer.length) {
      parseable = false;
      break;
    }
    const valueType = buffer.readUInt32LE(position);
    position += 4;
    if (valueType === 8) {
      if (position + 8 > buffer.length) {
        parseable = false;
        break;
      }
      position += 8 + Number(buffer.readBigUInt64LE(position));
    } else if (valueType === 9) {
      if (position + 12 > buffer.length) {
        parseable = false;
        break;
      }
      position += 12 + Number(buffer.readBigUInt64LE(position + 4)) * 4;
    } else {
      position += 4;
    }
    if (position > buffer.length) {
      parseable = false;
    }
  }
  facts['gguf.metadata-kv'] = { parsed: parseable, reason: `元数据键值共 ${metadataCount} 条` };

  let indexParseable = parseable;
  let maxEnd = 0;
  for (let index = 0; index < tensorCount && indexParseable; index += 1) {
    if (position + 12 > buffer.length) {
      indexParseable = false;
      break;
    }
    const nameLength = Number(buffer.readBigUInt64LE(position));
    position += 8 + nameLength;
    if (position + 4 > buffer.length) {
      indexParseable = false;
      break;
    }
    const dimensions = buffer.readUInt32LE(position);
    position += 4;
    if (position + dimensions * 8 + 12 > buffer.length) {
      indexParseable = false;
      break;
    }
    let elements = 1;
    for (let dimension = 0; dimension < dimensions; dimension += 1) {
      elements *= Number(buffer.readBigUInt64LE(position));
      position += 8;
    }
    const tensorType = buffer.readUInt32LE(position);
    position += 4;
    const offset = Number(buffer.readBigUInt64LE(position));
    position += 8;
    const bytesPerElement = tensorType === 0 ? 4 : 2;
    maxEnd = Math.max(maxEnd, offset + elements * bytesPerElement);
  }
  facts['gguf.tensor-index'] = { parsed: indexParseable, reason: `张量索引共 ${tensorCount} 条` };
  const dataStart = Math.ceil(position / 32) * 32;
  facts['gguf.alignment'] = { parsed: dataStart <= buffer.length, reason: `按 32 字节对齐后数据区起点 ${dataStart}` };
  facts['gguf.tensor-data'] = {
    parsed: dataStart + maxEnd <= buffer.length,
    reason: `张量数据需 ${maxEnd} 字节，数据区可用 ${buffer.length - dataStart} 字节`,
  };
  return facts;
}

/**
 * 提取 safetensors 夹具的结构事实。
 * @param {Buffer} buffer 制品字节
 * @returns {Record<string, unknown>}
 */
function extractSafetensorsFacts(buffer) {
  const facts = {};
  if (buffer.length < 16) {
    facts['safetensors.header-length-prefix'] = { parsed: false, reason: '文件不足 16 字节，长度前缀不完整' };
    return facts;
  }
  const headerLength = Number(buffer.readBigUInt64LE(0));
  facts['safetensors.header-length-prefix'] = {
    parsed: headerLength > 0 && 8 + headerLength <= buffer.length,
    reason: `头部长度前缀为 ${headerLength}`,
  };
  let header = null;
  try {
    header = JSON.parse(buffer.toString('utf8', 8, 8 + headerLength));
  } catch {
    header = null;
  }
  facts['safetensors.header-json'] = { parsed: header !== null && typeof header === 'object', reason: '头部 JSON 可解析' };
  if (header === null || typeof header !== 'object') {
    return facts;
  }
  const tensors = Object.entries(header).filter(([key, value]) => key !== '__metadata__' && value !== null && typeof value === 'object');
  const intervals = tensors.map(([name, value]) => ({ name, start: value.data_offsets[0], end: value.data_offsets[1] }));
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
  const withinBounds = sorted.every((interval) => interval.start >= 0 && interval.end <= buffer.length - dataStart);
  const noTail = sorted.length === 0 || sorted[sorted.length - 1].end === buffer.length - dataStart;
  facts['safetensors.tensor-index'] = {
    parsed: tensors.length > 0 && tensors.every(([, value]) => Array.isArray(value.data_offsets) && value.data_offsets.length === 2),
    reason: `张量索引共 ${tensors.length} 条`,
  };
  facts['safetensors.data-bounds'] = {
    parsed: withinBounds && noGap && noOverlap && noTail,
    reason: `越界=${!withinBounds} 间隙=${!noGap} 重叠=${!noOverlap} 未索引尾部=${!noTail}`,
  };
  facts['safetensors.metadata'] = Object.hasOwn(header, '__metadata__')
    ? { parsed: true, reason: '__metadata__ 槽位存在' }
    : { absent: true, reason: '该制品没有 __metadata__ 槽位' };
  return facts;
}

/**
 * 提取 pyc 夹具的结构事实。
 * @param {Buffer} buffer 制品字节
 * @returns {Record<string, unknown>}
 */
function extractPycFacts(buffer) {
  const facts = {};
  if (buffer.length < 16) {
    facts['pyc.magic'] = { parsed: false, reason: '文件不足 16 字节，pyc 头不完整' };
    return facts;
  }
  facts['pyc.magic'] = { parsed: buffer[2] === 0x0d && buffer[3] === 0x0a, reason: '魔数之后的 0D 0A 固定标记' };
  const flags = buffer.readUInt32LE(4);
  const hashBased = (flags & 1) === 1;
  const checkSource = (flags & 2) === 2;
  facts['pyc.header-flags'] = { parsed: true, reason: `标志位 ${flags}` };
  facts['pyc.source-hash'] = hashBased
    ? { parsed: true, reason: 'hash_based 制品带 8 字节源哈希' }
    : { absent: true, reason: '该制品不是 hash_based，没有源哈希字段' };
  facts['pyc.check-source-flag'] = checkSource
    ? { parsed: true, reason: 'check_source 标志已置位' }
    : { absent: true, reason: 'check_source 标志未置位' };
  const payload = buffer.subarray(16);
  facts['pyc.code-object'] = {
    parsed: payload.length > 0 && MARSHAL_TYPE_CODES.has(payload[0]),
    reason: `载荷 ${payload.length} 字节，首字节 0x${payload[0]?.toString(16)}`,
  };
  return facts;
}

/**
 * 提取 BEAM 夹具的结构事实。
 * @param {Buffer} buffer 制品字节
 * @returns {Record<string, unknown>}
 */
function extractBeamFacts(buffer) {
  const facts = {};
  if (buffer.length < 12) {
    facts['beam.for1-chunk'] = { parsed: false, reason: '文件不足 12 字节，IFF 外层块不完整' };
    return facts;
  }
  facts['beam.for1-chunk'] = { parsed: buffer.toString('latin1', 0, 4) === 'FOR1', reason: 'FOR1 外层块魔数' };
  facts['beam.beam-chunk'] = { parsed: buffer.toString('latin1', 8, 12) === 'BEAM', reason: 'BEAM 类型标记' };
  const formLength = buffer.readUInt32BE(4);
  facts['beam.chunk-table'] = { parsed: formLength + 8 <= buffer.length, reason: `外层块声明长度 ${formLength}` };
  const chunkIds = new Set();
  let position = 12;
  while (position + 8 <= Math.min(buffer.length, 8 + formLength)) {
    const id = buffer.toString('latin1', position, position + 4);
    const size = buffer.readUInt32BE(position + 4);
    chunkIds.add(id);
    position += 8 + size;
  }
  facts['beam.chunk.atom'] = chunkIds.has('Atom') ? { parsed: true, reason: 'Atom 块存在' } : { absent: true, reason: '该制品没有 Atom 块' };
  facts['beam.chunk.code'] = chunkIds.has('Code') ? { parsed: true, reason: 'Code 块存在' } : { absent: true, reason: '该制品没有 Code 块' };
  return facts;
}

/** 容器标识到提取函数的映射。 */
const EXTRACTORS = {
  elf: extractElfFacts,
  pe: extractPeFacts,
  'mach-o': extractMachoFacts,
  zip: extractZipFacts,
  gguf: extractGgufFacts,
  safetensors: extractSafetensorsFacts,
  pyc: extractPycFacts,
  beam: extractBeamFacts,
};

/**
 * 按容器提取结构事实。
 * @param {string} containerType 容器标识
 * @param {Buffer} buffer 制品字节
 * @returns {Record<string, unknown>} 键为必需项编号的事实表
 */
export function extractFacts(containerType, buffer) {
  const extractor = EXTRACTORS[containerType];
  if (extractor === undefined) {
    return {};
  }
  return extractor(buffer);
}
