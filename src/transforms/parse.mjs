// 写入侧的聚焦结构解析：回答“要改的字节在哪里”。
// 与 readers 的分工：readers 回答“制品里有什么事实”，本文件的函数只把写入位置算出来。
// 全部只读：任何解析失败都返回 {ok: false, reason}，由调用方转成“跳过并附原因”，
// 不向审计或加固抛异常，更不写任何一个字节。
//
// 这里刻意只保留覆写用得到的位置信息（节头偏移、字段偏移、载荷区间），
// 不做读取器那种完整事实提取，避免两套解析语义漂移后互相矛盾。

const ELF_MAGIC = Buffer.from([0x7f, 0x45, 0x4c, 0x46], 'latin1');

/** Mach-O 魔数表：值按小端读取后的键。 */
const MACHO_MAGICS = Object.freeze({
  0xfeedface: { bits: 32, big: false },
  0xcefaedfe: { bits: 32, big: true },
  0xfeedfacf: { bits: 64, big: false },
  0xcffaedfe: { bits: 64, big: true },
});

/** 胖二进制魔数，按大端读取。 */
const FAT_MAGICS = Object.freeze({ 0xcafebabe: { bits: 32 }, 0xcafebabf: { bits: 64 } });

/** PT_LOAD 标志位：可写、可执行。 */
const PF_WRITE = 0x2;
const PF_EXEC = 0x1;

/**
 * 读取定长无符号整数。越界返回 undefined。
 * @param {Buffer} bytes
 * @param {number} offset
 * @param {number} size
 * @param {boolean} big 大端为真
 * @returns {number | undefined}
 */
function readUInt(bytes, offset, size, big) {
  if (!Number.isInteger(offset) || offset < 0 || offset + size > bytes.length) {
    return undefined;
  }
  let value = 0;
  if (big) {
    for (let index = 0; index < size; index += 1) {
      value = value * 256 + bytes[offset + index];
    }
    return value;
  }
  for (let index = size - 1; index >= 0; index -= 1) {
    value = value * 256 + bytes[offset + index];
  }
  return value;
}

/**
 * 解析 ELF 节表，返回每个节的节头偏移与载荷区间。
 * 节名经 shstrndx 指向的节头字符串表解析；解析不到名字的节按空名字处理，不影响写入定位。
 * @param {Buffer} bytes
 * @returns {{ok: true, data: Record<string, unknown>} | {ok: false, reason: string}}
 */
export function parseElfStructure(bytes) {
  if (bytes.length < 16 || !bytes.subarray(0, 4).equals(ELF_MAGIC)) {
    return { ok: false, reason: '文件头不是 ELF 魔数' };
  }
  const is64 = bytes[4] === 2;
  const big = bytes[5] === 2;
  if (!is64 && bytes[4] !== 1) {
    return { ok: false, reason: `e_ident 的 EI_CLASS 取值 ${bytes[4]} 不是 1 或 2` };
  }
  if (!big && bytes[5] !== 1) {
    return { ok: false, reason: `e_ident 的 EI_DATA 取值 ${bytes[5]} 不是 1 或 2` };
  }
  const read = (offset, size) => readUInt(bytes, offset, size, big);
  const shoff = is64 ? read(40, 8) : read(32, 4);
  const shentsize = read(is64 ? 58 : 46, 2);
  const shnum = read(is64 ? 60 : 48, 2);
  const shstrndx = read(is64 ? 62 : 50, 2);
  if (shoff === undefined || shentsize === undefined || shnum === undefined || shstrndx === undefined) {
    return { ok: false, reason: 'ELF 头的节表字段读取越界' };
  }
  const data = { is64, big, shoff, shentsize, shnum, shstrndx, sections: [] };
  if (shoff === 0 || shnum === 0) {
    return { ok: false, reason: 'ELF 头声明 shoff 为 0 或节数为 0，没有节表可定位' };
  }
  const entrySize = Math.max(shentsize, is64 ? 64 : 40);
  for (let index = 0; index < shnum; index += 1) {
    const base = shoff + index * entrySize;
    const minimum = is64 ? 64 : 40;
    if (base + minimum > bytes.length) {
      return { ok: false, reason: `第 ${index} 号节头超出文件范围，节表无法完整定位` };
    }
    const section = is64
      ? {
          index,
          headerOffset: base,
          headerSize: minimum,
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
          headerOffset: base,
          headerSize: minimum,
          nameOffset: read(base, 4),
          type: read(base + 4, 4),
          flags: read(base + 8, 4),
          addr: read(base + 12, 4),
          offset: read(base + 16, 4),
          size: read(base + 20, 4),
          link: read(base + 24, 4),
          info: read(base + 28, 4),
          entsize: read(base + 36, 4),
        };
    for (const [key, value] of Object.entries(section)) {
      if (value === undefined) {
        return { ok: false, reason: `第 ${index} 号节头的字段 ${key} 读取越界` };
      }
    }
    data.sections.push(section);
  }
  const stringTable = data.sections[shstrndx];
  if (stringTable !== undefined && stringTable.offset + stringTable.size <= bytes.length) {
    const names = bytes.subarray(stringTable.offset, stringTable.offset + stringTable.size);
    for (const section of data.sections) {
      section.name = readFixedCString(names, section.nameOffset);
    }
  } else {
    for (const section of data.sections) {
      section.name = '';
    }
  }
  return { ok: true, data };
}

/**
 * 从字符串表里取空字符结尾的节名。取不到时返回空字符串，调用方按“名字未解析”处理。
 * @param {Buffer} names 字符串表字节
 * @param {number} offset
 * @returns {string}
 */
function readFixedCString(names, offset) {
  if (!Number.isInteger(offset) || offset < 0 || offset >= names.length) {
    return '';
  }
  let end = offset;
  while (end < names.length && names[end] !== 0) {
    end += 1;
  }
  return names.subarray(offset, end).toString('latin1');
}

/**
 * 定位 PE 的关键偏移：可选头、CheckSum 字段、数据目录与节表。
 * @param {Buffer} bytes
 * @returns {{ok: true, data: Record<string, unknown>} | {ok: false, reason: string}}
 */
export function parsePeStructure(bytes) {
  if (bytes.length < 0x40 || bytes[0] !== 0x4d || bytes[1] !== 0x5a) {
    return { ok: false, reason: '文件头不是 MZ 签名' };
  }
  const peOffset = readUInt(bytes, 0x3c, 4, false);
  if (peOffset === undefined || peOffset + 24 > bytes.length) {
    return { ok: false, reason: 'e_lfanew 指向的 PE 签名超出文件范围' };
  }
  if (readUInt(bytes, peOffset, 4, false) !== 0x00004550) {
    return { ok: false, reason: 'e_lfanew 处不是 PE\\0\\0 签名' };
  }
  const coff = peOffset + 4;
  const numberOfSections = readUInt(bytes, coff + 2, 2, false);
  const sizeOfOptionalHeader = readUInt(bytes, coff + 16, 2, false);
  if (numberOfSections === undefined || sizeOfOptionalHeader === undefined) {
    return { ok: false, reason: 'COFF 头字段读取越界' };
  }
  const optionalOffset = coff + 20;
  const data = {
    peOffset,
    numberOfSections,
    sizeOfOptionalHeader,
    optionalOffset,
    isPe32Plus: false,
    checksumFieldOffset: null,
    dataDirectoryOffset: null,
    numberOfRvaAndSizes: 0,
    sizeOfHeaders: null,
    sectionTableOffset: optionalOffset + sizeOfOptionalHeader,
    sections: [],
  };
  if (sizeOfOptionalHeader > 0) {
    const magic = readUInt(bytes, optionalOffset, 2, false);
    if (magic !== 0x10b && magic !== 0x20b) {
      return { ok: false, reason: `可选头魔数 0x${String(magic)} 不是 0x10b 或 0x20b` };
    }
    data.isPe32Plus = magic === 0x20b;
    data.checksumFieldOffset = optionalOffset + 64;
    data.sizeOfHeaders = readUInt(bytes, optionalOffset + 60, 4, false);
    data.numberOfRvaAndSizes = readUInt(bytes, optionalOffset + (data.isPe32Plus ? 108 : 92), 4, false);
    data.dataDirectoryOffset = optionalOffset + (data.isPe32Plus ? 112 : 96);
    if (data.sizeOfHeaders === undefined || data.numberOfRvaAndSizes === undefined) {
      return { ok: false, reason: '可选头字段读取越界' };
    }
  }
  for (let index = 0; index < numberOfSections; index += 1) {
    const base = data.sectionTableOffset + index * 40;
    if (base + 40 > bytes.length) {
      break;
    }
    let nameEnd = base;
    while (nameEnd < base + 8 && bytes[nameEnd] !== 0) {
      nameEnd += 1;
    }
    data.sections.push({
      index,
      headerOffset: base,
      name: bytes.subarray(base, nameEnd).toString('latin1'),
      virtualSize: readUInt(bytes, base + 8, 4, false),
      virtualAddress: readUInt(bytes, base + 12, 4, false),
      sizeOfRawData: readUInt(bytes, base + 16, 4, false),
      pointerToRawData: readUInt(bytes, base + 20, 4, false),
      characteristics: readUInt(bytes, base + 36, 4, false),
    });
  }
  return { ok: true, data };
}

/**
 * 把相对虚拟地址折算成文件偏移。节表之外的回落到文件头区间，与 PE 读取器同规则。
 * @param {number} rva
 * @param{Array<Record<string, number>>} sections
 * @param {number | null} sizeOfHeaders
 * @returns {number | undefined}
 */
export function peRvaToOffset(rva, sections, sizeOfHeaders) {
  if (sizeOfHeaders !== null && rva < sizeOfHeaders) {
    return rva;
  }
  for (const section of sections) {
    const span = Math.max(section.virtualSize ?? 0, section.sizeOfRawData ?? 0);
    if (rva >= section.virtualAddress && rva < section.virtualAddress + span) {
      return section.pointerToRawData + (rva - section.virtualAddress);
    }
  }
  return undefined;
}

/**
 * 定位 PE 调试目录里的 CODEVIEW 符号文件路径字节区间。
 * @param {Buffer} bytes
 * @param {Record<string, unknown>} pe parsePeStructure 的结果
 * @returns {{ok: true, paths: Array<{entryOffset: number, pathOffset: number, pathLength: number}>} | {ok: false, reason: string}}
 */
export function locatePeDebugPaths(bytes, pe) {
  if (pe.dataDirectoryOffset === null || 6 >= pe.numberOfRvaAndSizes) {
    return { ok: false, reason: 'PE 没有登记调试目录数据目录项' };
  }
  const base = pe.dataDirectoryOffset + 6 * 8;
  const virtualAddress = readUInt(bytes, base, 4, false);
  const size = readUInt(bytes, base + 4, 4, false);
  if (virtualAddress === undefined || size === undefined || (virtualAddress === 0 && size === 0)) {
    return { ok: false, reason: 'PE 调试目录数据目录项为空' };
  }
  const offset = peRvaToOffset(virtualAddress, pe.sections, pe.sizeOfHeaders);
  if (offset === undefined) {
    return { ok: false, reason: '调试目录的相对虚拟地址无法经节表折算成文件偏移' };
  }
  const paths = [];
  const entryCount = Math.max(1, Math.floor(size / 28));
  for (let index = 0; index < entryCount; index += 1) {
    const entry = offset + index * 28;
    if (entry + 28 > bytes.length) {
      break;
    }
    const type = readUInt(bytes, entry + 12, 4, false);
    const sizeOfData = readUInt(bytes, entry + 16, 4, false);
    // PE 规范排法：+20 是 AddressOfRawData（相对虚拟地址），+24 是 PointerToRawData（文件偏移）。
    // 在文件内定位 CODEVIEW 记录要用文件偏移，因此取 +24，与读取器同一约定。
    const pointerToRawData = readUInt(bytes, entry + 24, 4, false);
    if (type === undefined || sizeOfData === undefined || pointerToRawData === undefined) {
      continue;
    }
    if (type !== 2 || pointerToRawData + sizeOfData > bytes.length) {
      continue;
    }
    // CODEVIEW 记录：四字节签名、十六字节全局标识、四字节年龄，之后是空字符结尾的路径。
    const pathStart = pointerToRawData + 24;
    let pathEnd = pathStart;
    while (pathEnd < bytes.length && bytes[pathEnd] !== 0) {
      pathEnd += 1;
    }
    if (pathEnd > pathStart) {
      paths.push({ entryOffset: entry, pathOffset: pathStart, pathLength: pathEnd - pathStart });
    }
  }
  if (paths.length === 0) {
    return { ok: false, reason: '调试目录里没有取到 CODEVIEW 符号文件路径' };
  }
  return { ok: true, paths };
}

/**
 * 解析 Mach-O 结构：胖二进制按分片表逐个解析，返回每个分片的节表与节头偏移。
 * @param {Buffer} bytes
 * @returns {{ok: true, data: {slices: Array<Record<string, unknown>>}} | {ok: false, reason: string}}
 */
export function parseMachOStructure(bytes) {
  const firstMagic = readUInt(bytes, 0, 4, false);
  const fatSpec = FAT_MAGICS[readUInt(bytes, 0, 4, true) ?? -1];
  if (fatSpec !== undefined) {
    const count = readUInt(bytes, 4, 4, true);
    if (count === undefined || count > 64) {
      return { ok: false, reason: '胖二进制分片数读取失败或超出合理范围' };
    }
    const entrySize = fatSpec.bits === 64 ? 28 : 20;
    const slices = [];
    for (let index = 0; index < count; index += 1) {
      const base = 8 + index * entrySize;
      if (base + entrySize > bytes.length) {
        break;
      }
      const offset = readUInt(bytes, base + 8, 4, true);
      if (offset === undefined) {
        continue;
      }
      const slice = parseSlice(bytes, offset);
      slices.push(slice.ok ? slice.data : { base: offset, sections: [], unparsable: slice.reason });
    }
    return { ok: true, data: { slices } };
  }
  const spec = MACHO_MAGICS[firstMagic ?? -1];
  if (spec === undefined) {
    return { ok: false, reason: `魔数 0x${String(firstMagic)} 不是 Mach-O 魔数` };
  }
  const slice = parseSlice(bytes, 0);
  if (!slice.ok) {
    return { ok: false, reason: slice.reason };
  }
  return { ok: true, data: { slices: [slice.data] } };
}

/**
 * 解析单个 Mach-O 分片的加载命令与节表。
 * @param {Buffer} bytes
 * @param {number} base 分片起始偏移
 * @returns {{ok: true, data: Record<string, unknown>} | {ok: false, reason: string}}
 */
function parseSlice(bytes, base) {
  const magic = readUInt(bytes, base, 4, false);
  const spec = MACHO_MAGICS[magic ?? -1];
  if (spec === undefined) {
    return { ok: false, reason: `偏移 ${base} 处的魔数不是 Mach-O 魔数` };
  }
  const read = (offset, size) => readUInt(bytes, offset, size, spec.big);
  const headerSize = spec.bits === 64 ? 32 : 28;
  if (base + headerSize > bytes.length) {
    return { ok: false, reason: `偏移 ${base} 处的 Mach-O 头超出文件范围` };
  }
  const ncmds = read(base + 16, 4);
  const sizeofcmds = read(base + 20, 4);
  if (ncmds === undefined || sizeofcmds === undefined) {
    return { ok: false, reason: 'Mach-O 头字段读取越界' };
  }
  const commandEnd = Math.min(bytes.length, base + headerSize + sizeofcmds);
  const sections = [];
  let position = base + headerSize;
  for (let index = 0; index < Math.min(ncmds, 4096); index += 1) {
    if (position + 8 > commandEnd) {
      break;
    }
    const cmd = read(position, 4);
    const cmdsize = read(position + 4, 4);
    if (cmd === undefined || cmdsize === undefined || cmdsize < 8 || position + cmdsize > commandEnd) {
      break;
    }
    if (cmd === 0x19 || cmd === 0x1) {
      const is64 = cmd === 0x19;
      const segmentHeaderSize = is64 ? 72 : 56;
      const sectionSize = is64 ? 80 : 68;
      if (position + segmentHeaderSize <= commandEnd) {
        const segname = readMachoNames(bytes, position + 8, 16);
        const nsects = read(position + (is64 ? 64 : 48), 4) ?? 0;
        const sectionBase = position + segmentHeaderSize;
        for (let sectionIndex = 0; sectionIndex < nsects; sectionIndex += 1) {
          const offset = sectionBase + sectionIndex * sectionSize;
          if (offset + sectionSize > commandEnd) {
            break;
          }
          sections.push({
            segment: segname,
            name: readMachoNames(bytes, offset, 16),
            sectionHeaderOffset: offset,
            addr: read(offset + 32, is64 ? 8 : 4),
            size: read(offset + (is64 ? 40 : 36), is64 ? 8 : 4),
            offset: read(offset + (is64 ? 48 : 40), 4),
          });
        }
      }
    }
    position += cmdsize;
  }
  return { ok: true, data: { base, bits: spec.bits, big: spec.big, sections } };
}

/**
 * 读取 Mach-O 定长节名或段名字段：取首个空字符前的字节。
 * @param {Buffer} bytes
 * @param {number} offset
 * @param {number} length
 * @returns {string}
 */
function readMachoNames(bytes, offset, length) {
  if (offset + length > bytes.length) {
    return '';
  }
  let end = offset;
  while (end < offset + length && bytes[end] !== 0) {
    end += 1;
  }
  return bytes.subarray(offset, end).toString('latin1');
}

/** SHT_NOTE 节类型：节内存放注释记录。 */
const SHT_NOTE = 7;

/** PT_NOTE 段类型：段内同样可以放注释记录。 */
const PT_NOTE = 4;

/** NT_GNU_BUILD_ID 注释类型：GNU 构建标识。 */
const NT_GNU_BUILD_ID = 3;

/**
 * 定位 ELF 里全部 GNU 构建标识 note 的描述符区间。
 * 段内与节内各扫一遍：同一个 note 常被 PT_NOTE 段与 SHT_NOTE 节同时覆盖，
 * 按描述符字节区间去重后返回，避免同一份字节被覆写两次。
 * 只定位不写入：任何解析失败都返回 {ok: false, reason}。
 * @param {Buffer} bytes 制品字节
 * @returns {{ok: true, notes: Array<{descOffset: number, descSize: number}>} | {ok: false, reason: string}}
 */
export function locateElfBuildIdNotes(bytes) {
  const elf = parseElfStructure(bytes);
  if (!elf.ok) {
    return { ok: false, reason: elf.reason };
  }
  const read = (offset, size) => readUInt(bytes, offset, size, elf.data.big);
  const regions = [];
  const phoff = elf.data.is64 ? read(32, 8) : read(28, 4);
  const phentsize = elf.data.is64 ? read(54, 2) : read(42, 2);
  const phnum = elf.data.is64 ? read(56, 2) : read(44, 2);
  if (phoff !== undefined && phentsize !== undefined && phnum !== undefined && phoff !== 0 && phnum > 0) {
    const entrySize = Math.max(phentsize, elf.data.is64 ? 56 : 32);
    for (let index = 0; index < phnum; index += 1) {
      const base = phoff + index * entrySize;
      const minimum = elf.data.is64 ? 56 : 32;
      if (base + minimum > bytes.length) {
        break;
      }
      if (read(base, 4) !== PT_NOTE) {
        continue;
      }
      const offset = elf.data.is64 ? read(base + 8, 8) : read(base + 4, 4);
      const filesz = elf.data.is64 ? read(base + 32, 8) : read(base + 16, 4);
      if (offset === undefined || filesz === undefined || offset + filesz > bytes.length) {
        continue;
      }
      regions.push({ offset, size: filesz });
    }
  }
  for (const section of elf.data.sections) {
    if (section.type === SHT_NOTE && section.offset + section.size <= bytes.length) {
      regions.push({ offset: section.offset, size: section.size });
    }
  }

  const notes = [];
  const seen = new Set();
  for (const region of regions) {
    let position = region.offset;
    const end = Math.min(bytes.length, region.offset + region.size);
    while (position + 12 <= end) {
      const nameSize = read(position, 4);
      const descSize = read(position + 4, 4);
      const type = read(position + 8, 4);
      if (nameSize === undefined || descSize === undefined || type === undefined) {
        break;
      }
      const nameStart = position + 12;
      const descStart = nameStart + nameSize + ((4 - (nameSize % 4)) % 4);
      const descEnd = descStart + descSize;
      if (descEnd > end) {
        break;
      }
      const name = bytes.subarray(nameStart, nameStart + nameSize).toString('latin1').replace(/\0+$/, '');
      if (name === 'GNU' && type === NT_GNU_BUILD_ID && descSize > 0) {
        const key = `${descStart}:${descSize}`;
        if (!seen.has(key)) {
          seen.add(key);
          notes.push({ descOffset: descStart, descSize });
        }
      }
      position = descEnd + ((4 - (descSize % 4)) % 4);
    }
  }
  return { ok: true, notes };
}
