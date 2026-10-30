// transforms 测试用的字节级夹具构造器。
// 每个构造器产出最小但真实的格式字节：能被项目自己的读取器解析、被签名观察器识别，
// 因此在夹具上跑通的施加与复审结论才对真实制品有意义。
// 这里只摆字节，不做任何读取或写入制品之外的动作。

import { deflateRawSync } from 'node:zlib';

import { crc32 } from '../../src/signatures/crc32.mjs';

/** Go 构建信息魔数：0xFF 后接 " Go buildinf:"。 */
export const GO_BUILDINFO_MAGIC = Buffer.from([0xff, 0x20, 0x47, 0x6f, 0x20, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e, 0x66, 0x3a], 'latin1');

/** 向 8 字节边界取整。 */
function align8(value) {
  return Math.ceil(value / 8) * 8;
}

/**
 * 编码无前缀正数的 LEB128 变长整数（Go 构建信息用的编码）。
 * @param {number} value
 * @returns {Buffer}
 */
export function uvarint(value) {
  const bytes = [];
  let remaining = value;
  while (remaining >= 0x80) {
    bytes.push((remaining & 0x7f) | 0x80);
    remaining >>>= 7;
  }
  bytes.push(remaining);
  return Buffer.from(bytes);
}

/**
 * 构造 Go 构建信息 inline 编码块：魔数、版本串长度、版本串、模块信息长度。
 * @param {string} version 版本串，必须以 go 加数字开头
 * @returns {Buffer}
 */
export function goBuildinfoInline(version = 'go1.22.0') {
  const versionBytes = Buffer.from(version, 'latin1');
  return Buffer.concat([GO_BUILDINFO_MAGIC, uvarint(versionBytes.length), versionBytes, uvarint(0)]);
}

/**
 * 构造 Go 构建信息 pointer 编码块的指针部分：魔数后跟两个变长指针。
 * 指针目标串由调用方另行摆放，偏移在 ELF 布局确定后回填。
 * @returns {Buffer}
 */
export function goBuildinfoPointerStub() {
  return Buffer.concat([GO_BUILDINFO_MAGIC, uvarint(0), uvarint(0)]);
}

/**
 * 构造指针编码的目标串：变长长度加字符串内容。
 * @param {string} text
 * @returns {Buffer}
 */
export function goBuildinfoTarget(text) {
  const bytes = Buffer.from(text, 'latin1');
  return Buffer.concat([uvarint(bytes.length), bytes]);
}

// ---- ELF ----

/** ELF 节类型。 */
const SHT = Object.freeze({ PROGBITS: 1, SYMTAB: 2, STRTAB: 3 });

/**
 * 构造字符串表：首个字节为空字符，各名字依次追加。
 * @param {readonly string[]} names
 * @returns {{bytes: Buffer, offsets: Map<string, number>}}
 */
function buildStringTable(names) {
  const parts = [Buffer.alloc(1)];
  const offsets = new Map();
  for (const name of names) {
    offsets.set(name, parts.reduce((total, part) => total + part.length, 0));
    parts.push(Buffer.from(`${name}\0`, 'latin1'));
  }
  return { bytes: Buffer.concat(parts), offsets };
}

/**
 * 构造 64 位小端 ELF 夹具。
 * @param {{
 *   sections: Array<{name: string, type: number, data?: Buffer, link?: number, entsize?: number, addr?: number}>,
 *   loads: Array<{flags: number, vaddr?: number, memsz?: number}>,
 * }} options sections 按给定顺序摆放；loads 的 filesz 自动覆盖到文件末尾
 * @returns {{buffer: Buffer, sectionOffsets: Map<string, number>}}
 */
export function buildElf({ sections, loads }) {
  const names = [...sections.map((section) => section.name), '.shstrtab'];
  const stringTable = buildStringTable(names);
  const placed = [
    { name: '', type: 0, data: Buffer.alloc(0), link: 0, entsize: 0, addr: 0 },
    ...sections.map((section) => ({
      name: section.name,
      type: section.type,
      data: section.data ?? Buffer.alloc(0),
      link: section.link ?? 0,
      entsize: section.entsize ?? 0,
      addr: section.addr ?? 0,
    })),
    { name: '.shstrtab', type: SHT.STRTAB, data: stringTable.bytes, link: 0, entsize: 0, addr: 0 },
  ];
  const shstrndx = placed.length - 1;

  // 先摆节数据，再回填程序头与节表：程序头区域大小固定，不影响节偏移计算。
  let cursor = 64 + 56 * loads.length;
  for (const section of placed) {
    if (section.data.length === 0) {
      section.offset = 0;
      continue;
    }
    cursor = align8(cursor);
    section.offset = cursor;
    cursor += section.data.length;
  }
  const shoff = align8(cursor);
  const total = shoff + 64 * placed.length;

  const buffer = Buffer.alloc(total);
  // ELF 头。
  buffer[0] = 0x7f;
  buffer[1] = 0x45;
  buffer[2] = 0x4c;
  buffer[3] = 0x46;
  buffer[4] = 2; // ELFCLASS64
  buffer[5] = 1; // ELFDATA2LSB
  buffer[6] = 1; // EV_CURRENT
  buffer.writeUInt16LE(2, 16); // ET_EXEC
  buffer.writeUInt16LE(62, 18); // EM_X86_64
  buffer.writeUInt32LE(1, 20); // e_version
  buffer.writeBigUInt64LE(0x401000n, 24); // e_entry
  buffer.writeBigUInt64LE(64n, 32); // e_phoff
  buffer.writeBigUInt64LE(BigInt(shoff), 40); // e_shoff
  buffer.writeUInt32LE(0, 48); // e_flags
  buffer.writeUInt16LE(64, 52); // e_ehsize
  buffer.writeUInt16LE(56, 54); // e_phentsize
  buffer.writeUInt16LE(loads.length, 56); // e_phnum
  buffer.writeUInt16LE(64, 58); // e_shentsize
  buffer.writeUInt16LE(placed.length, 60); // e_shnum
  buffer.writeUInt16LE(shstrndx, 62); // e_shstrndx

  // 程序头：PT_LOAD 覆盖各自区间，末段覆盖到文件末尾。
  let phdrCursor = 64;
  for (const load of loads) {
    buffer.writeUInt32LE(1, phdrCursor); // PT_LOAD
    buffer.writeUInt32LE(load.flags, phdrCursor + 4);
    buffer.writeBigUInt64LE(0n, phdrCursor + 8); // p_offset
    buffer.writeBigUInt64LE(BigInt(load.vaddr ?? 0x400000), phdrCursor + 16); // p_vaddr
    buffer.writeBigUInt64LE(BigInt(load.vaddr ?? 0x400000), phdrCursor + 24); // p_paddr
    buffer.writeBigUInt64LE(BigInt(total), phdrCursor + 32); // p_filesz
    buffer.writeBigUInt64LE(BigInt(load.memsz ?? total), phdrCursor + 40); // p_memsz
    buffer.writeBigUInt64LE(0x1000n, phdrCursor + 48); // p_align
    phdrCursor += 56;
  }

  // 节数据。
  for (const section of placed) {
    if (section.data.length > 0) {
      section.data.copy(buffer, section.offset);
    }
  }

  // 节表。
  let shdrCursor = shoff;
  for (const section of placed) {
    buffer.writeUInt32LE(stringTable.offsets.get(section.name) ?? 0, shdrCursor);
    buffer.writeUInt32LE(section.type, shdrCursor + 4);
    buffer.writeBigUInt64LE(0n, shdrCursor + 8); // sh_flags
    buffer.writeBigUInt64LE(BigInt(section.addr), shdrCursor + 16); // sh_addr
    buffer.writeBigUInt64LE(BigInt(section.offset), shdrCursor + 24); // sh_offset
    buffer.writeBigUInt64LE(BigInt(section.data.length), shdrCursor + 32); // sh_size
    buffer.writeUInt32LE(section.link, shdrCursor + 40); // sh_link
    buffer.writeUInt32LE(0, shdrCursor + 44); // sh_info
    buffer.writeBigUInt64LE(1n, shdrCursor + 48); // sh_addralign
    buffer.writeBigUInt64LE(BigInt(section.entsize), shdrCursor + 56); // sh_entsize
    shdrCursor += 64;
  }

  const sectionOffsets = new Map();
  for (const section of placed) {
    sectionOffsets.set(section.name, section.offset);
  }
  return { buffer, sectionOffsets };
}

/**
 * 构造带静态符号表与动态符号表的 ELF 夹具。
 * @returns {{buffer: Buffer, sectionOffsets: Map<string, number>}}
 */
export function buildElfWithSymbols() {
  const strtab = Buffer.from('\0main\0helper\0', 'latin1');
  const symtab = Buffer.alloc(24 * 3);
  // 第一个符号为空符号；后两个符号的 st_name 分别指向 strtab 里的名字。
  symtab.writeUInt32LE(1, 24); // st_name = 1（"main"）
  symtab.writeUInt32LE(6, 48); // st_name = 6（"helper"）
  const dynstr = Buffer.from('\0printf\0', 'latin1');
  const dynsym = Buffer.alloc(24 * 2);
  dynsym.writeUInt32LE(1, 24);
  const built = buildElf({
    sections: [
      { name: '.text', type: SHT.PROGBITS, data: Buffer.from('code-bytes', 'latin1'), addr: 0x401000 },
      { name: '.dynstr', type: SHT.STRTAB, data: dynstr, addr: 0x402000 },
      { name: '.dynsym', type: 11, data: dynsym, link: 2, entsize: 24, addr: 0x402100 },
      { name: '.strtab', type: SHT.STRTAB, data: strtab, addr: 0x403000 },
      { name: '.symtab', type: SHT.SYMTAB, data: symtab, link: 4, entsize: 24, addr: 0x403100 },
    ],
    loads: [{ flags: 0x5 }],
  });
  return built;
}

/**
 * 构造带 .dep-v0 节的 ELF 夹具，载荷为裸 deflate 压缩的依赖清单。
 * @returns {{buffer: Buffer, sectionOffsets: Map<string, number>}}
 */
export function buildElfWithRustDep() {
  const payload = deflateRawSync(Buffer.from('serde-1.0.152 libc-0.2.139', 'latin1'));
  return buildElf({
    sections: [
      { name: '.text', type: SHT.PROGBITS, data: Buffer.from('code-bytes', 'latin1'), addr: 0x401000 },
      { name: '.dep-v0', type: SHT.PROGBITS, data: payload, addr: 0x402000 },
    ],
    loads: [{ flags: 0x5 }],
  });
}

/**
 * 构造 Go 构建信息 inline 编码的 ELF 夹具。
 * @returns {{buffer: Buffer, sectionOffsets: Map<string, number>}}
 */
export function buildElfGoInline() {
  return buildElf({
    sections: [
      { name: '.text', type: SHT.PROGBITS, data: Buffer.from('code-bytes', 'latin1'), addr: 0x401000 },
      { name: '.go.buildinfo', type: SHT.PROGBITS, data: goBuildinfoInline('go1.22.0'), addr: 0x402000 },
    ],
    loads: [{ flags: 0x5 }],
  });
}

/**
 * 构造 Go 构建信息 pointer 编码的 ELF 夹具：魔数落在可写且非执行的 load region 内。
 * 指针目标串摆在同一节内，偏移在布局确定后回填。
 * @returns {{buffer: Buffer, sectionOffsets: Map<string, number>}}
 */
export function buildElfGoPointer() {
  const versionTarget = goBuildinfoTarget('go1.21.5');
  const moduleTarget = goBuildinfoTarget('modinfo-bytes');
  // 两个指针各预留两字节：目标串偏移可能超过 127，单字节变长整数装不下。
  const pointerStub = Buffer.concat([GO_BUILDINFO_MAGIC, Buffer.alloc(4)]);
  const sectionData = Buffer.concat([pointerStub, versionTarget, moduleTarget]);
  const built = buildElf({
    sections: [
      { name: '.text', type: SHT.PROGBITS, data: Buffer.from('code-bytes', 'latin1'), addr: 0x401000 },
      { name: '.go.buildinfo', type: SHT.PROGBITS, data: sectionData, addr: 0x403000 },
    ],
    // 第一段可读可执行，第二段可写且不可执行：魔数落在第二段内。
    loads: [
      { flags: 0x5, vaddr: 0x400000 },
      { flags: 0x2, vaddr: 0x402000 },
    ],
  });
  const sectionOffset = built.sectionOffsets.get('.go.buildinfo');
  const magicOffset = sectionOffset;
  const versionOffset = sectionOffset + pointerStub.length;
  const moduleOffset = versionOffset + versionTarget.length;
  // 回填两个指针：魔数之后依次是版本串指针与模块信息指针。
  const firstPointer = uvarint(versionOffset);
  const secondPointer = uvarint(moduleOffset);
  if (firstPointer.length > 2 || secondPointer.length > 2) {
    throw new Error('指针偏移超出预留的两字节，夹具布局需要调整');
  }
  firstPointer.copy(built.buffer, magicOffset + GO_BUILDINFO_MAGIC.length);
  secondPointer.copy(built.buffer, magicOffset + GO_BUILDINFO_MAGIC.length + 2);
  return built;
}

/**
 * 构造只读数据区里带疑似凭据的 ELF 夹具。
 * @returns {{buffer: Buffer, sectionOffsets: Map<string, number>}}
 */
export function buildElfWithToken() {
  const token = 'AKIA1234567890ABCDEF';
  return buildElf({
    sections: [
      { name: '.text', type: SHT.PROGBITS, data: Buffer.from('code-bytes', 'latin1'), addr: 0x401000 },
      { name: '.rodata', type: SHT.PROGBITS, data: Buffer.from(`endpoint=https://api.example.com key=${token}\0`, 'latin1'), addr: 0x402000 },
    ],
    loads: [{ flags: 0x5 }],
  });
}

// ---- PE ----

/** PE 节特征位。 */
const PE_SCN = Object.freeze({ CODE: 0x60000020, INITIALIZED_DATA: 0xc0000040, READONLY_DATA: 0x40000040 });

/**
 * 构造 PE32+ 夹具。
 * @param {{
 *   sections: Array<{name: string, characteristics: number, data: Buffer}>,
 *   checksum?: number,
 *   securityDirectory?: {offset: number, size: number} | null,
 *   debug?: {rva: number, size: number} | null,
 * }} options
 * @returns {{buffer: Buffer, sectionRawOffsets: Map<string, number>, optionalHeaderOffset: number}}
 */
export function buildPe({ sections, checksum = 0, securityDirectory = null, debug = null }) {
  const sizeOfHeaders = 0x200;
  const peOffset = 0x40;
  const coffOffset = peOffset + 4;
  const optionalOffset = coffOffset + 20;
  const optionalSize = 240;
  const sectionTableOffset = optionalOffset + optionalSize;

  // 节数据从 0x200 起摆放，相对虚拟地址按 0x1000 递增。
  let cursor = sizeOfHeaders;
  const placed = sections.map((section, index) => {
    cursor = Math.ceil(cursor / 16) * 16;
    const rawOffset = cursor;
    cursor += section.data.length;
    return { ...section, rawOffset, virtualAddress: 0x1000 + index * 0x1000 };
  });
  const total = Math.max(cursor, sizeOfHeaders + 0x200);
  const buffer = Buffer.alloc(total);

  // DOS 头。
  buffer.write('MZ', 0, 'latin1');
  buffer.writeUInt32LE(peOffset, 0x3c);

  // PE 签名与 COFF 头。
  buffer.write('PE\0\0', peOffset, 'latin1');
  buffer.writeUInt16LE(0x8664, coffOffset); // 机器类型 x86-64
  buffer.writeUInt16LE(placed.length, coffOffset + 2); // 节数
  buffer.writeUInt32LE(0, coffOffset + 4); // 时间戳
  buffer.writeUInt32LE(0, coffOffset + 8); // 符号表指针
  buffer.writeUInt32LE(0, coffOffset + 12); // 符号数
  buffer.writeUInt16LE(optionalSize, coffOffset + 16); // 可选头大小
  buffer.writeUInt16LE(0x22, coffOffset + 18); // 特征位

  // 可选头 PE32+。
  buffer.writeUInt16LE(0x20b, optionalOffset); // 魔数
  buffer.writeUInt32LE(sizeOfHeaders, optionalOffset + 60); // SizeOfHeaders
  buffer.writeUInt32LE(checksum, optionalOffset + 64); // CheckSum
  buffer.writeUInt16LE(3, optionalOffset + 68); // 子系统：控制台
  buffer.writeUInt32LE(16, optionalOffset + 108); // NumberOfRvaAndSizes
  const dataDirectoryOffset = optionalOffset + 112;
  if (securityDirectory !== null) {
    buffer.writeUInt32LE(securityDirectory.offset, dataDirectoryOffset + 4 * 8);
    buffer.writeUInt32LE(securityDirectory.size, dataDirectoryOffset + 4 * 8 + 4);
  }
  if (debug !== null) {
    buffer.writeUInt32LE(debug.rva, dataDirectoryOffset + 6 * 8);
    buffer.writeUInt32LE(debug.size, dataDirectoryOffset + 6 * 8 + 4);
  }

  // 节表。
  let tableCursor = sectionTableOffset;
  for (const section of placed) {
    buffer.write(section.name.padEnd(8, '\0'), tableCursor, 'latin1');
    buffer.writeUInt32LE(section.data.length, tableCursor + 8); // VirtualSize
    buffer.writeUInt32LE(section.virtualAddress, tableCursor + 12); // VirtualAddress
    buffer.writeUInt32LE(section.data.length, tableCursor + 16); // SizeOfRawData
    buffer.writeUInt32LE(section.rawOffset, tableCursor + 20); // PointerToRawData
    buffer.writeUInt32LE(section.characteristics, tableCursor + 36);
    section.data.copy(buffer, section.rawOffset);
    tableCursor += 40;
  }

  const sectionRawOffsets = new Map();
  for (const section of placed) {
    sectionRawOffsets.set(section.name, section.rawOffset);
  }
  return { buffer, sectionRawOffsets, optionalHeaderOffset: optionalOffset };
}

/**
 * 构造 CODEVIEW 调试记录：四字节签名、十六字节全局标识、四字节年龄，之后是符号文件路径。
 * @param {string} path 符号文件路径
 * @returns {Buffer}
 */
export function buildCodeviewRecord(path) {
  const record = Buffer.alloc(24 + Buffer.byteLength(path) + 1);
  record.write('RSDS', 0, 'latin1');
  for (let index = 4; index < 24; index += 1) {
    record[index] = index;
  }
  record.write(path, 24, 'latin1');
  return record;
}

/**
 * 构造带调试目录与 Go 构建信息的 PE 夹具。
 * @returns {{buffer: Buffer, codeviewPathOffset: number}}
 */
export function buildPeWithDebugDirectory() {
  const codeview = buildCodeviewRecord('D:\\build\\agent\\app.pdb');
  const debugEntry = Buffer.alloc(28);
  debugEntry.writeUInt16LE(4, 8); // Major
  debugEntry.writeUInt32LE(2, 12); // Type = IMAGE_DEBUG_TYPE_CODEVIEW
  debugEntry.writeUInt32LE(codeview.length, 16); // SizeOfData
  const rdataData = Buffer.concat([debugEntry, codeview]);
  const built = buildPe({
    sections: [
      { name: '.text', characteristics: PE_SCN.CODE, data: Buffer.from('code-bytes', 'latin1') },
      { name: '.didat', characteristics: PE_SCN.INITIALIZED_DATA, data: goBuildinfoInline('go1.22.0') },
      { name: '.rdata', characteristics: PE_SCN.READONLY_DATA, data: rdataData },
    ],
  });
  // 调试目录项摆在 .rdata 开头，CODEVIEW 记录紧随其后；构造时节数据偏移已定，这里回填字段。
  const rawOffset = built.sectionRawOffsets.get('.rdata');
  const virtualAddress = 0x1000 + 2 * 0x1000;
  const directoryEntryOffset = rawOffset;
  // PE 规范排法：+20 是 AddressOfRawData（相对虚拟地址），+24 是 PointerToRawData（文件偏移）。
  // 读取器与 transforms 都按 +24 在文件内定位 CODEVIEW 记录，夹具按规范摆放，
  // 保证审计、施加、复审三方读到同一处字节，且与真实 PE 的布局一致。
  built.buffer.writeUInt32LE(virtualAddress, directoryEntryOffset + 20);
  built.buffer.writeUInt32LE(rawOffset + 28, directoryEntryOffset + 24);
  // 数据目录第 6 项指向调试目录。
  const dataDirectoryOffset = built.optionalHeaderOffset + 112;
  built.buffer.writeUInt32LE(virtualAddress, dataDirectoryOffset + 6 * 8);
  built.buffer.writeUInt32LE(28, dataDirectoryOffset + 6 * 8 + 4);
  return { buffer: built.buffer, codeviewPathOffset: rawOffset + 28 + 24 };
}

// ---- Mach-O ----

/** Mach-O 加载命令标识。 */
const LC = Object.freeze({ SEGMENT_64: 0x19, CODE_SIGNATURE: 0x1d });

/**
 * 构造 64 位小端 Mach-O 夹具。
 * @param {{
 *   segments: Array<{name: string, initprot: number, sections: Array<{name: string, data: Buffer, addr?: number}>}>,
 *   codeSignature?: {dataoff: number, datasize: number} | null,
 * }} options
 * @returns {{buffer: Buffer, sectionRawOffsets: Map<string, number>, sectionHeaderOffsets: Map<string, number>}}
 */
export function buildMachO({ segments, codeSignature = null }) {
  const headerSize = 32;
  let commandCount = segments.length + (codeSignature === null ? 0 : 1);
  let commandsSize = 0;
  for (const segment of segments) {
    commandsSize += 72 + 80 * segment.sections.length;
  }
  if (codeSignature !== null) {
    commandsSize += 16;
  }

  // 先算加载命令区结束位置，节数据依次摆放。
  let cursor = headerSize + commandsSize;
  const placedSegments = segments.map((segment, segmentIndex) => {
    const placedSections = segment.sections.map((section) => {
      const offset = cursor;
      cursor += section.data.length;
      return { ...section, offset };
    });
    return { ...segment, placedSections, fileoff: headerSize + commandsSize, filesize: placedSections.reduce((total, section) => total + section.data.length, 0), vmaddr: 0x100000000n + BigInt(segmentIndex) * 0x10000n };
  });
  const total = cursor;
  const buffer = Buffer.alloc(total);

  // Mach-O 头。
  buffer.writeUInt32LE(0xfeedfacf, 0); // MH_MAGIC_64 小端
  buffer.writeUInt32LE(0x01000007, 4); // CPU_TYPE_X86_64
  buffer.writeUInt32LE(3, 8); // CPU_SUBTYPE_X86_64_ALL
  buffer.writeUInt32LE(2, 12); // MH_EXECUTE
  buffer.writeUInt32LE(commandCount, 16); // ncmds
  buffer.writeUInt32LE(commandsSize, 20); // sizeofcmds
  buffer.writeUInt32LE(0, 24); // flags

  let commandCursor = headerSize;
  const sectionRawOffsets = new Map();
  const sectionHeaderOffsets = new Map();
  for (const segment of placedSegments) {
    buffer.writeUInt32LE(LC.SEGMENT_64, commandCursor);
    buffer.writeUInt32LE(72 + 80 * segment.placedSections.length, commandCursor + 4); // cmdsize
    buffer.write(`${segment.name}\0`, commandCursor + 8, 'latin1');
    buffer.writeBigUInt64LE(segment.vmaddr, commandCursor + 24); // vmaddr
    buffer.writeBigUInt64LE(BigInt(segment.filesize), commandCursor + 32); // vmsize
    buffer.writeBigUInt64LE(BigInt(segment.fileoff), commandCursor + 40); // fileoff
    buffer.writeBigUInt64LE(BigInt(segment.filesize), commandCursor + 48); // filesize
    buffer.writeUInt32LE(7, commandCursor + 56); // maxprot
    buffer.writeUInt32LE(segment.initprot, commandCursor + 60); // initprot
    buffer.writeUInt32LE(segment.placedSections.length, commandCursor + 64); // nsects
    let sectionCursor = commandCursor + 72;
    for (const section of segment.placedSections) {
      buffer.write(`${section.name}\0`, sectionCursor, 'latin1');
      buffer.write(`${segment.name}\0`, sectionCursor + 16, 'latin1');
      buffer.writeBigUInt64LE(segment.vmaddr, sectionCursor + 32); // addr
      buffer.writeBigUInt64LE(BigInt(section.data.length), sectionCursor + 40); // size
      buffer.writeUInt32LE(section.offset, sectionCursor + 48); // offset
      sectionHeaderOffsets.set(section.name, sectionCursor);
      sectionRawOffsets.set(section.name, section.offset);
      section.data.copy(buffer, section.offset);
      sectionCursor += 80;
    }
    commandCursor += 72 + 80 * segment.placedSections.length;
  }
  let codeSignatureCommandOffset = null;
  if (codeSignature !== null) {
    buffer.writeUInt32LE(LC.CODE_SIGNATURE, commandCursor);
    buffer.writeUInt32LE(16, commandCursor + 4);
    buffer.writeUInt32LE(codeSignature.dataoff, commandCursor + 8);
    buffer.writeUInt32LE(codeSignature.datasize, commandCursor + 12);
    codeSignatureCommandOffset = commandCursor;
  }
  return { buffer, sectionRawOffsets, sectionHeaderOffsets, codeSignatureCommandOffset };
}

/**
 * 构造带 Go 构建信息与 __DATA,.dep-v0 节的 Mach-O 夹具。
 * @returns {{buffer: Buffer, sectionHeaderOffsets: Map<string, number>}}
 */
export function buildMachOWithGoAndDep() {
  const depPayload = deflateRawSync(Buffer.from('serde-1.0.152 libc-0.2.139', 'latin1'));
  const built = buildMachO({
    segments: [
      {
        name: '__TEXT',
        initprot: 5,
        sections: [{ name: '__text', data: Buffer.from('code-bytes', 'latin1') }],
      },
      {
        name: '__DATA',
        initprot: 3,
        sections: [
          { name: '.dep-v0', data: depPayload },
          { name: '__go_buildinfo', data: goBuildinfoInline('go1.22.0') },
        ],
      },
    ],
  });
  return built;
}

/**
 * 构造带 LC_CODE_SIGNATURE 的 Mach-O 夹具。
 * @returns {{buffer: Buffer}}
 */
export function buildMachOWithCodeSignature() {
  const signaturePayload = Buffer.alloc(64, 0x5a);
  const built = buildMachO({
    segments: [
      {
        name: '__TEXT',
        initprot: 5,
        sections: [{ name: '__text', data: Buffer.from('code-bytes', 'latin1') }],
      },
      {
        name: '__DATA',
        initprot: 3,
        sections: [
          { name: '__go_buildinfo', data: goBuildinfoInline('go1.22.0') },
          { name: '__signature', data: signaturePayload },
        ],
      },
    ],
    codeSignature: { dataoff: 0, datasize: signaturePayload.length },
  });
  // 签名载荷摆在 __DATA 的 __signature 节里，回填 LC_CODE_SIGNATURE 的 dataoff。
  const payloadOffset = built.sectionRawOffsets.get('__signature');
  built.buffer.writeUInt32LE(payloadOffset, built.codeSignatureCommandOffset + 8);
  return built;
}

// ---- pyc ----

/**
 * 构造 hash_based 且 check_source 置位的 pyc 夹具。
 * @param {{checkSource?: boolean}} [options]
 * @returns {Buffer}
 */
export function buildPyc({ checkSource = true } = {}) {
  const buffer = Buffer.alloc(32);
  buffer[0] = 0xa5;
  buffer[1] = 0x0d;
  buffer[2] = 0x0d;
  buffer[3] = 0x0a;
  buffer.writeUInt32LE(checkSource ? 0b11 : 0b01, 4); // 标志位
  buffer.write('0123456789abcdef', 8, 'latin1'); // source_hash
  buffer.write('code-object-payload', 16, 'latin1');
  return buffer;
}

/**
 * 构造 pyc 夹具，把一个令牌放在指定偏移处，其余字节填 0x42。
 * 令牌前后各放一个零字节：令牌模式用前后断言排除偶然字节串，定界符不是令牌字符。
 * 用于覆写窗口与匹配长度的回归测试：令牌可以放到覆写侧窗口之外、读取器窗口之内。
 * @param {{offset: number, token: string}} options
 * @returns {Buffer}
 */
export function buildPycWithTokenAt({ offset, token }) {
  const head = buildPyc();
  const buffer = Buffer.alloc(offset + token.length + 512, 0x42);
  head.copy(buffer, 0);
  buffer[offset - 1] = 0x00; // 前置定界
  buffer.write(token, offset, 'latin1');
  buffer[offset + token.length] = 0x00; // 后置定界
  return buffer;
}

// ---- ZIP ----

/** ZIP 本地文件头签名。 */
const ZIP_LOCAL = Buffer.from('PK\x03\x04', 'latin1');
/** ZIP 中央目录文件头签名。 */
const ZIP_CENTRAL = Buffer.from('PK\x01\x02', 'latin1');
/** ZIP 中央目录结尾记录签名。 */
const ZIP_EOCD = Buffer.from('PK\x05\x06', 'latin1');

/**
 * 构造 ZIP 夹具：同时含存储条目与 deflate 条目。
 * @param {Array<{name: string, method?: 0 | 8, content: Buffer}>} entries
 * @returns {Buffer}
 */
export function buildZip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const entry of entries) {
    const method = entry.method ?? 0;
    const nameBytes = Buffer.from(entry.name, 'latin1');
    const data = method === 8 ? deflateRawSync(entry.content) : entry.content;
    const crc = crc32(entry.content);
    const local = Buffer.alloc(30 + nameBytes.length);
    local.set(ZIP_LOCAL, 0);
    local.writeUInt16LE(method, 8); // 压缩方法
    local.writeUInt32LE(crc, 14); // CRC32
    local.writeUInt32LE(data.length, 18); // 压缩大小
    local.writeUInt32LE(entry.content.length, 22); // 未压缩大小
    local.writeUInt16LE(nameBytes.length, 26);
    nameBytes.copy(local, 30);
    locals.push({ header: local, data, offset });

    const central = Buffer.alloc(46 + nameBytes.length);
    central.set(ZIP_CENTRAL, 0);
    central.writeUInt16LE(20, 4); // 版本 needed
    central.writeUInt16LE(20, 6); // 版本 made by
    central.writeUInt16LE(method, 10); // 压缩方法
    central.writeUInt32LE(crc, 16); // CRC32
    central.writeUInt32LE(data.length, 20); // 压缩大小
    central.writeUInt32LE(entry.content.length, 24); // 未压缩大小
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE(offset, 42); // 本地文件头偏移
    nameBytes.copy(central, 46);
    centrals.push(central);

    offset += local.length + data.length;
  }

  const localBytes = locals.flatMap((local) => [local.header, local.data]);
  const centralStart = localBytes.reduce((total, part) => total + part.length, 0);
  const centralBytes = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.set(ZIP_EOCD, 0);
  eocd.writeUInt16LE(entries.length, 8); // 本磁盘条目数
  eocd.writeUInt16LE(entries.length, 10); // 总条目数
  eocd.writeUInt32LE(centralBytes.length, 12); // 中央目录大小
  eocd.writeUInt32LE(centralStart, 16); // 中央目录偏移
  return Buffer.concat([...localBytes, centralBytes, eocd]);
}

// ---- safetensors ----

/**
 * 构造 safetensors 夹具：八字节小端头部长度前缀加 JSON 头，数据区紧随其后。
 * @param {Array<{name: string, dtype?: string, shape?: number[], data: Buffer}>} tensors
 * @returns {Buffer}
 */
export function buildSafetensors(tensors) {
  const header = {};
  let cursor = 0;
  const dataParts = [];
  for (const tensor of tensors) {
    header[tensor.name] = {
      dtype: tensor.dtype ?? 'F32',
      shape: tensor.shape ?? [tensor.data.length / 4],
      data_offsets: [cursor, cursor + tensor.data.length],
    };
    cursor += tensor.data.length;
    dataParts.push(tensor.data);
  }
  const headerBytes = Buffer.from(JSON.stringify(header), 'utf8');
  const prefix = Buffer.alloc(8);
  prefix.writeBigUInt64LE(BigInt(headerBytes.length));
  return Buffer.concat([prefix, headerBytes, ...dataParts]);
}

// ---- GGUF ----

/**
 * 编码 GGUF 字符串：八字节小端长度前缀加字节内容。
 * @param {string} value
 * @returns {Buffer}
 */
function ggufString(value) {
  const bytes = Buffer.from(value, 'utf8');
  const prefix = Buffer.alloc(8);
  prefix.writeBigUInt64LE(BigInt(bytes.length));
  return Buffer.concat([prefix, bytes]);
}

/**
 * 编码 GGUF 元数据键值对。
 * @param {{key: string, type: number, value: string | number | Array<string | number>}} item
 * @returns {Buffer}
 */
function ggufMetadata(item) {
  const parts = [ggufString(item.key), (() => {
    const type = Buffer.alloc(4);
    type.writeUInt32LE(item.type);
    return type;
  })()];
  if (item.type === 8) {
    parts.push(ggufString(String(item.value)));
    return Buffer.concat(parts);
  }
  if (item.type === 9) {
    const values = item.value;
    const elementType = Buffer.alloc(4);
    elementType.writeUInt32LE(typeof values[0] === 'string' ? 8 : 4);
    const count = Buffer.alloc(8);
    count.writeBigUInt64LE(BigInt(values.length));
    parts.push(elementType, count);
    for (const value of values) {
      parts.push(typeof value === 'string' ? ggufString(value) : (() => {
        const encoded = Buffer.alloc(4);
        encoded.writeUInt32LE(value);
        return encoded;
      })());
    }
    return Buffer.concat(parts);
  }
  // 标量按类型各自的大小写入：u32 写四字节，u64 写八字节，读取器按同一口径解析。
  const scalarSizes = { 0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8 };
  const size = scalarSizes[item.type] ?? 8;
  const encoded = Buffer.alloc(size);
  if (size === 8) {
    encoded.writeBigUInt64LE(BigInt(Number(item.value)));
  } else if (size === 1) {
    encoded.writeUInt8(Number(item.value));
  } else if (size === 2) {
    encoded.writeUInt16LE(Number(item.value));
  } else {
    encoded.writeUInt32LE(Number(item.value));
  }
  parts.push(encoded);
  return Buffer.concat(parts);
}

/**
 * 构造 GGUF 夹具：头部、元数据键值、张量索引、按 alignment 对齐后的张量数据。
 * @param {{
 *   metadata?: Array<{key: string, type: number, value: string | number | Array<string | number>}>,
 *   tensors: Array<{name: string, shape: number[], type?: number, data: Buffer}>,
 *   alignment?: number,
 * }} options
 * @returns {Buffer}
 */
export function buildGguf({ metadata = [], tensors, alignment = 32 }) {
  const header = Buffer.alloc(24);
  header.write('GGUF', 0, 'latin1');
  header.writeUInt32LE(3, 4); // 版本
  header.writeBigUInt64LE(BigInt(tensors.length), 8); // 张量数
  header.writeBigUInt64LE(BigInt(metadata.length), 16); // 元数据键数

  const metadataBytes = Buffer.concat(metadata.map((item) => ggufMetadata(item)));
  const tensorInfos = [];
  let dataOffset = 0;
  for (const tensor of tensors) {
    const type = tensor.type ?? 0;
    const info = Buffer.concat([
      ggufString(tensor.name),
      (() => {
        const dims = Buffer.alloc(4);
        dims.writeUInt32LE(tensor.shape.length);
        return dims;
      })(),
      ...tensor.shape.map((size) => {
        const dim = Buffer.alloc(8);
        dim.writeBigUInt64LE(BigInt(size));
        return dim;
      }),
      (() => {
        const typeBuffer = Buffer.alloc(4);
        typeBuffer.writeUInt32LE(type);
        return typeBuffer;
      })(),
      (() => {
        const offset = Buffer.alloc(8);
        offset.writeBigUInt64LE(BigInt(dataOffset));
        return offset;
      })(),
    ]);
    tensorInfos.push(info);
    dataOffset += tensor.data.length;
  }
  const tensorInfoBytes = Buffer.concat(tensorInfos);
  const headerEnd = 24 + metadataBytes.length + tensorInfoBytes.length;
  const tensorDataOffset = Math.ceil(headerEnd / alignment) * alignment;
  const padding = Buffer.alloc(tensorDataOffset - headerEnd);
  const data = Buffer.concat(tensors.map((tensor) => tensor.data));
  return Buffer.concat([header, metadataBytes, tensorInfoBytes, padding, data]);
}
