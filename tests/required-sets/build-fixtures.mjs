// required-sets 模块自用的字节级夹具构建。
// 每个夹具都是对应格式的真实最小字节图像：字段、偏移与长度都按格式规范书写，
// 目的是让必需集数据里的每一项都能在真实字节上被检验，而不是对着一份想象的结构自说自话。
//
// 字节完全确定（不含时间戳与随机数），因此可以记录 sha256 并在测试里断言稳定性。
// 这些夹具只服务于本模块的测试，不参与 tests/fixtures/manifest.json 的登记。

import { deflateRawSync, inflateRawSync } from 'node:zlib';
import { createHash } from 'node:crypto';

/** 小端无符号整数。 */
function u16le(value) {
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16LE(value);
  return buffer;
}

function u32le(value) {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32LE(value);
  return buffer;
}

function u64le(value) {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64LE(BigInt(value));
  return buffer;
}

/** 大端无符号整数。 */
function u32be(value) {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value);
  return buffer;
}

/** 按对齐值补齐。 */
function padTo(length, alignment) {
  const remainder = length % alignment;
  return remainder === 0 ? Buffer.alloc(0) : Buffer.alloc(alignment - remainder);
}

/** CRC32（ZIP 条目使用，多项式 0xEDB88320）。 */
const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[index] = value;
  }
  return table;
})();

/**
 * 计算 CRC32。
 * @param {Buffer} data 输入字节
 * @returns {number}
 */
export function crc32(data) {
  let crc = -1;
  for (const byte of data) {
    crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ byte) & 0xff];
  }
  return (crc ^ -1) >>> 0;
}

// ---------------------------------------------------------------------------
// ELF：64 位小端可执行文件，含程序头、节表、动态链接所需节与三类可豁免节。
// ---------------------------------------------------------------------------

const ELF_SHT = { PROGBITS: 1, SYMTAB: 2, STRTAB: 3, RELA: 4, DYNAMIC: 6, NOTE: 7, DYNSYM: 11, INIT_ARRAY: 14 };
const ELF_SHF = { WRITE: 0x1, ALLOC: 0x2, EXECINSTR: 0x4 };
const ELF_PT = { LOAD: 1, DYNAMIC: 2, INTERP: 3 };
const ELF_PF = { X: 1, W: 2, R: 4 };
const ELF_VADDR_BASE = 0x400000;

/**
 * 构造 ELF 夹具。
 * @param {{breakProgramHeaders?: boolean}} [options] breakProgramHeaders 为真时把 e_phoff 改成越界值
 * @returns {Buffer}
 */
export function buildElf(options = {}) {
  const interp = Buffer.from('/lib64/ld-linux-x86-64.so.2\0', 'latin1');
  const noteName = Buffer.from('GNU\0', 'latin1');
  const noteDesc = Buffer.alloc(20);
  for (let index = 0; index < noteDesc.length; index += 1) {
    noteDesc[index] = index;
  }
  const note = Buffer.concat([
    u32le(noteName.length),
    u32le(noteDesc.length),
    u32le(3),
    noteName,
    Buffer.from([0, 0, 0, 0]),
    noteDesc,
  ]);
  const goBuildinfo = Buffer.concat([
    Buffer.from([0xff], 'latin1'),
    Buffer.from(' Go buildinf:', 'latin1'),
    u16le(0),
    Buffer.from([8, 0, 0]),
    Buffer.alloc(28, 0x41),
  ]);
  const depV0 = Buffer.from('rust dependency list placeholder', 'latin1');
  const dynstr = Buffer.from('\0libc.so.6\0', 'latin1');

  const sections = [
    { name: '', type: 0, flags: 0, align: 0, content: Buffer.alloc(0), entsize: 0 },
    { name: '.interp', type: ELF_SHT.PROGBITS, flags: ELF_SHF.ALLOC, align: 1, content: interp, entsize: 0 },
    { name: '.note.gnu.build-id', type: ELF_SHT.NOTE, flags: ELF_SHF.ALLOC, align: 4, content: note, entsize: 0 },
    { name: '.text', type: ELF_SHT.PROGBITS, flags: ELF_SHF.ALLOC | ELF_SHF.EXECINSTR, align: 16, content: Buffer.from([0x90, 0x90, 0xc3]), entsize: 0 },
    { name: '.rodata', type: ELF_SHT.PROGBITS, flags: ELF_SHF.ALLOC, align: 8, content: Buffer.from('rodata\0', 'latin1'), entsize: 0 },
    { name: '.data', type: ELF_SHT.PROGBITS, flags: ELF_SHF.WRITE | ELF_SHF.ALLOC, align: 8, content: Buffer.from([1, 2, 3, 4]), entsize: 0 },
    { name: '.dynamic', type: ELF_SHT.DYNAMIC, flags: ELF_SHF.WRITE | ELF_SHF.ALLOC, align: 8, content: Buffer.alloc(80), entsize: 16 },
    { name: '.dynsym', type: ELF_SHT.DYNSYM, flags: ELF_SHF.ALLOC, align: 8, content: Buffer.alloc(24), entsize: 24 },
    { name: '.dynstr', type: ELF_SHT.STRTAB, flags: ELF_SHF.ALLOC, align: 1, content: dynstr, entsize: 0 },
    { name: '.rela.dyn', type: ELF_SHT.RELA, flags: ELF_SHF.ALLOC, align: 8, content: Buffer.alloc(24), entsize: 24 },
    { name: '.got', type: ELF_SHT.PROGBITS, flags: ELF_SHF.WRITE | ELF_SHF.ALLOC, align: 8, content: Buffer.alloc(8), entsize: 0 },
    { name: '.init_array', type: ELF_SHT.INIT_ARRAY, flags: ELF_SHF.WRITE | ELF_SHF.ALLOC, align: 8, content: Buffer.alloc(8), entsize: 8 },
    { name: '.go.buildinfo', type: ELF_SHT.PROGBITS, flags: ELF_SHF.ALLOC, align: 8, content: goBuildinfo, entsize: 0 },
    { name: '.dep-v0', type: ELF_SHT.PROGBITS, flags: ELF_SHF.ALLOC, align: 8, content: depV0, entsize: 0 },
    { name: '.symtab', type: ELF_SHT.SYMTAB, flags: 0, align: 8, content: Buffer.alloc(24), entsize: 24 },
    { name: '.strtab', type: ELF_SHT.STRTAB, flags: 0, align: 1, content: Buffer.from('\0', 'latin1'), entsize: 0 },
    { name: '.shstrtab', type: ELF_SHT.STRTAB, flags: 0, align: 1, content: Buffer.alloc(0), entsize: 0 },
  ];

  const shstrtab = Buffer.concat(sections.map((section) => Buffer.from(`${section.name}\0`, 'latin1')));
  const nameOffsets = new Map();
  let nameCursor = 0;
  for (const section of sections) {
    nameOffsets.set(section.name, nameCursor);
    nameCursor += section.name.length + 1;
  }
  sections[sections.length - 1].content = shstrtab;

  const programHeaderCount = 4;
  let cursor = 64 + programHeaderCount * 56;
  const offsets = new Map();
  for (const section of sections) {
    // .shstrtab 的内容排在节头表之后，偏移单独计算，这里跳过。
    if (section.name === '.shstrtab') {
      continue;
    }
    cursor += padTo(cursor, Math.max(section.align, 1)).length;
    offsets.set(section.name, cursor);
    cursor += section.content.length;
  }
  const sectionHeaderOffset = (() => {
    const padded = cursor + padTo(cursor, 8).length;
    return padded;
  })();
  const shstrtabOffset = sectionHeaderOffset + sections.length * 64;

  const vaddrOf = (name) => ELF_VADDR_BASE + (offsets.get(name) ?? 0);
  const sizeOf = (name) => sections.find((section) => section.name === name).content.length;

  const dynamic = Buffer.alloc(80);
  const dynamicEntries = [
    [5, vaddrOf('.dynstr')],
    [6, vaddrOf('.dynsym')],
    [10, sizeOf('.dynstr')],
    [11, 24],
    [0, 0],
  ];
  dynamicEntries.forEach(([tag, value], index) => {
    dynamic.writeBigInt64LE(BigInt(tag), index * 16);
    dynamic.writeBigInt64LE(BigInt(value), index * 16 + 8);
  });
  sections.find((section) => section.name === '.dynamic').content = dynamic;

  const entry = vaddrOf('.text');
  const textEnd = offsets.get('.rodata') + sizeOf('.rodata');
  const dataStart = offsets.get('.data');
  const dataEnd = offsets.get('.init_array') + sizeOf('.init_array');

  const programHeaders = Buffer.alloc(programHeaderCount * 56);
  const writeProgramHeader = (index, type, flags, offset, virtualAddress, fileSize, memorySize) => {
    const base = index * 56;
    programHeaders.writeUInt32LE(type, base);
    programHeaders.writeUInt32LE(flags, base + 4);
    programHeaders.writeBigUInt64LE(BigInt(offset), base + 8);
    programHeaders.writeBigUInt64LE(BigInt(virtualAddress), base + 16);
    programHeaders.writeBigUInt64LE(BigInt(0), base + 24);
    programHeaders.writeBigUInt64LE(BigInt(fileSize), base + 32);
    programHeaders.writeBigUInt64LE(BigInt(memorySize), base + 40);
    programHeaders.writeBigUInt64LE(BigInt(0x1000), base + 48);
  };
  writeProgramHeader(0, ELF_PT.LOAD, ELF_PF.R | ELF_PF.X, 0, ELF_VADDR_BASE, textEnd, textEnd);
  writeProgramHeader(1, ELF_PT.LOAD, ELF_PF.R | ELF_PF.W, dataStart, vaddrOf('.data'), dataEnd - dataStart, dataEnd - dataStart);
  writeProgramHeader(2, ELF_PT.INTERP, ELF_PF.R, offsets.get('.interp'), vaddrOf('.interp'), sizeOf('.interp'), sizeOf('.interp'));
  writeProgramHeader(3, ELF_PT.DYNAMIC, ELF_PF.R | ELF_PF.W, offsets.get('.dynamic'), vaddrOf('.dynamic'), sizeOf('.dynamic'), sizeOf('.dynamic'));

  const header = Buffer.alloc(64);
  Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00], 'latin1').copy(header, 0);
  header.writeUInt16LE(2, 16);
  header.writeUInt16LE(0x3e, 18);
  header.writeUInt32LE(1, 20);
  header.writeBigUInt64LE(BigInt(entry), 24);
  header.writeBigUInt64LE(BigInt(options.breakProgramHeaders === true ? 0x7ffffff0 : 64), 32);
  header.writeBigUInt64LE(BigInt(sectionHeaderOffset), 40);
  header.writeUInt32LE(0, 48);
  header.writeUInt16LE(64, 52);
  header.writeUInt16LE(56, 54);
  header.writeUInt16LE(programHeaderCount, 56);
  header.writeUInt16LE(64, 58);
  header.writeUInt16LE(sections.length, 60);
  header.writeUInt16LE(sections.length - 1, 62);

  const sectionHeaders = Buffer.alloc(sections.length * 64);
  sections.forEach((section, index) => {
    const base = index * 64;
    const sectionOffset = index === 0 ? 0 : section.name === '.shstrtab' ? shstrtabOffset : offsets.get(section.name);
    sectionHeaders.writeUInt32LE(nameOffsets.get(section.name), base);
    sectionHeaders.writeUInt32LE(section.type, base + 4);
    sectionHeaders.writeBigUInt64LE(BigInt(section.flags), base + 8);
    sectionHeaders.writeBigUInt64LE(BigInt(section.flags & ELF_SHF.ALLOC ? vaddrOf(section.name) : 0), base + 16);
    sectionHeaders.writeBigUInt64LE(BigInt(sectionOffset), base + 24);
    sectionHeaders.writeBigUInt64LE(BigInt(section.content.length), base + 32);
    sectionHeaders.writeUInt32LE(0, base + 40);
    sectionHeaders.writeUInt32LE(0, base + 44);
    sectionHeaders.writeBigUInt64LE(BigInt(section.align), base + 48);
    sectionHeaders.writeBigUInt64LE(BigInt(section.entsize), base + 56);
  });

  const parts = [header, programHeaders];
  let written = header.length + programHeaders.length;
  for (const section of sections) {
    // .shstrtab 的内容排在节头表之后，这里跳过，避免同一份字节进文件两次。
    if (section.name === '.shstrtab') {
      continue;
    }
    const padding = padTo(written, Math.max(section.align, 1));
    parts.push(padding);
    written += padding.length;
    parts.push(section.content);
    written += section.content.length;
  }
  parts.push(padTo(written, 8));
  parts.push(sectionHeaders);
  parts.push(shstrtab);
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------------------
// safetensors：8 字节长度前缀 + 头部 JSON + 张量数据。
// ---------------------------------------------------------------------------

/**
 * 构造 safetensors 夹具。
 * @param {{writeMetadata?: boolean}} [options] writeMetadata 为假时不写 __metadata__
 * @returns {Buffer}
 */
export function buildSafetensors(options = {}) {
  const header = {};
  if (options.writeMetadata !== false) {
    header.__metadata__ = { license: 'MIT', notice: '仅供测试' };
  }
  header.w = { dtype: 'F32', shape: [4], data_offsets: [0, 16] };
  const headerJson = Buffer.from(JSON.stringify(header), 'utf8');
  const data = Buffer.alloc(16);
  for (let index = 0; index < data.length; index += 1) {
    data[index] = index;
  }
  return Buffer.concat([u64le(headerJson.length), headerJson, data]);
}

// ---------------------------------------------------------------------------
// pyc：魔数 + 标志位 + 源哈希 + 码对象载荷。
// ---------------------------------------------------------------------------

/** Python 3.11 的 pyc 魔数（3495 = 0x0da7），字节 2 至 3 固定为 0D 0A。 */
const PYC_MAGIC = Buffer.from([0xa7, 0x0d, 0x0d, 0x0a]);

/**
 * 构造 pyc 夹具。
 * @param {{flags?: number, clearSourceHash?: boolean}} [options] flags 缺省为 3（hash_based 且 check_source）
 * @returns {Buffer}
 */
export function buildPyc(options = {}) {
  const flags = options.flags ?? 3;
  const sourceHash = options.clearSourceHash === true ? Buffer.alloc(8) : Buffer.from('01234567', 'latin1');
  // 载荷以 marshal 类型码 'c'（TYPE_CODE）开头，深度反序列化由读取器负责，夹具只保证载荷存在。
  const payload = Buffer.concat([Buffer.from('c', 'latin1'), Buffer.alloc(48, 0x5a)]);
  return Buffer.concat([PYC_MAGIC, u32le(flags), sourceHash, payload]);
}

// ---------------------------------------------------------------------------
// GGUF：头部 + 元数据键值 + 张量索引 + 按 32 字节对齐的张量数据。
// ---------------------------------------------------------------------------

const GGUF_ALIGNMENT = 32;

/**
 * 构造 GGUF 夹具。
 * @returns {Buffer}
 */
export function buildGguf() {
  const metadataKey = Buffer.from('general.license', 'utf8');
  const metadataValue = Buffer.from('MIT', 'utf8');
  const metadata = Buffer.concat([u64le(metadataKey.length), metadataKey, u32le(8), u64le(metadataValue.length), metadataValue]);
  const tensorName = Buffer.from('w', 'utf8');
  const tensorInfo = Buffer.concat([u64le(tensorName.length), tensorName, u32le(1), u64le(4), u32le(0), u64le(0)]);
  const tensorData = Buffer.alloc(16);
  for (let index = 0; index < tensorData.length; index += 1) {
    tensorData[index] = index;
  }
  const headerLength = 4 + 4 + 8 + 8 + metadata.length + tensorInfo.length;
  const header = Buffer.concat([
    Buffer.from('GGUF', 'latin1'),
    u32le(3),
    u64le(1),
    u64le(1),
    metadata,
    tensorInfo,
  ]);
  return Buffer.concat([header, padTo(headerLength, GGUF_ALIGNMENT), tensorData]);
}

// ---------------------------------------------------------------------------
// ZIP：一个存储条目加一个 deflate 条目，本地头、中央目录与结束记录齐全。
// ---------------------------------------------------------------------------

/**
 * 构造 ZIP 夹具。
 * @returns {Buffer}
 */
export function buildZip() {
  const entries = [
    { name: 'readme.txt', method: 0, content: Buffer.from('readme content\n', 'latin1') },
    { name: 'payload.bin', method: 8, content: Buffer.alloc(64, 0x61) },
  ];
  const localParts = [];
  const centralParts = [];
  let offset = 0;
  for (const entry of entries) {
    const stored = entry.method === 8 ? deflateRawSync(entry.content) : entry.content;
    const checksum = crc32(entry.content);
    const name = Buffer.from(entry.name, 'latin1');
    const local = Buffer.concat([
      u32le(0x04034b50),
      u16le(20),
      u16le(0),
      u16le(entry.method),
      u16le(0),
      u16le(0x2198),
      u32le(checksum),
      u32le(stored.length),
      u32le(entry.content.length),
      u16le(name.length),
      u16le(0),
      name,
    ]);
    localParts.push(local, stored);
    const central = Buffer.concat([
      u32le(0x02014b50),
      u16le(20),
      u16le(20),
      u16le(0),
      u16le(entry.method),
      u16le(0),
      u16le(0x2198),
      u32le(checksum),
      u32le(stored.length),
      u32le(entry.content.length),
      u16le(name.length),
      u16le(0),
      u16le(0),
      u16le(0),
      u16le(0),
      u32le(0x81a40000),
      u32le(offset),
      name,
    ]);
    centralParts.push(central);
    offset += local.length + stored.length;
  }
  const local = Buffer.concat(localParts);
  const central = Buffer.concat(centralParts);
  const end = Buffer.concat([
    u32le(0x06054b50),
    u16le(0),
    u16le(0),
    u16le(entries.length),
    u16le(entries.length),
    u32le(central.length),
    u32le(local.length),
    u16le(0),
  ]);
  return Buffer.concat([local, central, end]);
}

// ---------------------------------------------------------------------------
// Mach-O：64 位小端可执行文件，含两个 LC_SEGMENT_64、LC_UUID、LC_LOAD_DYLINKER
// 与 LC_CODE_SIGNATURE。
// ---------------------------------------------------------------------------

const MH_MAGIC_64 = 0xfeedfacf;
const LC_SEGMENT_64 = 0x19;
const LC_UUID = 0x1b;
const LC_CODE_SIGNATURE = 0x1d;
const LC_LOAD_DYLINKER = 0x0c;
const LC_DYLD_INFO_ONLY = 0x22;

/**
 * 写入定长字符串字段（不足补零，超出截断）。
 * @param {Buffer} target 目标缓冲区
 * @param {number} offset 写入偏移
 * @param {number} length 字段长度
 * @param {string} value 字符串
 */
function writeFixedString(target, offset, length, value) {
  target.write(value.slice(0, length - 1), offset, length - 1, 'latin1');
}

/**
 * 构造 Mach-O 夹具。
 * @returns {Buffer}
 */
export function buildMacho() {
  const textCode = Buffer.from([0x55, 0x48, 0x89, 0xe5, 0xc3]);
  const goBuildinfo = Buffer.concat([Buffer.from([0xff], 'latin1'), Buffer.from(' Go buildinf:', 'latin1'), Buffer.alloc(24, 0x42)]);
  const depV0 = Buffer.from('rust dependency list placeholder', 'latin1');
  const dylinkerPath = Buffer.from('/usr/lib/dyld\0', 'latin1');
  const signature = Buffer.concat([Buffer.from('fake code signature payload', 'latin1'), Buffer.alloc(16, 0x33)]);

  const commandCount = 6;
  const headerSize = 32;
  const segmentTextCommandSize = 72 + 2 * 80;
  const segmentDataCommandSize = 72 + 1 * 80;
  const uuidCommandSize = 24;
  const dylinkerCommandSize = 12 + Math.ceil(dylinkerPath.length / 8) * 8;
  const dyldInfoCommandSize = 48;
  const codeSignatureCommandSize = 16;
  const sizeofcmds =
    segmentTextCommandSize +
    segmentDataCommandSize +
    uuidCommandSize +
    dylinkerCommandSize +
    dyldInfoCommandSize +
    codeSignatureCommandSize;

  const textFileOffset = headerSize + sizeofcmds;
  const goBuildinfoFileOffset = textFileOffset + textCode.length;
  const dataFileOffset = goBuildinfoFileOffset + goBuildinfo.length;
  const depV0FileOffset = dataFileOffset;
  const signatureOffset = depV0FileOffset + depV0.length;

  const textVmaddr = 0x100000000;
  const dataVmaddr = 0x100001000;

  const commands = Buffer.alloc(sizeofcmds);
  let position = 0;
  const writeSegment = (segname, vmaddr, vmsize, fileoff, filesize, sectionList) => {
    commands.writeUInt32LE(LC_SEGMENT_64, position);
    commands.writeUInt32LE(72 + sectionList.length * 80, position + 4);
    writeFixedString(commands, position + 8, 16, segname);
    commands.writeBigUInt64LE(BigInt(vmaddr), position + 24);
    commands.writeBigUInt64LE(BigInt(vmsize), position + 32);
    commands.writeBigUInt64LE(BigInt(fileoff), position + 40);
    commands.writeBigUInt64LE(BigInt(filesize), position + 48);
    commands.writeUInt32LE(5, position + 56);
    commands.writeUInt32LE(5, position + 60);
    commands.writeUInt32LE(sectionList.length, position + 64);
    commands.writeUInt32LE(0, position + 68);
    position += 72;
    for (const section of sectionList) {
      writeFixedString(commands, position, 16, section.sectname);
      writeFixedString(commands, position + 16, 16, section.segname);
      commands.writeBigUInt64LE(BigInt(section.addr), position + 32);
      commands.writeBigUInt64LE(BigInt(section.size), position + 40);
      commands.writeUInt32LE(section.offset, position + 48);
      commands.writeUInt32LE(section.align, position + 52);
      commands.writeUInt32LE(0, position + 56);
      commands.writeUInt32LE(0, position + 60);
      commands.writeUInt32LE(0, position + 64);
      commands.writeUInt32LE(0, position + 68);
      commands.writeUInt32LE(0, position + 72);
      commands.writeUInt32LE(0, position + 76);
      position += 80;
    }
  };

  writeSegment('__TEXT', textVmaddr, 0x1000, 0, signatureOffset, [
    { sectname: '__text', segname: '__TEXT', addr: textVmaddr + textFileOffset, size: textCode.length, offset: textFileOffset, align: 4 },
    { sectname: '__go_buildinfo', segname: '__TEXT', addr: textVmaddr + goBuildinfoFileOffset, size: goBuildinfo.length, offset: goBuildinfoFileOffset, align: 0 },
  ]);
  writeSegment('__DATA', dataVmaddr, 0x1000, dataFileOffset, depV0.length, [
    { sectname: ',dep-v0', segname: '__DATA', addr: dataVmaddr, size: depV0.length, offset: depV0FileOffset, align: 0 },
  ]);

  commands.writeUInt32LE(LC_UUID, position);
  commands.writeUInt32LE(uuidCommandSize, position + 4);
  for (let index = 0; index < 16; index += 1) {
    commands[position + 8 + index] = index;
  }
  position += uuidCommandSize;

  commands.writeUInt32LE(LC_LOAD_DYLINKER, position);
  commands.writeUInt32LE(dylinkerCommandSize, position + 4);
  commands.writeUInt32LE(12, position + 8);
  dylinkerPath.copy(commands, position + 12);
  position += dylinkerCommandSize;

  commands.writeUInt32LE(LC_DYLD_INFO_ONLY, position);
  commands.writeUInt32LE(dyldInfoCommandSize, position + 4);
  for (let field = 0; field < 10; field += 1) {
    commands.writeUInt32LE(0, position + 8 + field * 4);
  }
  position += dyldInfoCommandSize;

  commands.writeUInt32LE(LC_CODE_SIGNATURE, position);
  commands.writeUInt32LE(codeSignatureCommandSize, position + 4);
  commands.writeUInt32LE(signatureOffset, position + 8);
  commands.writeUInt32LE(signature.length, position + 12);
  position += codeSignatureCommandSize;

  const header = Buffer.alloc(headerSize);
  header.writeUInt32LE(MH_MAGIC_64, 0);
  header.writeInt32LE(0x01000007, 4);
  header.writeInt32LE(3, 8);
  header.writeUInt32LE(2, 12);
  header.writeUInt32LE(commandCount, 16);
  header.writeUInt32LE(sizeofcmds, 20);
  header.writeUInt32LE(0, 24);
  header.writeUInt32LE(0, 28);

  return Buffer.concat([header, commands, textCode, goBuildinfo, depV0, signature]);
}

// ---------------------------------------------------------------------------
// BEAM：FOR1 外层块 + BEAM 类型 + Atom 与 Code 两个块。
// ---------------------------------------------------------------------------

/**
 * 构造 BEAM 夹具。
 * @returns {Buffer}
 */
export function buildBeam() {
  const chunks = [
    { id: 'Atom', payload: Buffer.from('atom table placeholder', 'latin1') },
    { id: 'Code', payload: Buffer.from('code placeholder', 'latin1') },
  ];
  const body = Buffer.concat(
    chunks.map((chunk) => Buffer.concat([Buffer.from(chunk.id, 'latin1'), u32be(chunk.payload.length), chunk.payload])),
  );
  return Buffer.concat([Buffer.from('FOR1', 'latin1'), u32be(body.length + 4), Buffer.from('BEAM', 'latin1'), body]);
}

// ---------------------------------------------------------------------------
// PE：DOS 头 + PE 签名 + COFF 头 + 可选头 + 节表 + 导入表 + 调试目录 + 安全目录。
// ---------------------------------------------------------------------------

const PE_FILE_ALIGNMENT = 0x200;
const PE_SECTION_ALIGNMENT = 0x1000;
const PE_TEXT_RVA = 0x1000;
const PE_GOBUILDINFO_RVA = 0x2000;

/**
 * 构造 PE 夹具。
 * @param {{checksum?: number}} [options] checksum 缺省为 0，可传入非零值覆盖
 * @returns {Buffer}
 */
export function buildPe(options = {}) {
  const sectionCount = 2;
  const optionalHeaderSize = 240;
  const sizeOfHeaders = 0x200;

  // .text 载荷：代码、导入表、提示名表、调试目录与 CodeView 记录。
  const code = Buffer.from([0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]);
  const dllName = Buffer.from('kernel32.dll\0', 'latin1');
  const procedureName = Buffer.from('ExitProcess\0', 'latin1');
  const hintName = Buffer.concat([u16le(0), procedureName]);
  const thunk = Buffer.concat([u64le(0), u64le(0)]);
  const importDescriptor = Buffer.concat([
    u32le(0),
    u32le(0),
    u32le(0xffffffff),
    u32le(0),
    u32le(0),
    u32le(0),
    u32le(0),
    u32le(0),
    u32le(0),
    u32le(0),
  ]);
  const pdbPath = Buffer.from('C:\\build\\app.pdb\0', 'latin1');
  const codeView = Buffer.concat([Buffer.from('RSDS', 'latin1'), Buffer.alloc(16, 0x7a), u32le(1), pdbPath]);
  const debugDirectory = Buffer.concat([
    u32le(0),
    u32le(0),
    u16le(0),
    u16le(0),
    u32le(2),
    u32le(codeView.length),
    u32le(0),
    u32le(0),
  ]);

  // 先在 .text 内依次排布，占位 RVA 待排布完成后回填。
  const textParts = [];
  const textOffsets = {};
  let textCursor = 0;
  const append = (key, buffer) => {
    textOffsets[key] = textCursor;
    textParts.push(buffer);
    textCursor += buffer.length;
  };
  append('code', code);
  append('hintName', hintName);
  append('thunk', thunk);
  append('dllName', dllName);
  append('importDescriptor', importDescriptor);
  append('debugDirectory', debugDirectory);
  append('codeView', codeView);
  const textContent = Buffer.concat(textParts);
  const rvaInText = (offset) => PE_TEXT_RVA + offset;

  const goBuildinfo = Buffer.concat([Buffer.from([0xff], 'latin1'), Buffer.from(' Go buildinf:', 'latin1'), Buffer.alloc(24, 0x43)]);
  const goBuildinfoFileOffset = sizeOfHeaders;
  const certificate = Buffer.from('fake pkcs7 certificate blob', 'latin1');
  const certificateOffset = goBuildinfoFileOffset + goBuildinfo.length;
  const winCertificate = Buffer.concat([u32le(8 + certificate.length), u16le(0x200), u16le(2), certificate]);

  // 回填导入描述符与调试目录里的 RVA 与文件偏移。
  importDescriptor.writeUInt32LE(rvaInText(textOffsets.thunk), 0);
  importDescriptor.writeUInt32LE(rvaInText(textOffsets.dllName), 12);
  importDescriptor.writeUInt32LE(rvaInText(textOffsets.thunk), 16);
  debugDirectory.writeUInt32LE(rvaInText(textOffsets.codeView), 20);
  debugDirectory.writeUInt32LE(goBuildinfoFileOffset + textOffsets.codeView, 24);

  const sizeOfImage = PE_SECTION_ALIGNMENT * (sectionCount + 1);
  const checksum = options.checksum ?? 0;

  const optionalHeader = Buffer.alloc(optionalHeaderSize);
  optionalHeader.writeUInt16LE(0x20b, 0);
  optionalHeader.writeUInt8(14, 2);
  optionalHeader.writeUInt8(0, 3);
  optionalHeader.writeUInt32LE(textContent.length, 4);
  optionalHeader.writeUInt32LE(goBuildinfo.length, 8);
  optionalHeader.writeUInt32LE(0, 12);
  optionalHeader.writeUInt32LE(PE_TEXT_RVA, 16);
  optionalHeader.writeUInt32LE(PE_TEXT_RVA, 20);
  optionalHeader.writeBigUInt64LE(0x140000000n, 24);
  optionalHeader.writeUInt32LE(PE_SECTION_ALIGNMENT, 32);
  optionalHeader.writeUInt32LE(PE_FILE_ALIGNMENT, 36);
  optionalHeader.writeUInt16LE(6, 40);
  optionalHeader.writeUInt16LE(0, 42);
  optionalHeader.writeUInt16LE(0, 44);
  optionalHeader.writeUInt16LE(0, 46);
  optionalHeader.writeUInt16LE(6, 48);
  optionalHeader.writeUInt16LE(0, 50);
  optionalHeader.writeUInt32LE(0, 52);
  optionalHeader.writeUInt32LE(sizeOfImage, 56);
  optionalHeader.writeUInt32LE(sizeOfHeaders, 60);
  optionalHeader.writeUInt32LE(checksum, 64);
  optionalHeader.writeUInt16LE(3, 68);
  optionalHeader.writeUInt16LE(0, 70);
  optionalHeader.writeBigUInt64LE(0x100000n, 72);
  optionalHeader.writeBigUInt64LE(0x1000n, 80);
  optionalHeader.writeBigUInt64LE(0x100000n, 88);
  optionalHeader.writeBigUInt64LE(0x1000n, 96);
  optionalHeader.writeUInt32LE(0, 104);
  optionalHeader.writeUInt32LE(16, 108);
  optionalHeader.writeUInt32LE(rvaInText(textOffsets.importDescriptor), 112 + 8);
  optionalHeader.writeUInt32LE(importDescriptor.length, 112 + 12);
  optionalHeader.writeUInt32LE(rvaInText(textOffsets.debugDirectory), 112 + 6 * 8);
  optionalHeader.writeUInt32LE(debugDirectory.length, 112 + 6 * 8 + 4);
  optionalHeader.writeUInt32LE(certificateOffset, 112 + 4 * 8);
  optionalHeader.writeUInt32LE(winCertificate.length, 112 + 4 * 8 + 4);

  const dosHeader = Buffer.alloc(0x40);
  dosHeader.write('MZ', 0, 'latin1');
  dosHeader.writeUInt32LE(0x40, 0x3c);
  const peSignature = Buffer.from('PE\0\0', 'latin1');
  const coffHeader = Buffer.alloc(20);
  coffHeader.writeUInt16LE(0x8664, 0);
  coffHeader.writeUInt16LE(sectionCount, 2);
  coffHeader.writeUInt32LE(0, 4);
  coffHeader.writeUInt32LE(0, 8);
  coffHeader.writeUInt32LE(0, 12);
  coffHeader.writeUInt16LE(optionalHeaderSize, 16);
  coffHeader.writeUInt16LE(0x22, 18);

  const sectionHeader = (name, virtualSize, virtualAddress, rawSize, rawPointer, characteristics) => {    const header = Buffer.alloc(40);
    writeFixedString(header, 0, 8, name);
    header.writeUInt32LE(virtualSize, 8);
    header.writeUInt32LE(virtualAddress, 12);
    header.writeUInt32LE(rawSize, 16);
    header.writeUInt32LE(rawPointer, 20);
    header.writeUInt32LE(0, 24);
    header.writeUInt32LE(0, 28);
    header.writeUInt32LE(0, 32);
    header.writeUInt32LE(characteristics, 36);
    return header;
  };
  const textSection = sectionHeader('.text', textContent.length, PE_TEXT_RVA, textContent.length, sizeOfHeaders, 0x60000020);
  // PE 节名上限 8 字节，Go 构建信息所在节按特征位 0xc0000040 识别，节名用短名。
  const goSection = sectionHeader('.gobld', goBuildinfo.length, PE_GOBUILDINFO_RVA, goBuildinfo.length, goBuildinfoFileOffset, 0xc0000040);

  const headers = Buffer.concat([dosHeader, peSignature, coffHeader, optionalHeader, textSection, goSection]);
  return Buffer.concat([headers, padTo(headers.length, PE_FILE_ALIGNMENT), textContent, goBuildinfo, winCertificate]);
}

/**
 * 构造全部夹具。
 * @returns {Record<string, Buffer>}
 */
export function buildFixtures() {
  return {
    elf: buildElf(),
    'elf-broken-program-headers': buildElf({ breakProgramHeaders: true }),
    pe: buildPe(),
    'pe-checksum-nonzero': buildPe({ checksum: 0x0000abcd }),
    'mach-o': buildMacho(),
    zip: buildZip(),
    gguf: buildGguf(),
    safetensors: buildSafetensors(),
    'safetensors-no-metadata': buildSafetensors({ writeMetadata: false }),
    pyc: buildPyc(),
    'pyc-hash-cleared': buildPyc({ clearSourceHash: true }),
    beam: buildBeam(),
  };
}

/**
 * 计算夹具摘要，供测试记录与断言稳定性使用。
 * @param {Record<string, Buffer>} fixtures 夹具表
 * @returns {Record<string, string>}
 */
export function digestFixtures(fixtures) {
  return Object.fromEntries(
    Object.entries(fixtures).map(([name, buffer]) => [name, createHash('sha256').update(buffer).digest('hex')]),
  );
}

// 供开发期核对：node tests/required-sets/build-fixtures.mjs 打印摘要与自检结果。
if (process.argv[1] !== undefined && process.argv[1].endsWith('build-fixtures.mjs')) {
  const fixtures = buildFixtures();
  for (const [name, digest] of Object.entries(digestFixtures(fixtures))) {
    process.stdout.write(`${name} ${fixtures[name].length} ${digest}\n`);
  }
  // 自检：ZIP 的 deflate 条目必须能被内置 zlib 解压，且 CRC32 与数据一致。
  const zip = fixtures.zip;
  const eocd = zip.length - 22;
  const centralSize = zip.readUInt32LE(eocd + 12);
  const centralOffset = zip.readUInt32LE(eocd + 16);
  let entry = centralOffset;
  for (let index = 0; index < 2; index += 1) {
    const method = zip.readUInt16LE(entry + 10);
    const checksum = zip.readUInt32LE(entry + 16);
    const compressedSize = zip.readUInt32LE(entry + 20);
    const nameLength = zip.readUInt16LE(entry + 28);
    const localOffset = zip.readUInt32LE(entry + 42);
    const localNameLength = zip.readUInt16LE(localOffset + 26);
    const dataStart = localOffset + 30 + localNameLength;
    const stored = zip.subarray(dataStart, dataStart + compressedSize);
    const plain = method === 8 ? inflateRawSync(stored) : stored;
    process.stdout.write(`zip entry ${index} method=${method} crc-ok=${crc32(plain) === checksum}\n`);
    entry += 46 + nameLength;
  }
  process.stdout.write(`central directory bytes ${centralSize}\n`);
}
