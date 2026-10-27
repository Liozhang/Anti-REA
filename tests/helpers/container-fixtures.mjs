// container 模块测试夹具：字节级精确的最小真实格式文件。
// 全部由确定性代码生成，不含随机源与时间戳，保证每次运行得到同一串字节。
// 夹具先在测试里写进临时目录，再由测试把 sha256 与登记值比对，
// 确保测试跑的是固定真实字节，而不是随手写的占位数据。

import { crc32, deflateRawSync } from 'node:zlib';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

/** 伪随机字节的线性同余种子。固定值，保证可复现。 */
const LCG_SEED = 20261027;

/**
 * 生成确定性字节序列：前 8 字节固定为不匹配任何魔数的图案，其余由线性同余序列填充。
 * @param {number} length 字节数
 * @returns {Buffer}
 */
function deterministicBytes(length) {
  const out = Buffer.alloc(length);
  out.set([0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33], 0);
  let state = LCG_SEED;
  for (let index = 8; index < length; index += 1) {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    out[index] = state & 0xff;
  }
  return out;
}

/**
 * 在右侧补零到给定长度。
 * @param {Buffer} buffer 原字节
 * @param {number} length 目标长度
 * @returns {Buffer}
 */
function padTo(buffer, length) {
  if (buffer.length >= length) {
    return buffer;
  }
  return Buffer.concat([buffer, Buffer.alloc(length - buffer.length)]);
}

/**
 * 构造最小 ELF64 小端可执行文件：一个程序头、.text 与 .shstrtab 两个节。
 * @returns {Buffer}
 */
function buildElf() {
  const shstrtab = Buffer.from('\0.text\0.shstrtab\0', 'latin1');
  const text = Buffer.from([0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);
  const ehsize = 64;
  const phentsize = 56;
  const shentsize = 64;
  const textOffset = ehsize + phentsize;
  const shstrtabOffset = textOffset + text.length;
  const shoff = shstrtabOffset + shstrtab.length;
  const total = shoff + shentsize * 3;
  const buf = Buffer.alloc(total);

  buf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
  buf.writeUInt16LE(2, 16); // e_type ET_EXEC
  buf.writeUInt16LE(62, 18); // e_machine EM_X86_64
  buf.writeUInt32LE(1, 20); // e_version
  // e_entry 指向 .text 在段内的地址：PT_LOAD 从 0x400000 起覆盖整个文件，
  // 入口必须落在段内，否则复审的 elf.segment-load 会判不可解析。
  buf.writeBigUInt64LE(0x400000n + BigInt(textOffset), 24); // e_entry
  buf.writeBigUInt64LE(BigInt(ehsize), 32); // e_phoff
  buf.writeBigUInt64LE(BigInt(shoff), 40); // e_shoff
  buf.writeUInt16LE(ehsize, 52);
  buf.writeUInt16LE(phentsize, 54);
  buf.writeUInt16LE(1, 56); // e_phnum
  buf.writeUInt16LE(shentsize, 58);
  buf.writeUInt16LE(3, 60); // e_shnum
  buf.writeUInt16LE(2, 62); // e_shstrndx

  buf.writeUInt32LE(1, 64); // p_type PT_LOAD
  buf.writeUInt32LE(5, 68); // p_flags R+X
  buf.writeBigUInt64LE(0n, 72); // p_offset
  buf.writeBigUInt64LE(0x400000n, 80); // p_vaddr
  buf.writeBigUInt64LE(0x400000n, 88); // p_paddr
  buf.writeBigUInt64LE(BigInt(total), 96); // p_filesz
  buf.writeBigUInt64LE(BigInt(total), 104); // p_memsz
  buf.writeBigUInt64LE(0x1000n, 112); // p_align

  text.copy(buf, textOffset);
  shstrtab.copy(buf, shstrtabOffset);

  const writeSection = (index, name, type, flags, addr, offset, size, align) => {
    const base = shoff + index * shentsize;
    buf.writeUInt32LE(name, base);
    buf.writeUInt32LE(type, base + 4);
    buf.writeBigUInt64LE(flags, base + 8);
    buf.writeBigUInt64LE(addr, base + 16);
    buf.writeBigUInt64LE(BigInt(offset), base + 24);
    buf.writeBigUInt64LE(BigInt(size), base + 32);
    buf.writeBigUInt64LE(BigInt(align), base + 48);
  };
  writeSection(0, 0, 0, 0n, 0n, 0, 0, 0);
  writeSection(1, 1, 1, 0x6n, 0x401000n, textOffset, text.length, 16);
  writeSection(2, 7, 3, 0n, 0n, shstrtabOffset, shstrtab.length, 1);
  return buf;
}

/**
 * 构造最小 PE32+ 文件：DOS 头、COFF 头、240 字节可选头、一个 .text 节。
 * @param {number} [peOffset] PE 签名偏移，默认 0x40
 * @param {number} [totalBytes] 文件总字节数，不足时在右侧补零
 * @returns {Buffer}
 */
function buildPe(peOffset = 0x40, totalBytes = 0x400) {
  const sizeOfHeaders = 0x200;
  const sizeOfRawData = 0x200;
  const buf = Buffer.alloc(Math.max(totalBytes, sizeOfHeaders + sizeOfRawData));
  buf.write('MZ', 0, 'latin1');
  buf.writeUInt16LE(0x0090, 2);
  buf.writeUInt16LE(0x0003, 4);
  buf.writeUInt32LE(peOffset, 0x3c); // e_lfanew

  buf.write('PE\0\0', peOffset, 'latin1');
  const coff = peOffset + 4;
  buf.writeUInt16LE(0x8664, coff); // machine AMD64
  buf.writeUInt16LE(1, coff + 2); // numberOfSections
  buf.writeUInt16LE(240, coff + 16); // sizeOfOptionalHeader
  buf.writeUInt16LE(0x0022, coff + 18); // characteristics

  const opt = coff + 20;
  buf.writeUInt16LE(0x020b, opt); // magic PE32+
  buf.writeUInt16LE(14, opt + 2); // majorLinkerVersion
  buf.writeUInt32LE(sizeOfRawData, opt + 4); // sizeOfCode
  buf.writeUInt32LE(0x1000, opt + 16); // addressOfEntryPoint
  buf.writeUInt32LE(0x1000, opt + 20); // baseOfCode
  buf.writeBigUInt64LE(0x140000000n, opt + 24); // imageBase
  buf.writeUInt32LE(0x1000, opt + 32); // sectionAlignment
  buf.writeUInt32LE(0x200, opt + 36); // fileAlignment
  buf.writeUInt32LE(0x3000, opt + 56); // sizeOfImage
  buf.writeUInt32LE(sizeOfHeaders, opt + 60); // sizeOfHeaders
  buf.writeUInt16LE(3, opt + 68); // subsystem CUI
  buf.writeUInt32LE(16, opt + 108); // numberOfRvaAndSizes

  const sectionTable = opt + 240;
  buf.write('.text\0\0\0', sectionTable, 'latin1');
  buf.writeUInt32LE(0x10, sectionTable + 8); // virtualSize
  buf.writeUInt32LE(0x1000, sectionTable + 12); // virtualAddress
  buf.writeUInt32LE(sizeOfRawData, sectionTable + 16); // sizeOfRawData
  buf.writeUInt32LE(sizeOfHeaders, sectionTable + 20); // pointerToRawData
  buf.writeUInt32LE(0x60000020, sectionTable + 36); // characteristics

  buf.writeUInt8(0xc3, sizeOfHeaders); // ret
  return buf;
}

/**
 * 构造最小 Mach-O 64 位可执行文件：一个 LC_SEGMENT_64。
 * @param {boolean} [bigEndian] 是否按大端编码
 * @returns {Buffer}
 */
function buildMachO(bigEndian = false) {
  const buf = Buffer.alloc(32 + 72);
  const u32 = (value, offset) => (bigEndian ? buf.writeUInt32BE(value, offset) : buf.writeUInt32LE(value, offset));
  const i32 = (value, offset) => (bigEndian ? buf.writeInt32BE(value, offset) : buf.writeInt32LE(value, offset));
  const u64 = (value, offset) => (bigEndian ? buf.writeBigUInt64BE(value, offset) : buf.writeBigUInt64LE(value, offset));

  u32(0xfeedfacf, 0); // MH_MAGIC_64
  i32(0x01000007, 4); // CPU_TYPE_X86_64
  i32(3, 8); // CPU_SUBTYPE_X86_64_ALL
  u32(2, 12); // MH_EXECUTE
  u32(1, 16); // ncmds
  u32(72, 20); // sizeofcmds
  u32(0, 24); // flags
  u32(0, 28); // reserved

  u32(0x19, 32); // LC_SEGMENT_64
  u32(72, 36); // cmdsize
  buf.write('__TEXT', 40, 'latin1');
  u64(0x100000000n, 56); // vmaddr
  u64(0x1000n, 64); // vmsize
  u64(0n, 72); // fileoff
  u64(0x1000n, 80); // filesize
  i32(5, 88); // maxprot
  i32(5, 92); // initprot
  u32(0, 96); // nsects
  u32(0, 100); // flags
  return buf;
}

/**
 * 构造最小 Mach-O 胖二进制：一片 x86_64 切片放在偏移 4096 处。
 * @returns {Buffer}
 */
function buildMachOFat() {
  const slice = buildMachO();
  const header = Buffer.alloc(28);
  header.writeUInt32BE(0xcafebabe, 0); // FAT_MAGIC
  header.writeUInt32BE(1, 4); // nfat_arch
  header.writeInt32BE(0x01000007, 8); // cputype
  header.writeInt32BE(3, 12); // cpusubtype
  header.writeUInt32BE(4096, 16); // offset
  header.writeUInt32BE(slice.length, 20); // size
  header.writeUInt32BE(12, 24); // align
  const buf = Buffer.alloc(4096 + slice.length);
  header.copy(buf, 0);
  slice.copy(buf, 4096);
  return buf;
}

/**
 * 构造最小 GGUF v3 文件：一条字符串元数据，零张量。
 * @returns {Buffer}
 */
function buildGguf() {
  const key = Buffer.from('general.architecture', 'latin1');
  const value = Buffer.from('demo', 'latin1');
  const header = Buffer.alloc(24);
  header.write('GGUF', 0, 'latin1');
  header.writeUInt32LE(3, 4); // version
  header.writeBigUInt64LE(0n, 8); // tensor_count
  header.writeBigUInt64LE(1n, 16); // metadata_kv_count
  const keyLength = Buffer.alloc(8);
  keyLength.writeBigUInt64LE(BigInt(key.length), 0);
  const valueType = Buffer.alloc(4);
  valueType.writeUInt32LE(8, 0); // string
  const valueLength = Buffer.alloc(8);
  valueLength.writeBigUInt64LE(BigInt(value.length), 0);
  return Buffer.concat([header, keyLength, key, valueType, valueLength, value]);
}

/**
 * 按 8 字节长度前缀加 JSON 头的结构封装 safetensors。
 * @param {Record<string, unknown>} headerObject 头部 JSON 对象
 * @param {Buffer} data 张量数据区
 * @returns {Buffer}
 */
function buildSafetensors(headerObject, data) {
  const header = Buffer.from(JSON.stringify(headerObject), 'utf8');
  const prefix = Buffer.alloc(8);
  prefix.writeBigUInt64LE(BigInt(header.length), 0);
  return Buffer.concat([prefix, header, data]);
}

/**
 * 构造头部超过 4096 字节识别窗口的 safetensors，用于验证结构魔数补读。
 * @returns {Buffer}
 */
function buildSafetensorsLargeHeader() {
  const header = { __metadata__: { note: 'large header fixture' } };
  for (let index = 0; index < 200; index += 1) {
    header[`model.layers.${index}.self_attn.q_proj.weight`] = {
      dtype: 'F32',
      shape: [4],
      data_offsets: [index * 16, index * 16 + 16],
    };
  }
  return buildSafetensors(header, Buffer.alloc(200 * 16));
}

/**
 * 构造 16 字节头的 pyc：魔数两字节、0D 0A、标志四字节，之后是源码哈希或时间戳与大小。
 * @param {{magic: number, flags: number, hashBased: boolean, bytecode?: Buffer}} options
 * @returns {Buffer}
 */
function buildPyc({ magic, flags, hashBased, bytecode = Buffer.alloc(24, 0x42) }) {
  const buf = Buffer.alloc(16 + bytecode.length);
  buf.writeUInt16LE(magic, 0);
  buf.writeUInt8(0x0d, 2);
  buf.writeUInt8(0x0a, 3);
  buf.writeUInt32LE(flags, 4);
  if (hashBased) {
    buf.writeBigUInt64LE(0x0123456789abcdefn, 8); // source hash
  } else {
    buf.writeUInt32LE(0x65f00000, 8); // mtime
    buf.writeUInt32LE(1024, 12); // source size
  }
  bytecode.copy(buf, 16);
  return buf;
}

/**
 * 构造最小 BEAM 文件：FOR1 外框套 BEAM，内含 AtU8、Code、StrT 三个块。
 * @returns {Buffer}
 */
function buildBeam() {
  const chunk = (name, body) => {
    const head = Buffer.alloc(8);
    head.write(name, 0, 'latin1');
    head.writeUInt32BE(body.length, 4);
    return Buffer.concat([head, body]);
  };
  const body = Buffer.concat([
    chunk('AtU8', Buffer.from([0x00, 0x00, 0x00, 0x53])),
    chunk('Code', Buffer.alloc(16, 0x11)),
    chunk('StrT', Buffer.from('demo\0', 'latin1')),
  ]);
  const beam = Buffer.alloc(8);
  beam.write('BEAM', 0, 'latin1');
  beam.writeUInt32BE(body.length, 4);
  const form = Buffer.alloc(8);
  form.write('FOR1', 0, 'latin1');
  form.writeUInt32BE(beam.length + body.length, 4);
  return Buffer.concat([form, beam, body]);
}

/**
 * 构造含存储条目与 deflate 条目的 ZIP：本地头、中央目录、结尾记录齐全。
 * @returns {Buffer}
 */
function buildZip() {
  const entries = [
    { name: 'stored.txt', method: 0, data: Buffer.from('hello zip stored entry\n', 'latin1') },
    { name: 'deflated.txt', method: 8, data: Buffer.from('hello zip deflated entry\n'.repeat(8), 'latin1') },
  ];
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name, 'latin1');
    const stored = entry.method === 8 ? deflateRawSync(entry.data) : entry.data;
    const checksum = crc32(entry.data);

    const local = Buffer.alloc(30 + name.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(entry.method, 8);
    local.writeUInt16LE(0x1234, 10);
    local.writeUInt16LE(0x5678, 12);
    local.writeUInt32LE(checksum, 14);
    local.writeUInt32LE(stored.length, 18);
    local.writeUInt32LE(entry.data.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    name.copy(local, 30);
    locals.push(local, stored);

    const central = Buffer.alloc(46 + name.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(0x031e, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(entry.method, 10);
    central.writeUInt16LE(0x1234, 12);
    central.writeUInt16LE(0x5678, 14);
    central.writeUInt32LE(checksum, 16);
    central.writeUInt32LE(stored.length, 20);
    central.writeUInt32LE(entry.data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset, 42);
    name.copy(central, 46);
    centrals.push(central);

    offset += local.length + stored.length;
  }
  const centralDirectory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralDirectory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, centralDirectory, end]);
}

/**
 * 构造只有结尾记录的空 ZIP。
 * @returns {Buffer}
 */
function buildEmptyZip() {
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  return end;
}

/**
 * 构造 MZ 头但 PE 签名处不是 PE\0\0 的文件。
 * @returns {Buffer}
 */
function buildMzWithoutSignature() {
  const buf = buildPe();
  buf.write('XXXX', 0x40, 'latin1');
  return buf;
}

/** 夹具登记表：相对路径、字节、期望判定结果。 */
export const CONTAINER_FIXTURES = Object.freeze([
  { relativePath: 'elf/basic.elf', bytes: buildElf(), expected: { type: 'elf' } },
  { relativePath: 'elf/header-only.elf', bytes: buildElf().subarray(0, 8), expected: { type: 'elf' } },
  { relativePath: 'pe/basic.pe', bytes: buildPe(), expected: { type: 'pe' } },
  { relativePath: 'pe/far-signature.pe', bytes: buildPe(5000, 8192), expected: { type: 'pe' } },
  { relativePath: 'mach-o/basic.macho', bytes: buildMachO(), expected: { type: 'mach-o' } },
  { relativePath: 'mach-o/big-endian.macho', bytes: buildMachO(true), expected: { type: 'mach-o' } },
  { relativePath: 'mach-o/fat.macho', bytes: buildMachOFat(), expected: { type: 'mach-o-fat' } },
  { relativePath: 'zip/mixed-entries.zip', bytes: buildZip(), expected: { type: 'zip' } },
  { relativePath: 'zip/empty.zip', bytes: buildEmptyZip(), expected: { type: 'zip' } },
  { relativePath: 'gguf/basic.gguf', bytes: buildGguf(), expected: { type: 'gguf' } },
  {
    relativePath: 'safetensors/basic.safetensors',
    bytes: buildSafetensors(
      { __metadata__: { format: 'pt' }, t1: { dtype: 'F32', shape: [2], data_offsets: [0, 8] } },
      Buffer.alloc(8, 0x5a),
    ),
    expected: { type: 'safetensors' },
  },
  { relativePath: 'safetensors/large-header.safetensors', bytes: buildSafetensorsLargeHeader(), expected: { type: 'safetensors' } },
  {
    relativePath: 'pyc/hash-based.pyc',
    bytes: buildPyc({ magic: 0x0da7, flags: 0x03, hashBased: true }),
    expected: { type: 'pyc' },
  },
  {
    relativePath: 'pyc/timestamp-based.pyc',
    bytes: buildPyc({ magic: 0x0d61, flags: 0x00, hashBased: false }),
    expected: { type: 'pyc' },
  },
  { relativePath: 'beam/basic.beam', bytes: buildBeam(), expected: { type: 'beam' } },
  { relativePath: 'malformed/empty.bin', bytes: Buffer.alloc(0), expected: { type: 'unknown' } },
  { relativePath: 'malformed/tiny.bin', bytes: Buffer.from([0x01, 0x02, 0x03]), expected: { type: 'unknown' } },
  { relativePath: 'malformed/random.bin', bytes: deterministicBytes(96), expected: { type: 'unsupported' } },
  {
    relativePath: 'malformed/text-crlf.txt',
    bytes: Buffer.from('ab\r\nhello world\r\n', 'latin1'),
    expected: { type: 'unsupported' },
  },
  { relativePath: 'malformed/mz-no-signature.bin', bytes: buildMzWithoutSignature(), expected: { type: 'unsupported' } },
  {
    relativePath: 'malformed/mz-truncated.bin',
    bytes: Buffer.concat([Buffer.from('MZ', 'latin1'), deterministicBytes(28)]),
    expected: { type: 'unknown' },
  },
  {
    relativePath: 'malformed/form-aiff.bin',
    bytes: Buffer.from('FORM' + String.fromCharCode(0, 0, 0, 20) + 'AIFF' + String.fromCharCode(0, 0, 0, 20) + 'xxxxxxxx', 'latin1'),
    expected: { type: 'unsupported' },
  },
  {
    relativePath: 'malformed/safetensors-bad-json.bin',
    bytes: (() => {
      const buf = Buffer.alloc(8 + 12);
      buf.writeBigUInt64LE(12n, 0);
      buf.write('not json!!!', 8, 'latin1');
      return buf;
    })(),
    expected: { type: 'unsupported' },
  },
  {
    relativePath: 'malformed/safetensors-short.bin',
    bytes: (() => {
      const header = Buffer.from(JSON.stringify({ __metadata__: { format: 'pt' } }), 'utf8');
      const buf = Buffer.alloc(8 + header.length);
      buf.writeBigUInt64LE(BigInt(header.length + 4096), 0); // 声明长度超过文件实际大小
      header.copy(buf, 8);
      return buf;
    })(),
    expected: { type: 'unknown' },
  },
  {
    relativePath: 'unsupported/il2cpp-metadata.bin',
    bytes: (() => {
      const buf = Buffer.alloc(64, 0);
      buf.writeUInt32LE(0xfab11baf, 0); // IL2CPP 全局元数据魔数
      buf.writeUInt32LE(31, 4); // version
      return buf;
    })(),
    expected: { type: 'unsupported' },
  },
  {
    relativePath: 'unsupported/apk-signature-scheme.bin',
    bytes: Buffer.concat([Buffer.from('APK Sig Block 42', 'latin1'), deterministicBytes(48)]),
    expected: { type: 'unsupported' },
  },
  {
    relativePath: 'unsupported/java-class.class',
    bytes: Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34, 0x00, 0x07, 0x21, 0x00]),
    expected: { type: 'unsupported' },
  },
]);

/**
 * 把全部夹具写到目标目录，保持相对路径结构。
 * @param {string} root 目标目录
 * @returns {Promise<Array<{relativePath: string, absolutePath: string, bytes: Buffer}>>}
 */
export async function writeContainerFixtures(root) {
  const written = [];
  for (const fixture of CONTAINER_FIXTURES) {
    const absolutePath = join(root, ...fixture.relativePath.split('/'));
    await mkdir(join(absolutePath, '..'), { recursive: true });
    await writeFile(absolutePath, fixture.bytes);
    written.push({ relativePath: fixture.relativePath, absolutePath, bytes: fixture.bytes });
  }
  return written;
}
