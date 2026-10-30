#!/usr/bin/env node
// 字节级夹具构建脚本。
// 作用有两个：
//   1. 生成 tests/fixtures/ 下的字节级夹具：v1 九类格式各至少一个，另加覆盖特定路径的附加夹具，
//      以及两类范围外格式夹具（IL2CPP 全局元数据、APK 签名方案）
//   2. 校验已提交夹具的 sha256 与 manifest.json 记录一致，保证测试跑的是固定真实字节
//
// 全部构造器都是确定性的：不含随机源、不含时间戳、不含环境相关取值，
// 因此同一份代码在任何时候运行都得到同一串字节，摘要可以登记进清单。
//
// 用法：
//   node tests/fixtures/build.mjs --check    只校验，不写任何文件
//   node tests/fixtures/build.mjs --force    重新生成全部字节级夹具并重写清单（开发期使用）
//   node tests/fixtures/build.mjs            校验后生成缺失的字节级夹具并登记摘要
//
// 导出的 BYTE_FIXTURES 与 buildFixtureBytes 供测试直接引用，
// 在不写盘的前提下核对构造器输出与已提交字节是否逐字节一致。

import { createHash } from 'node:crypto';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { crc32, deflateRawSync } from 'node:zlib';

// PE CheckSum 重算算法与工具共用同一份实现，保证夹具里的校验和与复审时的重算结果一致。
import { computePeChecksum } from '../../src/signatures/pe-checksum.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = HERE;

/** 清单模式标识。 */
const MANIFEST_SCHEMA = 'anti-rea.fixture-manifest/1';

/** 清单说明文字。 */
const MANIFEST_NOTE =
  '已提交夹具的 sha256 记录。字节级夹具由 tests/fixtures/build.mjs 的确定性构造器生成，' +
  '清单登记其摘要；稳定性用例断言每个夹具的摘要与本记录一致，保证测试跑的是固定真实字节。';

/** 手工维护的文本夹具（sample-app），只校验不生成。 */
const SAMPLE_APP_FILES = Object.freeze([
  'sample-app/README.md',
  'sample-app/LICENSE',
  'sample-app/package.json',
  'sample-app/config/settings.json',
  'sample-app/config/overrides.json',
  'sample-app/src/main.js',
  'sample-app/src/version.js',
]);

// ---------------------------------------------------------------------------
// 确定性小工具
// ---------------------------------------------------------------------------

/**
 * 生成确定性字节序列：线性同余序列填充，不含随机源。
 * @param {number} length 字节数
 * @param {number} seed 种子
 * @returns {Buffer}
 */
function patternBytes(length, seed) {
  const out = Buffer.alloc(length);
  let state = seed | 0;
  for (let index = 0; index < length; index += 1) {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    out[index] = state & 0xff;
  }
  return out;
}

/**
 * LEB128 无前缀正数编码（Go 构建信息指针使用）。
 * @param {number} value 非负整数
 * @returns {Buffer}
 */
function uvarint(value) {
  const out = [];
  let rest = value;
  do {
    let byte = rest & 0x7f;
    rest >>>= 7;
    if (rest > 0) {
      byte |= 0x80;
    }
    out.push(byte);
  } while (rest > 0);
  return Buffer.from(out);
}

/**
 * 固定字节数的 LEB128 编码，解码值为 value。
 * 两遍构造时用同一宽度写占位值与真实值，保证节内布局不随指针大小变化。
 * @param {number} value 非负整数，必须小于 2 的 (7 * byteLength) 次方
 * @param {number} byteLength 字节数
 * @returns {Buffer}
 */
function uvarintFixed(value, byteLength) {
  const out = Buffer.alloc(byteLength);
  let rest = value;
  for (let index = 0; index < byteLength; index += 1) {
    let byte = rest & 0x7f;
    rest >>>= 7;
    if (index < byteLength - 1) {
      byte |= 0x80;
    }
    out[index] = byte;
  }
  return out;
}

/** Go 构建信息魔数：0xFF 后接 " Go buildinf:"。 */
const GO_BUILDINFO_MAGIC = Buffer.from([0xff, 0x20, 0x47, 0x6f, 0x20, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e, 0x66, 0x3a]);

/** ELF64 小头字段尺寸。 */
const ELF_EHSIZE = 64;
const ELF_PHENTSIZE = 56;
const ELF_SHENTSIZE = 64;

/**
 * 构造 64 位小端 ELF 文件。
 * 布局：ELF 头、节数据（按各自对齐值顺序排布）、节头字符串表、节头表、程序头表。
 * e_phoff 与 e_shoff 都显式书写，读取器按偏移取，不假设程序头表紧挨文件头。
 * @param {Array<{name: string, type: number, flags: number, addr: number, align?: number, entsize?: number, linkName?: string, info?: number, content: Buffer}>} sections 用户节
 * @param {(layout: {sectionOffsets: number[], sectionSizes: number[], shoff: number, shnum: number, phoff: number}) => Array<{type: number, flags: number, vaddr: number, offset: number, filesz: number | 'to-end'}>} makeSegments 程序头
 * @returns {Buffer}
 */
function buildElf64(sections, makeSegments) {
  const names = ['', ...sections.map((section) => section.name), '.shstrtab'];
  let shstrtab = Buffer.alloc(0);
  const nameOffsets = names.map((name) => {
    const offset = shstrtab.length;
    shstrtab = Buffer.concat([shstrtab, Buffer.from(`${name}\0`, 'latin1')]);
    return offset;
  });

  let cursor = ELF_EHSIZE;
  const placed = sections.map((section, index) => {
    const align = Math.max(1, section.align ?? 1);
    const start = Math.ceil(cursor / align) * align;
    cursor = start + section.content.length;
    return { ...section, offset: start, nameOffset: nameOffsets[index + 1] };
  });
  const shstrtabOffset = cursor;
  cursor += shstrtab.length;
  const shoff = Math.ceil(cursor / 8) * 8;
  const shnum = sections.length + 2;
  const shstrndx = shnum - 1;
  const phoff = shoff + shnum * ELF_SHENTSIZE;

  const layout = {
    sectionOffsets: placed.map((section) => section.offset),
    sectionSizes: placed.map((section) => section.content.length),
    shoff,
    shnum,
    phoff,
  };
  const segments = makeSegments(layout);
  const phnum = segments.length;
  const fileSize = phoff + phnum * ELF_PHENTSIZE;
  const file = Buffer.alloc(fileSize, 0);

  const ehdr = file.subarray(0, ELF_EHSIZE);
  ehdr.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
  ehdr.writeUInt16LE(2, 16); // e_type ET_EXEC
  ehdr.writeUInt16LE(62, 18); // e_machine EM_X86_64
  ehdr.writeUInt32LE(1, 20); // e_version
  // e_entry 指向第一个节（.text）的文件偏移映射到段内的地址：PT_LOAD 从 0x400000 起、
  // 覆盖整个文件，入口必须落在段内，否则复审的 elf.segment-load 会判不可解析。
  ehdr.writeBigUInt64LE(0x400000n + BigInt(layout.sectionOffsets[0]), 24); // e_entry
  ehdr.writeBigUInt64LE(BigInt(phoff), 32); // e_phoff
  ehdr.writeBigUInt64LE(BigInt(shoff), 40); // e_shoff
  ehdr.writeUInt32LE(0, 48); // e_flags
  ehdr.writeUInt16LE(ELF_EHSIZE, 52);
  ehdr.writeUInt16LE(ELF_PHENTSIZE, 54);
  ehdr.writeUInt16LE(phnum, 56);
  ehdr.writeUInt16LE(ELF_SHENTSIZE, 58);
  ehdr.writeUInt16LE(shnum, 60);
  ehdr.writeUInt16LE(shstrndx, 62);

  for (const section of placed) {
    section.content.copy(file, section.offset);
  }
  shstrtab.copy(file, shstrtabOffset);

  const indexByName = new Map(placed.map((section, index) => [section.name, index + 1]));
  const writeSectionHeader = (index, header) => {
    const base = shoff + index * ELF_SHENTSIZE;
    file.writeUInt32LE(header.name ?? 0, base);
    file.writeUInt32LE(header.type ?? 0, base + 4);
    file.writeBigUInt64LE(BigInt(header.flags ?? 0), base + 8);
    file.writeBigUInt64LE(BigInt(header.addr ?? 0), base + 16);
    file.writeBigUInt64LE(BigInt(header.offset ?? 0), base + 24);
    file.writeBigUInt64LE(BigInt(header.size ?? 0), base + 32);
    file.writeUInt32LE(header.link ?? 0, base + 40);
    file.writeUInt32LE(header.info ?? 0, base + 44);
    file.writeBigUInt64LE(BigInt(header.align ?? 1), base + 48);
    file.writeBigUInt64LE(BigInt(header.entsize ?? 0), base + 56);
  };
  writeSectionHeader(0, {});
  placed.forEach((section, index) => {
    writeSectionHeader(index + 1, {
      name: section.nameOffset,
      type: section.type,
      flags: section.flags,
      addr: section.addr,
      offset: section.offset,
      size: section.content.length,
      link: section.linkName === undefined ? 0 : indexByName.get(section.linkName),
      info: section.info ?? 0,
      align: section.align ?? 1,
      entsize: section.entsize ?? 0,
    });
  });
  writeSectionHeader(shstrndx, { name: nameOffsets[nameOffsets.length - 1], type: 3, offset: shstrtabOffset, size: shstrtab.length, align: 1 });

  segments.forEach((segment, index) => {
    const base = phoff + index * ELF_PHENTSIZE;
    const filesz = segment.filesz === 'to-end' ? fileSize - segment.offset : segment.filesz;
    file.writeUInt32LE(segment.type, base);
    file.writeUInt32LE(segment.flags, base + 4);
    file.writeBigUInt64LE(BigInt(segment.offset), base + 8);
    file.writeBigUInt64LE(BigInt(segment.vaddr), base + 16);
    file.writeBigUInt64LE(BigInt(segment.vaddr), base + 24);
    file.writeBigUInt64LE(BigInt(filesz), base + 32);
    file.writeBigUInt64LE(BigInt(filesz), base + 40);
    file.writeBigUInt64LE(0x1000n, base + 48);
  });

  return file;
}

/**
 * 构造静态符号表与字符串表：三个符号，符号名取自字符串表。
 * @returns {{symtab: Buffer, strtab: Buffer}}
 */
function buildSymbolTable() {
  const names = ['main', 'helper_function', 'leaked_internal_name'];
  let strtab = Buffer.alloc(1);
  const offsets = names.map((name) => {
    const offset = strtab.length;
    strtab = Buffer.concat([strtab, Buffer.from(`${name}\0`, 'latin1')]);
    return offset;
  });
  const symtab = Buffer.alloc(names.length * 24);
  names.forEach((name, index) => {
    symtab.writeUInt32LE(offsets[index], index * 24);
    symtab.writeUInt8(0x12, index * 24 + 4);
    symtab.writeUInt8(0, index * 24 + 5);
    symtab.writeUInt16LE(1, index * 24 + 6);
    symtab.writeBigUInt64LE(0x401000n + BigInt(index) * 16n, index * 24 + 8);
    symtab.writeBigUInt64LE(16n, index * 24 + 16);
  });
  return { symtab, strtab };
}

/**
 * 构造 Go 构建信息 inline 编码载荷：魔数后跟版本串与模块信息的变长长度加内容。
 * @param {string} version 版本串
 * @param {string} modinfo 模块信息
 * @returns {Buffer}
 */
function goBuildinfoInline(version, modinfo) {
  const versionBuffer = Buffer.from(version, 'latin1');
  const modinfoBuffer = Buffer.from(modinfo, 'latin1');
  return Buffer.concat([
    GO_BUILDINFO_MAGIC,
    uvarint(versionBuffer.length),
    versionBuffer,
    uvarint(modinfoBuffer.length),
    modinfoBuffer,
  ]);
}

/**
 * 构造 Go 构建信息 pointer 编码载荷：魔数后跟两个指向目标区的变长指针，
 * 目标区各自是变长长度加字符串。指针宽度固定两字节，两遍构造布局不变。
 * @param {number} headerLength 指针区长度（含魔数）
 * @returns {Buffer}
 */
function goBuildinfoPointerHeader(headerLength) {
  const version = 'go1.22.5';
  const modinfo = 'path\tpointer.app\nmod\tpointer.app\tv0.1.0\n';
  const contentFor = (versionPointer, modinfoPointer) =>
    Buffer.concat([
      GO_BUILDINFO_MAGIC,
      versionPointer,
      modinfoPointer,
      Buffer.alloc(headerLength - 18, 0),
      uvarint(version.length),
      Buffer.from(version, 'latin1'),
      uvarint(modinfo.length),
      Buffer.from(modinfo, 'latin1'),
    ]);
  return { contentFor, version, modinfo, headerLength };
}

// ---------------------------------------------------------------------------
// 夹具构造器：ELF
// ---------------------------------------------------------------------------

/** elf/basic.elf：ELF 节表与符号表解析。 */
function buildElfBasic() {
  const { symtab, strtab } = buildSymbolTable();
  return buildElf64(
    [
      { name: '.text', type: 1, flags: 0x6, addr: 0x401000, align: 16, content: Buffer.from([0x55, 0x48, 0x89, 0xe5, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x5d, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90]) },
      { name: '.symtab', type: 2, flags: 0, addr: 0, align: 8, entsize: 24, linkName: '.strtab', info: 1, content: symtab },
      { name: '.strtab', type: 3, flags: 0, addr: 0, align: 1, content: strtab },
    ],
    () => [{ type: 1, flags: 5, vaddr: 0x400000, offset: 0, filesz: 'to-end' }],
  );
}

/** elf/go-buildinfo-inline.elf：Go 构建信息 inline 编码。 */
function buildElfGoInline() {
  return buildElf64(
    [
      { name: '.text', type: 1, flags: 0x6, addr: 0x401000, align: 16, content: Buffer.from('go binary text', 'latin1') },
      {
        name: '.go.buildinfo',
        type: 1,
        flags: 0x6,
        addr: 0x4c2000,
        align: 16,
        content: goBuildinfoInline('go1.22.0', 'path\tdemo.app\nmod\tdemo.app\t(devel)\n'),
      },
    ],
    () => [{ type: 1, flags: 5, vaddr: 0x400000, offset: 0, filesz: 'to-end' }],
  );
}

/** elf/go-buildinfo-pointer.elf：Go 构建信息 pointer 编码，魔数落在可写且非执行的 load region 内。 */
function buildElfGoPointer() {
  const headerLength = 32;
  const { contentFor } = goBuildinfoPointerHeader(headerLength);
  const sectionsFor = (content) => [
    { name: '.text', type: 1, flags: 0x6, addr: 0x401000, align: 16, content: Buffer.from('go binary text', 'latin1') },
    { name: '.go.buildinfo', type: 1, flags: 0x6, addr: 0x4c2000, align: 16, content },
  ];
  // 第一遍用占位指针构造，取 .go.buildinfo 节的文件偏移后回填真实指针。
  const probe = buildElf64(sectionsFor(contentFor(uvarintFixed(0, 2), uvarintFixed(0, 2))), () => []);
  const goOffset = probe.indexOf(GO_BUILDINFO_MAGIC);
  const versionLength = uvarint('go1.22.5'.length).length;
  const versionTarget = goOffset + headerLength;
  const modinfoTarget = versionTarget + versionLength + 'go1.22.5'.length;
  for (const pointer of [versionTarget, modinfoTarget]) {
    if (pointer >= 2 ** 14) {
      throw new Error(`pointer 编码指针 ${pointer} 超出两字节 uvarint 的表示范围`);
    }
  }
  return buildElf64(
    sectionsFor(contentFor(uvarintFixed(versionTarget, 2), uvarintFixed(modinfoTarget, 2))),
    ({ sectionOffsets, sectionSizes }) => [
      { type: 1, flags: 5, vaddr: 0x400000, offset: 0, filesz: sectionOffsets[1] },
      { type: 1, flags: 6, vaddr: 0x4c1000, offset: sectionOffsets[1], filesz: sectionSizes[1] },
    ],
  );
}

/** elf/rust-dep-v0.elf：.dep-v0 依赖节命中与等长覆写。 */
function buildElfRustDep() {
  const dependencies = ['serde 1.0.193', 'libc 0.2.146', 'tokio 1.32.0'];
  const payload = deflateRawSync(Buffer.from(`${dependencies.join('\n')}\n`, 'latin1'));
  return buildElf64(
    [
      { name: '.text', type: 1, flags: 0x6, addr: 0x401000, align: 16, content: Buffer.from('rust binary text', 'latin1') },
      { name: '.dep-v0', type: 1, flags: 0, addr: 0, align: 1, content: payload },
    ],
    () => [{ type: 1, flags: 5, vaddr: 0x400000, offset: 0, filesz: 'to-end' }],
  );
}

// ---------------------------------------------------------------------------
// 夹具构造器：PE
// ---------------------------------------------------------------------------

/**
 * 构造最小 PE32+ 文件：DOS 头、COFF 头、240 字节可选头、十六个数据目录、一个 .text 节。
 * @param {{withSecurity?: boolean, withChecksum?: boolean}} options withSecurity 带安全目录（占位签名表），withChecksum 可选头 CheckSum 非零
 * @returns {Buffer}
 */
function buildPe({ withSecurity = false, withChecksum = false } = {}) {
  const fileSize = withSecurity ? 0x440 : 0x400;
  const file = Buffer.alloc(fileSize, 0);

  file.write('MZ', 0, 'latin1');
  file.writeUInt16LE(0x0090, 2);
  file.writeUInt16LE(0x0003, 4);
  file.writeUInt32LE(0x40, 0x3c); // e_lfanew

  file.write('PE\0\0', 0x40, 'latin1');
  file.writeUInt16LE(0x8664, 0x44); // machine AMD64
  file.writeUInt16LE(1, 0x46); // numberOfSections
  file.writeUInt32LE(0x64000000, 0x48); // timeDateStamp 固定值
  file.writeUInt32LE(0, 0x4c); // pointerToSymbolTable
  file.writeUInt32LE(0, 0x50); // numberOfSymbols
  file.writeUInt16LE(240, 0x54); // sizeOfOptionalHeader
  file.writeUInt16LE(0x0022, 0x56); // characteristics

  const optional = 0x58;
  file.writeUInt16LE(0x020b, optional); // magic PE32+
  file.writeUInt32LE(0x200, optional + 4); // sizeOfCode
  file.writeUInt32LE(0x1000, optional + 16); // addressOfEntryPoint
  file.writeUInt32LE(0x1000, optional + 20); // baseOfCode
  file.writeBigUInt64LE(0x140000000n, optional + 24); // imageBase
  file.writeUInt32LE(0x1000, optional + 32); // sectionAlignment
  file.writeUInt32LE(0x200, optional + 36); // fileAlignment
  file.writeUInt32LE(0x3000, optional + 56); // sizeOfImage
  file.writeUInt32LE(0x200, optional + 60); // sizeOfHeaders
  // optional + 64 是 CheckSum，默认零，下面按需回填
  file.writeUInt16LE(3, optional + 68); // subsystem 控制台
  file.writeUInt32LE(16, optional + 108); // numberOfRvaAndSizes

  const dataDirectories = optional + 112;
  if (withSecurity) {
    // 安全目录的虚拟地址字段按 PE 规范是文件偏移，不是相对虚拟地址。
    file.writeUInt32LE(0x400, dataDirectories + 4 * 8);
    file.writeUInt32LE(0x40, dataDirectories + 4 * 8 + 4);
  }

  const sectionTable = 0x148;
  file.write('.text\0\0\0', sectionTable, 'latin1');
  file.writeUInt32LE(0x10, sectionTable + 8); // virtualSize
  file.writeUInt32LE(0x1000, sectionTable + 12); // virtualAddress
  file.writeUInt32LE(0x200, sectionTable + 16); // sizeOfRawData
  file.writeUInt32LE(0x200, sectionTable + 20); // pointerToRawData
  file.writeUInt32LE(0x60000020, sectionTable + 36); // characteristics
  file.write('basic pe text section', 0x200, 'latin1');

  if (withSecurity) {
    // WIN_CERTIFICATE 形态的占位签名表：只供观察器登记存在与大小，不是有效签名，
    // 也不声称任何签名者身份；观察器只回答“是否存在安全目录”。
    const certificate = Buffer.alloc(0x40, 0);
    certificate.writeUInt32LE(0x40, 0); // dwLength
    certificate.writeUInt16LE(0x0200, 4); // wRevision
    certificate.writeUInt16LE(0x0002, 6); // wCertificateType PKCS_SIGNED_DATA
    certificate.write('AUTHCODE-SIGNATURE-BLOCK', 8, 'latin1');
    certificate.copy(file, 0x400);
  }

  if (withChecksum) {
    const checksumFieldOffset = optional + 64;
    file.writeUInt32LE(computePeChecksum(file, checksumFieldOffset), checksumFieldOffset);
  }

  return file;
}

// ---------------------------------------------------------------------------
// 夹具构造器：Mach-O
// ---------------------------------------------------------------------------

/**
 * 构造最小 64 位小端 Mach-O 可执行文件：
 * LC_SEGMENT_64（__TEXT 一个 __text 节）、LC_UUID、LC_LOAD_DYLIB，可选 LC_CODE_SIGNATURE。
 * @param {{withCodeSignature?: boolean}} options
 * @returns {Buffer}
 */
function buildMachO({ withCodeSignature = false } = {}) {
  const sectionContent = Buffer.from('sample text segment content', 'latin1');
  const dylibName = '/usr/lib/libSystem.B.dylib\0';
  const dylibPayload = Buffer.alloc(16 + Math.ceil(dylibName.length / 8) * 8, 0);
  dylibPayload.writeUInt32LE(24, 0); // lc_str 名称偏移
  dylibPayload.writeUInt32LE(0x10000, 8); // timestamp 固定值
  dylibPayload.writeUInt32LE(0x10000, 12); // current_version
  dylibPayload.write(dylibName, 16, 'latin1');

  const headerSize = 32;
  const segmentSize = 72 + 80;
  const uuidSize = 8 + 16;
  const dylibSize = 8 + dylibPayload.length;
  const codeSignatureSize = withCodeSignature ? 16 : 0;
  const ncmds = withCodeSignature ? 4 : 3;
  const sizeofcmds = segmentSize + uuidSize + dylibSize + codeSignatureSize;
  const contentOffset = headerSize + sizeofcmds;
  const signatureOffset = contentOffset + sectionContent.length;
  const fileSize = signatureOffset + codeSignatureSize;
  const file = Buffer.alloc(fileSize, 0);

  file.writeUInt32LE(0xfeedfacf, 0); // MH_MAGIC_64
  file.writeUInt32LE(0x01000007, 4); // CPU_TYPE_X86_64
  file.writeUInt32LE(3, 8); // CPU_SUBTYPE_X86_64_ALL
  file.writeUInt32LE(2, 12); // MH_EXECUTE
  file.writeUInt32LE(ncmds, 16);
  file.writeUInt32LE(sizeofcmds, 20);
  file.writeUInt32LE(0, 24); // flags
  file.writeUInt32LE(0, 28); // reserved

  let position = headerSize;
  file.writeUInt32LE(0x19, position); // LC_SEGMENT_64
  file.writeUInt32LE(segmentSize, position + 4);
  file.write('__TEXT', position + 8, 'latin1');
  file.writeBigUInt64LE(0x100000000n, position + 24); // vmaddr
  file.writeBigUInt64LE(0x1000n, position + 32); // vmsize
  file.writeBigUInt64LE(0n, position + 40); // fileoff
  file.writeBigUInt64LE(BigInt(fileSize), position + 48); // filesize
  file.writeInt32LE(5, position + 56); // maxprot
  file.writeInt32LE(5, position + 60); // initprot
  file.writeUInt32LE(1, position + 64); // nsects
  file.writeUInt32LE(0, position + 68); // flags
  const section = position + 72;
  file.write('__text', section, 'latin1');
  file.write('__TEXT', section + 16, 'latin1');
  file.writeBigUInt64LE(0x100000000n + 0x1000n, section + 32); // addr
  file.writeBigUInt64LE(BigInt(sectionContent.length), section + 40); // size
  file.writeUInt32LE(contentOffset, section + 48); // offset
  position += segmentSize;

  file.writeUInt32LE(0x1b, position); // LC_UUID
  file.writeUInt32LE(uuidSize, position + 4);
  Buffer.from('0123456789abcdef', 'latin1').copy(file, position + 8);
  position += uuidSize;

  file.writeUInt32LE(0xc, position); // LC_LOAD_DYLIB
  file.writeUInt32LE(dylibSize, position + 4);
  dylibPayload.copy(file, position + 8);
  position += dylibSize;

  if (withCodeSignature) {
    file.writeUInt32LE(0x1d, position); // LC_CODE_SIGNATURE
    file.writeUInt32LE(16, position + 4);
    file.writeUInt32LE(signatureOffset, position + 8); // dataoff
    file.writeUInt32LE(16, position + 12); // datasize
    // 签名数据区占位：只供观察器登记存在与大小，不是有效签名。
    file.write('CODESIGNATURE', signatureOffset, 'latin1');
  }

  sectionContent.copy(file, contentOffset);
  return file;
}

// ---------------------------------------------------------------------------
// 夹具构造器：ZIP
// ---------------------------------------------------------------------------

/** zip/mixed-entries.zip：一个存储条目加一个 deflate 条目，本地头、中央目录与结尾记录齐全。 */
function buildZipMixed() {
  const entries = [
    { name: 'stored.txt', method: 0, content: Buffer.from('hello zip stored entry\n', 'latin1') },
    { name: 'deflated.txt', method: 8, content: Buffer.from('hello zip deflated entry\n'.repeat(8), 'latin1') },
  ];
  const parts = [];
  const centrals = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name, 'latin1');
    const stored = entry.method === 8 ? deflateRawSync(entry.content) : entry.content;
    const checksum = crc32(entry.content);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0, 6); // flags
    local.writeUInt16LE(entry.method, 8);
    local.writeUInt16LE(0x6000, 10); // 固定 DOS 时间
    local.writeUInt16LE(0x5b21, 12); // 固定 DOS 日期
    local.writeUInt32LE(checksum, 14);
    local.writeUInt32LE(stored.length, 18);
    local.writeUInt32LE(entry.content.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    const entryBytes = Buffer.concat([local, name, stored]);
    centrals.push({ name, method: entry.method, checksum, csize: stored.length, usize: entry.content.length, localOffset: offset });
    parts.push(entryBytes);
    offset += entryBytes.length;
  }

  const cdOffset = offset;
  for (const item of centrals) {
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(0x031e, 4); // version made by
    central.writeUInt16LE(20, 6); // version needed
    central.writeUInt16LE(0, 8); // flag
    central.writeUInt16LE(item.method, 10);
    central.writeUInt16LE(0x6000, 12);
    central.writeUInt16LE(0x5b21, 14);
    central.writeUInt32LE(item.checksum, 16);
    central.writeUInt32LE(item.csize, 20);
    central.writeUInt32LE(item.usize, 24);
    central.writeUInt16LE(item.name.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt32LE(item.localOffset, 42);
    parts.push(Buffer.concat([central, item.name]));
    offset += 46 + item.name.length;
  }

  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(centrals.length, 8);
  end.writeUInt16LE(centrals.length, 10);
  end.writeUInt32LE(offset - cdOffset, 12);
  end.writeUInt32LE(cdOffset, 16);
  parts.push(end);
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------------------
// 夹具构造器：GGUF 与 safetensors
// ---------------------------------------------------------------------------

/** gguf/basic.gguf：两条元数据、两个张量，alignment 显式声明为 32。 */
function buildGgufBasic() {
  const alignment = 32;
  const metadata = [
    ['general.architecture', 8, 'demo'],
    ['general.alignment', 4, alignment],
  ];
  const tensors = [
    { name: 't0', dims: [4], type: 0, offset: 0 },
    { name: 't1', dims: [4], type: 0, offset: 32 },
  ];

  const parts = [];
  let position = 0;
  const push = (buffer) => {
    parts.push(buffer);
    position += buffer.length;
  };
  const writeString = (text) => {
    const bytes = Buffer.from(text, 'latin1');
    const length = Buffer.alloc(8);
    length.writeBigUInt64LE(BigInt(bytes.length), 0);
    push(length);
    push(bytes);
  };

  const header = Buffer.alloc(24);
  header.write('GGUF', 0, 'latin1');
  header.writeUInt32LE(3, 4); // version
  header.writeBigUInt64LE(BigInt(tensors.length), 8);
  header.writeBigUInt64LE(BigInt(metadata.length), 16);
  push(header);

  for (const [key, typeId, value] of metadata) {
    writeString(key);
    const type = Buffer.alloc(4);
    type.writeUInt32LE(typeId, 0);
    push(type);
    if (typeId === 8) {
      writeString(value);
    } else {
      const scalar = Buffer.alloc(4);
      scalar.writeUInt32LE(value, 0);
      push(scalar);
    }
  }

  for (const tensor of tensors) {
    writeString(tensor.name);
    const dims = Buffer.alloc(4);
    dims.writeUInt32LE(tensor.dims.length, 0);
    push(dims);
    for (const dim of tensor.dims) {
      const size = Buffer.alloc(8);
      size.writeBigUInt64LE(BigInt(dim), 0);
      push(size);
    }
    const tail = Buffer.alloc(12);
    tail.writeUInt32LE(tensor.type, 0);
    tail.writeBigUInt64LE(BigInt(tensor.offset), 4);
    push(tail);
  }

  const tensorDataOffset = Math.ceil(position / alignment) * alignment;
  const dataLength = Math.max(
    ...tensors.map((tensor) => tensor.offset + tensor.dims.reduce((total, dim) => total * dim, 1) * 4),
  );
  return Buffer.concat([...parts, Buffer.alloc(tensorDataOffset - position, 0), patternBytes(dataLength, 0x33)]);
}

/** safetensors/basic.safetensors：__metadata__ 加两个张量，索引完整覆盖数据区。 */
function buildSafetensorsBasic() {
  const header = {
    __metadata__: { format: 'pt' },
    t0: { dtype: 'F32', shape: [2], data_offsets: [0, 8] },
    t1: { dtype: 'F32', shape: [2], data_offsets: [8, 16] },
  };
  const headerBytes = Buffer.from(JSON.stringify(header), 'utf8');
  const prefix = Buffer.alloc(8);
  prefix.writeBigUInt64LE(BigInt(headerBytes.length), 0);
  return Buffer.concat([prefix, headerBytes, patternBytes(16, 0x77)]);
}

// ---------------------------------------------------------------------------
// 夹具构造器：pyc 与 BEAM
// ---------------------------------------------------------------------------

/** pyc/hash-based-check-source.pyc：hash_based 且 check_source 置位的 pyc。 */
function buildPycHashBased() {
  const body = Buffer.alloc(32, 0);
  body[0] = 0xe3;
  body[8] = 0x64;
  body[31] = 0x53;
  const file = Buffer.alloc(16 + body.length, 0);
  file.writeUInt16LE(0x0da7, 0); // 魔数
  file.writeUInt8(0x0d, 2);
  file.writeUInt8(0x0a, 3);
  file.writeUInt32LE(0b11, 4); // hash_based 加 check_source
  Buffer.from('01234567', 'latin1').copy(file, 8); // source_hash 占位
  body.copy(file, 16);
  return file;
}

/** beam/basic.beam：FOR1 外框套 BEAM，含 AtU8、Code、StrT 三个块。 */
function buildBeamBasic() {
  const chunk = (id, body) => {
    const head = Buffer.alloc(8);
    head.write(id, 0, 'latin1');
    head.writeUInt32BE(body.length, 4);
    // 块长按偶数对齐，奇数字节补一个占位字节。
    const pad = body.length % 2 === 1 ? Buffer.alloc(1) : Buffer.alloc(0);
    return Buffer.concat([head, body, pad]);
  };
  const atom = (text) => {
    const bytes = Buffer.from(text, 'latin1');
    const length = Buffer.alloc(2);
    length.writeUInt16BE(bytes.length, 0);
    return Buffer.concat([length, bytes]);
  };
  const body = Buffer.concat([
    chunk('AtU8', Buffer.concat([atom('demo'), atom('code')])),
    chunk('Code', patternBytes(16, 0x11)),
    chunk('StrT', Buffer.from('demo\0\0', 'latin1')),
  ]);
  // BEAM 是 IFF 风格容器：FOR1 之后是四字节长度，接着是 BEAM 标记，块结构紧挨标记之后。
  const file = Buffer.alloc(12 + body.length);
  file.write('FOR1', 0, 'latin1');
  file.writeUInt32BE(4 + body.length, 4);
  file.write('BEAM', 8, 'latin1');
  body.copy(file, 12);
  return file;
}

// ---------------------------------------------------------------------------
// 夹具构造器：范围外格式
// ---------------------------------------------------------------------------

/** unsupported/global-metadata.dat：IL2CPP 全局元数据魔数，v1 不解析。 */
function buildIl2cppMetadata() {
  const file = Buffer.alloc(64, 0);
  file.writeUInt32LE(0xfab11baf, 0); // IL2CPP 全局元数据魔数
  file.writeUInt32LE(31, 4); // 版本
  file.writeUInt32LE(3, 8); // stringLiteral 计数（占位）
  file.writeUInt32LE(0x40, 12); // stringLiteral 数据偏移（占位）
  for (let index = 16; index < file.length; index += 1) {
    file[index] = (index * 7) & 0xff;
  }
  return file;
}

/** unsupported/apk-signature-scheme.apk：APK 签名块，不是 ZIP，v1 不解析。 */
function buildApkSigningBlock() {
  const pairs = patternBytes(24, 0x2a);
  const size = 8 + pairs.length + 16 + 8;
  const sizeField = Buffer.alloc(8);
  sizeField.writeBigUInt64LE(BigInt(size), 0);
  return Buffer.concat([sizeField, pairs, Buffer.from('APK Sig Block 42', 'latin1'), sizeField]);
}

// ---------------------------------------------------------------------------
// 夹具登记表
// ---------------------------------------------------------------------------

/** pe/basic.pe：PE 可选头、节表与数据目录。 */
function buildPeBasic() {
  return buildPe({});
}

/** pe/security-directory.pe：带安全目录的 PE，默认跳过改写。 */
function buildPeSecurity() {
  return buildPe({ withSecurity: true });
}

/** pe/checksum-nonzero.pe：可选头 CheckSum 非零的 PE。 */
function buildPeChecksum() {
  return buildPe({ withChecksum: true });
}

/** mach-o/basic.macho：Mach-O 加载命令与节表。 */
function buildMachOBasic() {
  return buildMachO({});
}

/** mach-o/code-signature.macho：带 LC_CODE_SIGNATURE 的 Mach-O，默认跳过改写。 */
function buildMachOSigned() {
  return buildMachO({ withCodeSignature: true });
}

/** 字节级夹具登记表：构造完全确定，摘要登记进 manifest.json。 */
export const BYTE_FIXTURES = Object.freeze([
  { id: 'elf-basic', path: 'elf/basic.elf', container: 'elf', build: buildElfBasic },
  { id: 'elf-go-buildinfo-inline', path: 'elf/go-buildinfo-inline.elf', container: 'elf', build: buildElfGoInline },
  { id: 'elf-go-buildinfo-pointer', path: 'elf/go-buildinfo-pointer.elf', container: 'elf', build: buildElfGoPointer },
  { id: 'elf-rust-dep-v0', path: 'elf/rust-dep-v0.elf', container: 'elf', build: buildElfRustDep },
  { id: 'pe-basic', path: 'pe/basic.pe', container: 'pe', build: buildPeBasic },
  { id: 'pe-security-directory', path: 'pe/security-directory.pe', container: 'pe', build: buildPeSecurity },
  { id: 'pe-checksum-nonzero', path: 'pe/checksum-nonzero.pe', container: 'pe', build: buildPeChecksum },
  { id: 'mach-o-basic', path: 'mach-o/basic.macho', container: 'mach-o', build: buildMachOBasic },
  { id: 'mach-o-code-signature', path: 'mach-o/code-signature.macho', container: 'mach-o', build: buildMachOSigned },
  { id: 'zip-mixed-entries', path: 'zip/mixed-entries.zip', container: 'zip', build: buildZipMixed },
  { id: 'gguf-basic', path: 'gguf/basic.gguf', container: 'gguf', build: buildGgufBasic },
  { id: 'safetensors-basic', path: 'safetensors/basic.safetensors', container: 'safetensors', build: buildSafetensorsBasic },
  { id: 'pyc-hash-based-check-source', path: 'pyc/hash-based-check-source.pyc', container: 'pyc', build: buildPycHashBased },
  { id: 'beam-basic', path: 'beam/basic.beam', container: 'beam', build: buildBeamBasic },
  { id: 'il2cpp-metadata', path: 'unsupported/global-metadata.dat', container: 'unsupported', build: buildIl2cppMetadata },
  { id: 'apk-signature-scheme', path: 'unsupported/apk-signature-scheme.apk', container: 'unsupported', build: buildApkSigningBlock },
]);

/**
 * 构造全部字节级夹具。
 * @returns {Array<{id: string, path: string, container: string, bytes: Buffer}>}
 */
export function buildFixtureBytes() {
  return BYTE_FIXTURES.map((fixture) => ({ id: fixture.id, path: fixture.path, container: fixture.container, bytes: fixture.build() }));
}

// ---------------------------------------------------------------------------
// 命令行
// ---------------------------------------------------------------------------

/**
 * 计算文件 sha256。
 * @param {string} path 文件路径
 * @returns {Promise<string>}
 */
async function sha256Of(path) {
  return createHash('sha256').update(await readFile(path)).digest('hex');
}

/**
 * 枚举清单之外散落在夹具目录里的文件。
 * @param {Set<string>} registered 已登记相对路径
 * @returns {Promise<string[]>}
 */
async function listUnregistered(registered) {
  const found = [];
  const queue = [FIXTURES_DIR];
  while (queue.length > 0) {
    const current = queue.shift();
    for (const dirent of await readdir(current, { withFileTypes: true })) {
      const absolute = join(current, dirent.name);
      if (dirent.isDirectory()) {
        queue.push(absolute);
        continue;
      }
      if (!dirent.isFile() || dirent.name === 'manifest.json' || dirent.name === 'build.mjs') {
        continue;
      }
      const relativePath = relative(FIXTURES_DIR, absolute).split('\\').join('/');
      if (!registered.has(relativePath)) {
        found.push(relativePath);
      }
    }
  }
  return found.sort();
}

/**
 * 读取夹具清单。
 * @returns {Promise<{schema: string, fixtures: Record<string, string>}>}
 */
async function readManifest() {
  const text = await readFile(join(FIXTURES_DIR, 'manifest.json'), 'utf8');
  const parsed = JSON.parse(text);
  return { schema: parsed.schema, fixtures: parsed.fixtures ?? {} };
}

/**
 * 序列化清单：键排序、两空格缩进、结尾换行，保证重复写出内容一致。
 * @param {Record<string, string>} fixtures 夹具摘要表
 * @returns {string}
 */
function serializeManifest(fixtures) {
  const sorted = Object.fromEntries(Object.entries(fixtures).sort(([left], [right]) => (left < right ? -1 : 1)));
  return `${JSON.stringify({ schema: MANIFEST_SCHEMA, note: MANIFEST_NOTE, fixtures: sorted }, null, 2)}\n`;
}

/**
 * 校验清单登记的每个夹具：文件存在且摘要一致。
 * @param {Record<string, string>} registered 清单摘要表
 * @returns {Promise<string[]>} 问题说明，空数组表示全部一致
 */
async function checkRegistered(registered) {
  const problems = [];
  for (const [relativePath, expected] of Object.entries(registered)) {
    const absolute = join(FIXTURES_DIR, relativePath);
    const actual = await sha256Of(absolute).catch(() => null);
    if (actual === null) {
      problems.push(`清单登记的夹具不存在：${relativePath}`);
      continue;
    }
    if (actual !== expected) {
      problems.push(`摘要不一致：${relativePath}，记录 ${expected}，实际 ${actual}`);
    }
  }
  return problems;
}

/**
 * 命令行主流程。
 * @returns {Promise<number>} 退出码
 */
async function main() {
  const args = process.argv.slice(2);
  const checkOnly = args.includes('--check');
  const force = args.includes('--force');
  if (args.some((arg) => !['--check', '--force'].includes(arg))) {
    process.stdout.write('用法：node tests/fixtures/build.mjs [--check | --force]\n');
    return 2;
  }

  const manifest = await readManifest().catch(() => null);
  if (manifest === null) {
    process.stdout.write('清单读取失败：tests/fixtures/manifest.json 缺失或不是合法 JSON\n');
    return 1;
  }
  const registered = new Set([...Object.keys(manifest.fixtures), ...SAMPLE_APP_FILES]);

  if (checkOnly) {
    const problems = await checkRegistered(manifest.fixtures);
    const unregistered = await listUnregistered(registered);
    if (unregistered.length > 0) {
      process.stdout.write(`未登记到清单的文件：\n${unregistered.map((line) => `  ${line}`).join('\n')}\n`);
    }
    if (problems.length > 0) {
      process.stdout.write(`已提交夹具校验未通过：\n${problems.map((line) => `  ${line}`).join('\n')}\n`);
      return 1;
    }
    process.stdout.write(`已提交夹具校验通过：${Object.keys(manifest.fixtures).length} 项摘要与清单一致\n`);
    return 0;
  }

  // 生成模式：先构造全部字节级夹具，与磁盘逐字节比对后再决定写盘。
  const built = buildFixtureBytes();
  const mismatches = [];
  for (const fixture of built) {
    const absolute = join(FIXTURES_DIR, fixture.path);
    const onDisk = await readFile(absolute).catch(() => null);
    if (onDisk === null) {
      // 缺失的夹具直接生成；目录可能还不存在，先建目录。
      await mkdir(dirname(absolute), { recursive: true });
      await writeFile(absolute, fixture.bytes);
      continue;
    }
    if (!onDisk.equals(fixture.bytes)) {
      // 已存在但字节不一致：只有 --force 才覆写，否则按不一致报告，避免悄悄改动已提交夹具。
      if (force) {
        await writeFile(absolute, fixture.bytes);
      } else {
        mismatches.push(`构建输出与已提交夹具不一致：${fixture.path}（用 --force 重新生成）`);
      }
    }
  }
  if (mismatches.length > 0) {
    process.stdout.write(`夹具生成中断：\n${mismatches.map((line) => `  ${line}`).join('\n')}\n`);
    return 1;
  }

  // 以磁盘实际字节重算全部登记项的摘要，再写出清单。
  const fixtures = {};
  for (const relativePath of [...SAMPLE_APP_FILES, ...built.map((fixture) => fixture.path)].sort()) {
    fixtures[relativePath] = await sha256Of(join(FIXTURES_DIR, relativePath));
  }
  const text = serializeManifest(fixtures);
  const manifestPath = join(FIXTURES_DIR, 'manifest.json');
  const current = await readFile(manifestPath, 'utf8').catch(() => null);
  if (current !== text) {
    await writeFile(manifestPath, text);
  }

  const unregistered = await listUnregistered(new Set(Object.keys(fixtures)));
  if (unregistered.length > 0) {
    process.stdout.write(`未登记到清单的文件：\n${unregistered.map((line) => `  ${line}`).join('\n')}\n`);
  }
  const problems = await checkRegistered(fixtures);
  if (problems.length > 0) {
    process.stdout.write(`已提交夹具校验未通过：\n${problems.map((line) => `  ${line}`).join('\n')}\n`);
    return 1;
  }
  process.stdout.write(`已提交夹具校验通过：${Object.keys(fixtures).length} 项摘要与清单一致\n`);
  return 0;
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await main();
}
