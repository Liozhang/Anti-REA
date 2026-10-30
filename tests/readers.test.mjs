// readers 模块测试：九类格式的真实夹具、畸形输入与部分读取。
// 夹具全部在临时目录里按字节级精确构造，不依赖仓库内其他模块的夹具生成进度。
// 覆盖三条路径：正常输入（事实被提取）、畸形输入（转成限制说明且不抛错）、部分读取（受预算约束时给部分结果加限制说明）。

import assert from 'node:assert/strict';
import { deflateRawSync, deflateSync } from 'node:zlib';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { LAYER_IDS, SEVERITY_IDS } from '../src/audit/layer-defs.mjs';
import { MITIGATION_IDS } from '../src/audit/finding.mjs';
import { auditArtifact } from '../src/audit/engine.mjs';
import { redactReport } from '../src/report/redact.mjs';
import { beamReader } from '../src/readers/beam.mjs';
import { crc32Of } from '../src/readers/zip.mjs';
import { dexReader } from '../src/readers/dex.mjs';
import { elfReader } from '../src/readers/elf.mjs';
import { ggufReader } from '../src/readers/gguf.mjs';
import { machoReader } from '../src/readers/macho.mjs';
import { peReader } from '../src/readers/pe.mjs';
import { pycReader } from '../src/readers/pyc.mjs';
import { overwriteTokenPlaceholder } from '../src/transforms/equal-length.mjs';
import { safetensorsReader } from '../src/readers/safetensors.mjs';
import { zipReader } from '../src/readers/zip.mjs';
import { scanTokens, TOKEN_PATTERNS } from '../src/readers/scan.mjs';
import { CONTAINER_FIXTURES } from './helpers/container-fixtures.mjs';
import { READER_REGISTRY, capabilityBoundaryFor } from '../src/readers/index.mjs';
import { SAMPLE_APP } from './helpers/cli.mjs';

/** 临时目录在测试结束后清理。 */
let workDir = null;

test.before(async () => {
  workDir = await mkdtemp(join(tmpdir(), 'anti-rea-readers-'));
});

test.after(async () => {
  if (workDir !== null) {
    await rm(workDir, { recursive: true, force: true });
  }
});

/**
 * 把夹具写进临时目录，返回条目对象（读取器入参）。
 * @param {string} name 文件名
 * @param {Buffer} bytes 夹具字节
 * @returns {Promise<{absolutePath: string, relativePath: string, bytes: number, sha256: null, container: {type: string}, detectionLimited: false, digestTruncated: false}>}
 */
async function writeFixture(name, bytes) {
  const absolutePath = join(workDir, name);
  await writeFile(absolutePath, bytes);
  return {
    absolutePath,
    relativePath: name,
    bytes: bytes.length,
    sha256: null,
    container: { type: 'test' },
    detectionLimited: false,
    digestTruncated: false,
  };
}

/**
 * 调用读取器，返回结果。读取器永不抛错，抛错即测试失败。
 * @param {Record<string, unknown>} reader 读取器
 * @param {{absolutePath: string, relativePath: string, bytes: number}} entry 条目
 * @param {Record<string, number>} [budgets] 预算
 * @returns {Promise<{findings: Array<Record<string, unknown>>, limitations: Array<Record<string, unknown>>}>}
 */
async function runReader(reader, entry, budgets) {
  const result = await reader.read({ entry, policy: {}, budgets: budgets ?? {} });
  assert.ok(Array.isArray(result.findings), 'findings 必须是数组');
  assert.ok(Array.isArray(result.limitations), 'limitations 必须是数组');
  for (const limitation of result.limitations) {
    assert.equal(typeof limitation.code, 'string');
    assert.ok(limitation.message.length > 0, '限制说明不得为空');
    assert.equal(typeof limitation.scope, 'string');
  }
  return result;
}

// ---------------------------------------------------------------------------
// 夹具构造：ELF
// ---------------------------------------------------------------------------

/** 小端四字节无符号整数。 */
function u32le(value) {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32LE(value >>> 0, 0);
  return buffer;
}

/** 大端四字节无符号整数。 */
function u32be(value) {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value >>> 0, 0);
  return buffer;
}

/**
 * 构造 64 位小端 ELF。
 * @param {Array<{name: string, type: number, content: Buffer, flags?: number, linkName?: string, info?: number, align?: number, entsize?: number}>} userSections 用户节
 * @param {Array<{type: number, flags: number, offset: number, vaddr: number, filesz: number}>} [programHeaders] 程序头
 * @returns {Buffer}
 */
function buildElf64(userSections, programHeaders = []) {
  const names = ['', ...userSections.map((section) => section.name), '.shstrtab'];
  let shstrtab = Buffer.alloc(0);
  const nameOffsets = names.map((name) => {
    const offset = shstrtab.length;
    shstrtab = Buffer.concat([shstrtab, Buffer.from(`${name}\0`, 'latin1')]);
    return offset;
  });

  const ehdrSize = 64;
  let offset = ehdrSize;
  const placed = userSections.map((section, index) => {
    const align = Math.max(1, section.align ?? 1);
    const start = Math.ceil(offset / align) * align;
    offset = start + section.content.length;
    return { ...section, offset: start, nameOffset: nameOffsets[index + 1] };
  });
  const shstrtabOffset = offset;
  offset += shstrtab.length;
  const shoff = Math.ceil(offset / 8) * 8;
  const shnum = userSections.length + 2;
  const shstrndx = shnum - 1;
  const phoff = shoff + shnum * 64;
  const fileSize = phoff + programHeaders.length * 56;

  const file = Buffer.alloc(fileSize, 0);
  const ehdr = file.subarray(0, ehdrSize);
  ehdr.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
  ehdr.writeUInt16LE(2, 16);
  ehdr.writeUInt16LE(62, 18);
  ehdr.writeUInt32LE(1, 20);
  ehdr.writeBigUInt64LE(0x401000n, 24);
  ehdr.writeBigUInt64LE(programHeaders.length > 0 ? BigInt(phoff) : 0n, 32);
  ehdr.writeBigUInt64LE(BigInt(shoff), 40);
  ehdr.writeUInt32LE(0, 48);
  ehdr.writeUInt16LE(64, 52);
  ehdr.writeUInt16LE(56, 54);
  ehdr.writeUInt16LE(programHeaders.length, 56);
  ehdr.writeUInt16LE(64, 58);
  ehdr.writeUInt16LE(shnum, 60);
  ehdr.writeUInt16LE(shstrndx, 62);

  for (const section of placed) {
    file.set(section.content, section.offset);
  }
  file.set(shstrtab, shstrtabOffset);

  const indexByName = new Map(placed.map((section, index) => [section.name, index + 1]));
  const writeSectionHeader = (index, header) => {
    const base = shoff + index * 64;
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
      link: section.linkName === undefined ? (section.link ?? 0) : indexByName.get(section.linkName),
      info: section.info,
      align: section.align,
      entsize: section.entsize,
    });
  });
  writeSectionHeader(shstrndx, { name: nameOffsets[nameOffsets.length - 1], type: 3, offset: shstrtabOffset, size: shstrtab.length, align: 1 });

  programHeaders.forEach((header, index) => {
    const base = phoff + index * 56;
    file.writeUInt32LE(header.type, base);
    file.writeUInt32LE(header.flags, base + 4);
    file.writeBigUInt64LE(BigInt(header.offset), base + 8);
    file.writeBigUInt64LE(BigInt(header.vaddr), base + 16);
    file.writeBigUInt64LE(BigInt(header.offset), base + 24);
    file.writeBigUInt64LE(BigInt(header.filesz), base + 32);
    file.writeBigUInt64LE(BigInt(header.filesz), base + 40);
    file.writeBigUInt64LE(0x1000n, base + 48);
  });

  return file;
}

/** ELF 节类型。 */
const SHT = Object.freeze({ PROGBITS: 1, SYMTAB: 2, STRTAB: 3, NOTE: 7 });

/**
 * 构造符号表与字符串表。
 * @param {string[]} names 符号名
 * @returns {{symtab: Buffer, strtab: Buffer}}
 */
function buildSymbols(names) {
  // 真实 ELF 字符串表以空字节开头，第 0 号名字是空串；这里保持一致。
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
    symtab.writeUInt16LE(1, index * 24 + 6);
    symtab.writeBigUInt64LE(0x401000n + BigInt(index) * 16n, index * 24 + 8);
    symtab.writeBigUInt64LE(16n, index * 24 + 16);
  });
  return { symtab, strtab };
}

/**
 * 构造 note 节内容。
 * @param {string} name note 名称
 * @param {number} type note 类型
 * @param {Buffer} desc 描述字节
 * @returns {Buffer}
 */
function buildNote(name, type, desc) {
  const nameBuffer = Buffer.from(`${name}\0`, 'latin1');
  const namePad = (4 - (nameBuffer.length % 4)) % 4;
  const descPad = (4 - (desc.length % 4)) % 4;
  return Buffer.concat([u32le(nameBuffer.length), u32le(desc.length), u32le(type), nameBuffer, Buffer.alloc(namePad), desc, Buffer.alloc(descPad)]);
}

/**
 * 构造 Go 构建信息 inline 编码载荷。
 * @param {string} version 版本串
 * @param {string} modinfo 模块信息
 * @returns {Buffer}
 */
function goBuildinfoInline(version, modinfo) {
  const versionBuffer = Buffer.from(version, 'latin1');
  const modinfoBuffer = Buffer.from(modinfo, 'latin1');
  return Buffer.concat([
    Buffer.from([0xff, 0x20, 0x47, 0x6f, 0x20, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e, 0x66, 0x3a]),
    Buffer.from([versionBuffer.length]),
    versionBuffer,
    Buffer.from([modinfoBuffer.length]),
    modinfoBuffer,
  ]);
}

/**
 * 构造 Rust 依赖节 .dep-v0 的载荷。
 * @param {string[]} dependencies 依赖条目
 * @param {'zlib' | 'raw'} format 压缩封装
 * @returns {Buffer}
 */
function depV0Payload(dependencies, format) {
  const text = `${dependencies.join('\n')}\n`;
  return format === 'zlib' ? deflateSync(Buffer.from(text, 'latin1')) : deflateRawSync(Buffer.from(text, 'latin1'));
}

// ---------------------------------------------------------------------------
// 夹具构造：PE
// ---------------------------------------------------------------------------

/**
 * 构造最小 PE32+ 文件。
 * @param {{withDebug?: boolean, withSecurity?: boolean, withChecksum?: boolean, withImports?: boolean, withGoBuildinfo?: boolean, token?: boolean}} options
 * @returns {Buffer}
 */
function buildPe(options = {}) {
  const sections = [
    { name: '.rdata', va: 0x200, raw: 0x200, rawSize: 0x200, characteristics: 0x40000040 },
    { name: '.text', va: 0x400, raw: 0x400, rawSize: 0x200, characteristics: 0x60000020 },
  ];
  if (options.withGoBuildinfo === true) {
    sections.push({ name: '.gobi', va: 0x600, raw: 0x600, rawSize: 0x40, characteristics: 0xc0000040 });
  }
  const sectionTableOffset = 0x148;
  const fileSize = sections.reduce((max, section) => Math.max(max, section.raw + section.rawSize), 0x640);
  const file = Buffer.alloc(fileSize, 0);

  file.write('MZ', 0, 'latin1');
  file.writeUInt32LE(0x40, 0x3c);
  file.write('PE\0\0', 0x40, 'latin1');
  file.writeUInt16LE(0x8664, 0x44);
  file.writeUInt16LE(sections.length, 0x46);
  file.writeUInt32LE(0x64, 0x48);
  file.writeUInt16LE(240, 0x54);
  file.writeUInt16LE(0x22, 0x56);

  const optional = 0x58;
  file.writeUInt16LE(0x20b, optional);
  file.writeUInt32LE(0x200, optional + 4);
  file.writeUInt32LE(0x1000, optional + 16);
  file.writeUInt32LE(0x1000, optional + 20);
  file.writeBigUInt64LE(0x140000000n, optional + 24);
  file.writeUInt32LE(0x1000, optional + 32);
  file.writeUInt32LE(0x200, optional + 36);
  file.writeUInt32LE(0x3000, optional + 56);
  file.writeUInt32LE(0x200, optional + 60);
  file.writeUInt32LE(options.withChecksum === true ? 0x12345678 : 0, optional + 64);
  file.writeUInt16LE(3, optional + 68);
  file.writeUInt32LE(16, optional + 108);

  const dataDirectories = optional + 112;
  if (options.withImports !== false) {
    file.writeUInt32LE(0x280, dataDirectories + 1 * 8);
    file.writeUInt32LE(40, dataDirectories + 1 * 8 + 4);
  }
  if (options.withDebug === true) {
    file.writeUInt32LE(0x200, dataDirectories + 6 * 8);
    file.writeUInt32LE(28, dataDirectories + 6 * 8 + 4);
  }
  if (options.withSecurity === true) {
    file.writeUInt32LE(0x2c0, dataDirectories + 4 * 8);
    file.writeUInt32LE(16, dataDirectories + 4 * 8 + 4);
  }

  sections.forEach((section, index) => {
    const base = sectionTableOffset + index * 40;
    file.write(section.name, base, 'latin1');
    file.writeUInt32LE(0x200, base + 8);
    file.writeUInt32LE(section.va, base + 12);
    file.writeUInt32LE(section.rawSize, base + 16);
    file.writeUInt32LE(section.raw, base + 20);
    file.writeUInt32LE(section.characteristics, base + 36);
  });

  if (options.withDebug === true) {
    const pdb = Buffer.from('C:\\build\\sample-app.pdb\0', 'latin1');
    const codeviewLength = 4 + 16 + 4 + pdb.length;
    const debugEntry = Buffer.alloc(28);
    debugEntry.writeUInt32LE(2, 12);
    debugEntry.writeUInt32LE(codeviewLength, 16);
    debugEntry.writeUInt32LE(0x220, 20);
    debugEntry.writeUInt32LE(0x220, 24);
    debugEntry.copy(file, 0x200);
    const codeview = Buffer.alloc(24 + pdb.length);
    codeview.write('RSDS', 0, 'latin1');
    codeview.writeUInt32LE(1, 20);
    pdb.copy(codeview, 24);
    codeview.copy(file, 0x220);
  }

  if (options.withImports !== false) {
    const descriptor = Buffer.alloc(40);
    descriptor.writeUInt32LE(0x2a0, 12);
    descriptor.writeUInt32LE(0x2a0, 16);
    descriptor.copy(file, 0x280);
    file.write('KERNEL32.dll\0', 0x2a0, 'latin1');
  }

  if (options.withSecurity === true) {
    const signature = Buffer.from('AUTHCODE-SIGNATURE-BLOCK', 'latin1');
    signature.copy(file, 0x2c0);
  }

  if (options.withGoBuildinfo === true) {
    goBuildinfoInline('go1.22.0', 'path\tsample.app\nmod\tsample.app\t(devel)\n').copy(file, 0x600);
  }

  if (options.token === true) {
    file.write('AKIAIOSFODNN7EXAMPLE', 0x400, 'latin1');
  } else {
    file.write('sample text section without credentials', 0x400, 'latin1');
  }

  return file;
}

// ---------------------------------------------------------------------------
// 夹具构造：Mach-O
// ---------------------------------------------------------------------------

/**
 * 构造最小 64 位小端 Mach-O。
 * @param {{withDepV0?: boolean, withCodeSignature?: boolean, withUuid?: boolean, withDylib?: boolean}} options
 * @returns {Buffer}
 */
function buildMacho(options = {}) {
  const commands = [];
  const sectionContents = [];

  const addSegment = (segname, sectionName, content) => {
    const section = Buffer.alloc(80);
    section.write(sectionName, 0, 'latin1');
    section.write(segname, 16, 'latin1');
    sectionContents.push({ segname, sectionName, content });
    commands.push({ cmd: 0x19, segname, nsects: 1, section });
  };

  addSegment('__TEXT', '__text', Buffer.from('sample text segment content', 'latin1'));
  if (options.withDepV0 === true) {
    addSegment('__DATA', '.dep-v0', depV0Payload(['serde 1.0.210', 'serde_json 1.0.128'], 'raw'));
  }

  if (options.withUuid !== false) {
    commands.push({ cmd: 0x1b, payload: Buffer.from('0123456789abcdef', 'latin1') });
  }
  if (options.withDylib !== false) {
    const name = '/usr/lib/libSystem.B.dylib\0';
    const payload = Buffer.alloc(16 + Math.ceil(name.length / 8) * 8);
    // lc_str 的偏移相对加载命令起点：命令头 8 字节加动态库结构 16 字节，名称落在 24。
    payload.writeUInt32LE(24, 0);
    payload.writeUInt32LE(0x10000, 8);
    payload.writeUInt32LE(0x10000, 12);
    payload.write(name, 16, 'latin1');
    commands.push({ cmd: 0xc, payload });
  }

  const headerSize = 32;
  const commandSize = commands.reduce((total, command) => {
    if (command.cmd === 0x19) {
      return total + 72 + command.section.length;
    }
    return total + 8 + command.payload.length;
  }, 0);

  // 先按内容长度占位，再回填各节的文件偏移与签名数据位置。
  const contentStart = headerSize + commandSize + (options.withCodeSignature === true ? 16 : 0);
  let contentOffset = contentStart;
  const placedSections = sectionContents.map((section) => {
    const start = contentOffset;
    contentOffset += section.content.length;
    return { ...section, offset: start };
  });
  const signatureOffset = contentOffset;
  const fileSize = signatureOffset + (options.withCodeSignature === true ? 16 : 0);

  const file = Buffer.alloc(fileSize, 0);
  file.writeUInt32LE(0xfeedfacf, 0);
  file.writeUInt32LE(0x01000007, 4);
  file.writeUInt32LE(3, 8);
  file.writeUInt32LE(2, 12);
  file.writeUInt32LE(commands.length + (options.withCodeSignature === true ? 1 : 0), 16);
  file.writeUInt32LE(commandSize + (options.withCodeSignature === true ? 16 : 0), 20);
  file.writeUInt32LE(0, 24);

  let position = headerSize;
  for (const command of commands) {
    if (command.cmd === 0x19) {
      const cmdsize = 72 + command.section.length;
      file.writeUInt32LE(command.cmd, position);
      file.writeUInt32LE(cmdsize, position + 4);
      file.write(command.segname, position + 8, 'latin1');
      file.writeBigUInt64LE(0x1000n, position + 24);
      file.writeBigUInt64LE(0x1000n, position + 32);
      const sectionOffset = placedSections.find((section) => section.segname === command.segname).offset;
      const sectionSize = sectionContents.find((section) => section.segname === command.segname).content.length;
      file.writeBigUInt64LE(BigInt(sectionOffset), position + 40);
      file.writeBigUInt64LE(BigInt(sectionSize), position + 48);
      file.writeUInt32LE(5, position + 56);
      file.writeUInt32LE(5, position + 60);
      file.writeUInt32LE(1, position + 64);
      const section = command.section;
      section.writeBigUInt64LE(0x1000n, 32);
      section.writeBigUInt64LE(BigInt(sectionSize), 40);
      section.writeUInt32LE(sectionOffset, 48);
      section.copy(file, position + 72);
      position += cmdsize;
    } else if (command.cmd === 0x1b) {
      const cmdsize = 8 + command.payload.length;
      file.writeUInt32LE(command.cmd, position);
      file.writeUInt32LE(cmdsize, position + 4);
      command.payload.copy(file, position + 8);
      position += cmdsize;
    } else {
      const cmdsize = 8 + command.payload.length;
      file.writeUInt32LE(command.cmd, position);
      file.writeUInt32LE(cmdsize, position + 4);
      command.payload.copy(file, position + 8);
      position += cmdsize;
    }
  }

  if (options.withCodeSignature === true) {
    file.writeUInt32LE(0x1d, position);
    file.writeUInt32LE(16, position + 4);
    file.writeUInt32LE(signatureOffset, position + 8);
    file.writeUInt32LE(16, position + 12);
    file.write('CODESIGNATURE', signatureOffset, 'latin1');
  }

  for (const section of placedSections) {
    section.content.copy(file, section.offset);
  }
  return file;
}

/**
 * 构造胖二进制：两个分片。
 * @returns {Buffer}
 */
function buildMachoFat() {
  const slice = buildMacho({ withCodeSignature: false });
  const entrySize = 20;
  const firstOffset = 8 + 2 * entrySize;
  const secondOffset = firstOffset + slice.length;
  const file = Buffer.alloc(secondOffset + slice.length, 0);
  file.writeUInt32BE(0xcafebabe, 0);
  file.writeUInt32BE(2, 4);
  file.writeUInt32BE(0x01000007, 8);
  file.writeUInt32BE(3, 12);
  file.writeUInt32BE(firstOffset, 16);
  file.writeUInt32BE(slice.length, 20);
  file.writeUInt32BE(0, 24);
  file.writeUInt32BE(0x0100000c, 8 + entrySize);
  file.writeUInt32BE(0, 8 + entrySize + 4);
  file.writeUInt32BE(secondOffset, 8 + entrySize + 8);
  file.writeUInt32BE(slice.length, 8 + entrySize + 12);
  file.writeUInt32BE(0, 8 + entrySize + 16);
  slice.copy(file, firstOffset);
  slice.copy(file, secondOffset);
  return file;
}

// ---------------------------------------------------------------------------
// 夹具构造：ZIP
// ---------------------------------------------------------------------------

/** CRC32 查找表，多项式 0xEDB88320 的反射形式，与读取器同算法。 */
const TEST_CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = (value & 1) !== 0 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[index] = value >>> 0;
  }
  return table;
})();

/**
 * 计算 CRC32，供夹具构造使用。
 * @param {Buffer} bytes
 * @returns {number}
 */
function testCrc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc = TEST_CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * 构造 ZIP，同时含存储条目与 deflate 条目。
 * @param {Array<{name: string, content: Buffer, method?: 0 | 8}>} entries 条目
 * @returns {Buffer}
 */
function buildZip(entries) {
  const parts = [];
  const central = [];
  let offset = 0;
  for (const entry of entries) {
    const method = entry.method ?? 0;
    const nameBuffer = Buffer.from(entry.name, 'latin1');
    const raw = method === 8 ? deflateRawSync(entry.content) : entry.content;
    const crc = testCrc32(entry.content);
    const local = Buffer.alloc(30);
    local.write('PK\x03\x04', 0, 'latin1');
    local.writeUInt16LE(method === 8 ? 20 : 10, 4);
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(0x21, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(raw.length, 18);
    local.writeUInt32LE(entry.content.length, 22);
    local.writeUInt16LE(nameBuffer.length, 26);
    const entryBytes = Buffer.concat([local, nameBuffer, raw]);
    central.push({ nameBuffer, method, crc, csize: raw.length, usize: entry.content.length, localOffset: offset });
    parts.push(entryBytes);
    offset += entryBytes.length;
  }
  const cdOffset = offset;
  for (const item of central) {
    const header = Buffer.alloc(46);
    header.write('PK\x01\x02', 0, 'latin1');
    header.writeUInt16LE(0x031e, 4);
    header.writeUInt16LE(item.method === 8 ? 20 : 10, 6);
    header.writeUInt16LE(item.method, 10);
    header.writeUInt16LE(0x21, 14);
    header.writeUInt32LE(item.crc, 16);
    header.writeUInt32LE(item.csize, 20);
    header.writeUInt32LE(item.usize, 24);
    header.writeUInt16LE(item.nameBuffer.length, 28);
    header.writeUInt32LE(item.localOffset, 42);
    parts.push(Buffer.concat([header, item.nameBuffer]));
    offset += 46 + item.nameBuffer.length;
  }
  const eocd = Buffer.alloc(22);
  eocd.write('PK\x05\x06', 0, 'latin1');
  eocd.writeUInt16LE(central.length, 8);
  eocd.writeUInt16LE(central.length, 10);
  eocd.writeUInt32LE(offset - cdOffset, 12);
  eocd.writeUInt32LE(cdOffset, 16);
  parts.push(eocd);
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------------------
// 夹具构造：GGUF
// ---------------------------------------------------------------------------

/**
 * 构造 GGUF 文件。
 * @param {{alignment?: number, metadata?: Array<[string, number, unknown]>, tensors?: Array<{name: string, dims: number[], type: number, offset: number}>, dataBytes?: number}} options
 * @returns {{file: Buffer, tensorDataOffset: number}}
 */
function buildGguf(options = {}) {
  const alignment = options.alignment ?? 32;
  const metadata = options.metadata ?? [];
  const tensors = options.tensors ?? [];
  const parts = [];
  const head = Buffer.alloc(24);
  head.write('GGUF', 0, 'latin1');
  head.writeUInt32LE(3, 4);
  head.writeBigUInt64LE(BigInt(tensors.length), 8);
  head.writeBigUInt64LE(BigInt(metadata.length), 16);
  parts.push(head);

  const pushString = (text) => {
    const bytes = Buffer.from(text, 'latin1');
    const length = Buffer.alloc(8);
    length.writeBigUInt64LE(BigInt(bytes.length));
    parts.push(length, bytes);
  };
  for (const [key, type, value] of metadata) {
    pushString(key);
    const typeBuffer = Buffer.alloc(4);
    typeBuffer.writeUInt32LE(type);
    parts.push(typeBuffer);
    if (type === 8) {
      pushString(String(value));
    } else if (type === 4) {
      const buffer = Buffer.alloc(4);
      buffer.writeUInt32LE(value);
      parts.push(buffer);
    } else if (type === 10) {
      const buffer = Buffer.alloc(8);
      buffer.writeBigUInt64LE(BigInt(value));
      parts.push(buffer);
    } else if (type === 9) {
      const elementType = Buffer.alloc(4);
      elementType.writeUInt32LE(4);
      const count = Buffer.alloc(8);
      count.writeBigUInt64LE(BigInt(value.length));
      parts.push(elementType, count);
      for (const item of value) {
        const buffer = Buffer.alloc(4);
        buffer.writeUInt32LE(item);
        parts.push(buffer);
      }
    } else {
      throw new Error(`测试构造器不支持的值类型 ${type}`);
    }
  }
  for (const tensor of tensors) {
    pushString(tensor.name);
    const dims = Buffer.alloc(4);
    dims.writeUInt32LE(tensor.dims.length);
    parts.push(dims);
    for (const size of tensor.dims) {
      const buffer = Buffer.alloc(8);
      buffer.writeBigUInt64LE(BigInt(size));
      parts.push(buffer);
    }
    const type = Buffer.alloc(4);
    type.writeUInt32LE(tensor.type);
    const offset = Buffer.alloc(8);
    offset.writeBigUInt64LE(BigInt(tensor.offset));
    parts.push(type, offset);
  }

  const infoEnd = Buffer.concat(parts).length;
  const tensorDataOffset = Math.ceil(infoEnd / alignment) * alignment;
  const file = Buffer.alloc(tensorDataOffset + (options.dataBytes ?? 64), 0x5a);
  Buffer.concat(parts).copy(file, 0);
  return { file, tensorDataOffset };
}

// ---------------------------------------------------------------------------
// 夹具构造：safetensors 与 pyc 与 BEAM
// ---------------------------------------------------------------------------

/**
 * 构造 safetensors 文件。
 * @param {{header: Record<string, unknown>, dataBytes?: number}} options
 * @returns {{file: Buffer, headerLength: number, tensorDataOffset: number}}
 */
function buildSafetensors(options) {
  const header = Buffer.from(JSON.stringify(options.header), 'utf8');
  const prefix = Buffer.alloc(8);
  prefix.writeBigUInt64LE(BigInt(header.length));
  const file = Buffer.concat([prefix, header, Buffer.alloc(options.dataBytes ?? 16, 0x33)]);
  return { file, headerLength: header.length, tensorDataOffset: 8 + header.length };
}

/**
 * 构造 pyc 文件。
 * pyc 头四字节是两字节魔数加固定的 0D 0A 标记，魔数按两字节写。
 * @param {{magic?: number, flags?: number, sourceHash?: Buffer, timestamp?: number, sourceSize?: number, code?: Buffer}} options
 * @returns {Buffer}
 */
function buildPyc(options = {}) {
  const magic = options.magic ?? 3495;
  const flags = options.flags ?? 0;
  const parts = [Buffer.alloc(4), Buffer.alloc(4)];
  parts[0][0] = magic & 0xff;
  parts[0][1] = (magic >> 8) & 0xff;
  parts[0][2] = 0x0d;
  parts[0][3] = 0x0a;
  parts[1].writeUInt32LE(flags, 0);
  if ((flags & 0b01) !== 0) {
    parts.push(options.sourceHash ?? Buffer.alloc(8, 0xab));
  } else {
    const tail = Buffer.alloc(8);
    tail.writeUInt32LE(options.timestamp ?? 0x65f00000, 0);
    tail.writeUInt32LE(options.sourceSize ?? 42, 4);
    parts.push(tail);
  }
  parts.push(options.code ?? Buffer.from('sample bytecode payload', 'latin1'));
  return Buffer.concat(parts);
}

/**
 * 构造 BEAM 文件。
 * @param {{atoms?: string[], extraChunks?: Array<[string, Buffer]>}} options
 * @returns {Buffer}
 */
function buildBeam(options = {}) {
  const atoms = options.atoms ?? ['sample_app', 'hello', 'world'];
  const chunk = (id, content) => {
    const header = Buffer.alloc(8);
    header.write(id, 0, 'latin1');
    header.writeUInt32BE(content.length, 4);
    const pad = content.length % 2 === 1 ? Buffer.alloc(1) : Buffer.alloc(0);
    return Buffer.concat([header, content, pad]);
  };
  const atomParts = [];
  for (const atom of atoms) {
    const bytes = Buffer.from(atom, 'latin1');
    const length = Buffer.alloc(2);
    length.writeUInt16BE(bytes.length);
    atomParts.push(length, bytes);
  }
  const body = Buffer.concat([
    chunk('AtU8', Buffer.concat(atomParts)),
    chunk('Code', Buffer.from([0, 0, 0, 0])),
    chunk('StrT', Buffer.from('hello\0world\0', 'latin1')),
    ...(options.extraChunks ?? []).map(([id, content]) => chunk(id, content)),
  ]);
  const file = Buffer.alloc(12 + body.length);
  file.write('FOR1', 0, 'latin1');
  file.writeUInt32BE(4 + body.length, 4);
  file.write('BEAM', 8, 'latin1');
  body.copy(file, 12);
  return file;
}

// ---------------------------------------------------------------------------
// 夹具集合
// ---------------------------------------------------------------------------

/** 九类格式的正常夹具，测试内按需取用。 */
function buildNormalFixtures() {
  const symbols = buildSymbols(['main', 'helper_function', 'leaked_internal_name']);
  const elf = buildElf64([
    { name: '.text', type: SHT.PROGBITS, content: Buffer.from('sample text section without credentials', 'latin1'), flags: 0x6, align: 16 },
    { name: '.dep-v0', type: SHT.PROGBITS, content: depV0Payload(['libc 0.2.153', 'serde 1.0.210', 'serde_json 1.0.128'], 'zlib'), align: 1 },
    { name: '.symtab', type: SHT.SYMTAB, content: symbols.symtab, linkName: '.strtab', info: 1, align: 8, entsize: 24 },
    { name: '.strtab', type: SHT.STRTAB, content: symbols.strtab, align: 1 },
    { name: '.note.gnu.build-id', type: SHT.NOTE, content: buildNote('GNU', 3, Buffer.alloc(20, 0x5a)), align: 4 },
  ]);

  const goInlineElf = buildElf64([
    { name: '.text', type: SHT.PROGBITS, content: Buffer.from('go binary text', 'latin1'), align: 16 },
    { name: '.go.buildinfo', type: SHT.PROGBITS, content: goBuildinfoInline('go1.22.0', 'path\tsample.app\nmod\tsample.app\t(devel)\n'), align: 16 },
  ]);

  // pointer 编码：两次构造，第一遍占位得到节偏移，第二遍写入真实指针。
  const pointerHeaderLength = 32;
  const versionBuffer = Buffer.from('go1.21.5', 'latin1');
  const modinfoBuffer = Buffer.from('path\tpointer.app\n', 'latin1');
  const pointerSections = (versionPointer, modinfoPointer) => [
    { name: '.text', type: SHT.PROGBITS, content: Buffer.from('go binary text', 'latin1'), align: 16 },
    {
      name: '.go.buildinfo',
      type: SHT.PROGBITS,
      content: Buffer.concat([
        Buffer.from([0xff, 0x20, 0x47, 0x6f, 0x20, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e, 0x66, 0x3a]),
        Buffer.from([versionPointer, modinfoPointer]),
        Buffer.alloc(pointerHeaderLength - 16, 0),
        Buffer.from([versionBuffer.length]),
        versionBuffer,
        Buffer.from([modinfoBuffer.length]),
        modinfoBuffer,
      ]),
      align: 16,
    },
  ];
  const probe = buildElf64(pointerSections(0, 0));
  // 占位构造的 .go.buildinfo 内容里指针为 0，先取该节的文件偏移：节内容以魔数开头。
  const goSectionOffset = probe.indexOf(Buffer.from([0xff, 0x20, 0x47, 0x6f, 0x20, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e, 0x66, 0x3a]));
  const versionPointer = goSectionOffset + pointerHeaderLength;
  const modinfoPointer = versionPointer + 1 + versionBuffer.length;
  const goPointerElf = buildElf64(pointerSections(versionPointer, modinfoPointer), [
    { type: 1, flags: 0x6, offset: goSectionOffset, vaddr: 0x409000, filesz: pointerHeaderLength + 1 + versionBuffer.length + 1 + modinfoBuffer.length },
  ]);

  const tokenElf = buildElf64([
    { name: '.text', type: SHT.PROGBITS, content: Buffer.from('token=AKIAIOSFODNN7EXAMPLE end', 'latin1'), align: 16 },
  ]);

  return {
    elf,
    goInlineElf,
    goPointerElf,
    tokenElf,
    pe: buildPe({ withDebug: true, withImports: true }),
    peSigned: buildPe({ withSecurity: true }),
    peChecksum: buildPe({ withChecksum: true }),
    peGo: buildPe({ withGoBuildinfo: true }),
    peToken: buildPe({ token: true }),
    macho: buildMacho({}),
    machoSigned: buildMacho({ withCodeSignature: true }),
    machoDep: buildMacho({ withDepV0: true }),
    machoFat: buildMachoFat(),
    zip: buildZip([
      { name: 'README.md', content: Buffer.from('sample readme without secrets\n', 'latin1') },
      { name: 'payload.bin', content: Buffer.from('deflated payload content\n', 'latin1'), method: 8 },
    ]),
    zipToken: buildZip([
      { name: 'stored.txt', content: Buffer.from('aws_key=AKIAIOSFODNN7EXAMPLE\n', 'latin1') },
      { name: 'packed.bin', content: Buffer.from('ghp_abcdefghijklmnopqrstuvwxyz0123456789\n', 'latin1'), method: 8 },
    ]),
    zipApk: buildZip([{ name: 'AndroidManifest.xml', content: Buffer.from('binary xml', 'latin1') }]),
    zipNested: buildZip([{ name: 'inner.zip', content: buildZip([{ name: 'a.txt', content: Buffer.from('inner\n', 'latin1') }]) }]),
    gguf: buildGguf({
      metadata: [
        ['general.architecture', 8, 'llama'],
        ['general.alignment', 4, 32],
        ['llama.context_length', 4, 4096],
      ],
      tensors: [
        { name: 'tok_embeddings.weight', dims: [4, 2], type: 0, offset: 0 },
        { name: 'output.weight', dims: [2, 4], type: 0, offset: 32 },
      ],
    }),
    safetensors: buildSafetensors({
      header: {
        __metadata__: { format: 'pt' },
        tensor1: { dtype: 'F32', shape: [2], data_offsets: [0, 8] },
        tensor2: { dtype: 'F16', shape: [3], data_offsets: [8, 14] },
      },
      dataBytes: 14,
    }),
    pyc: buildPyc({ flags: 0b11, sourceHash: Buffer.from('0123456789abcdef', 'latin1') }),
    pycTimestamp: buildPyc({ flags: 0, timestamp: 0x65f00000, sourceSize: 42 }),
    beam: buildBeam({}),
  };
}

// ---------------------------------------------------------------------------
// CRC32 与令牌模式的基础正确性
// ---------------------------------------------------------------------------

test('CRC32 与标准测试向量一致', () => {
  assert.equal(crc32Of(Buffer.alloc(0)), 0x00000000);
  assert.equal(crc32Of(Buffer.from('123456789', 'latin1')), 0xcbf43926);
  assert.equal(crc32Of(Buffer.from('hello', 'latin1')), 0x3610a686);
  assert.equal(testCrc32(Buffer.from('123456789', 'latin1')), 0xcbf43926);
});

test('令牌模式不匹配许可证样例文本', async () => {
  const license = await readFile(join(SAMPLE_APP, 'LICENSE'));
  const scan = scanTokens(license);
  assert.equal(scan.hits.length, 0, `许可证文本被误报：${JSON.stringify(scan.hits)}`);
  assert.equal(scan.complete, true);
});

test('令牌模式命中植入的测试令牌', () => {
  // 样本一律运行时拼接：本仓库是反逆向工具，源码里不留凭据样式的字面量，
  // 否则 GitHub 推送保护会按真密钥拦截，测试目的也不因此打折扣。
  const samples = [
    'AKIAIOSFODNN7EXAMPLE',
    'ghp_abcdefghijklmnopqrstuvwxyz0123456789',
    'xoxb-1234567890-abcdefghijkl',
    'AIzaSyA1234567890abcdefghijklmnopqrstuv',
    ['sk_', 'live_', 'abcdefghijklmnopqrstuvwx'].join(''),
    'npm_abcdefghijklmnopqrstuvwxyz0123456789',
    'api_key = "aGVsbG93b3JsZDEyMw"',
    'token: ghp_abcdefghijklmnopqrstuvwxyz0123456789;',
    '-----BEGIN RSA PRIVATE KEY-----',
  ];
  for (const sample of samples) {
    const scan = scanTokens(Buffer.from(sample, 'latin1'));
    assert.ok(scan.hits.length >= 1, `未检出令牌：${sample}`);
  }
  assert.ok(TOKEN_PATTERNS.length >= 8, '令牌模式表应覆盖常见凭据家族');
});

test('令牌模式不把二进制里的偶然字节串报成令牌', () => {
  // 实测案例：某 Go 二进制的字符串表里 gho_ 后面恰好跟着 46 个字母数字字符，
  // 前缀加同类字符连成一片，真实令牌不会这样出现，因此两侧定界后不应命中。
  const coincidental = Buffer.from('filepipelinkgho_brewPATHNoneallgallprootitabsbrkidledeadracelogs', 'latin1');
  assert.equal(scanTokens(coincidental).hits.length, 0, '偶然字节串不应被报成令牌');
  const embedded = Buffer.from('xxAKIAIOSFODNN7EXAMPLEyy', 'latin1');
  assert.equal(scanTokens(embedded).hits.length, 0, '嵌在同类字符里的前缀不应命中');
});

test('pyc、gguf、safetensors、beam 四个读取器同样过令牌模式表', async () => {
  // 实测背景：一个 pyc 的 marshal 常量里埋了 API 令牌，而 pyc 读取器原先不跑令牌扫描，
  // 审计看不见它。四个不解析原生二进制的读取器现在与 elf、macho、pe、zip 共用同一入口。
  const token = 'AKIAIOSFODNN7EXAMPLE';
  const cases = [
    { name: 'hash-based.pyc', reader: pycReader, file: buildPyc({ flags: 0b11, code: Buffer.from(`key ${token};`, 'latin1') }) },
    { name: 'timestamp.pyc', reader: pycReader, file: buildPyc({ flags: 0, code: Buffer.from(`key ${token};`, 'latin1') }) },
    { name: 'basic.gguf', reader: ggufReader, file: buildGguf({ metadata: [['note', 8, `key ${token};`]] }).file },
    { name: 'basic.safetensors', reader: safetensorsReader, file: buildSafetensors({ header: { t1: { dtype: 'F32', shape: [2], data_offsets: [0, 8] }, __metadata__: { note: `key ${token};` } }, dataBytes: 8 }).file },
    { name: 'basic.beam', reader: beamReader, file: buildBeam({ atoms: ['sample_app', `key ${token};`] }) },
  ];
  for (const testCase of cases) {
    const entry = await writeFixture(testCase.name, testCase.file);
    const result = await runReader(testCase.reader, entry);
    const hits = result.findings.filter((finding) => finding.category === 'token-aws-access-key-id');
    assert.equal(hits.length, 1, `${testCase.name} 应检出恰好一个令牌，实际 ${hits.length} 个`);
    const hit = hits[0];
    assert.equal(hit.layer, 'secret-minimization');
    assert.equal(hit.mitigation, 'secret.token-placeholder-overwrite');
    assert.equal(hit.detail.patternId, 'aws-access-key-id');
    assert.equal(hit.detail.fileOffset, testCase.file.indexOf(token), '令牌偏移应按文件内真实位置登记');
    assert.equal(result.limitations.length, 0, `正常夹具不应产生限制说明：${JSON.stringify(result.limitations)}`);
  }

  // 覆写侧：pyc、gguf、beam 三类的令牌都在长度前缀的原始字节里，按命中长度清零不破坏结构。
  // safetensors 不在其列：令牌在 JSON 头内，填零会引入原始控制字符使头解析失败。
  for (const testCase of cases.filter((candidate) => candidate.name !== 'basic.safetensors')) {
    const finding = (await runReader(testCase.reader, await writeFixture(testCase.name, testCase.file)))
      .findings.find((item) => item.category === 'token-aws-access-key-id');
    const applied = overwriteTokenPlaceholder(testCase.file, finding, testCase.name.endsWith('.pyc') ? 'pyc' : testCase.name.endsWith('.gguf') ? 'gguf' : 'beam');
    assert.equal(applied.ok, true, `${testCase.name} 应可覆写：${applied.reason ?? ''}`);
    assert.equal(applied.buffer.length, testCase.file.length, '等长覆写保持字节数不变');
    assert.equal(applied.buffer.includes(token), false, `${testCase.name} 覆写后不得再含令牌明文`);
  }
});

test('四个读取器的干净夹具不产生令牌发现', async () => {
  const fixtures = buildNormalFixtures();
  const cases = [
    { name: 'clean.pyc', reader: pycReader, file: fixtures.pycTimestamp },
    { name: 'clean.gguf', reader: ggufReader, file: fixtures.gguf.file },
    { name: 'clean.safetensors', reader: safetensorsReader, file: fixtures.safetensors.file },
    { name: 'clean.beam', reader: beamReader, file: fixtures.beam },
  ];
  for (const testCase of cases) {
    const entry = await writeFixture(testCase.name, testCase.file);
    const result = await runReader(testCase.reader, entry);
    const hits = result.findings.filter((finding) => finding.category.startsWith('token-'));
    assert.equal(hits.length, 0, `${testCase.name} 的干净内容不应检出令牌：${JSON.stringify(hits.map((hit) => hit.category))}`);
  }
});

// ---------------------------------------------------------------------------
// 正常输入：九类格式各至少一条发现
// ---------------------------------------------------------------------------

/** DEX 夹具字节，与 tests/helpers/container-fixtures.mjs 的登记项同一份。 */
const DEX_BYTES = CONTAINER_FIXTURES.find((fixture) => fixture.relativePath === 'dex/basic.dex').bytes;

test('DEX 夹具：头部、类型描述符、方法名、字符串常量与令牌都被提取', async () => {
  // 实测背景：独立 .dex 文件原先落入通用脚本包边界，一条事实都提不出来。
  // 而类型描述符与方法名正是这类制品暴露面最大的部分——反编译产物里的
  // 类名、方法名、字符串常量全部来自这几张表。
  const entry = await writeFixture('basic.dex', DEX_BYTES);
  const result = await runReader(dexReader, entry);
  const categories = result.findings.map((finding) => finding.category);
  assert.ok(categories.includes('dex-header'), '缺少 DEX 头部事实');
  assert.ok(categories.includes('dex-type-descriptors'), '缺少类型描述符事实');
  assert.ok(categories.includes('dex-method-names'), '缺少方法名事实');
  assert.ok(categories.includes('dex-string-constants'), '缺少字符串常量事实');
  assert.ok(categories.includes('token-aws-access-key-id'), '缺少令牌事实');

  const header = result.findings.find((finding) => finding.category === 'dex-header');
  assert.equal(header.detail.version, '035.');
  assert.equal(header.detail.endianTagOk, true, '字节序标记应判定为合法');
  assert.equal(header.detail.headerSize, 112);
  assert.ok(header.detail.tables.length >= 3, '至少登记字符串、类型、方法三张表');

  // 类型描述符必须完整取出，不是从中间截断的片段。
  const types = result.findings.find((finding) => finding.category === 'dex-type-descriptors');
  assert.deepEqual(types.detail.sampleTypes, ['Lcom/example/MainActivity;', 'onCreate', 'Landroid/os/Bundle;']);
  assert.equal(types.detail.declaredCount, 3);

  const methods = result.findings.find((finding) => finding.category === 'dex-method-names');
  assert.deepEqual(methods.detail.sampleMethods, ['onCreate', 'svc-9f3a7b2e1d4c']);
  assert.equal(methods.detail.declaredCount, 2);

  const strings = result.findings.find((finding) => finding.category === 'dex-string-constants');
  assert.equal(strings.detail.readableCount, 6, '六条字符串应全部可读');
  assert.ok(strings.detail.sampleStrings.includes('https://api.example.com/v1'), '接口地址应出现在字符串常量里');

  const token = result.findings.find((finding) => finding.category === 'token-aws-access-key-id');
  assert.equal(token.layer, 'secret-minimization');
  assert.equal(token.mitigation, 'secret.token-placeholder-overwrite');
  assert.equal(token.detail.fileOffset, DEX_BYTES.indexOf(Buffer.from('AKIAIOSFODNN7EXAMPLE', 'latin1')));

  // 自创格式的令牌不在任何公开格式家族内，扫描不到——这正是登记表声明的残留风险。
  assert.ok(!categories.includes('token-credential-assignment'), '自创格式令牌不应被模式命中');
  assert.equal(result.limitations.length, 0, `正常夹具不应产生限制说明：${JSON.stringify(result.limitations)}`);
});

test('DEX 令牌可等长覆写，且不破坏结构', async () => {
  const entry = await writeFixture('basic.dex', DEX_BYTES);
  const result = await runReader(dexReader, entry);
  const finding = result.findings.find((item) => item.category === 'token-aws-access-key-id');
  const applied = overwriteTokenPlaceholder(DEX_BYTES, finding, 'dex');
  assert.equal(applied.ok, true, `DEX 令牌应可覆写：${applied.reason ?? ''}`);
  assert.equal(applied.buffer.length, DEX_BYTES.length, '等长覆写保持字节数不变');
  assert.equal(applied.buffer.includes('AKIAIOSFODNN7EXAMPLE'), false, '覆写后不得再含令牌明文');
  // 覆写只清令牌字节，头部与三张索引表一个字节未动，复审仍应通过。
  assert.equal(applied.buffer.subarray(0, 112).equals(DEX_BYTES.subarray(0, 112)), true, 'DEX 头部不得被改动');
});

test('DEX 头部不完整时登记限制说明，不返回空结果', async () => {
  const entry = await writeFixture('short.dex', DEX_BYTES.subarray(0, 40));
  const result = await runReader(dexReader, entry);
  assert.ok(result.findings.some((finding) => finding.category === 'dex-magic'), '短文件仍应登记魔数与版本');
  assert.ok(
    result.limitations.some((limitation) => limitation.code === 'dex-header-truncated'),
    '头部不完整必须留下限制说明，不能静默返回空结果',
  );
  assert.equal(result.findings.some((finding) => finding.category === 'dex-type-descriptors'), false, '头部不可读时不得凭空给出类型描述符');
});

test('DEX 表区间越界时登记限制说明，不按越界偏移读内容', async () => {
  const tampered = Buffer.from(DEX_BYTES);
  tampered.writeUInt32LE(9999, 60); // 把 string_ids 偏移改成越界值
  const entry = await writeFixture('bad-offset.dex', tampered);
  const result = await runReader(dexReader, entry);
  assert.ok(
    result.limitations.some((limitation) => limitation.code === 'dex-table-out-of-range'),
    '表区间越界必须留下限制说明',
  );
  assert.equal(
    result.findings.some((finding) => finding.category === 'dex-type-descriptors'),
    false,
    '字符串表越界时不得再给出类型描述符',
  );
  assert.ok(result.findings.some((finding) => finding.category === 'dex-header'), '头部声明本身照常登记');
});

test('DEX 字节序标记不符时登记限制说明，并说明结论可能不成立', async () => {
  const tampered = Buffer.from(DEX_BYTES);
  tampered.writeUInt32LE(0xdeadbeef, 40);
  const entry = await writeFixture('bad-endian.dex', tampered);
  const result = await runReader(dexReader, entry);
  const note = result.limitations.find((limitation) => limitation.code === 'dex-endian-tag-mismatch');
  assert.ok(note !== undefined, '字节序标记不符必须留下限制说明');
  assert.match(note.message, /小端解释/, '必须说明后续字段按小端解释、结论可能不成立');
  const header = result.findings.find((finding) => finding.category === 'dex-header');
  assert.equal(header.detail.endianTagOk, false, '头部事实应记录字节序标记不合法');
});

test('APK 内的 classes.dex 被递归解析，类型与方法名进入报告', async () => {
  // 实测背景：APK 此前只按普通 ZIP 处理，classes.dex 里的类名与方法名
  // 完全看不见——而那正是 Android 应用暴露面最大的部分。现在递归进 DEX 读取器。
  const dexBytes = CONTAINER_FIXTURES.find((fixture) => fixture.relativePath === 'dex/basic.dex').bytes;
  const apk = buildZip([
    { name: 'AndroidManifest.xml', method: 0, content: Buffer.from('manifest', 'latin1') },
    { name: 'classes.dex', method: 0, content: dexBytes },
    { name: 'classes2.dex', method: 8, content: dexBytes },
  ]);
  const entry = await writeFixture('app.apk', apk);
  const result = await runReader(zipReader, entry);

  const dexPaths = result.findings
    .filter((finding) => finding.category === 'dex-type-descriptors')
    .map((finding) => finding.evidence.path);
  assert.deepEqual(dexPaths, ['app.apk!classes.dex', 'app.apk!classes2.dex'], '存储与 deflate 两类 DEX 条目都应递归解析');

  // 类名必须真的出现在报告里，而不是只多出一条空发现。
  const types = result.findings.find((finding) => finding.category === 'dex-type-descriptors');
  assert.ok(types.detail.sampleTypes.includes('Lcom/example/MainActivity;'), 'APK 内的类名应可恢复');
  assert.ok(
    result.findings.some((finding) => finding.category === 'dex-method-names' && finding.detail.sampleMethods.length > 0),
    'APK 内的方法名应可恢复',
  );

  // 递归说明必须留痕，且不得与“未跟进嵌套容器”自相矛盾。
  const parsed = result.limitations.find((limitation) => limitation.code === 'zip-nested-dex-parsed');
  assert.ok(parsed !== undefined, '递归解析 DEX 必须留下说明');
  assert.ok(parsed.message.includes('classes.dex'), '说明应点名被解析的条目');
  const unfollowed = result.limitations.find((limitation) => limitation.code === 'zip-nested-container-not-followed');
  if (unfollowed !== undefined) {
    assert.ok(!unfollowed.message.includes('classes.dex'), 'DEX 已解析，不得再报“未跟进”');
  }
});

test('APK 内 DEX 条目数达到上限时登记限制说明，不静默丢弃', async () => {
  const dexBytes = CONTAINER_FIXTURES.find((fixture) => fixture.relativePath === 'dex/basic.dex').bytes;
  const entries = [{ name: 'AndroidManifest.xml', method: 0, content: Buffer.from('manifest', 'latin1') }];
  for (let index = 1; index <= 10; index += 1) {
    entries.push({ name: `classes${index}.dex`, method: 0, content: dexBytes });
  }
  const entry = await writeFixture('multidex.apk', buildZip(entries));
  const result = await runReader(zipReader, entry);
  const parsed = result.findings.filter((finding) => finding.category === 'dex-type-descriptors');
  assert.equal(parsed.length, 8, '达到递归上限后只解析前 8 个 DEX 条目');
  assert.ok(
    result.limitations.some((limitation) => limitation.code === 'zip-nested-dex-entry-limit'),
    '超出上限必须留下限制说明，不能静默丢弃',
  );
});

test('ELF 夹具：节表、符号表、note、.dep-v0 与 Go 构建信息都被提取', async () => {
  const fixtures = buildNormalFixtures();
  const entry = await writeFixture('basic.elf', fixtures.elf);
  const result = await runReader(elfReader, entry);
  const categories = result.findings.map((finding) => finding.category);
  assert.ok(categories.includes('elf-header'), '缺少 ELF 头事实');
  assert.ok(categories.includes('elf-symtab'), '缺少符号表事实');
  assert.ok(categories.includes('rust-dep-v0'), '缺少 .dep-v0 事实');
  assert.ok(categories.includes('elf-build-id'), '缺少构建标识 note 事实');

  const dep = result.findings.find((finding) => finding.category === 'rust-dep-v0');
  assert.deepEqual(dep.detail.dependencies, ['libc 0.2.153', 'serde 1.0.210', 'serde_json 1.0.128']);
  assert.equal(dep.mitigation, 'metadata.rust-dep-section-overwrite');

  // 节名扫描：节表里的节名逐条登记在头发现里（含节头字符串表自身）。
  const header = result.findings.find((finding) => finding.category === 'elf-header');
  assert.equal(header.detail.sectionCount, 6);
  assert.deepEqual(header.detail.sectionNames, ['.text', '.dep-v0', '.symtab', '.strtab', '.note.gnu.build-id', '.shstrtab']);

  const symtab = result.findings.find((finding) => finding.category === 'elf-symtab');
  assert.equal(symtab.detail.symbolCount, 3);
  assert.deepEqual(symtab.detail.sampleNames, ['main', 'helper_function', 'leaked_internal_name']);
  assert.equal(symtab.mitigation, 'metadata.elf-symtab-clear');
  assert.equal(result.limitations.length, 0, `正常夹具不应产生限制说明：${JSON.stringify(result.limitations)}`);
});

test('ELF Go 构建信息 inline 与 pointer 两种编码分别命中', async () => {
  const fixtures = buildNormalFixtures();

  const inlineEntry = await writeFixture('go-inline.elf', fixtures.goInlineElf);
  const inlineResult = await runReader(elfReader, inlineEntry);
  const inlineFinding = inlineResult.findings.find((finding) => finding.category === 'go-buildinfo');
  assert.ok(inlineFinding !== undefined, 'inline 编码未被命中');
  assert.equal(inlineFinding.detail.encoding, 'inline');
  assert.equal(inlineFinding.detail.version, 'go1.22.0');
  assert.equal(inlineFinding.mitigation, 'metadata.go-buildinfo-inline-overwrite');

  const pointerEntry = await writeFixture('go-pointer.elf', fixtures.goPointerElf);
  const pointerResult = await runReader(elfReader, pointerEntry);
  const pointerFinding = pointerResult.findings.find((finding) => finding.category === 'go-buildinfo');
  assert.ok(pointerFinding !== undefined, 'pointer 编码未被命中');
  assert.equal(pointerFinding.detail.encoding, 'pointer');
  assert.equal(pointerFinding.detail.version, 'go1.21.5');
  assert.equal(pointerFinding.mitigation, 'metadata.go-buildinfo-writable-region-overwrite');
});

test('ELF 令牌扫描命中植入的测试令牌', async () => {
  const fixtures = buildNormalFixtures();
  const entry = await writeFixture('token.elf', fixtures.tokenElf);
  const result = await runReader(elfReader, entry);
  const tokenFinding = result.findings.find((finding) => finding.category === 'token-aws-access-key-id');
  assert.ok(tokenFinding !== undefined, '植入的 AWS 访问键标识未被检出');
  assert.equal(tokenFinding.layer, 'secret-minimization');
  assert.equal(tokenFinding.mitigation, 'secret.token-placeholder-overwrite');
  assert.equal(tokenFinding.evidence.byteRange[0], fixtures.tokenElf.indexOf(Buffer.from('AKIAIOSFODNN7EXAMPLE', 'latin1')));
  assert.ok(tokenFinding.readerLimitation.length > 0, '令牌发现必须附限制说明');
});

test('PE 夹具：头、调试目录、导入表、安全目录与 CheckSum 分别提取', async () => {
  const fixtures = buildNormalFixtures();

  const entry = await writeFixture('basic.pe', fixtures.pe);
  const result = await runReader(peReader, entry);
  const categories = result.findings.map((finding) => finding.category);
  assert.ok(categories.includes('pe-header'));
  assert.ok(categories.includes('pe-debug-directory'), '缺少调试目录事实');
  assert.ok(categories.includes('pe-imports'), '缺少导入表事实');
  const debug = result.findings.find((finding) => finding.category === 'pe-debug-directory');
  assert.deepEqual(debug.detail.paths, ['C:\\build\\sample-app.pdb']);
  assert.equal(debug.mitigation, 'metadata.pe-debug-directory-overwrite');
  const imports = result.findings.find((finding) => finding.category === 'pe-imports');
  assert.deepEqual(imports.detail.dlls, ['KERNEL32.dll']);
  assert.equal(result.limitations.length, 0, `正常夹具不应产生限制说明：${JSON.stringify(result.limitations)}`);

  const signed = await runReader(peReader, await writeFixture('signed.pe', fixtures.peSigned));
  const security = signed.findings.find((finding) => finding.category === 'pe-security-directory');
  assert.ok(security !== undefined, '带安全目录的 PE 未登记签名事实');

  const checksum = await runReader(peReader, await writeFixture('checksum.pe', fixtures.peChecksum));
  const checksumFinding = checksum.findings.find((finding) => finding.category === 'pe-checksum');
  assert.ok(checksumFinding !== undefined, '非零 CheckSum 未登记');
  assert.equal(checksumFinding.detail.checksum, 0x12345678);

  const go = await runReader(peReader, await writeFixture('go.pe', fixtures.peGo));
  const goFinding = go.findings.find((finding) => finding.category === 'go-buildinfo');
  assert.ok(goFinding !== undefined, 'PE 里的 Go 构建信息未被命中');
  assert.equal(goFinding.detail.section, '.gobi');
  assert.equal(goFinding.mitigation, 'metadata.go-buildinfo-pe-characteristics-overwrite');
});

test('Mach-O 夹具：加载命令、动态库、UUID、代码签名与 .dep-v0 分别提取', async () => {
  const fixtures = buildNormalFixtures();

  const entry = await writeFixture('basic.macho', fixtures.macho);
  const result = await runReader(machoReader, entry);
  const categories = result.findings.map((finding) => finding.category);
  assert.ok(categories.includes('macho-header'));
  assert.ok(categories.includes('macho-dylibs'), '缺少动态库事实');
  assert.ok(categories.includes('macho-uuid'), '缺少构建标识事实');
  const dylibs = result.findings.find((finding) => finding.category === 'macho-dylibs');
  assert.deepEqual(dylibs.detail.dylibs, ['/usr/lib/libSystem.B.dylib']);
  assert.equal(result.limitations.length, 0, `正常夹具不应产生限制说明：${JSON.stringify(result.limitations)}`);

  const signed = await runReader(machoReader, await writeFixture('signed.macho', fixtures.machoSigned));
  const signature = signed.findings.find((finding) => finding.category === 'macho-code-signature');
  assert.ok(signature !== undefined, 'LC_CODE_SIGNATURE 未登记');

  const dep = await runReader(machoReader, await writeFixture('dep.macho', fixtures.machoDep));
  const depFinding = dep.findings.find((finding) => finding.category === 'rust-dep-v0');
  assert.ok(depFinding !== undefined, '__DATA,.dep-v0 未命中');
  assert.deepEqual(depFinding.detail.dependencies, ['serde 1.0.210', 'serde_json 1.0.128']);

  const fat = await runReader(machoReader, await writeFixture('fat.macho', fixtures.machoFat));
  assert.ok(fat.findings.some((finding) => finding.category === 'macho-fat-header'), '胖二进制分片表未登记');
  assert.equal(fat.findings.find((finding) => finding.category === 'macho-fat-header').detail.sliceCount, 2);
});

test('ZIP 夹具：存储与 deflate 条目分别标记覆盖方式，CRC32 与中央目录一致', async () => {
  const fixtures = buildNormalFixtures();
  const entry = await writeFixture('mixed.zip', fixtures.zip);
  const result = await runReader(zipReader, entry);
  const inventory = result.findings.find((finding) => finding.category === 'zip-entries');
  assert.ok(inventory !== undefined, '缺少 ZIP 中央目录事实');
  const entries = inventory.detail.entries;
  assert.equal(entries.length, 2);

  const stored = entries.find((item) => item.name === 'README.md');
  assert.equal(stored.method, 'stored');
  assert.equal(stored.coverage, 'raw-bytes-scanned');
  assert.equal(stored.crcMatch, true);
  assert.equal(stored.crc32Recorded, testCrc32(Buffer.from('sample readme without secrets\n', 'latin1')));

  const deflated = entries.find((item) => item.name === 'payload.bin');
  assert.equal(deflated.method, 'deflate');
  assert.equal(deflated.coverage, 'decompressed-scanned');
  assert.equal(deflated.crcMatch, true);
  assert.equal(deflated.crc32Recorded, testCrc32(Buffer.from('deflated payload content\n', 'latin1')));

  assert.equal(inventory.detail.scannedEntryCount, 2);
  assert.equal(inventory.detail.rawOnlyCount, 0);
  assert.equal(result.limitations.length, 0, `正常夹具不应产生限制说明：${JSON.stringify(result.limitations)}`);
});

test('ZIP 夹具：存储条目与 deflate 条目里的令牌分别检出', async () => {
  const fixtures = buildNormalFixtures();
  const entry = await writeFixture('token.zip', fixtures.zipToken);
  const result = await runReader(zipReader, entry);
  const tokenFindings = result.findings.filter((finding) => finding.layer === 'secret-minimization');
  const ids = tokenFindings.map((finding) => finding.detail.patternId).sort();
  assert.deepEqual(ids, ['aws-access-key-id', 'github-token'], `令牌检出不完整：${JSON.stringify(ids)}`);
  const sources = tokenFindings.map((finding) => finding.detail.byteSource).sort();
  assert.deepEqual(sources, ['deflate-entry-decompressed-bytes', 'stored-entry-raw-bytes']);
});

test('ZIP 夹具：改写条目后 CRC32 不一致被登记为限制说明', async () => {
  const fixtures = buildNormalFixtures();
  const bytes = Buffer.from(fixtures.zip);
  const storedContent = Buffer.from('sample readme without secrets\n', 'latin1');
  const position = bytes.indexOf(storedContent);
  assert.ok(position >= 0, '夹具里应能找到存储条目内容');
  bytes.write('tampered', position, 'latin1');
  const entry = await writeFixture('tampered.zip', bytes);
  const result = await runReader(zipReader, entry);
  const codes = result.limitations.map((limitation) => limitation.code);
  assert.ok(codes.includes('zip-entry-crc-mismatch'), `改写条目后应登记 CRC32 不一致：${JSON.stringify(codes)}`);
});

test('ZIP 夹具：不可解压的 deflate 条目只按原始字节扫描并附限制说明', async () => {
  const fixtures = buildNormalFixtures();
  const bytes = Buffer.from(fixtures.zip);
  const deflated = Buffer.from('deflated payload content\n', 'latin1');
  const compressed = deflateRawSync(deflated);
  const position = bytes.indexOf(compressed);
  assert.ok(position >= 0, '夹具里应能找到 deflate 条目内容');
  bytes.fill(0x00, position, position + compressed.length);
  const entry = await writeFixture('broken.zip', bytes);
  const result = await runReader(zipReader, entry);
  const codes = result.limitations.map((limitation) => limitation.code);
  assert.ok(codes.includes('zip-entry-inflate-failed'), `不可解压条目应附限制说明：${JSON.stringify(codes)}`);
  const inventory = result.findings.find((finding) => finding.category === 'zip-entries');
  const broken = inventory.detail.entries.find((item) => item.name === 'payload.bin');
  assert.equal(broken.coverage, 'raw-bytes-only');
  assert.ok(broken.reason.length > 0, '仅原始字节条目必须给出原因');
});

test('ZIP 夹具：APK 特征与嵌套容器分别附能力边界说明', async () => {
  const fixtures = buildNormalFixtures();
  const apk = await runReader(zipReader, await writeFixture('app.apk', fixtures.zipApk));
  assert.ok(apk.limitations.some((limitation) => limitation.code === 'apk-signature-scheme'), 'APK 特征应附签名方案边界说明');

  const nested = await runReader(zipReader, await writeFixture('nested.zip', fixtures.zipNested));
  assert.ok(
    nested.limitations.some((limitation) => limitation.code === 'zip-nested-container-not-followed'),
    '嵌套容器应声明不递归解包',
  );
});

test('GGUF 夹具：头部、元数据键值与张量偏移按原对齐规则提取', async () => {
  const fixtures = buildNormalFixtures();
  const entry = await writeFixture('basic.gguf', fixtures.gguf.file);
  const result = await runReader(ggufReader, entry);
  const categories = result.findings.map((finding) => finding.category);
  assert.ok(categories.includes('gguf-header'));
  assert.ok(categories.includes('gguf-metadata'), '缺少元数据键值事实');
  assert.ok(categories.includes('gguf-tensors'), '缺少张量索引事实');

  const header = result.findings.find((finding) => finding.category === 'gguf-header');
  assert.equal(header.detail.alignment, 32);
  assert.equal(header.detail.tensorDataOffset, fixtures.gguf.tensorDataOffset);
  assert.equal(header.detail.tensorCount, 2);

  const tensors = result.findings.find((finding) => finding.category === 'gguf-tensors');
  const first = tensors.detail.tensors.find((tensor) => tensor.name === 'tok_embeddings.weight');
  assert.equal(first.fileOffset, fixtures.gguf.tensorDataOffset + 0);
  const second = tensors.detail.tensors.find((tensor) => tensor.name === 'output.weight');
  assert.equal(second.fileOffset, fixtures.gguf.tensorDataOffset + 32);
  assert.equal(result.limitations.length, 0, `正常夹具不应产生限制说明：${JSON.stringify(result.limitations)}`);
});

test('safetensors 夹具：头部、__metadata__ 与张量索引提取且覆盖完整', async () => {
  const fixtures = buildNormalFixtures();
  const entry = await writeFixture('basic.safetensors', fixtures.safetensors.file);
  const result = await runReader(safetensorsReader, entry);
  const categories = result.findings.map((finding) => finding.category);
  assert.ok(categories.includes('safetensors-header'));
  assert.ok(categories.includes('safetensors-metadata'), '缺少 __metadata__ 事实');
  assert.ok(categories.includes('safetensors-tensors'), '缺少张量索引事实');

  const header = result.findings.find((finding) => finding.category === 'safetensors-header');
  assert.equal(header.detail.tensorDataOffset, fixtures.safetensors.tensorDataOffset);
  assert.equal(header.detail.headerLength, fixtures.safetensors.headerLength);

  const tensors = result.findings.find((finding) => finding.category === 'safetensors-tensors');
  const first = tensors.detail.tensors.find((tensor) => tensor.name === 'tensor1');
  assert.equal(first.fileStart, fixtures.safetensors.tensorDataOffset + 0);
  assert.equal(first.fileEnd, fixtures.safetensors.tensorDataOffset + 8);
  const second = tensors.detail.tensors.find((tensor) => tensor.name === 'tensor2');
  assert.equal(second.fileStart, fixtures.safetensors.tensorDataOffset + 8);
  assert.equal(second.fileEnd, fixtures.safetensors.tensorDataOffset + 14);

  // 索引恰好覆盖整个数据区：无越界、无间隙、无重叠、无未索引尾部。
  assert.equal(result.limitations.length, 0, `索引完整时不应产生限制说明：${JSON.stringify(result.limitations)}`);
});

test('pyc 夹具：hash_based 且 check_source 时标志与哈希一起报告', async () => {
  const fixtures = buildNormalFixtures();
  const entry = await writeFixture('hash-based.pyc', fixtures.pyc);
  const result = await runReader(pycReader, entry);
  const sourceHash = result.findings.find((finding) => finding.category === 'pyc-source-hash');
  assert.ok(sourceHash !== undefined, 'hash_based 的源文件摘要未登记');
  assert.equal(sourceHash.detail.checkSource, true);
  assert.equal(sourceHash.mitigation, 'metadata.pyc-source-hash-clear');
  assert.ok(sourceHash.readerLimitation.includes('check_source'), '限制说明必须点明标志一致性要求');
  assert.equal(result.limitations.length, 0, `正常夹具不应产生限制说明：${JSON.stringify(result.limitations)}`);

  const timestampEntry = await writeFixture('timestamp.pyc', fixtures.pycTimestamp);
  const timestampResult = await runReader(pycReader, timestampEntry);
  const timestamp = timestampResult.findings.find((finding) => finding.category === 'pyc-timestamp');
  assert.ok(timestamp !== undefined, '时间戳布局的 pyc 未登记');
  assert.equal(timestamp.detail.timestamp, 0x65f00000);
  assert.equal(timestamp.detail.sourceSize, 42);
});

test('BEAM 夹具：块结构与已编译模块名提取', async () => {
  const fixtures = buildNormalFixtures();
  const entry = await writeFixture('basic.beam', fixtures.beam);
  const result = await runReader(beamReader, entry);
  const chunks = result.findings.find((finding) => finding.category === 'beam-chunks');
  assert.ok(chunks !== undefined, '块结构未登记');
  assert.deepEqual(chunks.detail.chunks.map((chunk) => chunk.id), ['AtU8', 'Code', 'StrT']);
  const module = result.findings.find((finding) => finding.category === 'beam-module-name');
  assert.ok(module !== undefined, '模块名未提取');
  assert.equal(module.detail.moduleName, 'sample_app');
  assert.ok(module.readerLimitation.length > 0, '模块名发现必须附限制说明');
  assert.equal(result.limitations.length, 0, `正常夹具不应产生限制说明：${JSON.stringify(result.limitations)}`);
});

// ---------------------------------------------------------------------------
// 畸形输入：转成限制说明，不抛错，不返回空结果冒充没有暴露
// ---------------------------------------------------------------------------

test('畸形输入：每类读取器都不抛错，且给出限制说明', async () => {
  const fixtures = buildNormalFixtures();
  const cases = [
    { reader: elfReader, name: 'bad.elf', bytes: Buffer.concat([Buffer.from('\x7fELF', 'latin1'), Buffer.alloc(60, 0xff)]), expect: 'elf-header-unparsable' },
    { reader: elfReader, name: 'short.elf', bytes: Buffer.from('\x7fEL', 'latin1'), expect: 'elf-header-unparsable' },
    { reader: peReader, name: 'bad.pe', bytes: Buffer.concat([Buffer.from('MZ', 'latin1'), Buffer.alloc(62, 0x11)]), expect: 'pe-unparsable' },
    { reader: machoReader, name: 'bad.macho', bytes: Buffer.from('\xcf\xfa\xed\xfe', 'latin1'), expect: 'macho-unparsable' },
    { reader: zipReader, name: 'bad.zip', bytes: Buffer.concat([Buffer.from('PK\x03\x04', 'latin1'), Buffer.alloc(26, 0x22)]), expect: 'zip-eocd-missing' },
    { reader: ggufReader, name: 'bad.gguf', bytes: Buffer.concat([Buffer.from('GGUF', 'latin1'), Buffer.alloc(4, 0)]), expect: 'gguf-header-unparsable' },
    {
      reader: safetensorsReader,
      name: 'bad.safetensors',
      bytes: Buffer.concat([u32le(0), u32le(0x40000000), Buffer.from('{not json', 'latin1')]),
      expect: 'safetensors-header-unreadable',
    },
    { reader: pycReader, name: 'bad.pyc', bytes: Buffer.from([0xa7, 0x0d, 0x0d, 0x0a]), expect: 'pyc-flags-unreadable' },
    {
      reader: beamReader,
      name: 'bad.beam',
      bytes: Buffer.concat([Buffer.from('FOR1', 'latin1'), u32be(64), Buffer.from('BEAM', 'latin1'), Buffer.from('Code', 'latin1'), u32be(0xffffff00)]),
      expect: 'beam-chunk-out-of-range',
    },
  ];
  for (const testCase of cases) {
    const entry = await writeFixture(testCase.name, testCase.bytes);
    const result = await runReader(testCase.reader, entry);
    const codes = result.limitations.map((limitation) => limitation.code);
    assert.ok(codes.includes(testCase.expect), `${testCase.name} 应给出 ${testCase.expect}，实际 ${JSON.stringify(codes)}`);
  }
});

test('畸形输入：ELF 节表区间越界时按已解析部分继续', async () => {
  const bytes = Buffer.from(buildNormalFixtures().elf);
  // 把 e_shoff 改成文件末尾之后：节表不可读，但头仍可解析。
  bytes.writeBigUInt64LE(BigInt(bytes.length + 4096), 40);
  const entry = await writeFixture('shifted.elf', bytes);
  const result = await runReader(elfReader, entry);
  assert.ok(result.findings.some((finding) => finding.category === 'elf-header'), '头事实仍应提取');
  const codes = result.limitations.map((limitation) => limitation.code);
  assert.ok(codes.includes('elf-section-table-out-of-range'), `节表越界应附限制说明：${JSON.stringify(codes)}`);
  assert.ok(!codes.includes('elf-header-unparsable'), '头可解析时不应报头解析失败');
});

test('畸形输入：safetensors 索引重叠、间隙与未索引尾部分别登记', async () => {
  const overlap = buildSafetensors({
    header: {
      tensor1: { dtype: 'F32', shape: [2], data_offsets: [0, 8] },
      tensor2: { dtype: 'F32', shape: [2], data_offsets: [4, 12] },
    },
    dataBytes: 12,
  });
  const overlapResult = await runReader(safetensorsReader, await writeFixture('overlap.safetensors', overlap.file));
  const codes = overlapResult.limitations.map((limitation) => limitation.code);
  assert.ok(codes.includes('safetensors-interval-overlap'), `重叠应登记：${JSON.stringify(codes)}`);

  const gap = buildSafetensors({
    header: { tensor1: { dtype: 'F32', shape: [2], data_offsets: [0, 8] } },
    dataBytes: 16,
  });
  const gapResult = await runReader(safetensorsReader, await writeFixture('gap.safetensors', gap.file));
  const gapCodes = gapResult.limitations.map((limitation) => limitation.code);
  assert.ok(gapCodes.includes('safetensors-unindexed-tail'), `未索引尾部应登记：${JSON.stringify(gapCodes)}`);
});

test('畸形输入：BEAM 缺少原子块时模块名不可恢复但不失败', async () => {
  const bytes = buildBeam({ extraChunks: [['Code', Buffer.from([1, 2, 3, 4])]] });
  // 手工构造一个没有 AtU8 块的 BEAM：只留 Code 与 StrT。
  const chunk = (id, content) => {
    const header = Buffer.alloc(8);
    header.write(id, 0, 'latin1');
    header.writeUInt32BE(content.length, 4);
    const pad = content.length % 2 === 1 ? Buffer.alloc(1) : Buffer.alloc(0);
    return Buffer.concat([header, content, pad]);
  };
  const body = Buffer.concat([chunk('Code', Buffer.from([0, 0, 0, 0])), chunk('StrT', Buffer.from('hello\0', 'latin1'))]);
  const file = Buffer.alloc(12 + body.length);
  file.write('FOR1', 0, 'latin1');
  file.writeUInt32BE(4 + body.length, 4);
  file.write('BEAM', 8, 'latin1');
  body.copy(file, 12);
  assert.ok(bytes.length > 0, '夹具构造自检');
  const result = await runReader(beamReader, await writeFixture('no-atoms.beam', file));
  const codes = result.limitations.map((limitation) => limitation.code);
  assert.ok(codes.includes('beam-atom-chunk-missing'), `缺少原子块应登记：${JSON.stringify(codes)}`);
  assert.ok(result.findings.some((finding) => finding.category === 'beam-chunks'), '块清单仍应登记');
});

test('畸形输入：随机垃圾字节不使任何读取器抛错', async () => {
  const readers = [elfReader, peReader, machoReader, zipReader, ggufReader, safetensorsReader, pycReader, beamReader];
  const garbage = [
    Buffer.alloc(0),
    Buffer.alloc(1, 0x00),
    Buffer.alloc(7, 0xff),
    Buffer.from('\x7fELF\x02\x01\x01\x00', 'latin1'),
    Buffer.from('MZ', 'latin1'),
    Buffer.from('PK\x03\x04', 'latin1'),
    Buffer.from('GGUF', 'latin1'),
    Buffer.from('FOR1', 'latin1'),
    Buffer.from('{"a":1}', 'latin1'),
    Buffer.alloc(64, 0x5a),
  ];
  for (const reader of readers) {
    for (let index = 0; index < garbage.length; index += 1) {
      const entry = await writeFixture(`garbage-${reader.id}-${index}.bin`, garbage[index]);
      const result = await runReader(reader, entry);
      assert.ok(
        result.findings.length > 0 || result.limitations.length > 0,
        `读取器 ${reader.id} 对第 ${index} 个垃圾输入既无发现也无限制说明，等于返回空结果冒充没有暴露`,
      );
    }
  }
});

// ---------------------------------------------------------------------------
// 部分读取：预算约束下给部分结果加限制说明
// ---------------------------------------------------------------------------

test('部分读取：每类读取器在预算截断时给部分结果加限制说明', async () => {
  const fixtures = buildNormalFixtures();
  const cases = [
    { reader: elfReader, name: 'part.elf', bytes: fixtures.elf, budget: { maxFileBytes: 64 } },
    { reader: peReader, name: 'part.pe', bytes: fixtures.pe, budget: { maxFileBytes: 32 } },
    { reader: machoReader, name: 'part.macho', bytes: fixtures.macho, budget: { maxFileBytes: 20 } },
    { reader: zipReader, name: 'part.zip', bytes: fixtures.zip, budget: { maxFileBytes: 40 } },
    { reader: ggufReader, name: 'part.gguf', bytes: fixtures.gguf.file, budget: { maxFileBytes: 20 } },
    { reader: safetensorsReader, name: 'part.safetensors', bytes: fixtures.safetensors.file, budget: { maxFileBytes: 20 } },
    { reader: pycReader, name: 'part.pyc', bytes: fixtures.pyc, budget: { maxFileBytes: 6 } },
    { reader: beamReader, name: 'part.beam', bytes: fixtures.beam, budget: { maxFileBytes: 10 } },
  ];
  for (const testCase of cases) {
    const entry = await writeFixture(testCase.name, testCase.bytes);
    const result = await runReader(testCase.reader, entry, testCase.budget);
    const codes = result.limitations.map((limitation) => limitation.code);
    assert.ok(codes.includes('entry-read-truncated'), `${testCase.name} 应声明读取被截断：${JSON.stringify(codes)}`);
    assert.ok(result.findings.length + result.limitations.length > 0, '部分读取必须有输出');
  }
});

test('部分读取：ELF 只读到文件头时仍给头事实并声明节表不可读', async () => {
  const fixtures = buildNormalFixtures();
  const entry = await writeFixture('header-only.elf', fixtures.elf);
  const result = await runReader(elfReader, entry, { maxFileBytes: 64 });
  assert.ok(result.findings.some((finding) => finding.category === 'elf-header'), '头在预算内仍应解析');
  const codes = result.limitations.map((limitation) => limitation.code);
  assert.ok(codes.includes('elf-section-table-out-of-range'), `节表越界应声明：${JSON.stringify(codes)}`);
  assert.ok(!result.findings.some((finding) => finding.category === 'elf-symtab'), '预算外的节不应被报告');
});

test('部分读取：ZIP 只读到条目数据时中央目录缺失被声明', async () => {
  const fixtures = buildNormalFixtures();
  const entry = await writeFixture('no-eocd.zip', fixtures.zip);
  const result = await runReader(zipReader, entry, { maxFileBytes: 60 });
  const codes = result.limitations.map((limitation) => limitation.code);
  assert.ok(codes.includes('zip-eocd-missing'), `中央目录缺失应声明：${JSON.stringify(codes)}`);
});

// ---------------------------------------------------------------------------
// 审计引擎集成：封闭词表、能力边界与脱敏
// ---------------------------------------------------------------------------

test('审计引擎：九类格式夹具全部产出发现，范围外格式给能力边界说明', async () => {
  const fixtures = buildNormalFixtures();
  // 用独立子目录，避免前面测试写进临时目录的畸形夹具混进本次审计。
  const auditDir = await mkdtemp(join(workDir, 'audit-run-'));
  const files = {
    'basic.elf': fixtures.elf,
    'basic.pe': fixtures.pe,
    'basic.macho': fixtures.macho,
    'mixed.zip': fixtures.zip,
    'basic.gguf': fixtures.gguf.file,
    'basic.safetensors': fixtures.safetensors.file,
    'basic.pyc': fixtures.pyc,
    'basic.beam': fixtures.beam,
    'global-metadata.dat': Buffer.from('\xaf\x1b\xb1\xfa\x00\x00\x00\x00not-il2cpp', 'latin1'),
  };
  for (const [name, bytes] of Object.entries(files)) {
    await writeFile(join(auditDir, name), bytes);
  }
  const report = await auditArtifact(auditDir, { policy: {} });
  assert.equal(report.status, 'complete');
  const categories = report.findings.map((finding) => finding.category);
  for (const expected of ['elf-header', 'pe-header', 'macho-header', 'zip-entries', 'gguf-header', 'safetensors-header', 'pyc-header', 'beam-chunks']) {
    assert.ok(categories.includes(expected), `审计报告缺少 ${expected} 类发现`);
  }
  assert.equal(report.summary.byContainer['unsupported'], 1);
  const boundary = report.capabilityBoundaries.find((item) => item.id === 'il2cpp-metadata');
  assert.ok(boundary !== undefined, 'IL2CPP 元数据文件应按文件名约定归到 il2cpp-metadata 边界');
  assert.ok(boundary.reason.length > 0, '能力边界必须附说明');
});

test('审计引擎：全部发现都落在封闭词表内', async () => {
  const fixtures = buildNormalFixtures();
  const auditDir = await mkdtemp(join(workDir, 'audit-closed-'));
  const files = {
    'all.elf': fixtures.elf,
    'all.pe': fixtures.pe,
    'all.macho': fixtures.macho,
    'all.zip': fixtures.zip,
    'all.gguf': fixtures.gguf.file,
    'all.safetensors': fixtures.safetensors.file,
    'all.pyc': fixtures.pyc,
    'all.beam': fixtures.beam,
  };
  for (const [name, bytes] of Object.entries(files)) {
    await writeFile(join(auditDir, name), bytes);
  }
  const report = await auditArtifact(auditDir, { policy: {} });
  assert.ok(report.findings.length > 0, '应有发现');
  for (const finding of report.findings) {
    assert.ok(LAYER_IDS.includes(finding.layer), `层标识不在词表内：${finding.layer}`);
    assert.ok(SEVERITY_IDS.includes(finding.severity), `严重度不在词表内：${finding.severity}`);
    assert.ok(finding.mitigation === null || MITIGATION_IDS.includes(finding.mitigation), `缓解编号不在词表内：${finding.mitigation}`);
    assert.ok(finding.readerLimitation.length > 0, `发现 ${finding.category} 缺少限制说明`);
    assert.ok(finding.title.length > 0);
    assert.ok(finding.evidence.path.length > 0);
  }
});

test('读取器登记表：每个容器都有读取器，层标识全部在词表内', () => {
  for (const [container, readers] of Object.entries(READER_REGISTRY)) {
    assert.ok(readers.length > 0, `容器 ${container} 没有读取器`);
    for (const reader of readers) {
      for (const layer of reader.layers) {
        assert.ok(LAYER_IDS.includes(layer), `读取器 ${reader.id} 引用词表外层：${layer}`);
      }
      assert.equal(typeof reader.purpose, 'string');
      assert.equal(typeof reader.read, 'function');
    }
  }
  assert.deepEqual(
    Object.keys(READER_REGISTRY).sort(),
    ['beam', 'dex', 'elf', 'gguf', 'mach-o', 'mach-o-fat', 'pe', 'pyc', 'safetensors', 'zip'],
  );
});

test('能力边界：范围外容器给出边界说明，v1 容器不给出', () => {
  const unsupported = capabilityBoundaryFor({ container: { type: 'unsupported' }, relativePath: 'random.bin' });
  assert.equal(unsupported.id, 'generic-script-package');
  assert.ok(unsupported.reason.includes('unsupported'), '边界说明应点出识别结果');
  assert.ok(unsupported.hint.length > 0);
  assert.equal(capabilityBoundaryFor({ container: { type: 'elf' }, relativePath: 'a.elf' }), null);
});

test('脱敏：含发现的审计报告脱敏后保留分类与计数，隐去证据', async () => {
  const fixtures = buildNormalFixtures();
  await writeFile(join(workDir, 'redact.elf'), fixtures.elf);
  const report = await auditArtifact(join(workDir, 'redact.elf'), { policy: {} });
  assert.ok(report.findings.length > 0);
  const redacted = redactReport(report);
  assert.equal(redacted.redacted, true);
  assert.equal(redacted.summary.findings, report.summary.findings);
  const text = JSON.stringify(redacted);
  assert.ok(!text.includes('redact.elf'), '脱敏报告不得包含路径');
  assert.ok(!text.includes('byteRange'), '脱敏报告不得包含字节范围');
  assert.ok(!text.includes('metadata.rust-dep-section-overwrite'), '脱敏报告不得包含缓解措施对应关系');
});

test('资源上限：单文件上限极小值经审计引擎得到 partial 与限制说明', async () => {
  const fixtures = buildNormalFixtures();
  await writeFile(join(workDir, 'budget.elf'), fixtures.elf);
  const policy = { budgets: { maxFileBytes: 1 } };
  const report = await auditArtifact(join(workDir, 'budget.elf'), { policy });
  assert.equal(report.status, 'partial');
  assert.ok(report.limitations.some((limitation) => limitation.code === 'max-file-bytes-exceeded'));
});
