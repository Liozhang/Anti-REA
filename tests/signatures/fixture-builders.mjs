// signatures 模块测试的字节级夹具构造器。
// 这些构造器生成最小但格式合法的真实字节：ZIP、PE、Mach-O（瘦与胖）、ELF。
// 只用于本模块测试，不写入 tests/fixtures/（那是 fixtures 模块的领地），也不进静态检查范围。

import { deflateRawSync } from 'node:zlib';

import { crc32 } from '../../src/signatures/crc32.mjs';

/**
 * 构造一个 ZIP。每个条目可指定 method（0 存储 / 8 deflate），
 * 并可单独覆写本地头与中央目录的 CRC32 以制造不一致。
 * @param {Array<{name: string, data: Buffer, method?: 0 | 8, crcLocal?: number, crcCentral?: number}>} entries
 * @returns {Buffer}
 */
export function buildZip(entries) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.name, 'utf8');
    const rawData = entry.data;
    const method = entry.method ?? 0;
    const storedData = method === 8 ? deflateRawSync(rawData) : rawData;
    const realCrc = crc32(rawData);
    const crcLocal = entry.crcLocal ?? realCrc;
    const crcCentral = entry.crcCentral ?? realCrc;

    const lfh = Buffer.alloc(30);
    lfh.writeUInt32LE(0x04034b50, 0);
    lfh.writeUInt16LE(20, 4);
    lfh.writeUInt16LE(0, 6);
    lfh.writeUInt16LE(method, 8);
    lfh.writeUInt16LE(0, 10);
    lfh.writeUInt16LE(0, 12);
    lfh.writeUInt32LE(crcLocal >>> 0, 14);
    lfh.writeUInt32LE(storedData.length, 18);
    lfh.writeUInt32LE(rawData.length, 22);
    lfh.writeUInt16LE(nameBuf.length, 26);
    lfh.writeUInt16LE(0, 28);
    localParts.push(lfh, nameBuf, storedData);

    const cdh = Buffer.alloc(46);
    cdh.writeUInt32LE(0x02014b50, 0);
    cdh.writeUInt16LE(20, 4);
    cdh.writeUInt16LE(20, 6);
    cdh.writeUInt16LE(0, 8);
    cdh.writeUInt16LE(method, 10);
    cdh.writeUInt16LE(0, 12);
    cdh.writeUInt16LE(0, 14);
    cdh.writeUInt32LE(crcCentral >>> 0, 16);
    cdh.writeUInt32LE(storedData.length, 20);
    cdh.writeUInt32LE(rawData.length, 24);
    cdh.writeUInt16LE(nameBuf.length, 28);
    cdh.writeUInt16LE(0, 30);
    cdh.writeUInt16LE(0, 32);
    cdh.writeUInt16LE(0, 34);
    cdh.writeUInt16LE(0, 36);
    cdh.writeUInt32LE(0, 38);
    cdh.writeUInt32LE(offset, 42);
    centralParts.push(cdh, nameBuf);

    offset += lfh.length + nameBuf.length + storedData.length;
  }

  const localBlob = Buffer.concat(localParts);
  const centralBlob = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralBlob.length, 12);
  eocd.writeUInt32LE(localBlob.length, 16);
  eocd.writeUInt16LE(0, 20);
  return Buffer.concat([localBlob, centralBlob, eocd]);
}

/**
 * 构造一个最小 PE。可选是否带安全目录、CheckSum 取值、PE32 或 PE32+。
 * @param {{isPe32Plus?: boolean, checksum?: number, securitySize?: number, securityOffset?: number, extraBytes?: number}} [options]
 * @returns {Buffer}
 */
export function buildPe(options = {}) {
  const isPe32Plus = options.isPe32Plus ?? true;
  const checksum = options.checksum ?? 0;
  const securitySize = options.securitySize ?? 0;
  const securityOffset = options.securityOffset ?? 0;

  const dosHeader = Buffer.alloc(64);
  dosHeader.write('MZ', 0, 'ascii');
  dosHeader.writeUInt32LE(64, 0x3c);

  const peSig = Buffer.from([0x50, 0x45, 0x00, 0x00]);

  const coff = Buffer.alloc(20);
  coff.writeUInt16LE(0x8664, 0);
  coff.writeUInt16LE(1, 2);
  coff.writeUInt32LE(0, 4);
  coff.writeUInt32LE(0, 8);
  coff.writeUInt32LE(0, 12);
  coff.writeUInt16LE(isPe32Plus ? 240 : 224, 16);
  coff.writeUInt16LE(0x0022, 18);

  const ohSize = isPe32Plus ? 240 : 224;
  const oh = Buffer.alloc(ohSize);
  oh.writeUInt16LE(isPe32Plus ? 0x20b : 0x10b, 0);
  oh.writeUInt32LE(checksum >>> 0, 64);
  if (isPe32Plus) {
    oh.writeUInt32LE(16, 108);
    oh.writeUInt32LE(securityOffset >>> 0, 144);
    oh.writeUInt32LE(securitySize >>> 0, 148);
  } else {
    oh.writeUInt32LE(16, 92);
    oh.writeUInt32LE(securityOffset >>> 0, 128);
    oh.writeUInt32LE(securitySize >>> 0, 132);
  }

  const section = Buffer.alloc(40);
  section.write('.text\0\0\0', 0, 'latin1');

  const body = Buffer.concat([dosHeader, peSig, coff, oh, section]);
  if (options.extraBytes) {
    return Buffer.concat([body, Buffer.alloc(options.extraBytes)]);
  }
  return body;
}

/**
 * 构造一个瘦 64 位 Mach-O，可选带 LC_CODE_SIGNATURE。
 * @param {{withCodeSignature?: boolean}} [options]
 * @returns {Buffer}
 */
export function buildMacho64(options = {}) {
  const withCodeSignature = options.withCodeSignature ?? false;

  const segment = Buffer.alloc(72);
  segment.writeUInt32LE(0x19, 0); // LC_SEGMENT_64
  segment.writeUInt32LE(72, 4);
  segment.write('__TEXT\0\0\0\0\0\0\0\0\0\0', 8, 'latin1');

  const commands = [segment];
  if (withCodeSignature) {
    const codeSig = Buffer.alloc(16);
    codeSig.writeUInt32LE(0x1d, 0); // LC_CODE_SIGNATURE
    codeSig.writeUInt32LE(16, 4);
    codeSig.writeUInt32LE(0x1000, 8); // dataoff
    codeSig.writeUInt32LE(0x200, 12); // datasize
    commands.push(codeSig);
  }

  const header = Buffer.alloc(32);
  header.writeUInt32LE(0xfeedfacf, 0);
  header.writeUInt32LE(0x0100000c, 4); // CPU_TYPE_ARM64
  header.writeUInt32LE(0, 8);
  header.writeUInt32LE(2, 12); // MH_EXECUTE
  header.writeUInt32LE(commands.length, 16);
  header.writeUInt32LE(commands.reduce((sum, cmd) => sum + cmd.length, 0), 20);
  header.writeUInt32LE(0, 24);
  header.writeUInt32LE(0, 28);
  return Buffer.concat([header, ...commands]);
}

/**
 * 构造一个胖二进制，内含一个 Mach-O 分片。
 * @param {{withCodeSignature?: boolean}} [options]
 * @returns {Buffer}
 */
export function buildMachoFat(options = {}) {
  const slice = buildMacho64(options);
  const sliceOffset = 0x1000;
  const fatHeader = Buffer.alloc(8);
  fatHeader.writeUInt32BE(0xcafebabe, 0);
  fatHeader.writeUInt32BE(1, 4);
  const fatArch = Buffer.alloc(20);
  fatArch.writeUInt32BE(0x0100000c, 0);
  fatArch.writeUInt32BE(0, 4);
  fatArch.writeUInt32BE(sliceOffset, 8);
  fatArch.writeUInt32BE(slice.length, 12);
  fatArch.writeUInt32BE(12, 16);
  const header = Buffer.concat([fatHeader, fatArch]);
  const gap = Buffer.alloc(sliceOffset - header.length);
  return Buffer.concat([header, gap, slice]);
}

/**
 * 构造一个 64 位 ELF，可选带一个 PT_NOTE 段（GNU build id）。
 * @param {{withNotes?: boolean}} [options]
 * @returns {Buffer}
 */
export function buildElf64(options = {}) {
  const withNotes = options.withNotes ?? true;

  const noteName = Buffer.from('GNU\0', 'latin1');
  const noteDesc = Buffer.alloc(20);
  for (let i = 0; i < 20; i += 1) {
    noteDesc[i] = i + 1;
  }
  let noteData = Buffer.alloc(0);
  if (withNotes) {
    const noteHeader = Buffer.alloc(12);
    noteHeader.writeUInt32LE(noteName.length, 0);
    noteHeader.writeUInt32LE(noteDesc.length, 4);
    noteHeader.writeUInt32LE(3, 8); // NT_GNU_BUILD_ID
    noteData = Buffer.concat([noteHeader, noteName, noteDesc]);
  }

  const ehsize = 64;
  const phentsize = 56;
  const phnum = withNotes ? 1 : 0;
  const phoff = ehsize;
  const noteOffset = phoff + phnum * phentsize;

  const header = Buffer.alloc(ehsize);
  header[0] = 0x7f;
  header[1] = 0x45;
  header[2] = 0x4c;
  header[3] = 0x46;
  header[4] = 2; // ELFCLASS64
  header[5] = 1; // ELFDATA2LSB
  header[6] = 1; // EV_CURRENT
  header.writeUInt16LE(2, 16); // ET_EXEC
  header.writeUInt16LE(62, 18); // EM_X86_64
  header.writeUInt32LE(1, 20);
  header.writeBigUInt64LE(0n, 24);
  header.writeBigUInt64LE(BigInt(phoff), 32);
  header.writeBigUInt64LE(0n, 40);
  header.writeUInt32LE(0, 48);
  header.writeUInt16LE(ehsize, 52);
  header.writeUInt16LE(phentsize, 54);
  header.writeUInt16LE(phnum, 56);
  header.writeUInt16LE(0, 58);
  header.writeUInt16LE(0, 60);
  header.writeUInt16LE(0, 62);

  const parts = [header];
  if (withNotes) {
    const ph = Buffer.alloc(phentsize);
    ph.writeUInt32LE(4, 0); // PT_NOTE
    ph.writeUInt32LE(0, 4);
    ph.writeBigUInt64LE(BigInt(noteOffset), 8);
    ph.writeBigUInt64LE(0n, 16);
    ph.writeBigUInt64LE(0n, 24);
    ph.writeBigUInt64LE(BigInt(noteData.length), 32);
    ph.writeBigUInt64LE(BigInt(noteData.length), 40);
    ph.writeBigUInt64LE(4n, 48);
    parts.push(ph);
  }
  parts.push(noteData);
  return Buffer.concat(parts);
}
