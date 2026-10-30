// ELF 夹具构造器：64 位小端 ELF、符号表与字符串表。
// 从 tests/readers.test.mjs 抽出，供读取器上限类测试共用，避免同一套字节级构造写两份。

/** 小端四字节无符号整数。 */
export function u32le(value) {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32LE(value >>> 0, 0);
  return buffer;
}

/** 大端四字节无符号整数。 */
export function u32be(value) {
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
export function buildElf64(userSections, programHeaders = []) {
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
export const SHT = Object.freeze({ PROGBITS: 1, SYMTAB: 2, STRTAB: 3, NOTE: 7 });

/**
 * 构造符号表与字符串表。
 * @param {string[]} names 符号名
 * @returns {{symtab: Buffer, strtab: Buffer}}
 */
export function buildSymbols(names) {
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
