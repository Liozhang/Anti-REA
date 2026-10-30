// 读取器记录数上限测试：截断必须留声。
//
// 这一文件守的是一条口径：任何读取器因为内部登记上限而少解析了记录，
// 就必须在 limitations 里点明数量和上限。此前的漏洞是全类事件里
// Mach-O 加载命令、ELF 程序头清单、ELF 符号名三处静默停账——
// 一个声明 42 亿条命令的文件和一个声明 4096 条的文件，报告逐字节相同，
// 使用者无从分辨。同类事件在 DEX、GGUF、safetensors 与 ELF 节名那几处本来就留声，
// 这里把剩下的补齐，并用反向断言保证正常夹具不被误报。

import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { elfReader } from '../src/readers/elf.mjs';
import { machoReader } from '../src/readers/macho.mjs';
import { renderTextReport, TEXT_FINDING_LIMIT } from '../src/report/serialize.mjs';
import { buildElf64, buildSymbols, SHT } from './helpers/elf-fixture.mjs';
import { CONTAINER_FIXTURES } from './helpers/container-fixtures.mjs';

/** 临时目录在测试结束后清理。 */
let workDir = null;

test.before(async () => {
  workDir = await mkdtemp(join(tmpdir(), 'anti-rea-reader-limits-'));
});

test.after(async () => {
  if (workDir !== null) {
    await rm(workDir, { recursive: true, force: true });
  }
});

/**
 * 把夹具写进临时目录，返回读取器入参的条目对象。
 * @param {string} name 文件名
 * @param {Buffer} bytes 夹具字节
 * @returns {Promise<{absolutePath: string, relativePath: string, bytes: number}>}
 */
async function writeFixture(name, bytes) {
  const absolutePath = join(workDir, name);
  await writeFile(absolutePath, bytes);
  return { absolutePath, relativePath: name, bytes: bytes.length };
}

/**
 * 调用读取器并校验限制说明的形状，与 tests/readers.test.mjs 的 runReader 同一口径。
 * @param {Record<string, unknown>} reader 读取器
 * @param {{absolutePath: string, relativePath: string, bytes: number}} entry 条目
 * @returns {Promise<{findings: Array<Record<string, unknown>>, limitations: Array<Record<string, unknown>>}>}
 */
async function runReader(reader, entry) {
  const result = await reader.read({ entry, policy: {}, budgets: {} });
  assert.ok(Array.isArray(result.findings), 'findings 必须是数组');
  assert.ok(Array.isArray(result.limitations), 'limitations 必须是数组');
  for (const limitation of result.limitations) {
    assert.equal(typeof limitation.code, 'string');
    assert.ok(limitation.message.length > 0, '限制说明不得为空');
    assert.equal(typeof limitation.scope, 'string');
  }
  return result;
}

/**
 * 构造含指定条数加载命令的 64 位小端 Mach-O。
 * 每条命令只写 cmd 与 cmdsize 两个字段，共 8 字节；读取器对未知命令只登记不解析，
 * 正好用来把命令数推过登记上限而不必构造真实的段与动态库命令。
 * @param {number} commandCount 加载命令条数
 * @returns {Buffer}
 */
function buildMachoWithCommands(commandCount) {
  const headerSize = 32;
  const commandSize = 8;
  const file = Buffer.alloc(headerSize + commandCount * commandSize, 0);
  file.writeUInt32LE(0xfeedfacf, 0); // MH_MAGIC_64
  file.writeUInt32LE(0x0100000c, 4); // CPU_TYPE_X86_64
  file.writeUInt32LE(3, 8); // CPU_SUBTYPE_X86_64_ALL
  file.writeUInt32LE(6, 12); // MH_DYLINKER
  file.writeUInt32LE(commandCount, 16); // ncmds
  file.writeUInt32LE(commandCount * commandSize, 20); // sizeofcmds
  for (let index = 0; index < commandCount; index += 1) {
    const base = headerSize + index * commandSize;
    file.writeUInt32LE(0x25, base); // LC 编号取一个读取器不特殊处理的值
    file.writeUInt32LE(commandSize, base + 4); // cmdsize
  }
  return file;
}

/** 取已提交夹具的字节。 */
function fixtureBytes(relativePath) {
  const found = CONTAINER_FIXTURES.find((item) => item.relativePath === relativePath);
  assert.ok(found !== undefined, `找不到夹具 ${relativePath}`);
  return Buffer.from(found.bytes);
}

// ---------------------------------------------------------------------------
// Mach-O 加载命令数上限
// ---------------------------------------------------------------------------

test('Mach-O 加载命令数超过登记上限时留下限制说明，点明声明数与实际解析数', async () => {
  const declared = 4200;
  const entry = await writeFixture('many-commands.macho', buildMachoWithCommands(declared));
  const result = await runReader(machoReader, entry);

  const note = result.limitations.find((limitation) => limitation.code === 'macho-load-command-limit');
  assert.ok(note !== undefined, '加载命令数超限却没有限制说明，报告分辨不出声明数与登记上限的差别');
  assert.match(note.message, /4200/, '限制说明要点明声明的命令数');
  assert.match(note.message, /4096/, '限制说明要点明登记上限');
  assert.match(note.message, /本次解析 4096 条/, '限制说明要点明实际解析条数，不能拿上限冒充实际值');

  const header = result.findings.find((finding) => finding.category === 'macho-header');
  assert.equal(header.detail.loadCommandCount, declared, '头发现照实报告声明的命令数');
  assert.equal(header.detail.loadCommandKinds.length, 4096, '解析出的命令清单应止于登记上限');
  assert.match(header.readerLimitation, /4096/, '头发现自带的读取器说明也要点明上限');
});

test('Mach-O 加载命令数未超上限时不产生该限制说明', async () => {
  const entry = await writeFixture('basic.macho', fixtureBytes('mach-o/basic.macho'));
  const result = await runReader(machoReader, entry);
  assert.deepEqual(
    result.limitations.filter((limitation) => limitation.code === 'macho-load-command-limit'),
    [],
    '正常夹具不得被误报成超限',
  );
  assert.equal(result.limitations.length, 0, `正常夹具不应产生任何限制说明：${JSON.stringify(result.limitations)}`);
});

// ---------------------------------------------------------------------------
// ELF 程序头清单上限
// ---------------------------------------------------------------------------

test('ELF NOTE 段数超过登记上限时留下限制说明', async () => {
  const declared = 40;
  const programHeaders = [];
  for (let index = 0; index < declared; index += 1) {
    programHeaders.push({ type: 4, flags: 0x4, offset: 0, vaddr: 0x400000, filesz: 0 });
  }
  const entry = await writeFixture('many-notes.elf', buildElf64([], programHeaders));
  const result = await runReader(elfReader, entry);

  const note = result.limitations.find((limitation) => limitation.code === 'elf-program-header-limit');
  assert.ok(note !== undefined, 'NOTE 段数超限却没有限制说明');
  assert.match(note.message, /40/, '限制说明要点明实际段数');
  assert.match(note.message, /32/, '限制说明要点明登记上限');

  const header = result.findings.find((finding) => finding.category === 'elf-header');
  assert.equal(header.detail.programHeaders.length, 32, '程序头清单应止于登记上限');
});

test('ELF NOTE 段数未超上限时不产生该限制说明', async () => {
  const entry = await writeFixture('basic.elf', fixtureBytes('elf/basic.elf'));
  const result = await runReader(elfReader, entry);
  assert.deepEqual(
    result.limitations.filter((limitation) => limitation.code === 'elf-program-header-limit'),
    [],
    '正常夹具不得被误报成超限',
  );
});

// ---------------------------------------------------------------------------
// ELF 符号名清单上限
// ---------------------------------------------------------------------------

test('ELF 符号名超过登记上限时留下限制说明，清单止于上限', async () => {
  const names = Array.from({ length: 20 }, (unused, index) => `symbol_${index}`);
  const symbols = buildSymbols(names);
  const elf = buildElf64([
    { name: '.symtab', type: SHT.SYMTAB, content: symbols.symtab, linkName: '.strtab', info: 1, align: 8, entsize: 24 },
    { name: '.strtab', type: SHT.STRTAB, content: symbols.strtab, align: 1 },
  ]);
  const entry = await writeFixture('many-symbols.elf', elf);
  const result = await runReader(elfReader, entry);

  const note = result.limitations.find((limitation) => limitation.code === 'elf-symbol-name-limit');
  assert.ok(note !== undefined, '符号名超限却没有限制说明，报告里的摘录看起来就像符号表只有这么几个名字');
  assert.match(note.message, /12/, '限制说明要点明登记上限');
  assert.match(note.message, /8 个/, '限制说明要点明被跳过取名的符号数');

  const symtab = result.findings.find((finding) => finding.category === 'elf-symtab');
  assert.equal(symtab.detail.symbolCount, 20, '符号总数照实报告，不因清单截断而少报');
  assert.equal(symtab.detail.sampleNames.length, 12, '符号名清单应止于登记上限');
});

test('ELF 符号名未超上限时不产生该限制说明，清单保持完整', async () => {
  const names = ['main', 'helper_function', 'leaked_internal_name'];
  const symbols = buildSymbols(names);
  const elf = buildElf64([
    { name: '.symtab', type: SHT.SYMTAB, content: symbols.symtab, linkName: '.strtab', info: 1, align: 8, entsize: 24 },
    { name: '.strtab', type: SHT.STRTAB, content: symbols.strtab, align: 1 },
  ]);
  const entry = await writeFixture('few-symbols.elf', elf);
  const result = await runReader(elfReader, entry);

  assert.deepEqual(
    result.limitations.filter((limitation) => limitation.code === 'elf-symbol-name-limit'),
    [],
    '符号名未超限不得被误报',
  );
  const symtab = result.findings.find((finding) => finding.category === 'elf-symtab');
  assert.deepEqual(symtab.detail.sampleNames, names, '未超限时符号名清单应完整');
});

// ---------------------------------------------------------------------------
// 胖二进制分片那一支
// ---------------------------------------------------------------------------

test('胖二进制 Mach-O 的分片加载命令超限同样留声，不因走 parseFat 而漏掉', async () => {
  // 胖二进制头 8 字节，每个分片描述 28 字节；分片偏移指向一个命令数超限的 Mach-O。
  const slice = buildMachoWithCommands(4200);
  const sliceOffset = 8 + 28;
  const file = Buffer.alloc(sliceOffset + slice.length, 0);
  file.writeUInt32BE(0xcafebabe, 0); // FAT_MAGIC 大端
  file.writeUInt32BE(1, 4); // 分片数
  file.writeUInt32BE(0x0100000c, 8); // cputype
  file.writeUInt32BE(3, 12); // cpusubtype
  file.writeUInt32BE(sliceOffset, 16); // 分片偏移
  file.writeUInt32BE(slice.length, 20); // 分片长度
  file.writeUInt32BE(12, 24); // 对齐
  slice.copy(file, sliceOffset);

  const entry = await writeFixture('fat-over-cap.macho', file);
  const result = await runReader(machoReader, entry);

  const note = result.limitations.find((limitation) => limitation.code === 'macho-load-command-limit');
  assert.ok(note !== undefined, '胖二进制分片的超限说明不能丢：parseFat 只取 parsed.data，漏一层就整条消失');
  assert.match(note.message, /第 0 号分片/, '限制说明要带上前缀，指明是哪个分片');
});

// ---------------------------------------------------------------------------
// 人读报表的列举上限
// ---------------------------------------------------------------------------

test('人读报表把限制说明截到列举上限并给出提示，计数行仍是真实总数', async () => {
  const total = TEXT_FINDING_LIMIT + 7;
  const limitations = Array.from({ length: total }, (unused, index) => ({
    code: `probe-code-${index}`,
    message: `第 ${index} 条限制说明`,
    scope: 'entry',
  }));
  const text = renderTextReport({ schema: 'anti-rea.audit-report/1', limitations });

  assert.ok(text.includes(`限制说明：${total} 项`), '计数行必须是真实总数，不能跟着列举一起截');
  assert.equal((text.match(/probe-code-/g) ?? []).length, TEXT_FINDING_LIMIT, '列举应止于上限');
  assert.match(text, new RegExp(`另有 ${total - TEXT_FINDING_LIMIT} 项限制说明未在此列出`), '超出部分要给提示，与发现的措辞一致');
});
