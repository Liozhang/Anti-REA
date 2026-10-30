// 读取器成本测量：把每个读取器在真实夹具与畸形输入上的耗时、发现数、限制说明数打成一张表。
//
// 存在的理由：这个项目的资源预算是按字节设的，而字节不约束工作量——
// 一个 291 字节的 DEX 可以把字符串索引数声明成 42 亿，一个 104 字节的 Mach-O
// 可以把加载命令数声明成 42 亿。真正兜住工作量的是各读取器自己的记录数上限，
// 而这些上限的数值此前没有任何实测依据，全是照别处抄的。
//
// 这个脚本把依据留在仓库里：任何人改了一个上限，重跑一次就能看到代价变了没有。
// 它只打印，不做断言。墙上时间在共享机器上不可靠，写进测试只会制造偶发失败；
// 边界行为（超限必须留声、正常夹具不得误报）由 tests/reader-limits.test.mjs 断言，
// 那个文件不含任何耗时判断。
//
// 用法：node scripts/measure-readers.mjs
// 退出码：读取器抛错时为 1，否则为 0。

import { deflateRawSync } from 'node:zlib';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { DEFAULT_BUDGETS } from '../src/policy/schema.mjs';
import { readersForContainer } from '../src/readers/index.mjs';
import { CONTAINER_FIXTURES, writeContainerFixtures } from '../tests/helpers/container-fixtures.mjs';

/** 表格各列的宽度。 */
const COLUMNS = Object.freeze({
  reader: 14,
  millis: 10,
  findings: 8,
  limitations: 9,
});

/**
 * 取已提交夹具的字节。
 * @param {string} relativePath 夹具相对路径
 * @returns {Buffer}
 */
function fixtureBytes(relativePath) {
  const found = CONTAINER_FIXTURES.find((item) => item.relativePath === relativePath);
  if (found === undefined) {
    throw new Error(`找不到夹具 ${relativePath}`);
  }
  return Buffer.from(found.bytes);
}

/**
 * 构造含指定条数加载命令的 64 位小端 Mach-O。每条命令只写 cmd 与 cmdsize 两个字段。
 * @param {number} commandCount 加载命令条数
 * @returns {Buffer}
 */
function buildMachoWithCommands(commandCount) {
  const headerSize = 32;
  const commandSize = 8;
  const file = Buffer.alloc(headerSize + commandCount * commandSize, 0);
  file.writeUInt32LE(0xfeedfacf, 0);
  file.writeUInt32LE(0x0100000c, 4);
  file.writeUInt32LE(3, 8);
  file.writeUInt32LE(6, 12);
  file.writeUInt32LE(commandCount, 16);
  file.writeUInt32LE(commandCount * commandSize, 20);
  for (let index = 0; index < commandCount; index += 1) {
    const base = headerSize + index * commandSize;
    file.writeUInt32LE(0x25, base);
    file.writeUInt32LE(commandSize, base + 4);
  }
  return file;
}

/**
 * 构造含指定条目数的 ZIP，条目一律用存储方式，避免把解压成本混进条目数的比较里。
 * @param {number} entryCount 条目数
 * @returns {Buffer}
 */
function buildZip(entryCount) {
  const crc32Of = (buffer) => {
    let crc = ~0;
    for (const byte of buffer) {
      crc ^= byte;
      for (let bit = 0; bit < 8; bit += 1) {
        crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
      }
    }
    return (~crc) >>> 0;
  };
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (let index = 0; index < entryCount; index += 1) {
    const name = Buffer.from(`dir${index % 64}/file-${index}.txt`, 'utf8');
    const content = Buffer.from(`内容 ${index}\n`, 'utf8');
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt32LE(crc32Of(content), 14);
    local.writeUInt32LE(content.length, 18);
    local.writeUInt32LE(content.length, 22);
    local.writeUInt16LE(name.length, 26);
    const localFull = Buffer.concat([local, name, content]);
    locals.push(localFull);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt32LE(crc32Of(content), 16);
    central.writeUInt32LE(content.length, 20);
    central.writeUInt32LE(content.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset, 42);
    centrals.push(Buffer.concat([central, name]));
    offset += localFull.length;
  }
  const centralStart = offset;
  const centralBuffer = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entryCount, 8);
  end.writeUInt16LE(entryCount, 10);
  end.writeUInt32LE(centralBuffer.length, 12);
  end.writeUInt32LE(centralStart, 16);
  return Buffer.concat([...locals, centralBuffer, end]);
}

/**
 * 构造声明指定张量数的 safetensors：头部是 JSON，数据区只有少量字节，
 * 因此每个张量的区间都越界——这正是实测中限制说明刷出几千条的那个形状。
 * @param {number} tensorCount 张量数
 * @returns {Buffer}
 */
function buildSafetensors(tensorCount) {
  const header = { __metadata__: { format: 'pt' } };
  for (let index = 0; index < tensorCount; index += 1) {
    header[`model.layers.${index}.weight`] = { dtype: 'F32', shape: [8], data_offsets: [index * 32, index * 32 + 32] };
  }
  const json = Buffer.from(JSON.stringify(header), 'utf8');
  const file = Buffer.concat([Buffer.alloc(8), json, Buffer.alloc(64, 0)]);
  file.writeBigUInt64LE(BigInt(json.length), 0);
  return file;
}

/** 畸形输入清单：每一件的共同点是字节很少或中等，声明的记录数极大。 */
function pathologicalCases() {
  const dex = fixtureBytes('dex/basic.dex');
  for (const offset of [56, 64, 72, 80, 88, 96]) {
    dex.writeUInt32LE(0xffffffff, offset);
  }

  const macho = fixtureBytes('mach-o/basic.macho');
  macho.writeUInt32LE(0xffffffff, 16);

  const gguf = fixtureBytes('gguf/basic.gguf');
  gguf.writeBigUInt64LE(2n ** 40n, 8);

  const elf = fixtureBytes('elf/basic.elf');
  elf.writeUInt16LE(0xffff, 60);

  return [
    { label: 'DEX 六表计数全声明 42 亿条', container: 'dex', bytes: dex },
    { label: 'Mach-O 加载命令数声明 42 亿条', container: 'mach-o', bytes: macho },
    { label: 'Mach-O 真实构造 4200 条加载命令', container: 'mach-o', bytes: buildMachoWithCommands(4200) },
    { label: 'GGUF 张量数声明 1 万亿', container: 'gguf', bytes: gguf },
    { label: 'ELF 节数声明 65535', container: 'elf', bytes: elf },
    { label: 'safetensors 声明 1000 个张量', container: 'safetensors', bytes: buildSafetensors(1000) },
    { label: 'safetensors 声明 5000 个张量', container: 'safetensors', bytes: buildSafetensors(5000) },
    { label: 'ZIP 装入 100 个条目', container: 'zip', bytes: buildZip(100) },
    { label: 'ZIP 装入 5000 个条目', container: 'zip', bytes: buildZip(5000) },
    { label: 'ZIP 装入 50000 个条目', container: 'zip', bytes: buildZip(50000) },
  ];
}

/**
 * 打印一行结果。输入说明与字节数由调用方在标题行打出，这里只打读取器与三个计数。
 * @param {{reader: string, millis: number, findings: number, limitations: number}} row
 */
function printRow(row) {
  const cells = [
    row.reader.padEnd(COLUMNS.reader),
    row.millis.toFixed(1).padStart(COLUMNS.millis),
    String(row.findings).padStart(COLUMNS.findings),
    String(row.limitations).padStart(COLUMNS.limitations),
  ];
  console.log(`    ${cells.join(' ')}`);
}

/**
 * 跑一个输入，打印结果，返回是否有读取器抛错。
 * @param {string} label 输入说明
 * @param {Buffer} bytes 输入字节
 * @param {string} container 容器标识
 * @param {string} workDir 临时目录
 * @returns {Promise<boolean>} 是否有读取器抛错
 */
async function measure(label, bytes, container, workDir) {
  const absolutePath = join(workDir, 'sample.bin');
  await writeFile(absolutePath, bytes);
  const entry = { absolutePath, relativePath: 'sample.bin', bytes: bytes.length };
  const readers = readersForContainer(container);
  if (readers.length === 0) {
    console.log(`${label}  ${bytes.length} 字节  该容器没有登记读取器，跳过`);
    return false;
  }
  console.log(`${label}  ${bytes.length} 字节`);
  let failed = false;
  for (const reader of readers) {
    const started = process.hrtime.bigint();
    try {
      const result = await reader.read({ entry, policy: { budgets: DEFAULT_BUDGETS }, budgets: DEFAULT_BUDGETS });
      printRow({
        reader: reader.id,
        millis: Number(process.hrtime.bigint() - started) / 1e6,
        findings: result.findings.length,
        limitations: result.limitations.length,
      });
      // 触顶截断必须留声：一条限制说明都没有而记录数确实被上限截断，是静默丢事实。
      // 这里只提示，不判定——哪些上限该出声由 tests/reader-limits.test.mjs 断言。
      const capCodes = result.limitations.filter((note) => note.code.endsWith('-limit')).map((note) => note.code);
      if (capCodes.length > 0) {
        console.log(`      触顶：${[...new Set(capCodes)].join('、')}`);
      }
    } catch (error) {
      failed = true;
      printRow({ reader: reader.id, millis: 0, findings: 0, limitations: 0 });
      console.log(`      抛出：${String(error?.message ?? error)}`);
    }
  }
  return failed;
}

/** 脚本入口。 */
async function main() {
  const workDir = await mkdtemp(join(tmpdir(), 'anti-rea-measure-'));
  let failed = false;
  try {
    console.log('每一行：读取器｜毫秒｜发现数｜限制说明数');
    console.log('');
    console.log('一、已提交夹具');
    await writeContainerFixtures(workDir);
    for (const fixture of CONTAINER_FIXTURES) {
      const bytes = fixtureBytes(fixture.relativePath);
      failed = (await measure(fixture.relativePath, bytes, fixture.expected.type, workDir)) || failed;
    }
    console.log('');
    console.log('二、畸形输入：字节很少或中等，声明的记录数极大');
    for (const item of pathologicalCases()) {
      failed = (await measure(item.label, item.bytes, item.container, workDir)) || failed;
    }
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
  if (failed) {
    console.error('有读取器抛出意外错误：畸形输入的正确输出是限制说明，不是异常');
    process.exitCode = 1;
  }
}

await main();
