// verify 模块测试：复审引擎作为加固的安全门。
// 覆盖三类输入：
//   正常输入   九类格式加胖二进制的完好夹具、基线比对与豁免派生、显式施加记录、重新签名标记
//   畸形输入   程序头被破坏的 ELF、标志与哈希不一致的 pyc、未重算的 PE CheckSum、
//              未重算 CRC32 的 ZIP、签名载荷被截断的 Mach-O、整体被截断的制品、
//              伪魔数文件、空文件、不存在的目标、畸形施加记录
//   部分读取   单文件上限设为极小值时全部检查记 pending，总体结论 partial 且退出码 1
// 夹具说明：字节级夹具取自 tests/required-sets/build-fixtures.mjs 的确定性构造，
// 胖二进制在本文件内构造；全部先写进临时目录再复审，断言复审前后制品逐字节不变。

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { auditArtifact } from '../src/audit/engine.mjs';
import { UsageError } from '../src/errors.mjs';
import { createMcpServer } from '../src/mcp/server.mjs';
import { REQUIRED_SETS } from '../src/required-sets/sets.mjs';
import { analyzePe, computePeChecksum } from '../src/signatures/index.mjs';
import { CHECK_FAMILIES, CHECK_STATUSES, VERIFY_REPORT_SCHEMA, verifyArtifact } from '../src/verify/index.mjs';
import { inspectContainer } from '../src/verify/facts.mjs';
import { buildFixtures } from './required-sets/build-fixtures.mjs';
import { runCli } from './helpers/cli.mjs';

/** 确定性字节级夹具表。 */
const FIXTURES = buildFixtures();

/** Go 构建信息 inline 魔数，ELF 夹具里以它定位构建信息载荷。 */
const GO_BUILDINFO_MAGIC = Buffer.from('\xff Go buildinf:', 'latin1');

/** 默认策略：层全部开启、预算取默认值、签名改动一律不允许。 */
const DEFAULT_POLICY = {};

/**
 * 建一个临时目录，调用方负责删除。
 * @returns {Promise<string>} 目录路径
 */
async function makeDir() {
  return await mkdtemp(join(tmpdir(), 'anti-rea-verify-'));
}

/**
 * 把制品字节写进临时目录。
 * @param {string} dir 目录路径
 * @param {string} name 文件名
 * @param {Buffer} content 制品字节
 * @returns {Promise<string>} 文件路径
 */
async function writeArtifact(dir, name, content) {
  const path = join(dir, name);
  await writeFile(path, content);
  return path;
}

/**
 * 计算文件 sha256，用于断言复审不改动制品。
 * @param {string} path 文件路径
 * @returns {Promise<string>}
 */
async function digestOf(path) {
  return createHash('sha256').update(await readFile(path)).digest('hex');
}

/**
 * 从报告里取某检查族的第一条记录。
 * @param {Record<string, unknown>} report 复审报告
 * @param {string} family 检查族
 * @returns {Record<string, unknown>}
 */
function checkOf(report, family) {
  const found = report.checks.find((check) => check.family === family);
  assert.notEqual(found, undefined, `报告里没有检查族 ${family} 的记录`);
  return found;
}

/**
 * 断言报告里每条检查记录都取封闭词表内的检查族与状态。
 * @param {Record<string, unknown>} report 复审报告
 */
function assertClosedVocabulary(report) {
  for (const check of report.checks) {
    assert.ok(CHECK_FAMILIES.includes(check.family), `检查族不在封闭集合内：${check.family}`);
    assert.ok(CHECK_STATUSES.includes(check.status), `检查状态不在封闭集合内：${check.status}`);
    assert.ok(typeof check.reason === 'string' && check.reason.length > 0, '每条检查都必须带原因');
  }
}

/**
 * 构造一个最小胖 Mach-O：一个 64 位小端分片，含 LC_SEGMENT_64 与带真实载荷的
 * LC_CODE_SIGNATURE，签名载荷相对分片起点存放，整份文件自洽。
 * @returns {Buffer}
 */
function buildFatMacho() {
  const signature = Buffer.from('fat slice code signature payload', 'latin1');
  const segment = Buffer.alloc(72);
  segment.writeUInt32LE(0x19, 0); // LC_SEGMENT_64
  segment.writeUInt32LE(72, 4);
  segment.write('__TEXT', 8, 'latin1');
  const codeSignature = Buffer.alloc(16);
  codeSignature.writeUInt32LE(0x1d, 0); // LC_CODE_SIGNATURE
  codeSignature.writeUInt32LE(16, 4);
  codeSignature.writeUInt32LE(120, 8); // dataoff 相对分片起点
  codeSignature.writeUInt32LE(signature.length, 12);
  const sliceHeader = Buffer.alloc(32);
  sliceHeader.writeUInt32LE(0xfeedfacf, 0);
  sliceHeader.writeUInt32LE(0x0100000c, 4);
  sliceHeader.writeUInt32LE(2, 12); // MH_EXECUTE
  sliceHeader.writeUInt32LE(2, 16); // ncmds
  sliceHeader.writeUInt32LE(88, 20); // sizeofcmds
  const slice = Buffer.concat([sliceHeader, segment, codeSignature, signature]);

  const fatHeader = Buffer.alloc(8);
  fatHeader.writeUInt32BE(0xcafebabe, 0); // FAT_MAGIC 大端存放
  fatHeader.writeUInt32BE(1, 4); // nfat_arch
  const fatArch = Buffer.alloc(20);
  fatArch.writeInt32BE(0x0100000c, 0);
  fatArch.writeInt32BE(0, 4);
  fatArch.writeUInt32BE(4096, 8); // offset
  fatArch.writeUInt32BE(slice.length, 12); // size
  fatArch.writeUInt32BE(12, 16); // align
  const header = Buffer.concat([fatHeader, fatArch]);
  const gap = Buffer.alloc(4096 - header.length);
  return Buffer.concat([header, gap, slice]);
}

/**
 * 构造一个声明 general.alignment 的完好 GGUF：头部、元数据键值、张量索引、
 * 按该对齐值对齐的张量数据，与 src/transforms/relayout.mjs 的 parseGguf 同一口径。
 * @param {number} alignment 对齐值
 * @returns {Buffer}
 */
function buildGgufWithAlignment(alignment) {
  const u64le = (value) => {
    const buffer = Buffer.alloc(8);
    buffer.writeBigUInt64LE(BigInt(value));
    return buffer;
  };
  const u32le = (value) => {
    const buffer = Buffer.alloc(4);
    buffer.writeUInt32LE(value);
    return buffer;
  };
  const str = (value) => {
    const bytes = Buffer.from(value, 'utf8');
    return Buffer.concat([u64le(bytes.length), bytes]);
  };
  const metadata = Buffer.concat([
    str('general.architecture'),
    u32le(8),
    str('llama'),
    str('general.alignment'),
    u32le(4),
    u32le(alignment),
    // 字符串数组元数据（真实 GGUF 的词表类键常用）：结束位置必须逐项走长度前缀。
    str('tokenizer.tokens'),
    u32le(9),
    u32le(8),
    u64le(2),
    str('hello'),
    str('world'),
  ]);
  const tensorInfo = Buffer.concat([str('w'), u32le(1), u64le(4), u32le(0), u64le(0)]);
  const tensorData = Buffer.alloc(16, 0x5a);
  const headerEnd = 24 + metadata.length + tensorInfo.length;
  const tensorDataOffset = Math.ceil(headerEnd / alignment) * alignment;
  const header = Buffer.concat([Buffer.from('GGUF', 'latin1'), u32le(3), u64le(1), u64le(3), metadata, tensorInfo]);
  return Buffer.concat([header, Buffer.alloc(tensorDataOffset - headerEnd), tensorData]);
}

// ---------------------------------------------------------------------------
// 正常输入：完好夹具全部通过
// ---------------------------------------------------------------------------

test('九类格式与胖二进制的完好夹具复审通过，退出码为 0', async () => {
  const dir = await makeDir();
  try {
    const cases = [
      ['elf', FIXTURES.elf],
      ['pe', FIXTURES.pe],
      ['mach-o', FIXTURES['mach-o']],
      ['mach-o-fat', buildFatMacho()],
      ['zip', FIXTURES.zip],
      ['gguf', FIXTURES.gguf],
      ['safetensors', FIXTURES.safetensors],
      ['pyc', FIXTURES.pyc],
      ['beam', FIXTURES.beam],
    ];
    for (const [name, bytes] of cases) {
      const path = await writeArtifact(dir, `${name}.bin`, bytes);
      const before = await digestOf(path);
      const { exitCode, report } = await verifyArtifact(path);
      assert.equal(exitCode, 0, `${name} 应通过复审`);
      assert.equal(report.status, 'passed', `${name} 的总体判定应为 passed`);
      assert.equal(report.schema, VERIFY_REPORT_SCHEMA);
      assert.equal(report.tool, 'verify-artifact');
      assert.equal(report.summary.failed, 0, `${name} 不得有失败项`);
      assert.equal(report.summary.pending, 0, `${name} 不得有未决项`);
      assert.ok(report.summary.checks > 0, `${name} 至少要跑一个检查族`);
      assert.equal(report.requiresResign, false, `${name} 没有施加记录，不得标记重新签名`);
      assertClosedVocabulary(report);
      assert.equal(await digestOf(path), before, '复审不得改动制品字节');
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('必需集每一项都在完好夹具上拿到事实，没有静默的未判定项', async () => {
  const cases = [
    ['elf', FIXTURES.elf],
    ['pe', FIXTURES.pe],
    ['mach-o', FIXTURES['mach-o']],
    ['mach-o-fat', buildFatMacho()],
    ['zip', FIXTURES.zip],
    ['gguf', FIXTURES.gguf],
    ['safetensors', FIXTURES.safetensors],
    ['pyc', FIXTURES.pyc],
    ['beam', FIXTURES.beam],
  ];
  for (const [container, bytes] of cases) {
    const inspection = inspectContainer(container, bytes);
    assert.notEqual(inspection, null, `${container} 应有检查函数`);
    assert.equal(inspection.parse.parseable, true, `${container} 的完好夹具应可解析`);
    for (const item of REQUIRED_SETS[container].items) {
      assert.ok(Object.hasOwn(inspection.facts, item.id), `${container} 的必需项 ${item.id} 没有拿到结构事实`);
    }
  }
});

test('GGUF 对齐判定读 general.alignment 覆盖，未声明时缺省三十二字节', async () => {
  const dir = await makeDir();
  try {
    // 文件自身声明 64 字节对齐：判定必须按 64 算数据区起点，与重布局写入同口径。
    const declared = buildGgufWithAlignment(64);
    const inspection = inspectContainer('gguf', declared);
    assert.equal(inspection.parse.parseable, true);
    // 字符串数组元数据必须逐项走长度前缀，后面的张量索引才找得对位置。
    assert.equal(inspection.facts['gguf.metadata-kv'].parsed, true);
    assert.equal(inspection.facts['gguf.tensor-index'].parsed, true);
    assert.equal(inspection.facts['gguf.alignment'].parsed, true);
    assert.match(inspection.facts['gguf.alignment'].reason, /按 64 字节对齐后数据区起点/);
    assert.equal(inspection.facts['gguf.tensor-data'].parsed, true);

    // 未声明 general.alignment 的夹具按缺省三十二字节判定。
    assert.equal(FIXTURES.gguf.includes(Buffer.from('general.alignment', 'latin1')), false, '夹具不得自带对齐声明');
    assert.match(inspectContainer('gguf', FIXTURES.gguf).facts['gguf.alignment'].reason, /按 32 字节对齐/);

    // 端到端：声明 64 字节对齐的完好 GGUF 通过复审，对齐必需项不误判。
    const path = await writeArtifact(dir, 'aligned.gguf', declared);
    const { exitCode, report } = await verifyArtifact(path);
    assert.equal(exitCode, 0);
    assert.equal(checkOf(report, 'required-sections').status, 'passed');
    assert.equal(checkOf(report, 'container-parse').status, 'passed');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('畸形 GGUF：元数据表或张量索引截断记失败原因，不抛异常', () => {
  const u64le = (value) => {
    const buffer = Buffer.alloc(8);
    buffer.writeBigUInt64LE(BigInt(value));
    return buffer;
  };
  const u32le = (value) => {
    const buffer = Buffer.alloc(4);
    buffer.writeUInt32LE(value);
    return buffer;
  };
  const str = (value) => {
    const bytes = Buffer.from(value, 'latin1');
    return Buffer.concat([u64le(bytes.length), bytes]);
  };
  const oneEntry = Buffer.concat([str('general.license'), u32le(8), str('MIT')]);

  // 元数据键数声明 3 条，文件只有 1 条且在 EOF 收尾：越界读取必须转成失败原因。
  const truncatedMetadata = Buffer.concat([Buffer.from('GGUF', 'latin1'), u32le(3), u64le(0), u64le(3), oneEntry]);
  const metadataInspection = inspectContainer('gguf', truncatedMetadata);
  assert.equal(metadataInspection.parse.parseable, false);
  assert.equal(metadataInspection.facts['gguf.metadata-kv'].parsed, false);

  // 张量数声明 1 条，张量索引从 EOF 起读。
  const truncatedTensor = Buffer.concat([Buffer.from('GGUF', 'latin1'), u32le(3), u64le(1), u64le(1), oneEntry]);
  const tensorInspection = inspectContainer('gguf', truncatedTensor);
  assert.equal(tensorInspection.facts['gguf.tensor-index'].parsed, false);
});

test('目录目标逐条目复审，范围外条目记入限制说明而不是静默跳过', async () => {
  const dir = await makeDir();
  try {
    await writeArtifact(dir, 'app.elf', FIXTURES.elf);
    await writeArtifact(dir, 'data.zip', FIXTURES.zip);
    await writeArtifact(dir, 'notes.txt', Buffer.from('普通文本\n', 'latin1'));
    const { exitCode, report } = await verifyArtifact(dir);
    assert.equal(exitCode, 0);
    assert.equal(report.status, 'passed');
    assert.equal(report.summary.entriesInspected, 2, '两个受支持条目进入结构复审');
    assert.equal(report.summary.outOfScopeEntries, 1, '文本条目不落入 v1 格式集');
    const codes = report.limitations.map((limitation) => limitation.code);
    assert.ok(codes.includes('verify-out-of-scope'), '范围外条目必须留下限制说明');
    const entries = new Set(report.checks.map((check) => check.entry));
    assert.deepEqual([...entries].sort(), ['app.elf', 'data.zip']);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('MCP verify_artifact 与复审引擎结论一致：完好制品 isError 为 false，损坏制品为 true', async () => {
  const dir = await makeDir();
  try {
    const good = await writeArtifact(dir, 'app.elf', FIXTURES.elf);
    const broken = await writeArtifact(dir, 'broken.elf', FIXTURES['elf-broken-program-headers']);
    const server = createMcpServer();

    const passed = await server.handle({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'verify_artifact', arguments: { path: good } },
    });
    assert.equal(passed.result.isError, false);
    assert.equal(passed.result.structuredContent.status, 'passed');

    const failed = await server.handle({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'verify_artifact', arguments: { path: broken } },
    });
    assert.equal(failed.result.isError, true);
    assert.equal(failed.result.structuredContent.status, 'failed');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('命令行 verify 对完好制品退出码 0，对损坏制品退出码 1', async () => {
  const dir = await makeDir();
  try {
    const good = await writeArtifact(dir, 'app.elf', FIXTURES.elf);
    const broken = await writeArtifact(dir, 'broken.elf', FIXTURES['elf-broken-program-headers']);

    const passed = await runCli(['verify', good, '--json']);
    assert.equal(passed.code, 0);
    assert.equal(JSON.parse(passed.stdout).status, 'passed');

    const failed = await runCli(['verify', broken, '--json']);
    assert.equal(failed.code, 1);
    const report = JSON.parse(failed.stdout);
    assert.equal(report.status, 'failed');
    assert.ok(report.summary.failed > 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 正常输入：校验和、签名与 pyc 标志的一致性判定
// ---------------------------------------------------------------------------

test('PE 非零 CheckSum 经等长改写后重算，复审判定一致', async () => {
  const dir = await makeDir();
  try {
    const stale = await writeArtifact(dir, 'stale.pe', FIXTURES['pe-checksum-nonzero']);
    const staleResult = await verifyArtifact(stale);
    assert.equal(staleResult.exitCode, 1, '未重算的 CheckSum 必须判不通过');
    assert.equal(checkOf(staleResult.report, 'checksum-consistency').status, 'failed');

    // 等长改写一个数据字节后同帧重算：模拟加固流程对 CheckSum 的维护。
    const pe = Buffer.from(FIXTURES['pe-checksum-nonzero']);
    const fieldOffset = analyzePe(pe).checksum.fieldOffset;
    pe[pe.length - 3] ^= 0xff;
    pe.writeUInt32LE(computePeChecksum(pe, fieldOffset) >>> 0, fieldOffset);
    const fixed = await writeArtifact(dir, 'fixed.pe', pe);
    const { exitCode, report } = await verifyArtifact(fixed);
    assert.equal(exitCode, 0);
    const check = checkOf(report, 'checksum-consistency');
    assert.equal(check.status, 'passed');
    assert.equal(check.detail.stored, check.detail.recomputed, '重算值必须写回字段');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('pyc：清零 source_hash 且一并清除 check_source 时判定一致，只清零哈希时判不一致', async () => {
  const dir = await makeDir();
  try {
    // 畸形状态：flags 仍置 check_source，源哈希却已清零。
    const inconsistent = await writeArtifact(dir, 'half.pyc', FIXTURES['pyc-hash-cleared']);
    const bad = await verifyArtifact(inconsistent);
    assert.equal(bad.exitCode, 1);
    const badCheck = checkOf(bad.report, 'pyc-flag-consistency');
    assert.equal(badCheck.status, 'failed');
    assert.match(badCheck.reason, /check_source/);

    // 缓解后的预期状态：清零 source_hash 的同时把 flags 从 3 改成 1。
    const pyc = Buffer.from(FIXTURES.pyc);
    pyc.writeUInt32LE(1, 4);
    pyc.fill(0, 8, 16);
    const hardened = await writeArtifact(dir, 'hardened.pyc', pyc);
    const { exitCode, report } = await verifyArtifact(hardened);
    assert.equal(exitCode, 0);
    const check = checkOf(report, 'pyc-flag-consistency');
    assert.equal(check.status, 'passed');
    assert.match(check.reason, /check_source 一并清除/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('pyc：载荷首字节带 FLAG_REF 位时按掩码后的类型码判定', async () => {
  // 实测背景：Python 3.13 编译的模块，码对象载荷首字节是 0xe3（FLAG_REF 加 TYPE_CODE）。
  // 原先直接拿原字节查表，每个真实 pyc 都被误判成容器结构损坏，复审必然不通过。
  const withRef = Buffer.from(FIXTURES.pyc);
  withRef[16] = 0xe3;
  const refInspection = inspectContainer('pyc', withRef);
  assert.equal(refInspection.parse.parseable, true, '带 FLAG_REF 的载荷应判可解析');
  assert.match(refInspection.facts['pyc.code-object'].reason, /FLAG_REF 置位/);

  // 掩去 FLAG_REF 之后仍不是已登记类型码的，照旧判损坏。
  const unknown = Buffer.from(FIXTURES.pyc);
  unknown[16] = 0x80 | 0x7f;
  const unknownInspection = inspectContainer('pyc', unknown);
  assert.equal(unknownInspection.parse.parseable, false);
  assert.match(unknownInspection.facts['pyc.code-object'].reason, /掩去 FLAG_REF 后不是已登记/);

  const dir = await makeDir();
  try {
    const refPath = await writeArtifact(dir, 'ref-flag.pyc', withRef);
    const ref = await verifyArtifact(refPath);
    assert.equal(ref.exitCode, 0, `带 FLAG_REF 的真实 pyc 应通过复审：${JSON.stringify(ref.report.checks)}`);

    const unknownPath = await writeArtifact(dir, 'unknown-type.pyc', unknown);
    const bad = await verifyArtifact(unknownPath);
    assert.equal(bad.exitCode, 1);
    assert.equal(checkOf(bad.report, 'container-parse').status, 'failed');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('ZIP：条目数据被改写而未同帧重算 CRC32 时，校验和与必需集双双判不通过', async () => {
  const dir = await makeDir();
  try {
    const intact = await writeArtifact(dir, 'intact.zip', FIXTURES.zip);
    const intactResult = await verifyArtifact(intact);
    assert.equal(intactResult.exitCode, 0);
    assert.equal(checkOf(intactResult.report, 'checksum-consistency').status, 'passed');

    // 第一个条目是存储条目，本地数据紧跟在本地文件头与条目名之后。
    const zip = Buffer.from(FIXTURES.zip);
    const nameLength = zip.readUInt16LE(26);
    zip[30 + nameLength] ^= 0xff;
    const tampered = await writeArtifact(dir, 'tampered.zip', zip);
    const { exitCode, report } = await verifyArtifact(tampered);
    assert.equal(exitCode, 1);
    const checksum = checkOf(report, 'checksum-consistency');
    assert.equal(checksum.status, 'failed');
    assert.deepEqual(checksum.detail.inconsistentEntries, ['readme.txt']);
    // 条目 CRC32 同时是 ZIP 必需集的一项，改写后必须同帧重算。
    assert.equal(checkOf(report, 'required-sections').status, 'failed');
    assert.ok(checkOf(report, 'required-sections').detail.failedItems.includes('zip.entry-crc32'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('Mach-O：LC_CODE_SIGNATURE 载荷被截断时签名一致性判不通过，载荷完整时通过', async () => {
  const dir = await makeDir();
  try {
    const signed = await writeArtifact(dir, 'signed.macho', FIXTURES['mach-o']);
    const signedResult = await verifyArtifact(signed);
    assert.equal(signedResult.exitCode, 0);
    const signedCheck = checkOf(signedResult.report, 'signature-consistency');
    assert.equal(signedCheck.status, 'passed');
    assert.match(signedCheck.reason, /LC_CODE_SIGNATURE/);

    const cut = Buffer.from(FIXTURES['mach-o']).subarray(0, FIXTURES['mach-o'].length - 10);
    const truncated = await writeArtifact(dir, 'cut.macho', cut);
    const { exitCode, report } = await verifyArtifact(truncated);
    assert.equal(exitCode, 1);
    const check = checkOf(report, 'signature-consistency');
    assert.equal(check.status, 'failed');
    assert.match(check.reason, /签名载荷不完整/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('胖二进制：分片加载命令与签名载荷都在位时复审通过', async () => {
  const dir = await makeDir();
  try {
    const fat = await writeArtifact(dir, 'app.macho', buildFatMacho());
    const { exitCode, report } = await verifyArtifact(fat);
    assert.equal(exitCode, 0);
    assert.equal(checkOf(report, 'container-parse').status, 'passed');
    assert.equal(checkOf(report, 'signature-consistency').status, 'passed');
    assert.equal(checkOf(report, 'required-sections').status, 'passed');
    assert.equal(checkOf(report, 'required-sections').detail.unverifiedItems.length, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 正常输入：基线比对、豁免派生与重新签名标记
// ---------------------------------------------------------------------------

test('按施加记录派生豁免：清零 .go.buildinfo 后该项从必需集移除，其余项仍须可解析', async () => {
  const dir = await makeDir();
  try {
    const original = await writeArtifact(dir, 'app.elf', FIXTURES.elf);
    const baseline = await auditArtifact(original);

    // 等长清零 Go 构建信息魔数：模拟 metadata.go-buildinfo-pointer-overwrite 施加后的状态。
    const hardenedBytes = Buffer.from(FIXTURES.elf);
    const magicAt = hardenedBytes.indexOf(GO_BUILDINFO_MAGIC);
    assert.ok(magicAt >= 0, 'ELF 夹具应含 Go 构建信息魔数');
    hardenedBytes.fill(0, magicAt, magicAt + GO_BUILDINFO_MAGIC.length);
    const hardened = await writeArtifact(dir, 'app.elf.hardened', hardenedBytes);

    const { exitCode, report } = await verifyArtifact(hardened, { baseline });
    assert.equal(exitCode, 0, '施加记录覆盖的项被豁免后，复审应通过');
    assert.equal(report.applied.source, 'baseline-diff');
    assert.deepEqual(report.applied.mitigations, ['metadata.go-buildinfo-pointer-overwrite']);
    const required = checkOf(report, 'required-sections');
    assert.equal(required.status, 'passed');
    assert.ok(required.detail.exempted.includes('elf.section.go-buildinfo'), '构建信息节应按施加记录豁免');
    assert.equal(required.detail.failedItems.length, 0);
    assert.equal(required.detail.unverifiedItems.length, 0);
    assert.equal(required.detail.required.length, REQUIRED_SETS.elf.items.length - 1, '除豁免项外全部仍须可解析');

    // 前后差异：消失一项、无新增、其余残留。
    assert.equal(report.comparison.resolved.length, 1);
    assert.equal(report.comparison.resolved[0].category, 'go-buildinfo');
    assert.equal(report.comparison.introduced.length, 0);
    assert.equal(report.comparison.persisting.length, 4);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('没有基线与施加记录时，必需集一项都不豁免', async () => {
  const dir = await makeDir();
  try {
    const path = await writeArtifact(dir, 'app.elf', FIXTURES.elf);
    const { report } = await verifyArtifact(path);
    assert.equal(report.applied.source, 'none');
    assert.deepEqual(report.applied.mitigations, []);
    assert.deepEqual(checkOf(report, 'required-sections').detail.exempted, []);
    assert.equal(report.comparison, null, '未给基线时不输出前后差异');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('显式施加记录的三种形状都归一出同一组豁免', async () => {
  const dir = await makeDir();
  try {
    const hardenedBytes = Buffer.from(FIXTURES.elf);
    hardenedBytes.fill(0, hardenedBytes.indexOf(GO_BUILDINFO_MAGIC), hardenedBytes.indexOf(GO_BUILDINFO_MAGIC) + GO_BUILDINFO_MAGIC.length);
    const path = await writeArtifact(dir, 'app.elf', hardenedBytes);
    const shapes = [
      ['metadata.go-buildinfo-pointer-overwrite'],
      [{ mitigation: 'metadata.go-buildinfo-pointer-overwrite' }],
      { applied: [{ mitigation: 'metadata.go-buildinfo-pointer-overwrite' }] },
    ];
    for (const applied of shapes) {
      const { exitCode, report } = await verifyArtifact(path, { applied });
      assert.equal(exitCode, 0);
      assert.equal(report.applied.source, 'explicit');
      assert.deepEqual(report.applied.mitigations, ['metadata.go-buildinfo-pointer-overwrite']);
      assert.ok(checkOf(report, 'required-sections').detail.exempted.includes('elf.section.go-buildinfo'));
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('畸形施加记录按用法错误拒绝，退出码 2', async () => {
  const dir = await makeDir();
  try {
    const path = await writeArtifact(dir, 'app.elf', FIXTURES.elf);
    await assert.rejects(
      () => verifyArtifact(path, { applied: 'not-a-record' }),
      (error) => error instanceof UsageError && error.code === 2,
    );
    await assert.rejects(
      () => verifyArtifact(path, { applied: [{ noMitigationField: true }] }),
      (error) => error instanceof UsageError && error.code === 2,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('签名制品施加过缓解措施时标记 requires_resign，但不因此判不通过', async () => {
  const dir = await makeDir();
  try {
    const path = await writeArtifact(dir, 'signed.macho', FIXTURES['mach-o']);
    const { exitCode, report } = await verifyArtifact(path, { applied: ['metadata.go-buildinfo-macho-rw-overwrite'] });
    assert.equal(exitCode, 0, '签名载荷范围完整时不因需要重新签名而失败');
    assert.equal(report.requiresResign, true);
    const check = checkOf(report, 'signature-consistency');
    assert.equal(check.status, 'passed');
    assert.equal(check.detail.requiresResign, true);
    assert.match(check.reason, /重新签名/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('基线不是审计报告时不崩溃，全部本次发现按新增处理', async () => {
  const dir = await makeDir();
  try {
    const path = await writeArtifact(dir, 'app.elf', FIXTURES.elf);
    const { exitCode, report } = await verifyArtifact(path, { baseline: { hello: 'world' } });
    assert.equal(exitCode, 0);
    // 基线读不到 findings 时按空前缀比对：本次全部发现都是新增，没有消失与残留。
    const current = await auditArtifact(path);
    assert.deepEqual(report.comparison.resolved, []);
    assert.deepEqual(report.comparison.persisting, []);
    assert.equal(report.comparison.introduced.length, new Set(current.findings.map((finding) => [finding.layer, finding.category, finding.reader].join('|'))).size);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 畸形输入
// ---------------------------------------------------------------------------

test('程序头被破坏的 ELF：容器解析与必需集双双判不通过，退出码 1', async () => {
  const dir = await makeDir();
  try {
    const path = await writeArtifact(dir, 'broken.elf', FIXTURES['elf-broken-program-headers']);
    const { exitCode, report } = await verifyArtifact(path);
    assert.equal(exitCode, 1);
    assert.equal(report.status, 'failed');
    const parse = checkOf(report, 'container-parse');
    assert.equal(parse.status, 'failed');
    assert.match(parse.reason, /程序头表/);
    const required = checkOf(report, 'required-sections');
    assert.equal(required.status, 'failed');
    assert.ok(required.detail.failedItems.includes('elf.program-headers'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('人为截断的制品：结构复审判不通过，退出码 1', async () => {
  const dir = await makeDir();
  try {
    // 截到节表之前：程序头表与节表都越界。
    const truncated = await writeArtifact(dir, 'cut.elf', FIXTURES.elf.subarray(0, 200));
    const { exitCode, report } = await verifyArtifact(truncated);
    assert.equal(exitCode, 1);
    assert.equal(checkOf(report, 'container-parse').status, 'failed');
    assert.equal(checkOf(report, 'required-sections').status, 'failed');

    // ZIP 截掉结尾记录：容器无法定位中央目录。
    const cutZip = await writeArtifact(dir, 'cut.zip', FIXTURES.zip.subarray(0, FIXTURES.zip.length - 30));
    const zipResult = await verifyArtifact(cutZip);
    assert.equal(zipResult.exitCode, 1);
    assert.equal(checkOf(zipResult.report, 'container-parse').status, 'failed');
    assert.match(checkOf(zipResult.report, 'container-parse').reason, /结束记录/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('伪魔数与空文件不崩溃：声称受支持却结构坏死的判不通过，范围外的不做结构复审', async () => {
  const dir = await makeDir();
  try {
    // ELF 魔数之后全零：phoff 为 0，程序头表不存在。
    const fakeElf = await writeArtifact(dir, 'fake.elf', Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(60, 0)]));
    const fakeResult = await verifyArtifact(fakeElf);
    assert.equal(fakeResult.exitCode, 1);
    assert.equal(checkOf(fakeResult.report, 'container-parse').status, 'failed');

    // 空文件、随机字节、纯文本：不落入 v1 格式集，没有结构可复审，不冒充通过也不判失败。
    for (const [name, bytes] of [
      ['empty.bin', Buffer.alloc(0)],
      ['random.bin', Buffer.from('definitely not a container format at all', 'latin1')],
    ]) {
      const path = await writeArtifact(dir, name, bytes);
      const { exitCode, report } = await verifyArtifact(path);
      assert.equal(exitCode, 0, `${name} 没有容器结构可复审，不应判失败`);
      assert.equal(report.status, 'passed');
      assert.equal(report.checks.length, 0);
      assert.equal(report.summary.outOfScopeEntries, 1);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('目标不存在时按用法错误拒绝，退出码 2', async () => {
  await assert.rejects(
    () => verifyArtifact(join(tmpdir(), 'anti-rea-verify-missing-target')),
    (error) => error instanceof UsageError && error.code === 2,
  );
});

// ---------------------------------------------------------------------------
// 部分读取：预算受限时记 pending，总体结论 partial，退出码 1
// ---------------------------------------------------------------------------

test('单文件上限极小时全部检查记 pending，结论 partial 且退出码 1，进程不失败', async () => {
  const dir = await makeDir();
  try {
    const path = await writeArtifact(dir, 'app.zip', FIXTURES.zip);
    const { exitCode, report } = await verifyArtifact(path, { policy: { budgets: { maxFileBytes: 16 } } });
    assert.equal(exitCode, 1, '复审无法完成时安全门不得放行');
    assert.equal(report.status, 'partial');
    assert.equal(report.summary.failed, 0, '部分读取不是制品损坏的证据，不得记失败');
    assert.equal(report.summary.pending, report.checks.length);
    for (const check of report.checks) {
      assert.equal(check.status, 'pending');
      assert.match(check.reason, /结构复审无法完成/);
    }
    const codes = report.limitations.map((limitation) => limitation.code);
    assert.ok(codes.includes('verify-read-truncated'), '部分读取必须附限制说明');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('目录目标受预算约束时逐个条目记 pending，不因个别条目无法读取而失败退出', async () => {
  const dir = await makeDir();
  try {
    await writeArtifact(dir, 'app.elf', FIXTURES.elf);
    await writeArtifact(dir, 'data.zip', FIXTURES.zip);
    const { exitCode, report } = await verifyArtifact(dir, { policy: { budgets: { maxFileBytes: 16 } } });
    assert.equal(exitCode, 1);
    assert.equal(report.status, 'partial');
    assert.equal(report.summary.failed, 0);
    const entries = new Set(report.checks.filter((check) => check.status === 'pending').map((check) => check.entry));
    assert.deepEqual([...entries].sort(), ['app.elf', 'data.zip']);
    assertClosedVocabulary(report);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 检查族封闭性
// ---------------------------------------------------------------------------

test('检查族与检查状态都是封闭集合，报告只用词表内取值', () => {
  assert.deepEqual([...CHECK_FAMILIES], [
    'container-parse',
    'signature-consistency',
    'checksum-consistency',
    'pyc-flag-consistency',
    'required-sections',
  ]);
  assert.deepEqual([...CHECK_STATUSES], ['passed', 'failed', 'pending', 'not-applicable']);
  assert.equal(new Set(CHECK_FAMILIES).size, CHECK_FAMILIES.length);
  assert.equal(new Set(CHECK_STATUSES).size, CHECK_STATUSES.length);
});
