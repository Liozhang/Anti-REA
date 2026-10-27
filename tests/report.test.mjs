// report 模块测试：机器可读报告的序列化、脱敏与加固前后差异比对。
// 夹具全部来自 tests/helpers/container-fixtures.mjs 的字节级精确构造，先写进临时目录再审计，
// 跑的是真实格式字节；畸形输入与部分读取用真实夹具的截断形态与策略预算构造。

import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { auditArtifact } from '../src/audit/engine.mjs';
import { createFinding } from '../src/audit/finding.mjs';
import { DEFAULT_POLICY } from '../src/policy/schema.mjs';
import * as reportModule from '../src/report/index.mjs';
import { diffAudits, sameDigest } from '../src/report/diff.mjs';
import { isRedacted, redactReport } from '../src/report/redact.mjs';
import { renderTextReport, serializeReport, TRUNCATION_MARK } from '../src/report/serialize.mjs';
import { verifyArtifact } from '../src/verify/index.mjs';
import { runCli } from './helpers/cli.mjs';
import { CONTAINER_FIXTURES, writeContainerFixtures } from './helpers/container-fixtures.mjs';

/** 取登记表里的夹具字节。@param {string} relativePath @returns {Buffer} */
function fixtureBytes(relativePath) {
  const fixture = CONTAINER_FIXTURES.find((item) => item.relativePath === relativePath);
  assert.notEqual(fixture, undefined, `登记表缺少夹具：${relativePath}`);
  return fixture.bytes;
}

/**
 * 建一个装了全部夹具的临时工作区。
 * @returns {Promise<{dir: string, root: string, cleanup: () => Promise<void>}>}
 */
async function fixtureWorkspace() {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-report-'));
  const root = join(dir, 'fixtures');
  await writeContainerFixtures(root);
  return { dir, root, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

/** 只放两类制品的临时目录，用于构造前后差异。@returns {Promise<{dir: string, cleanup: () => Promise<void>}>} */
async function pairWorkspace() {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-report-pair-'));
  return { dir, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

// —— 序列化：正常输入 ——

test('真实审计报告序列化后可原样解析', async () => {
  const workspace = await fixtureWorkspace();
  try {
    const report = await auditArtifact(workspace.root);
    assert.ok(report.findings.length > 0, '夹具目录应产生真实发现');
    const text = serializeReport(report, { policy: DEFAULT_POLICY });
    assert.ok(!text.includes(TRUNCATION_MARK), '默认预算不应截断');
    assert.deepEqual(JSON.parse(text), report, '序列化再解析应与原报告逐字段相等');
  } finally {
    await workspace.cleanup();
  }
});

test('人读文本包含工具、状态、摘要、逐层计数、能力边界与限制说明', async () => {
  const workspace = await fixtureWorkspace();
  try {
    const report = await auditArtifact(workspace.root);
    const text = renderTextReport(report);
    assert.ok(text.includes('工具：audit-artifact'));
    assert.ok(text.includes(`状态：${report.status}`));
    assert.ok(text.includes(`制品摘要：${report.artifact.sha256}`));
    assert.ok(text.includes('制品字节数：'));
    assert.ok(text.includes(`发现数：${report.summary.findings}`));
    for (const [layer, count] of Object.entries(report.summary.byLayer)) {
      if (count > 0) {
        assert.ok(text.includes(`${layer}：${count}`), `人读文本应包含层 ${layer} 的计数`);
      }
    }
    assert.ok(text.includes(`能力边界：${report.capabilityBoundaries.length} 项`));
    assert.ok(text.includes(`限制说明：${report.limitations.length} 项`));
    assert.ok(text.endsWith('\n'), '人读文本以换行收尾');
  } finally {
    await workspace.cleanup();
  }
});

test('复审报告的人读文本显示检查统计，不拿发现数 0 冒充', async () => {
  const workspace = await fixtureWorkspace();
  try {
    const { report } = await verifyArtifact(join(workspace.root, 'elf', 'basic.elf'));
    // 复审报告按检查族汇总，没有 summary.findings 字段。
    assert.equal(report.summary.findings, undefined, '复审报告不得带发现数字段');
    assert.ok(report.summary.checks > 0, '复审至少要跑一个检查族');
    const text = renderTextReport(report);
    assert.ok(!text.includes('发现数'), '复审报告不得显示发现数 0');
    assert.ok(text.includes(`检查数：${report.summary.checks} 项`));
    assert.ok(text.includes(`通过 ${report.summary.passed}`));
    assert.ok(text.includes(`失败 ${report.summary.failed}`));
    assert.ok(text.includes(`待定 ${report.summary.pending}`));
    assert.ok(text.includes(`不适用 ${report.summary.notApplicable}`));
  } finally {
    await workspace.cleanup();
  }
});

test('自定义缩进生效', async () => {
  const workspace = await fixtureWorkspace();
  try {
    const report = await auditArtifact(join(workspace.root, 'elf', 'basic.elf'));
    const compact = serializeReport(report, { indent: 0 });
    assert.ok(!compact.includes('\n'), '缩进为 0 时不应有换行');
    assert.deepEqual(JSON.parse(compact), report);
  } finally {
    await workspace.cleanup();
  }
});

// —— 序列化：资源上限与畸形输入 ——

test('报表字节上限减半时丢掉明细保留汇总，且不超限', async () => {
  const findings = [];
  for (let index = 0; index < 3000; index += 1) {
    findings.push(
      createFinding({
        layer: 'metadata-hygiene',
        severity: 'info',
        title: `标题 ${index}`,
        category: 'elf-header',
        evidence: { path: `elf/app-${index}.elf`, byteRange: [0, 64] },
        reader: 'elf',
        readerLimitation: '只读头部，不解析节表',
      }),
    );
  }
  const report = {
    schema: 'anti-rea.audit-report/1',
    tool: 'audit-artifact',
    status: 'complete',
    artifact: { kind: 'directory', path: '/build/out', sha256: 'a'.repeat(64), bytes: 4096, entryCount: 3000 },
    findings,
    limitations: [],
    summary: { findings: findings.length },
  };
  const full = serializeReport(report);
  const limit = Math.floor(Buffer.byteLength(full, 'utf8') / 2);
  const text = serializeReport(report, { policy: { budgets: { maxReportBytes: limit } } });
  assert.ok(Buffer.byteLength(text, 'utf8') <= limit, '截断后的报表不得超过策略上限');
  const parsed = JSON.parse(text);
  assert.equal(parsed.truncated, true, '截断必须留下标记');
  assert.equal(parsed.truncation.limit, limit);
  assert.equal(parsed.findings, undefined, '超限时先丢 findings 明细');
  assert.equal(parsed.summary.findings, findings.length, '汇总必须保留');
});

test('汇总也放不下时硬截断，输出不超限且留有截断痕迹', async () => {
  const findings = [];
  for (let index = 0; index < 2000; index += 1) {
    findings.push(
      createFinding({
        layer: 'metadata-hygiene',
        severity: 'info',
        title: `标题 ${index}`,
        category: 'elf-header',
        evidence: { path: `elf/app-${index}.elf`, byteRange: [0, 64] },
        reader: 'elf',
        readerLimitation: '只读头部，不解析节表',
      }),
    );
  }
  const boundaries = [];
  for (let index = 0; index < 20000; index += 1) {
    boundaries.push({ id: 'generic-script-package', label: '范围外容器', reason: `第 ${index} 个范围外条目`, count: 1 });
  }
  const report = {
    schema: 'anti-rea.audit-report/1',
    tool: 'audit-artifact',
    status: 'complete',
    artifact: { kind: 'directory', path: '/build/out', sha256: 'b'.repeat(64), bytes: 4096, entryCount: 22000 },
    findings,
    capabilityBoundaries: boundaries,
    limitations: [],
    summary: { findings: findings.length },
  };
  const limit = 5000;
  const text = serializeReport(report, { policy: { budgets: { maxReportBytes: limit } } });
  assert.ok(Buffer.byteLength(text, 'utf8') <= limit, '硬截断后仍不得超过策略上限');
  assert.ok(
    text.includes(TRUNCATION_MARK) || text.includes('"truncated": true'),
    '硬截断必须留下痕迹：要么有截断标记，要么前缀里看得到 truncated 字段',
  );
});

test('上限为零或放不下截断标记时输出退化为可容纳的前缀', async () => {
  const report = { schema: 'anti-rea.audit-report/1', tool: 'audit-artifact', status: 'complete', artifact: { sha256: 'c'.repeat(64) } };
  const markBytes = Buffer.byteLength(TRUNCATION_MARK, 'utf8');

  const zero = serializeReport(report, { policy: { budgets: { maxReportBytes: 0 } } });
  assert.equal(zero, '', '上限为零时输出空串，不抛错');

  const tiny = serializeReport(report, { policy: { budgets: { maxReportBytes: 10 } } });
  assert.ok(Buffer.byteLength(tiny, 'utf8') <= 10, '放不下截断标记时也不得超限');

  const exact = serializeReport(report, { policy: { budgets: { maxReportBytes: markBytes } } });
  assert.ok(exact.endsWith(TRUNCATION_MARK), '上限恰好等于标记长度时应原样附上标记');
  assert.equal(Buffer.byteLength(exact, 'utf8'), markBytes);
});

test('硬截断按字符边界回退，不把多字节字符切成两半', () => {
  // 单行 JSON（缩进为 0）没有换行可切，只能按字节边界回退：
  // 中文内容被切成半个字符时会产出替换字符，字节数还会胀出上限。
  const report = {
    schema: 'anti-rea.audit-report/1',
    tool: 'audit-artifact',
    status: 'complete',
    note: '中文说明'.repeat(2000),
  };
  const limit = 300;
  const text = serializeReport(report, { indent: 0, policy: { budgets: { maxReportBytes: limit } } });
  assert.ok(Buffer.byteLength(text, 'utf8') <= limit, '截断后不得超过策略上限');
  assert.ok(!text.includes('\uFFFD'), '不得留下替换字符');
  assert.equal(Buffer.from(text, 'utf8').toString('utf8'), text, '输出必须是合法 UTF-8 文本');
});

test('畸形输入序列化不抛错', async () => {
  assert.equal(serializeReport(undefined), 'null');
  assert.equal(serializeReport(null), 'null');
  assert.equal(serializeReport(42), '42');
  const hugeArray = new Array(50000).fill('x');
  const text = serializeReport(hugeArray, { policy: { budgets: { maxReportBytes: 512 } } });
  assert.ok(Buffer.byteLength(text, 'utf8') <= 512, '超限的畸形输入也要落进上限内');
  const text2 = renderTextReport(null);
  assert.ok(text2.includes('工具：未知'), '人读文本对空报告给占位而不是抛错');
  assert.ok(text2.includes('状态：未知'));
});

// —— 差异比对：正常输入 ——

test('同一制品两次审计全部判为残留', async () => {
  const workspace = await fixtureWorkspace();
  try {
    const first = await auditArtifact(workspace.root);
    const second = await auditArtifact(workspace.root);
    const diff = diffAudits(first, second);
    assert.equal(diff.persisting.length, first.findings.length, '同一份制品重复审计不应有任何发现消失或新增');
    assert.equal(diff.resolved.length, 0);
    assert.equal(diff.introduced.length, 0);
  } finally {
    await workspace.cleanup();
  }
});

test('重布局写入后字节范围变化不误判为消失又新增', async () => {
  const workspace = await fixtureWorkspace();
  try {
    const original = fixtureBytes('safetensors/basic.safetensors');
    const headerLength = Number(original.readBigUInt64LE(0));
    const header = JSON.parse(original.subarray(8, 8 + headerLength).toString('utf8'));
    const before = await auditArtifact(join(workspace.root, 'safetensors', 'basic.safetensors'));
    assert.ok(before.findings.length >= 3, 'safetensors 夹具应报头部、元数据与张量三类事实');

    // 重布局写入：头部写入 __metadata__ 后变长，张量数据整体后移，字节范围全部变化。
    const grownHeader = Buffer.from(JSON.stringify({ ...header, __metadata__: { ...header.__metadata__, notice: 'x'.repeat(64) } }), 'utf8');
    const prefix = Buffer.alloc(8);
    prefix.writeBigUInt64LE(BigInt(grownHeader.length), 0);
    const relocated = Buffer.concat([prefix, grownHeader, original.subarray(8 + headerLength)]);
    const relocatedPath = join(workspace.dir, 'relocated.safetensors');
    await writeFile(relocatedPath, relocated);
    const after = await auditArtifact(relocatedPath);

    // 先证明字节范围确实变过，否则后面的断言是空转。
    const beforeRanges = before.findings.map((finding) => JSON.stringify(finding.evidence.byteRange));
    const afterRanges = after.findings.map((finding) => JSON.stringify(finding.evidence.byteRange));
    assert.notDeepEqual(afterRanges, beforeRanges, '重布局后字节范围应发生变化');

    const diff = diffAudits(before, after);
    assert.equal(diff.persisting.length, before.findings.length, '同一事实只换了字节范围，不应判成消失');
    assert.equal(diff.resolved.length, 0);
    assert.equal(diff.introduced.length, 0);
  } finally {
    await workspace.cleanup();
  }
});

test('制品变化产生消失与新增发现', async () => {
  const workspace = await pairWorkspace();
  try {
    const beforeDir = join(workspace.dir, 'before');
    const afterDir = join(workspace.dir, 'after');
    await mkdir(beforeDir, { recursive: true });
    await mkdir(afterDir, { recursive: true });
    await writeFile(join(beforeDir, 'app.elf'), fixtureBytes('elf/basic.elf'));
    await writeFile(join(beforeDir, 'app.zip'), fixtureBytes('zip/mixed-entries.zip'));
    await writeFile(join(afterDir, 'random.bin'), fixtureBytes('malformed/random.bin'));
    await writeFile(join(afterDir, 'model.gguf'), fixtureBytes('gguf/basic.gguf'));

    const before = await auditArtifact(beforeDir);
    const after = await auditArtifact(afterDir);
    const diff = diffAudits(before, after);

    const readersOf = (list) => new Set(list.map((finding) => finding.reader));
    assert.ok(diff.resolved.length > 0, '制品换掉后原有发现应判为消失');
    assert.ok(readersOf(diff.resolved).has('elf'), 'ELF 头部事实应消失');
    assert.ok(readersOf(diff.resolved).has('zip'), 'ZIP 条目事实应消失');
    assert.ok(readersOf(diff.introduced).has('gguf'), 'GGUF 事实应判为新增');
    assert.equal(diff.persisting.length, 0, '两类目录没有共同事实');
  } finally {
    await workspace.cleanup();
  }
});

// —— 差异比对：部分读取与畸形输入 ——

test('部分读取的报告与完整报告比对：未读到的发现记消失', async () => {
  const workspace = await fixtureWorkspace();
  try {
    const full = await auditArtifact(workspace.root);
    const partial = await auditArtifact(workspace.root, { policy: { budgets: { maxFileBytes: 1 } } });
    assert.equal(partial.status, 'partial', '单文件上限设为 1 字节时应产部分结果');
    assert.ok(
      partial.limitations.some((limitation) => limitation.code === 'max-file-bytes-exceeded'),
      '部分结果必须附单文件上限限制说明',
    );
    // 基线是完整审计，本次只读到一部分：基线有而本次没有的发现记消失。
    const diff = diffAudits(full, partial);
    assert.equal(diff.persisting.length, 0, '部分读取一条内容都没读到，没有可残留的发现');
    assert.equal(diff.introduced.length, 0, '部分读取不会凭空多出发现');
    assert.equal(diff.resolved.length, full.findings.length, '未读到的发现按消失计入比对');

    // 部分报告照样要能序列化与脱敏：留痕不能因为读了一半就断。
    assert.deepEqual(JSON.parse(serializeReport(partial)), partial);
    const redacted = redactReport(partial);
    assert.equal(redacted.redacted, true);
    assert.equal(redacted.summary.findings, partial.summary.findings);
  } finally {
    await workspace.cleanup();
  }
});

test('畸形比对输入按空列表处理', () => {
  for (const [left, right] of [
    [null, null],
    [undefined, undefined],
    [{}, {}],
    [{ findings: 'not-an-array' }, { findings: 42 }],
    [{ findings: null }, { findings: [null, 7, 'x'] }],
  ]) {
    const diff = diffAudits(left, right);
    assert.deepEqual(diff, { resolved: [], introduced: [], persisting: [] }, `畸形输入不应产生比对结果：${JSON.stringify(String(left))}`);
  }
  // 可识别项照常比对，混在畸形条目里不被丢弃。
  const finding = createFinding({
    layer: 'metadata-hygiene',
    severity: 'info',
    title: '标题',
    category: 'elf-header',
    evidence: { path: 'app.elf' },
    reader: 'elf',
    readerLimitation: '限制',
  });
  const diff = diffAudits({ findings: [null, finding] }, { findings: [finding, 'junk'] });
  assert.equal(diff.persisting.length, 1);
  assert.equal(diff.resolved.length, 0);
  assert.equal(diff.introduced.length, 0);
});

test('同一标识多条发现按次数配对', () => {
  const make = (title) =>
    createFinding({
      layer: 'metadata-hygiene',
      severity: 'info',
      title,
      category: 'elf-header',
      evidence: { path: 'app.elf' },
      reader: 'elf',
      readerLimitation: '限制',
    });
  const twoVsOne = diffAudits({ findings: [make('一'), make('二')] }, { findings: [make('三')] });
  assert.equal(twoVsOne.persisting.length, 1, '次数相同部分残留');
  assert.equal(twoVsOne.resolved.length, 1, '基线多出来的一条记消失');
  assert.equal(twoVsOne.introduced.length, 0);

  const oneVsTwo = diffAudits({ findings: [make('一')] }, { findings: [make('二'), make('三')] });
  assert.equal(oneVsTwo.persisting.length, 1);
  assert.equal(oneVsTwo.introduced.length, 1, '本次多出来的一条记新增');
  assert.equal(oneVsTwo.resolved.length, 0);
});

test('sameDigest 判定逐字节相同', () => {
  const digest = 'd'.repeat(64);
  assert.equal(sameDigest({ sha256: digest }, { sha256: digest }), true);
  assert.equal(sameDigest({ sha256: digest }, { sha256: 'e'.repeat(64) }), false);
  assert.equal(sameDigest({ sha256: digest }, {}), false, '缺摘要不能算相同');
  assert.equal(sameDigest({}, { sha256: digest }), false);
  assert.equal(sameDigest(null, { sha256: digest }), false);
  assert.equal(sameDigest({ sha256: digest }, undefined), false);
  assert.equal(sameDigest(undefined, undefined), false);
  assert.equal(sameDigest('sha', { sha256: digest }), false, '标量不是制品摘要');
});

// —— 脱敏 ——

test('真实审计报告脱敏后隐去路径、字节范围与缓解对应关系', async () => {
  const workspace = await fixtureWorkspace();
  try {
    const report = await auditArtifact(workspace.root);
    // 给其中一条发现补上缓解编号与证据摘录：真实夹具的发现多为 info 级、摘录为空，
    // 这里保证待隐去的三类内容都真实存在，断言不是空转。
    const withMitigation = {
      ...report,
      findings: report.findings.map((finding, index) =>
        index === 0
          ? { ...finding, mitigation: 'metadata.go-buildinfo-inline-overwrite', evidence: { ...finding.evidence, excerpt: 'go1.22.0 linux/amd64' } }
          : finding,
      ),
    };
    const redacted = redactReport(withMitigation);
    const text = JSON.stringify(redacted);

    assert.equal(redacted.redacted, true);
    assert.equal(isRedacted(redacted), true);
    assert.equal(isRedacted(withMitigation), false, '原报告不因脱敏调用而变成脱敏报告');
    assert.ok(!text.includes('byteRange'), '不得保留字节范围字段');
    assert.ok(!text.includes('go1.22.0'), '不得保留证据摘录');
    assert.ok(!text.includes('metadata.go-buildinfo-inline-overwrite'), '不得保留缓解措施对应关系');
    for (const fixture of CONTAINER_FIXTURES) {
      const base = fixture.relativePath.split('/').pop();
      assert.ok(!text.includes(fixture.relativePath), `脱敏报告不得保留条目路径：${fixture.relativePath}`);
      assert.ok(!text.includes(base), `脱敏报告不得保留条目文件名：${base}`);
    }
    assert.ok(!text.includes(workspace.root.split(/[\\/]/).pop()), '脱敏报告不得保留制品目录名');
  } finally {
    await workspace.cleanup();
  }
});

test('脱敏保留分类、计数与制品摘要，且不修改原报告', async () => {
  const workspace = await fixtureWorkspace();
  try {
    const report = await auditArtifact(workspace.root);
    const snapshot = JSON.stringify(report);
    const redacted = redactReport(report);
    assert.equal(JSON.stringify(report), snapshot, '脱敏不得修改原报告对象');

    assert.equal(redacted.artifact.sha256, report.artifact.sha256, '制品摘要保留，供收件方核对同一制品');
    assert.equal(redacted.artifact.bytes, report.artifact.bytes);
    assert.equal(redacted.artifact.entryCount, report.artifact.entryCount);
    assert.equal(redacted.status, report.status);
    assert.deepEqual(redacted.summary, report.summary, '逐层逐严重度计数原样保留');
    assert.equal(redacted.findings.length, report.findings.length, '发现条数保留');
    assert.deepEqual(
      redacted.findings.map((finding) => [finding.layer, finding.severity, finding.category, finding.reader]),
      report.findings.map((finding) => [finding.layer, finding.severity, finding.category, finding.reader]),
      '分类信息逐条保留',
    );
    assert.equal(redacted.capabilityBoundaries.length, report.capabilityBoundaries.length);
    for (const [index, boundary] of redacted.capabilityBoundaries.entries()) {
      assert.equal(boundary.count, report.capabilityBoundaries[index].count, '能力边界计数保留');
    }
    assert.deepEqual(
      redacted.limitations.map((limitation) => limitation.code),
      report.limitations.map((limitation) => limitation.code),
      '限制说明的标识保留，消息按脱敏处理',
    );
  } finally {
    await workspace.cleanup();
  }
});

test('限制说明里的条目路径被替换，非路径斜杠不误伤', () => {
  const report = {
    schema: 'anti-rea.audit-report/1',
    tool: 'audit-artifact',
    status: 'partial',
    artifact: { kind: 'file', path: 'C:\\secret\\build\\app.bin', sha256: 'f'.repeat(64), bytes: 2048 },
    findings: [
      {
        layer: 'metadata-hygiene',
        severity: 'high',
        title: 'ELF 头',
        category: 'elf-header',
        evidence: { path: 'C:\\secret\\build\\app.bin', byteRange: [0, 64], excerpt: 'go1.22.0' },
        reader: 'elf',
        readerLimitation: '只读头部',
        mitigation: 'metadata.elf-symtab-clear',
      },
    ],
    limitations: [
      { code: 'reader-error', message: '读取器 elf 在解析 src/main.js 时遇到意外错误：boom', scope: 'entry' },
      { code: 'other', message: '范围覆盖 elf/pe/mach-o 三类容器，和/或 组合都不涉路径', scope: 'entry' },
    ],
    capabilityBoundaries: [],
    summary: {},
  };
  const redacted = redactReport(report);
  const text = JSON.stringify(redacted);
  assert.ok(!text.includes('app.bin'), '制品路径与裸文件名都应隐去');
  assert.ok(!text.includes('secret'), '路径片段应隐去');
  assert.ok(!text.includes('src/main.js'), '限制说明里的条目相对路径应隐去');
  assert.ok(!text.includes('main.js'), '路径末段也应隐去');
  assert.ok(text.includes('（路径已脱敏）'), '隐去处应留占位符，让收件方知道有内容被脱敏');
  assert.ok(text.includes('和/或'), '非路径斜杠不得误伤');
  assert.ok(text.includes('elf/pe/mach-o'), '非路径斜杠组合不得误伤');
});

test('复审风格报告脱敏后比对变计数、检查项不出现、重新签名标记保留', () => {
  const verifyReport = {
    schema: 'anti-rea.verify-report/1',
    tool: 'verify-artifact',
    status: 'passed',
    artifact: { kind: 'file', path: '/build/out/app.elf', sha256: 'a'.repeat(64), bytes: 337, container: 'elf' },
    checks: [{ family: 'container-parse', container: 'elf', entry: 'app.elf', status: 'passed', reason: '可解析' }],
    comparison: { resolved: [{ layer: 'metadata-hygiene', category: 'elf-header', reader: 'elf' }], introduced: [], persisting: [] },
    applied: { source: 'explicit', mitigations: ['metadata.elf-symtab-clear'] },
    requiresResign: true,
    limitations: [
      { code: 'verify-read-truncated', message: '条目 app.elf 只读取前 8 字节（共 337 字节），未覆盖部分没有做结构复审', scope: 'entry' },
    ],
    summary: { checks: 1, passed: 1, failed: 0, pending: 0 },
  };
  const redacted = redactReport(verifyReport);
  assert.equal(redacted.redacted, true);
  assert.deepEqual(redacted.comparison, { resolved: 1, introduced: 0, persisting: 0 }, '差异比对脱敏后只留计数');
  assert.equal(redacted.checks, undefined, '逐条目检查项带路径，不得出现在脱敏报告里');
  assert.equal(redacted.applied, undefined, '施加记录是缓解措施对应关系，不得出现在脱敏报告里');
  assert.equal(redacted.requiresResign, true, '需要重新签名是与路径无关的安全信号，必须保留');
  assert.equal(redacted.limitations[0].code, 'verify-read-truncated', '限制说明的标识保留');
  assert.ok(!redacted.limitations[0].message.includes('app.elf'), '限制说明里的条目路径也要隐去');
  assert.ok(redacted.limitations[0].message.includes('（路径已脱敏）'), '隐去处留占位符');
  const text = JSON.stringify(redacted);
  assert.ok(!text.includes('/build/out/app.elf'), '不得保留制品路径');
  assert.ok(!text.includes('app.elf'), '不得保留条目路径');
  assert.ok(!text.includes('metadata.elf-symtab-clear'), '不得保留缓解措施编号');
});

test('脱敏报告仍是可解析的机器可读报告', async () => {
  const workspace = await fixtureWorkspace();
  try {
    const report = await auditArtifact(workspace.root);
    const text = serializeReport(redactReport(report), { policy: DEFAULT_POLICY });
    const parsed = JSON.parse(text);
    assert.equal(parsed.redacted, true);
    assert.equal(isRedacted(parsed), true);
    assert.equal(parsed.summary.findings, report.summary.findings);
    assert.equal(parsed.artifact.path, undefined, '脱敏报告不携带制品路径字段');
  } finally {
    await workspace.cleanup();
  }
});

// —— 与命令行共用同一套工作流 ——

test('audit --json 输出可解析，--redacted 输出不含路径', async () => {
  const workspace = await fixtureWorkspace();
  try {
    const dirName = workspace.root.split(/[\\/]/).pop();
    const plain = await runCli(['audit', workspace.root, '--json']);
    assert.equal(plain.code, 0, '审计正常完成（包括发现暴露）时退出码为 0');
    const parsed = JSON.parse(plain.stdout);
    assert.equal(parsed.summary.findings, parsed.findings.length);

    const redactedRun = await runCli(['audit', workspace.root, '--json', '--redacted']);
    assert.equal(redactedRun.code, 0);
    const redacted = JSON.parse(redactedRun.stdout);
    assert.equal(redacted.redacted, true);
    assert.equal(redacted.artifact.sha256, parsed.artifact.sha256, '脱敏不改变制品摘要');
    assert.ok(!redactedRun.stdout.includes(workspace.root), '脱敏输出不得包含制品绝对路径');
    assert.ok(!redactedRun.stdout.includes(dirName), '脱敏输出不得包含制品目录名');
    for (const fixture of CONTAINER_FIXTURES) {
      assert.ok(!redactedRun.stdout.includes(fixture.relativePath), `脱敏输出不得包含条目路径：${fixture.relativePath}`);
    }
    assert.ok(!redactedRun.stdout.includes('byteRange'), '脱敏输出不得包含字节范围字段');
  } finally {
    await workspace.cleanup();
  }
});

test('audit --format text 渲染人读文本', async () => {
  const workspace = await fixtureWorkspace();
  try {
    const result = await runCli(['audit', join(workspace.root, 'elf', 'basic.elf'), '--format', 'text']);
    assert.equal(result.code, 0);
    assert.ok(result.stdout.includes('工具：audit-artifact'));
    assert.ok(result.stdout.includes('状态：'));
    assert.ok(result.stdout.includes('制品摘要：'));
    assert.ok(result.stdout.includes('metadata-hygiene：1'), '人读文本应含该层的计数');
  } finally {
    await workspace.cleanup();
  }
});

test('report 模块出口导出一致', () => {
  assert.equal(typeof reportModule.serializeReport, 'function');
  assert.equal(typeof reportModule.renderTextReport, 'function');
  assert.equal(typeof reportModule.redactReport, 'function');
  assert.equal(typeof reportModule.isRedacted, 'function');
  assert.equal(typeof reportModule.diffAudits, 'function');
  assert.equal(typeof reportModule.sameDigest, 'function');
  assert.equal(typeof reportModule.TRUNCATION_MARK, 'string');
});
