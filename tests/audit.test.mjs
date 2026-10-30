// 审计引擎与发现模型：把读取器输出归入七层封闭词表，给出严重度与缓解编号。
// 覆盖三类输入：
//   正常输入   已提交夹具目录与文件、注入的读取器表、真实字节构造的各类文件头
//   畸形输入   空路径、不存在的路径、空文件、截断文件头、伪魔数、词表外的发现
//   部分读取   单文件上限、累计扫描窗口、目录条目数上限触发的部分结果与限制说明
// 夹具说明：字节级夹具在临时目录里现构造，不写进仓库，避免与其他模块的夹具登记表相互干扰；
// 目录类输入用已提交且摘要登记在 tests/fixtures/manifest.json 的 sample-app，保证跑的是固定真实字节。

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, open, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { test } from 'node:test';

import { AUDIT_REPORT_SCHEMA, assertAuditReport, auditArtifact } from '../src/audit/engine.mjs';
import {
  MITIGATION_IDS,
  assertFindingVocabulary,
  createFinding,
  findingId,
  numberFindings,
  summarizeFindings,
} from '../src/audit/finding.mjs';
import { LAYER_IDS, SEVERITY_IDS } from '../src/audit/layer-defs.mjs';
import { NotImplementedError } from '../src/errors.mjs';
import { DEFAULT_POLICY } from '../src/policy/schema.mjs';
import { redactReport } from '../src/report/redact.mjs';
import { REPO_ROOT, SAMPLE_APP } from './helpers/cli.mjs';

/** ELF 魔数加填充，够过容器识别的前缀窗口。 */
const ELF_BYTES = Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(60, 0x00)]);

/**
 * 在临时目录里写一个制品文件，返回目录与路径。调用方负责删除目录。
 * @param {string} name 文件名
 * @param {Buffer | string} content 文件内容
 * @returns {Promise<{dir: string, path: string}>}
 */
async function makeArtifact(name, content) {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-audit-'));
  const path = join(dir, name);
  await writeFile(path, content);
  return { dir, path };
}

/**
 * 构造一个注入用读取器：读取器只返回预定事实，用来观察引擎的归组与把关。
 * @param {string} id 读取器标识
 * @param {readonly string[]} layers 层标识
 * @param {{findings?: unknown[], limitations?: unknown[], throws?: Error}} behavior 行为
 * @returns {{id: string, formats: string[], layers: string[], purpose: string, read: Function}}
 */
function fakeReader(id, layers, behavior = {}) {
  return {
    id,
    formats: ['elf'],
    layers,
    purpose: `测试用读取器 ${id}`,
    async read() {
      if (behavior.throws !== undefined) {
        throw behavior.throws;
      }
      return { findings: behavior.findings ?? [], limitations: behavior.limitations ?? [] };
    },
  };
}

/**
 * 造一条发现，字段取自负 closure 词表。
 * @param {Partial<{layer: string, severity: string, title: string, category: string, path: string, reader: string, mitigation: string}>} overrides
 * @returns {Record<string, unknown>}
 */
function sampleFinding(overrides = {}) {
  const { path = 'app.elf', reader = 'elf', ...rest } = overrides;
  return createFinding({
    layer: 'metadata-hygiene',
    severity: 'low',
    title: '标题',
    category: '分类',
    evidence: { path, byteRange: [16, 32], excerpt: 'go1.22.0' },
    reader,
    readerLimitation: '只覆盖已读区间',
    ...rest,
  });
}

/** 带预算覆盖的策略。 */
function policyWithBudgets(budgets) {
  return { ...DEFAULT_POLICY, budgets: { ...DEFAULT_POLICY.budgets, ...budgets } };
}

// ---- 发现模型：编号、词表校验与汇总 ----

test('缓解措施编号是封闭集合：不重复、前缀归层、全部对应词表内的层', () => {
  assert.equal(MITIGATION_IDS.length, 15);
  assert.equal(new Set(MITIGATION_IDS).size, MITIGATION_IDS.length, '编号不得重复');
  const layerOfPrefix = {
    'metadata.': 'metadata-hygiene',
    'content.': 'content-protection',
    'runtime.': 'runtime-observation-resistance',
    'model.': 'model-truthful-signals',
    'secret.': 'secret-minimization',
  };
  for (const id of MITIGATION_IDS) {
    assert.equal(typeof id, 'string');
    assert.ok(id.length > 0, '编号不得为空');
    const prefix = Object.keys(layerOfPrefix).find((candidate) => id.startsWith(candidate));
    assert.notEqual(prefix, undefined, `编号 ${id} 的前缀不在既定集合内`);
    assert.ok(LAYER_IDS.includes(layerOfPrefix[prefix]), `编号 ${id} 对应的层不在词表内`);
  }
});

test('createFinding 接受正常输入并补全可选字段', () => {
  const finding = createFinding({
    layer: 'metadata-hygiene',
    severity: 'high',
    title: 'Go 构建信息',
    category: 'go-buildinfo',
    evidence: { path: 'app.elf', byteRange: [1024, 2048], excerpt: 'go1.22.0' },
    reader: 'elf',
    readerLimitation: '只覆盖 inline 编码',
    mitigation: 'metadata.go-buildinfo-inline-overwrite',
    detail: { encoding: 'inline' },
  });
  assert.equal(finding.layer, 'metadata-hygiene');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.mitigation, 'metadata.go-buildinfo-inline-overwrite');
  assert.deepEqual(finding.evidence, { path: 'app.elf', byteRange: [1024, 2048], excerpt: 'go1.22.0' });
  assert.deepEqual(finding.detail, { encoding: 'inline' });

  const bare = createFinding({
    layer: 'secret-minimization',
    severity: 'info',
    title: '标题',
    category: '分类',
    evidence: { path: 'app.elf' },
    reader: 'elf',
    readerLimitation: '无',
  });
  assert.equal(bare.mitigation, null, '未标注缓解编号时必须是 null 而不是 undefined');
  assert.equal(bare.evidence.byteRange, null);
  assert.equal(bare.evidence.excerpt, null);
  assert.equal(bare.detail, undefined);
});

test('createFinding 拒绝畸形输入：词表外取值、缺证据、类型错误', () => {
  const base = {
    layer: 'metadata-hygiene',
    severity: 'low',
    title: '标题',
    category: '分类',
    evidence: { path: 'x' },
    reader: 'elf',
    readerLimitation: '限制',
  };
  assert.throws(() => createFinding({ ...base, layer: 'not-a-layer' }), /层标识不在封闭词表内/);
  assert.throws(() => createFinding({ ...base, severity: 'critical' }), /严重度不在封闭词表内/);
  assert.throws(() => createFinding({ ...base, mitigation: 'not.a.real.mitigation' }), /缓解措施编号不在已登记集合内/);
  assert.throws(() => createFinding({ ...base, evidence: undefined }), TypeError);
  assert.throws(() => createFinding({ ...base, evidence: {} }), /evidence\.path/);
  assert.throws(() => createFinding({ ...base, evidence: { path: '' } }), /evidence\.path/);
  assert.throws(() => createFinding({ ...base, evidence: { path: 'x', byteRange: [1] } }), /byteRange/);
  assert.throws(() => createFinding({ ...base, evidence: { path: 'x', byteRange: [1, -2] } }), /byteRange/);
  assert.throws(() => createFinding({ ...base, title: '' }), /title/);
  assert.throws(() => createFinding({ ...base, readerLimitation: 7 }), /readerLimitation/);
  assert.throws(() => createFinding({ ...base, readerLimitation: undefined }), /readerLimitation/);
  assert.throws(() => createFinding(null), TypeError);
  assert.throws(() => createFinding('metadata-hygiene'), TypeError);
  assert.throws(() => createFinding([base]), TypeError);
});

test('findingId 按层生成四位序号，拒绝词表外标识与非法序号', () => {
  assert.equal(findingId('metadata-hygiene', 1), 'F-metadata-hygiene-0001');
  assert.equal(findingId('legal-operational', 42), 'F-legal-operational-0042');
  assert.equal(findingId('secret-minimization', 12345), 'F-secret-minimization-12345');
  assert.throws(() => findingId('not-a-layer', 1), /层标识不在封闭词表内/);
  assert.throws(() => findingId('metadata-hygiene', -1), /非负整数/);
  assert.throws(() => findingId('metadata-hygiene', 1.5), /非负整数/);
  assert.throws(() => findingId('metadata-hygiene', '1'), /非负整数/);
});

test('numberFindings 按层内递增编号，编号在报告内唯一', () => {
  const findings = [
    sampleFinding({ layer: 'metadata-hygiene' }),
    sampleFinding({ layer: 'content-protection', severity: 'high' }),
    sampleFinding({ layer: 'metadata-hygiene', severity: 'medium' }),
    sampleFinding({ layer: 'legal-operational', severity: 'info', mitigation: null }),
  ];
  const returned = numberFindings(findings);
  assert.equal(returned, findings, '编号写回同一数组');
  assert.deepEqual(
    findings.map((finding) => finding.id),
    ['F-metadata-hygiene-0001', 'F-content-protection-0001', 'F-metadata-hygiene-0002', 'F-legal-operational-0001'],
  );
  assert.equal(new Set(findings.map((finding) => finding.id)).size, findings.length, '编号不得重复');
  for (const finding of findings) {
    assert.ok(finding.id.startsWith(`F-${finding.layer}-`), '编号必须带层前缀');
  }
});

test('assertFindingVocabulary 接受正常发现，拒绝词表外与残片输入', () => {
  const finding = sampleFinding();
  assert.equal(assertFindingVocabulary(finding), finding, '校验通过时返回同一对象');
  assert.throws(() => assertFindingVocabulary({ ...sampleFinding(), layer: 'not-a-layer' }), /层标识不在封闭词表内/);
  assert.throws(() => assertFindingVocabulary({ ...sampleFinding(), severity: 'fatal' }), /严重度不在封闭词表内/);
  assert.throws(() => assertFindingVocabulary({ ...sampleFinding(), mitigation: 'nope' }), /缓解措施编号不在已登记集合内/);
  assert.throws(() => assertFindingVocabulary({ ...sampleFinding(), evidence: { byteRange: [0, 1] } }), /evidence\.path/);
  assert.throws(() => assertFindingVocabulary(null), TypeError);
  assert.throws(() => assertFindingVocabulary([sampleFinding()]), TypeError);
  assert.throws(() => assertFindingVocabulary({ label: '只有标题的残片' }), /层标识不在封闭词表内/);
});

test('summarizeFindings 按层与严重度汇总，拒绝词表外取值', () => {
  const empty = summarizeFindings([]);
  assert.equal(empty.total, 0);
  assert.deepEqual(Object.keys(empty.byLayer).sort(), [...LAYER_IDS].sort());
  assert.deepEqual(Object.keys(empty.bySeverity).sort(), [...SEVERITY_IDS].sort());

  const summary = summarizeFindings([
    sampleFinding({ layer: 'metadata-hygiene', severity: 'high' }),
    sampleFinding({ layer: 'metadata-hygiene', severity: 'high' }),
    sampleFinding({ layer: 'secret-minimization', severity: 'low' }),
  ]);
  assert.equal(summary.total, 3);
  assert.equal(summary.byLayer['metadata-hygiene'], 2);
  assert.equal(summary.byLayer['secret-minimization'], 1);
  assert.equal(summary.byLayer['content-protection'], 0);
  assert.equal(summary.bySeverity.high, 2);
  assert.equal(summary.bySeverity.low, 1);

  assert.throws(() => summarizeFindings([{ layer: 'not-a-layer', severity: 'low' }]), /层标识不在封闭词表内/);
  assert.throws(() => summarizeFindings([{ layer: 'metadata-hygiene', severity: 'nope' }]), /严重度不在封闭词表内/);
});

// ---- 审计引擎：正常输入 ----

test('审计单个普通文件正常完成，退出路径不抛错', async () => {
  const { dir, path } = await makeArtifact('README.md', '# 说明文档\n普通文本内容。\n');
  try {
    const report = await auditArtifact(path, { now: () => new Date('2020-01-02T03:04:05Z') });
    assert.equal(report.schema, AUDIT_REPORT_SCHEMA);
    assert.equal(report.tool, 'audit-artifact');
    assert.equal(report.status, 'complete');
    assert.equal(report.artifact.kind, 'file');
    assert.equal(report.artifact.container, 'unsupported');
    assert.equal(report.artifact.entryCount, 1);
    assert.equal(report.artifact.bytes, (await stat(path)).size);
    assert.match(report.artifact.sha256, /^[0-9a-f]{64}$/);
    assert.deepEqual(report.findings, []);
    assert.equal(report.capabilityBoundaries.length, 1);
    assert.equal(report.capabilityBoundaries[0].count, 1);
    assert.ok(report.capabilityBoundaries[0].reason.length > 0, '能力边界必须附说明');
    assert.equal(report.generatedAt, '2020-01-02T03:04:05.000Z');
    assert.equal(report.summary.findings, 0);
    assert.deepEqual(Object.keys(report.summary.byLayer).sort(), [...LAYER_IDS].sort());
    assert.equal(assertAuditReport(report), report, '审计报告可直接作为加固输入');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('单文件制品的摘要就是文件自身字节的 sha256，收件方重算即可核对', async () => {
  const { dir, path } = await makeArtifact('README.md', '# 说明文档\n普通文本内容。\n');
  try {
    const report = await auditArtifact(path);
    assert.equal(
      report.artifact.sha256,
      createHash('sha256').update(await readFile(path)).digest('hex'),
      '单文件制品摘要必须是文件自身字节的 sha256，不是条目摘要的再摘要',
    );
    // 脱敏保留摘要，收件方仍能核对收到的是同一份制品。
    const redacted = redactReport(report);
    assert.equal(redacted.artifact.sha256, report.artifact.sha256);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('Java 类文件按范围外容器审计，留下能力边界而不是送进 Mach-O 读取器', async () => {
  // CAFEBABE 同时是 Java 类文件魔数：识别阶段按分片表判为范围外容器后，
  // 审计不再把它当胖二进制解析，也不把读取器缺失冒充成“没有暴露”。
  const javaClass = Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34, 0x00, 0x07, 0x21, 0x00]);
  const { dir, path } = await makeArtifact('App.class', javaClass);
  try {
    const report = await auditArtifact(path);
    assert.equal(report.artifact.container, 'unsupported');
    assert.deepEqual(report.containers, [{ type: 'unsupported', count: 1 }]);
    assert.deepEqual(report.findings, [], '范围外容器不产生 Mach-O 胖二进制发现');
    assert.equal(report.capabilityBoundaries.length, 1, '范围外条目必须留下能力边界说明');
    assert.match(report.capabilityBoundaries[0].reason, /识别结果为 unsupported/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('审计已提交的 sample-app 夹具目录正常完成，两次审计摘要一致', async () => {
  const first = await auditArtifact(SAMPLE_APP);
  const second = await auditArtifact(SAMPLE_APP);
  assert.equal(first.status, 'complete');
  assert.equal(first.artifact.kind, 'directory');
  assert.equal(first.artifact.entryCount, 7);
  assert.equal(first.artifact.container, undefined, '目录目标不报单一容器');
  assert.equal(first.artifact.sha256, second.artifact.sha256, '同一制品两次审计必须得到同一摘要');
  assert.deepEqual(first.findings, []);
  assert.deepEqual(
    first.containers,
    [{ type: 'unsupported', count: 7 }],
    '夹具内七个文件都不落入 v1 九类格式',
  );
  assert.equal(first.capabilityBoundaries.length, 1);
  assert.equal(first.capabilityBoundaries[0].count, 7);
  // 目录条目按路径排序，条目清单可复现。
  const names = await readdir(SAMPLE_APP, { recursive: true });
  assert.ok(names.length >= 5);
});

test('注入读取器时按七层归组，给出编号、严重度与缓解编号', async () => {
  const { dir, path } = await makeArtifact('app.elf', ELF_BYTES);
  try {
    const readers = {
      elf: [
        fakeReader('elf', ['metadata-hygiene', 'secret-minimization'], {
          findings: [
            sampleFinding({ layer: 'metadata-hygiene', severity: 'high', mitigation: 'metadata.go-buildinfo-inline-overwrite' }),
            sampleFinding({ layer: 'secret-minimization', severity: 'medium', mitigation: 'secret.token-placeholder-overwrite', category: 'token' }),
            sampleFinding({ layer: 'content-protection', severity: 'low', mitigation: null }),
          ],
          limitations: [{ code: 'entry-read-truncated', message: '只读取了前 64 字节', scope: 'entry' }],
        }),
      ],
    };
    const report = await auditArtifact(path, { readers, toolName: 'audit_artifact' });

    assert.equal(report.tool, 'audit_artifact', 'MCP 调用面可以标记自己的工具名');
    assert.equal(report.status, 'complete');
    assert.equal(report.artifact.container, 'elf');
    assert.equal(report.capabilityBoundaries.length, 0, '有读取器的容器不报能力边界');
    assert.equal(report.findings.length, 3);

    assert.deepEqual(
      report.findings.map((finding) => finding.id),
      ['F-metadata-hygiene-0001', 'F-secret-minimization-0001', 'F-content-protection-0001'],
    );
    for (const finding of report.findings) {
      assert.ok(LAYER_IDS.includes(finding.layer));
      assert.ok(SEVERITY_IDS.includes(finding.severity));
      assert.equal(finding.evidence.path, 'app.elf', '证据路径用条目相对路径');
      assert.ok(finding.mitigation === null || MITIGATION_IDS.includes(finding.mitigation));
      assert.equal(typeof finding.readerLimitation, 'string');
    }

    assert.equal(report.summary.findings, 3);
    assert.equal(report.summary.byLayer['metadata-hygiene'], 1);
    assert.equal(report.summary.byLayer['secret-minimization'], 1);
    assert.equal(report.summary.byLayer['content-protection'], 1);
    assert.equal(report.summary.bySeverity.high, 1);
    assert.equal(report.summary.bySeverity.medium, 1);
    assert.equal(report.summary.bySeverity.low, 1);
    assert.equal(report.summary.byContainer.elf, 1);
    assert.equal(report.summary.limitations, 1);
    assert.equal(report.limitations[0].code, 'entry-read-truncated');

    // 脱敏保留分类与计数，隐去路径、摘录、字节范围与缓解对应关系。
    const redacted = redactReport(report);
    const text = JSON.stringify(redacted);
    assert.equal(redacted.redacted, true);
    assert.ok(!text.includes('app.elf'), '脱敏报告不得保留证据路径');
    assert.ok(!text.includes('go1.22.0'), '脱敏报告不得保留证据摘录');
    assert.ok(!text.includes('metadata.go-buildinfo-inline-overwrite'), '脱敏报告不得保留缓解对应关系');
    assert.ok(!text.includes('byteRange'), '脱敏报告不得保留字节范围字段');
    assert.equal(redacted.artifact.sha256, report.artifact.sha256);
    assert.equal(redacted.artifact.bytes, report.artifact.bytes);
    assert.equal(redacted.summary.findings, 3);
    assert.deepEqual(redacted.summary.byLayer, report.summary.byLayer);
    assert.deepEqual(
      redacted.findings.map((finding) => finding.layer),
      ['metadata-hygiene', 'secret-minimization', 'content-protection'],
    );
    assert.equal(redacted.findings[0].category, '分类');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('同一制品两次审计得到同一组发现编号', async () => {
  const { dir, path } = await makeArtifact('app.elf', ELF_BYTES);
  try {
    const readers = {
      elf: [fakeReader('elf', ['metadata-hygiene'], { findings: [sampleFinding(), sampleFinding({ severity: 'high' })] })],
    };
    const first = await auditArtifact(path, { readers });
    const second = await auditArtifact(path, { readers });
    assert.deepEqual(
      first.findings.map((finding) => finding.id),
      second.findings.map((finding) => finding.id),
    );
    assert.deepEqual(
      first.findings.map((finding) => finding.id),
      ['F-metadata-hygiene-0001', 'F-metadata-hygiene-0002'],
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('读取器声明尚未实现时登记限制说明，不冒充没有暴露', async () => {
  const { dir, path } = await makeArtifact('app.elf', ELF_BYTES);
  try {
    const readers = {
      elf: [fakeReader('elf', ['metadata-hygiene'], { throws: new NotImplementedError('readers/elf', 'ELF 事实提取') })],
    };
    const report = await auditArtifact(path, { readers });
    assert.equal(report.status, 'complete', '读取器未实现不是部分结果，是已知边界');
    assert.deepEqual(report.findings, []);
    assert.equal(report.limitations.length, 1);
    assert.equal(report.limitations[0].code, 'reader-not-implemented');
    assert.match(report.limitations[0].message, /不等于没有暴露/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('读取器抛出意外错误时审计失败，不把失败算成没有暴露', async () => {
  const { dir, path } = await makeArtifact('app.elf', ELF_BYTES);
  try {
    const readers = { elf: [fakeReader('elf', ['metadata-hygiene'], { throws: new Error('boom') })] };
    await assert.rejects(() => auditArtifact(path, { readers }), /boom/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('读取器返回非数组 findings 时登记限制说明', async () => {
  const { dir, path } = await makeArtifact('app.elf', ELF_BYTES);
  try {
    const readers = {
      elf: [fakeReader('elf', ['metadata-hygiene'], { findings: { not: 'an array' } })],
    };
    const report = await auditArtifact(path, { readers });
    assert.deepEqual(report.findings, []);
    assert.ok(report.limitations.some((limitation) => limitation.code === 'reader-error'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('读取器提交词表外发现时转为限制说明，报告不收录越界取值', async () => {
  const { dir, path } = await makeArtifact('app.elf', ELF_BYTES);
  try {
    const readers = {
      elf: [
        fakeReader('elf', ['metadata-hygiene'], {
          findings: [
            { ...sampleFinding(), layer: 'not-a-layer' },
            { ...sampleFinding(), mitigation: 'not.a.real.mitigation' },
            sampleFinding({ severity: 'high' }),
          ],
        }),
      ],
    };
    const report = await auditArtifact(path, { readers });
    assert.equal(report.findings.length, 1, '只有通过词表校验的发现进报告');
    assert.equal(report.findings[0].severity, 'high');
    const rejected = report.limitations.filter((limitation) => limitation.code === 'finding-rejected');
    assert.equal(rejected.length, 2);
    assert.match(rejected[0].message, /层标识不在封闭词表内/);
    assert.match(rejected[1].message, /缓解措施编号不在已登记集合内/);
    assert.match(rejected[0].message, /不等于没有暴露/);
    assert.equal(report.summary.findings, 1);
    assert.equal(report.summary.byLayer['not-a-layer'], undefined, '汇总不得出现词表外层的计数键');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('策略关闭某层时该层所属读取器不运行，登记 layer-disabled 限制说明', async () => {
  const { dir, path } = await makeArtifact('app.elf', ELF_BYTES);
  try {
    const readers = { elf: [fakeReader('elf', ['metadata-hygiene', 'secret-minimization'], { findings: [sampleFinding()] })] };

    const allOff = await auditArtifact(path, {
      readers,
      policy: { layers: { 'metadata-hygiene': false, 'secret-minimization': false } },
    });
    assert.deepEqual(allOff.findings, []);
    assert.equal(allOff.limitations.length, 1);
    assert.equal(allOff.limitations[0].code, 'layer-disabled');
    assert.match(allOff.limitations[0].message, /已被策略关闭/);

    // 层开关的粒度是读取器：还有一个层开着，读取器照跑。
    const oneOff = await auditArtifact(path, {
      readers,
      policy: { layers: { 'metadata-hygiene': false } },
    });
    assert.equal(oneOff.findings.length, 1);
    assert.deepEqual(oneOff.limitations, []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ---- 审计引擎：畸形输入 ----

test('目标路径缺失、空白或不存在时按用法错误处理', async () => {
  for (const target of ['', '   ', null, undefined, 42]) {
    await assert.rejects(() => auditArtifact(target), /目标路径|缺少目标/, `输入 ${String(target)} 应被拒`);
  }
  await assert.rejects(() => auditArtifact(join(tmpdir(), 'anti-rea-no-such-target-xyz')), /目标不存在或不可访问/);
});

test('审计结果文件校验拒绝各类畸形输入', () => {
  const valid = { schema: AUDIT_REPORT_SCHEMA, findings: [] };
  assert.equal(assertAuditReport(valid), valid);
  const withExtra = { ...valid, extra: '附带字段不影响校验' };
  assert.equal(assertAuditReport(withExtra), withExtra);
  for (const bad of [
    null,
    undefined,
    'anti-rea.audit-report/1',
    42,
    [],
    {},
    { schema: 7, findings: [] },
    { schema: 'anti-rea.other-report/1', findings: [] },
    { schema: AUDIT_REPORT_SCHEMA },
    { schema: AUDIT_REPORT_SCHEMA, findings: {} },
    { schema: AUDIT_REPORT_SCHEMA, findings: 'none' },
  ]) {
    assert.throws(() => assertAuditReport(bad), /审计结果文件/, `输入 ${JSON.stringify(bad)} 应被拒`);
  }
});

test('空文件与截断文件头按容器识别结果处理，审计不失败', async () => {
  const empty = await makeArtifact('empty.bin', Buffer.alloc(0));
  const short = await makeArtifact('short.bin', Buffer.from([0x7f, 0x45]));
  try {
    const emptyReport = await auditArtifact(empty.path);
    assert.equal(emptyReport.status, 'complete');
    assert.equal(emptyReport.artifact.container, 'unknown', '文件头不足四字节无法按魔数判定');
    assert.equal(emptyReport.artifact.entryCount, 1);
    assert.equal(emptyReport.capabilityBoundaries.length, 1);
    assert.deepEqual(emptyReport.findings, []);

    const shortReport = await auditArtifact(short.path);
    assert.equal(shortReport.status, 'complete');
    assert.equal(shortReport.artifact.container, 'unknown');
    assert.equal(shortReport.artifact.entryCount, 1);
  } finally {
    await rm(empty.dir, { recursive: true, force: true });
    await rm(short.dir, { recursive: true, force: true });
  }
});

test('伪魔数与坏 safetensors 头被判为范围外容器，报告能力边界', async () => {
  const cases = [
    { name: 'fake-pe.bin', bytes: Buffer.concat([Buffer.from('MZ'), Buffer.alloc(64, 0x41)]) },
    { name: 'bad-safetensors.bin', bytes: Buffer.concat([Buffer.from([0x7b]), Buffer.from('ffffffffffffffff', 'hex')]) },
    { name: 'truncated-gguf.bin', bytes: Buffer.from('GGUX') },
  ];
  for (const testCase of cases) {
    const artifact = await makeArtifact(testCase.name, testCase.bytes);
    try {
      const report = await auditArtifact(artifact.path);
      assert.equal(report.status, 'complete', `${testCase.name} 不应让审计失败`);
      assert.equal(report.artifact.container, 'unsupported', `${testCase.name} 不应落入 v1 九类格式`);
      assert.equal(report.capabilityBoundaries.length, 1);
      assert.ok(report.capabilityBoundaries[0].reason.includes('unsupported'), '能力边界要说明识别结果');
      assert.deepEqual(report.findings, []);
    } finally {
      await rm(artifact.dir, { recursive: true, force: true });
    }
  }
});

test('畸形 pyc 文件被判为 pyc 容器，报告不得假装没有暴露', async () => {
  // 魔数两字节之后固定是 0D 0A：这个四字节文件满足 pyc 判定，却不是可解析的 pyc。
  const artifact = await makeArtifact('fake.pyc', Buffer.from([0x33, 0x0d, 0x0d, 0x0a]));
  try {
    const report = await auditArtifact(artifact.path);
    assert.equal(report.artifact.container, 'pyc');
    const producedFacts = report.findings.length > 0;
    const declaredBoundary = report.limitations.length > 0;
    assert.ok(producedFacts || declaredBoundary, '畸形制品要么给出事实，要么给出限制说明');
  } finally {
    await rm(artifact.dir, { recursive: true, force: true });
  }
});

// ---- 审计引擎：部分读取（资源预算） ----

test('单文件上限设为极小值时输出 partial 并附限制说明', async () => {
  const artifact = await makeArtifact('big.bin', Buffer.alloc(4096, 0x41));
  try {
    const report = await auditArtifact(artifact.path, { policy: policyWithBudgets({ maxFileBytes: 1 }) });
    assert.equal(report.status, 'partial');
    const codes = report.limitations.map((limitation) => limitation.code);
    assert.ok(codes.includes('max-file-bytes-exceeded'), `缺少单文件上限限制说明：${JSON.stringify(codes)}`);
    assert.ok(report.limitations.every((limitation) => limitation.message.length > 0), '限制说明不得为空');
    assert.equal(report.summary.limitations, report.limitations.length);
  } finally {
    await rm(artifact.dir, { recursive: true, force: true });
  }
});

test('单文件上限小于文件时同时记录文件头读取受限', async () => {
  const artifact = await makeArtifact('big.bin', Buffer.alloc(4096, 0x41));
  try {
    const report = await auditArtifact(artifact.path, { policy: policyWithBudgets({ maxFileBytes: 16 }) });
    assert.equal(report.status, 'partial');
    const codes = report.limitations.map((limitation) => limitation.code);
    assert.ok(codes.includes('max-file-bytes-exceeded'), JSON.stringify(codes));
    assert.ok(codes.includes('detection-prefix-limited'), `文件头读取量受上限约束必须记录：${JSON.stringify(codes)}`);
  } finally {
    await rm(artifact.dir, { recursive: true, force: true });
  }
});

test('累计扫描窗口耗尽时输出 partial 并附摘要截断说明', async () => {
  const artifact = await makeArtifact('big.bin', Buffer.alloc(4096, 0x41));
  try {
    const report = await auditArtifact(artifact.path, { policy: policyWithBudgets({ maxTotalScanBytes: 1 }) });
    assert.equal(report.status, 'partial');
    assert.ok(report.limitations.some((limitation) => limitation.code === 'digest-truncated'));
    assert.match(report.artifact.sha256, /^[0-9a-f]{64}$/, '摘要截断不等于没有摘要');
  } finally {
    await rm(artifact.dir, { recursive: true, force: true });
  }
});

test('目录条目数达到上限时输出 partial，能力边界仍按已枚举条目聚合', async () => {
  const report = await auditArtifact(SAMPLE_APP, { policy: policyWithBudgets({ maxFiles: 1 }) });
  assert.equal(report.status, 'partial');
  assert.equal(report.artifact.entryCount, 1, '只枚举到上限内的条目');
  assert.ok(report.limitations.some((limitation) => limitation.code === 'max-files-exceeded'));
  assert.equal(report.capabilityBoundaries.length, 1);
  assert.equal(report.capabilityBoundaries[0].count, 1, '边界计数跟随已枚举条目');
  const names = await readdir(SAMPLE_APP, { recursive: true });
  assert.ok(names.length >= 5, '夹具目录文件数应超过上限');
});

test('单文件上限为 0 时全部条目跳过，审计仍正常完成', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-audit-zero-'));
  try {
    await writeFile(join(dir, 'a.bin'), Buffer.alloc(16, 0x41));
    await writeFile(join(dir, 'b.bin'), Buffer.alloc(16, 0x42));
    const report = await auditArtifact(dir, { policy: policyWithBudgets({ maxFileBytes: 0 }) });
    assert.equal(report.artifact.entryCount, 2, '条目仍然枚举与分类，只是不读内容');
    assert.equal(report.status, 'partial');
    assert.deepEqual(report.findings, []);
    const codes = report.limitations.map((limitation) => limitation.code);
    assert.equal(codes.filter((code) => code === 'max-file-bytes-exceeded').length, 2);
    assert.equal(codes.filter((code) => code === 'detection-prefix-limited').length, 2);
    // 上限为 0 时一个字节都没读，容器判定只能是 unknown，而不是把没读过的文件误判成某类格式。
    assert.deepEqual(report.containers, [{ type: 'unknown', count: 2 }]);
    // 被预算跳过的条目不进入能力边界聚合：它没有读过内容，痕迹留在容器计数与限制说明里。
    assert.deepEqual(report.capabilityBoundaries, []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ---- 审计引擎：识别阶段跳过的条目 ----

test('目录中不可读条目逐条转为 audit-entry-skipped 限制说明，不冒充没有暴露', async () => {
  // 目录夹具用已提交的 sample-app；不可读条目靠注入的 open 构造：
  // 各平台上都无法用权限位稳定造出“列得出来却打不开”的条目，注入与 identifyArtifact 的 io 参数同形。
  const failing = async (path, flags) => {
    if (String(path).endsWith('README.md')) {
      const error = new Error(`permission denied, open '${path}'`);
      error.code = 'EACCES';
      throw error;
    }
    return open(path, flags);
  };

  const plain = await auditArtifact(SAMPLE_APP);
  assert.equal(plain.status, 'complete', '条目全部可读时是完整结果');
  assert.equal(plain.artifact.entryCount, 7, '夹具目录共七个条目');
  assert.deepEqual(
    plain.limitations.filter((limitation) => limitation.code === 'audit-entry-skipped'),
    [],
    '条目全部可读时不应出现跳过说明',
  );

  const report = await auditArtifact(SAMPLE_APP, { io: { open: failing } });
  assert.equal(report.status, 'partial', '有条目没审计到就不是完整结果');
  assert.equal(report.artifact.entryCount, 6, '不可读条目不进入条目清单');

  const skippedLimitations = report.limitations.filter((limitation) => limitation.code === 'audit-entry-skipped');
  assert.equal(skippedLimitations.length, 1, '每个不可读条目一条限制说明');
  assert.equal(skippedLimitations[0].scope, 'entry');
  assert.match(skippedLimitations[0].message, /README\.md/, '消息要点名条目相对路径');
  assert.match(skippedLimitations[0].message, /EACCES/, '消息要带跳过原因');
  assert.ok(!skippedLimitations[0].message.includes(SAMPLE_APP), '消息不得带出绝对路径');
  assert.ok(report.limitations.every((limitation) => limitation.message.length > 0), '限制说明不得为空');
  assert.equal(report.summary.limitations, report.limitations.length);

  // 被跳过的条目没有参与审计：容器计数少一个，能力边界跟着少一个，也没有发现。
  assert.deepEqual(report.containers, [{ type: 'unsupported', count: 6 }]);
  assert.equal(report.capabilityBoundaries.length, 1);
  assert.equal(report.capabilityBoundaries[0].count, 6);
  assert.deepEqual(report.findings, []);
});

test('多个不可读条目各留一条限制说明，审计仍正常完成', async () => {
  const failing = async (path, flags) => {
    if (String(path).endsWith('version.js') || String(path).endsWith('settings.json')) {
      const error = new Error(`permission denied, open '${path}'`);
      error.code = 'EACCES';
      throw error;
    }
    return open(path, flags);
  };
  const report = await auditArtifact(SAMPLE_APP, { io: { open: failing } });
  const skippedLimitations = report.limitations.filter((limitation) => limitation.code === 'audit-entry-skipped');
  assert.equal(skippedLimitations.length, 2, '不可读条目不得合并成一条说明');
  const messages = skippedLimitations.map((limitation) => limitation.message);
  assert.ok(messages.some((message) => /version\.js/.test(message)), 'src/version.js 应各有一条说明');
  assert.ok(messages.some((message) => /settings\.json/.test(message)), 'config/settings.json 应各有一条说明');
  assert.ok(messages.every((message) => /EACCES/.test(message)), '每条说明都要带自己的跳过原因');
  assert.equal(report.artifact.entryCount, 5);
  assert.equal(report.status, 'partial');
});

// ---- 模块边界：审计路径不执行目标 ----

test('审计模块源码不导入子进程与工作线程模块', async () => {
  const auditDir = new URL('../src/audit/', import.meta.url);
  const names = await readdir(auditDir);
  const sources = names.filter((name) => name.endsWith('.mjs'));
  assert.ok(sources.length >= 4, `审计模块文件过少：${sources.join('、')}`);
  const forbidden = ['node:child_process', 'node:worker_threads', 'child_process', 'worker_threads'];
  for (const name of sources) {
    const text = await readFile(new URL(name, auditDir), 'utf8');
    for (const module of forbidden) {
      assert.ok(!text.includes(`'${module}'`) && !text.includes(`"${module}"`), `${name} 不得引用 ${module}`);
    }
    assert.ok(!/\b(exec|execFile|spawn|spawnSync|fork)\s*\(/.test(text), `${name} 不得启动子进程`);
  }
});

test('审计路径只读取字节，不写目标文件', async () => {
  const { dir, path } = await makeArtifact('app.elf', ELF_BYTES);
  try {
    const before = createHash('sha256').update(await readFile(path)).digest('hex');
    const readers = { elf: [fakeReader('elf', ['metadata-hygiene'], { findings: [sampleFinding()] })] };
    await auditArtifact(path, { readers });
    const after = createHash('sha256').update(await readFile(path)).digest('hex');
    assert.equal(after, before, '审计是只读操作，制品必须逐字节不变');
    const entries = await readdir(dir);
    assert.deepEqual(entries, [basename(path)], '审计不得在制品目录里留下文件');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
