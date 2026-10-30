// 脱敏报告：保留分类与计数，隐去精确路径、字节范围与缓解措施对应关系。

import assert from 'node:assert/strict';
import { mkdir, mkdtemp, open, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { auditArtifact } from '../src/audit/engine.mjs';
import { redactReport } from '../src/report/redact.mjs';
import { runCli, SAMPLE_APP } from './helpers/cli.mjs';

test('命令行 --redacted 输出不含精确路径', async () => {
  const result = await runCli(['audit', SAMPLE_APP, '--json', '--redacted']);
  assert.equal(result.code, 0);
  const text = result.stdout;
  assert.ok(!text.includes('sample-app'), '脱敏报告不得包含制品路径');
  assert.ok(!text.includes('main.js'), '脱敏报告不得包含条目文件名');
  assert.ok(!text.includes('README.md'), '脱敏报告不得包含条目文件名');
});

test('命令行 --redacted 保留分类与计数', async () => {
  const plain = JSON.parse((await runCli(['audit', SAMPLE_APP, '--json'])).stdout);
  const redacted = JSON.parse((await runCli(['audit', SAMPLE_APP, '--json', '--redacted'])).stdout);
  assert.equal(redacted.redacted, true);
  assert.equal(redacted.artifact.sha256, plain.artifact.sha256);
  assert.equal(redacted.artifact.bytes, plain.artifact.bytes);
  assert.equal(redacted.artifact.entryCount, plain.artifact.entryCount);
  assert.equal(redacted.capabilityBoundaries.length, plain.capabilityBoundaries.length);
  assert.equal(redacted.capabilityBoundaries[0].count, plain.capabilityBoundaries[0].count);
  assert.deepEqual(redacted.summary.byLayer, plain.summary.byLayer);
});

test('脱敏函数隐去证据路径、字节范围与缓解措施对应关系', () => {
  const original = {
    schema: 'anti-rea.audit-report/1',
    tool: 'audit-artifact',
    status: 'complete',
    artifact: { kind: 'file', path: '/secret/build/app.bin', sha256: 'a'.repeat(64), bytes: 2048, container: 'elf' },
    findings: [
      {
        layer: 'metadata-hygiene',
        severity: 'high',
        title: 'Go 构建信息',
        category: 'go-buildinfo',
        evidence: { path: '/secret/build/app.bin', byteRange: [1024, 2048], excerpt: 'go1.22.0' },
        reader: 'elf',
        readerLimitation: '只覆盖 inline 编码',
        mitigation: 'metadata.go-buildinfo-inline-overwrite',
      },
    ],
    capabilityBoundaries: [{ id: 'generic-script-package', label: '范围外容器', reason: '不匹配九类格式', count: 3 }],
    limitations: [],
    summary: { findings: 1, byLayer: { 'metadata-hygiene': 1 }, bySeverity: { high: 1 } },
  };

  const redacted = redactReport(original);
  const text = JSON.stringify(redacted);
  assert.ok(!text.includes('/secret/build/app.bin'), '不得保留精确路径');
  assert.ok(!text.includes('go1.22.0'), '不得保留证据摘录');
  assert.ok(!text.includes('metadata.go-buildinfo-inline-overwrite'), '不得保留缓解措施对应关系');
  assert.ok(!text.includes('byteRange'), '不得保留字节范围字段');
  assert.equal(redacted.findings.length, 1);
  assert.equal(redacted.findings[0].layer, 'metadata-hygiene');
  assert.equal(redacted.summary.findings, 1);
  assert.equal(redacted.capabilityBoundaries[0].count, 3);
});

test('脱敏不修改原报告对象', () => {
  const original = {
    schema: 'anti-rea.audit-report/1',
    tool: 'audit-artifact',
    status: 'complete',
    artifact: { kind: 'file', path: '/tmp/app.bin', sha256: 'b'.repeat(64), bytes: 16 },
    findings: [],
    capabilityBoundaries: [],
    limitations: [],
    summary: {},
  };
  const snapshot = JSON.stringify(original);
  redactReport(original);
  assert.equal(JSON.stringify(original), snapshot);
});

test('脱敏替换限制说明里结构化携带的条目路径，不依赖路径形态', () => {
  // “bin/tool”这类无扩展名的产物内相对路径：形态 scrub 的两条规则都不命中
  // （词首不是根、末段没有扩展名），修复前会原样留在脱敏报告里。
  const original = {
    schema: 'anti-rea.audit-report/1',
    tool: 'audit-artifact',
    status: 'partial',
    artifact: { kind: 'directory', path: 'C:/app', sha256: 'c'.repeat(64), bytes: 32, entryCount: 1 },
    findings: [],
    capabilityBoundaries: [],
    limitations: [
      {
        code: 'audit-entry-skipped',
        message: '条目 bin/tool 在识别阶段即不可读（EACCES），本次没有提取到任何事实',
        scope: 'entry',
        path: 'bin/tool',
      },
    ],
    summary: {},
  };

  const redacted = redactReport(original);
  const note = redacted.limitations[0];
  assert.ok(!note.message.includes('bin/tool'), '脱敏后消息不得残留条目路径');
  assert.ok(note.message.includes('（路径已脱敏）'), '条目路径应被占位符替换');
  assert.equal(note.path, undefined, '脱敏输出不得携带路径字段本身');
  assert.equal(note.code, 'audit-entry-skipped', '限制标识必须保留');
});

test('不可读条目的路径经审计引擎结构化带上，脱敏后不外泄', async () => {
  // 端到端：识别阶段不可读的条目产出 audit-entry-skipped，消息里带条目相对路径。
  // 该路径必须同时出现在限制说明的 path 字段上，脱敏才能精确替换。
  const dir = await mkdtemp(join(tmpdir(), 'antirea-redact-'));
  try {
    await mkdir(join(dir, 'bin'), { recursive: true });
    await writeFile(join(dir, 'bin', 'tool'), Buffer.from('binary-ish payload', 'latin1'));
    const failing = async (path, flags) => {
      if (String(path).endsWith('tool')) {
        const error = new Error(`permission denied, open '${path}'`);
        error.code = 'EACCES';
        throw error;
      }
      return open(path, flags);
    };

    const report = await auditArtifact(dir, { io: { open: failing } });
    const skipped = report.limitations.filter((note) => note.code === 'audit-entry-skipped');
    assert.equal(skipped.length, 1, '不可读条目应有一条限制说明');
    const entryPath = skipped[0].path;
    assert.ok(typeof entryPath === 'string' && entryPath.replaceAll('\\', '/').endsWith('bin/tool'), '限制说明必须结构化携带条目路径');
    assert.ok(skipped[0].message.includes(entryPath), '消息里应带同一条路径');

    const redacted = redactReport(report);
    const messages = redacted.limitations.map((note) => note.message).join('\n');
    assert.ok(!messages.includes(entryPath), '脱敏后不得残留条目路径');
    assert.ok(messages.includes('（路径已脱敏）'), '条目路径应被占位符替换');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
