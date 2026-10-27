// 脱敏报告：保留分类与计数，隐去精确路径、字节范围与缓解措施对应关系。

import assert from 'node:assert/strict';
import { test } from 'node:test';

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
    capabilityBoundaries: [{ id: 'generic-script-package', label: '范围外容器', reason: '不匹配八类格式', count: 3 }],
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
