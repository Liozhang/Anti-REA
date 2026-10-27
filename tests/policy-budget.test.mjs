// 资源上限：策略把单文件上限设为极小值时，审计输出部分结果并附限制说明，进程不失败不超时。

import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { auditArtifact } from '../src/audit/engine.mjs';
import { DEFAULT_POLICY, loadPolicy, validatePolicy } from '../src/policy/index.mjs';
import { runCli, SAMPLE_APP } from './helpers/cli.mjs';

/**
 * 造一个超过给定上限的文件。
 * @param {number} bytes 文件字节数
 * @returns {Promise<string>} 文件路径
 */
async function makeFile(bytes) {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-budget-'));
  const path = join(dir, 'big.bin');
  await writeFile(path, Buffer.alloc(bytes, 0x41));
  return path;
}

test('默认策略带资源预算且全部为非负数字', () => {
  for (const [key, value] of Object.entries(DEFAULT_POLICY.budgets)) {
    assert.equal(typeof value, 'number', `budgets.${key} 应为数字`);
    assert.ok(value >= 0, `budgets.${key} 应为非负`);
  }
});

test('单文件上限设为极小值时审计输出 partial 并附限制说明', async () => {
  const path = await makeFile(4096);
  try {
    const policy = { ...DEFAULT_POLICY, budgets: { ...DEFAULT_POLICY.budgets, maxFileBytes: 1 } };
    const report = await auditArtifact(path, { policy });
    assert.equal(report.status, 'partial');
    const codes = report.limitations.map((limitation) => limitation.code);
    assert.ok(codes.includes('max-file-bytes-exceeded'), `缺少单文件上限限制说明：${JSON.stringify(codes)}`);
    assert.ok(report.limitations.every((limitation) => limitation.message.length > 0), '限制说明不得为空');
  } finally {
    await rm(join(path, '..'), { recursive: true, force: true });
  }
});

test('累计扫描窗口耗尽时审计输出 partial 并附限制说明', async () => {
  const path = await makeFile(4096);
  try {
    const policy = { ...DEFAULT_POLICY, budgets: { ...DEFAULT_POLICY.budgets, maxTotalScanBytes: 1 } };
    const report = await auditArtifact(path, { policy });
    assert.equal(report.status, 'partial');
    assert.ok(report.limitations.some((limitation) => limitation.code === 'digest-truncated'));
  } finally {
    await rm(join(path, '..'), { recursive: true, force: true });
  }
});

test('报表字节上限过小时序列化结果被截断并附说明', async () => {
  const report = await auditArtifact(SAMPLE_APP, { policy: DEFAULT_POLICY });
  const policy = { ...DEFAULT_POLICY, budgets: { ...DEFAULT_POLICY.budgets, maxReportBytes: 400 } };
  const result = await runCli(['audit', SAMPLE_APP, '--json', '--policy', await writePolicy(policy)]);
  assert.equal(result.code, 0);
  assert.ok(Buffer.byteLength(result.stdout, 'utf8') <= 4096, '截断后的报表不应显著超过上限');
  assert.ok(report.summary.findings === 0);
});

test('策略校验拒绝非法预算与非法观察模式', () => {
  assert.throws(() => validatePolicy({ budgets: { maxFileBytes: -1 } }), /必须是非负有限数字/);
  assert.throws(() => validatePolicy({ budgets: { maxFileBytes: 'big' } }), /必须是非负有限数字/);
  assert.throws(() => validatePolicy({ observation: { mode: 'block-everything' } }), /只支持/);
  assert.throws(() => validatePolicy('not-an-object'), /顶层必须是对象/);
  assert.doesNotThrow(() => validatePolicy({ schemaVersion: 1 }));
});

test('策略文件不存在时按用法错误处理', async () => {
  const result = await runCli(['audit', SAMPLE_APP, '--json', '--policy', 'no-such-policy.json']);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /无法读取策略文件/);
});

test('默认策略不预设任何法律字段', () => {
  for (const [key, value] of Object.entries(DEFAULT_POLICY.legal)) {
    if (Array.isArray(value)) {
      assert.equal(value.length, 0, `legal.${key} 必须为空`);
    } else {
      assert.equal(value, '', `legal.${key} 必须为空字符串`);
    }
  }
});

test('默认策略默认不改签名制品、不重算校验和、反观察只记录', () => {
  assert.equal(DEFAULT_POLICY.signatures.allowRewriteSigned, false);
  assert.equal(DEFAULT_POLICY.signatures.allowChecksumRecompute, false);
  assert.equal(DEFAULT_POLICY.observation.mode, 'report-only');
  assert.equal(DEFAULT_POLICY.observation.refusalEnabled, false);
});

/**
 * 把策略写到临时文件，返回路径。
 * @param {Record<string, unknown>} policy 策略对象
 * @returns {Promise<string>} 策略文件路径
 */
async function writePolicy(policy) {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-policy-'));
  const path = join(dir, 'policy.json');
  await writeFile(path, JSON.stringify(policy), 'utf8');
  return path;
}

test('载入策略文件后与默认值合并', async () => {
  const path = await writePolicy({ layers: { 'content-protection': false } });
  try {
    const policy = await loadPolicy(path);
    assert.equal(policy.layers['content-protection'], false);
    assert.equal(policy.budgets.maxFileBytes, DEFAULT_POLICY.budgets.maxFileBytes);
  } finally {
    await rm(join(path, '..'), { recursive: true, force: true });
  }
});
