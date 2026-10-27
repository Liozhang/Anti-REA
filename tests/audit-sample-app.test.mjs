// 端到端夹具目录：普通应用目录的审计应当正常完成，加固不写入任何字节。

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { runCli, SAMPLE_APP } from './helpers/cli.mjs';

/**
 * 递归汇总目录内每个文件的 sha256，用于比对加固前后是否有字节变化。
 * @param {string} root 目录
 * @returns {Promise<Record<string, string>>}
 */
async function digestTree(root) {
  const result = {};
  const queue = [root];
  while (queue.length > 0) {
    const current = queue.shift();
    for (const dirent of await readdir(current, { withFileTypes: true })) {
      const absolute = join(current, dirent.name);
      if (dirent.isDirectory()) {
        queue.push(absolute);
        continue;
      }
      if (dirent.isFile()) {
        result[absolute] = createHash('sha256').update(await readFile(absolute)).digest('hex');
      }
    }
  }
  return result;
}

test('sample-app 夹具目录存在且含说明文档与若干普通文件', async () => {
  const readme = await stat(join(SAMPLE_APP, 'README.md'));
  assert.equal(readme.isFile(), true);
  const files = await readdir(SAMPLE_APP, { recursive: true });
  assert.ok(files.length >= 5, `夹具文件过少：${files.join('、')}`);
});

test('审计 sample-app 正常完成，退出码 0，条目被判为范围外容器', async () => {
  const result = await runCli(['audit', SAMPLE_APP, '--json']);
  assert.equal(result.code, 0);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, 'complete');
  assert.equal(report.artifact.entryCount, 7);
  assert.equal(report.findings.length, 0);
  assert.equal(report.capabilityBoundaries.length, 1);
  assert.equal(report.capabilityBoundaries[0].id, 'generic-script-package');
  assert.equal(report.capabilityBoundaries[0].count, 7);
  assert.ok(report.capabilityBoundaries[0].reason.length > 0, '能力边界必须附说明');
});

test('审计报告为 partial 时退出码仍为 0：被跳过的条目不改变退出码口径', async () => {
  // 跳过条目让报告变成 partial，但审计本身正常完成，退出码口径与完整报告一致。
  // 这里用预算把报告压成 partial：各平台都无法稳定造出“列得出来却打不开”的条目，
  // 命令行入口没有文件系统注入点，注入路径的验证见 tests/audit.test.mjs。
  const policyDir = await mkdtemp(join(tmpdir(), 'anti-rea-audit-policy-'));
  const policyPath = join(policyDir, 'policy.json');
  await writeFile(policyPath, JSON.stringify({ budgets: { maxFileBytes: 1, maxTotalScanBytes: 1 } }), 'utf8');
  try {
    const result = await runCli(['audit', SAMPLE_APP, '--json', '--policy', policyPath]);
    assert.equal(result.code, 0, '部分结果的审计仍然正常完成');
    const report = JSON.parse(result.stdout);
    assert.equal(report.status, 'partial');
    assert.ok(report.limitations.length > 0, 'partial 必须附限制说明');
    assert.ok(report.limitations.every((limitation) => limitation.message.length > 0), '限制说明不得为空');
  } finally {
    await rm(policyDir, { recursive: true, force: true });
  }
});

test('同一目录两次审计得到同一制品摘要', async () => {
  const first = JSON.parse((await runCli(['audit', SAMPLE_APP, '--json'])).stdout);
  const second = JSON.parse((await runCli(['audit', SAMPLE_APP, '--json'])).stdout);
  assert.equal(first.artifact.sha256, second.artifact.sha256);
  assert.match(first.artifact.sha256, /^[0-9a-f]{64}$/);
});

test('审计单个普通文件正常完成，退出码 0', async () => {
  const result = await runCli(['audit', join(SAMPLE_APP, 'README.md'), '--json']);
  assert.equal(result.code, 0);
  const report = JSON.parse(result.stdout);
  assert.equal(report.artifact.kind, 'file');
  assert.equal(report.artifact.container, 'unsupported');
});

test('加固 sample-app 退出码 0，未写入任何字节，夹具逐字节不变', async () => {
  const audit = await runCli(['audit', SAMPLE_APP, '--json']);
  const auditPath = join(await mkdtemp(join(tmpdir(), 'anti-rea-audit-')), 'audit.json');
  await writeFile(auditPath, audit.stdout, 'utf8');

  const before = await digestTree(SAMPLE_APP);
  const result = await runCli(['harden', SAMPLE_APP, '--from', auditPath, '--json']);
  assert.equal(result.code, 0);
  const report = JSON.parse(result.stdout.replace(/^警告：[^\n]*\n/, ''));
  assert.equal(report.changed, false);
  assert.equal(report.applied.length, 0);
  const after = await digestTree(SAMPLE_APP);
  assert.deepEqual(after, before, '加固未施加任何措施时，夹具必须逐字节不变');
  await rm(join(SAMPLE_APP, '..', 'sample-app.hardened'), { force: true });
});

test('复审 sample-app 退出码 0 且判定为通过', async () => {
  const result = await runCli(['verify', SAMPLE_APP, '--json']);
  assert.equal(result.code, 0);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, 'passed');
  assert.equal(report.summary.failed, 0);
});
