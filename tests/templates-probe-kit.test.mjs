// 模板目录：仓库根 templates/ 放反运行时观察集成包模板，位于静态依赖检查范围之外。
// 本用例锁定目录存在、内容约定、探针检测项词表，以及默认策略下的真实生成行为。

import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { DEFAULT_PROBE_EXCEPTIONS, PROBE_CHECKS, PROBE_KIT_PARTS, buildProbeKit } from '../src/probe-kit/index.mjs';
import { REPO_ROOT } from './helpers/cli.mjs';

const TEMPLATES_DIR = join(REPO_ROOT, 'templates');

test('templates/ 目录存在', async () => {
  const info = await stat(TEMPLATES_DIR);
  assert.equal(info.isDirectory(), true);
});

test('templates/ 的说明写清了目录用途与检查边界', async () => {
  const text = await readFile(join(TEMPLATES_DIR, 'README.md'), 'utf8');
  assert.match(text, /probe-kit|反运行时观察/);
  assert.match(text, /静态/);
});

test('templates/probe-kit/ 放全三份模板', async () => {
  for (const name of ['runtime-probe.template.mjs', 'manual-checklist.template.md', 'integration-notes.template.md']) {
    const info = await stat(join(TEMPLATES_DIR, 'probe-kit', name));
    assert.equal(info.isFile(), true);
  }
});

test('探针检测项是封闭词表', () => {
  const ids = PROBE_CHECKS.map((check) => check.id);
  assert.equal(new Set(ids).size, ids.length);
  assert.deepEqual([...ids].sort(), [
    'env-write-marker',
    'injected-script-prefix',
    'inspector-port',
    'pseudo-terminal-signs',
    'traced-state',
  ]);
  assert.ok(ids.includes('env-write-marker'));
  assert.ok(ids.includes('pseudo-terminal-signs'));
  assert.ok(ids.includes('traced-state'));
  assert.ok(ids.includes('inspector-port'));
});

test('默认例外清单覆盖持续集成与远程 Shell 会话', () => {
  assert.ok(DEFAULT_PROBE_EXCEPTIONS.includes('CI'));
  assert.ok(DEFAULT_PROBE_EXCEPTIONS.includes('SSH_CONNECTION'));
});

test('集成包内容清单声明默认只输出包、不改动制品', () => {
  assert.ok(PROBE_KIT_PARTS.some((part) => part.includes('检测代码片段')));
  assert.ok(PROBE_KIT_PARTS.some((part) => part.includes('不自动改动制品')));
});

test('默认策略生成集成包：三份产物落盘，响应模式是记录并继续', async () => {
  const root = await mkdtemp(join(tmpdir(), 'anti-rea-templates-'));
  const outDir = join(root, 'kit');
  try {
    const report = await buildProbeKit({ policy: {}, outDir });
    assert.equal(report.status, 'generated');
    assert.equal(report.response.mode, 'report-only');
    assert.equal(report.changed, true);
    assert.deepEqual(
      report.files.map((file) => file.name),
      ['runtime-probe.mjs', 'manual-checklist.md', 'INTEGRATION.md'],
    );
    for (const file of report.files) {
      const info = await stat(file.path);
      assert.equal(info.isFile(), true);
      assert.equal(info.size, file.bytes);
    }
    // 集成包不进 templates/ 自身：生成产物写在调用方给出的目录。
    const probe = await readFile(join(outDir, 'runtime-probe.mjs'), 'utf8');
    assert.match(probe, /RESPONSE_MODE/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
