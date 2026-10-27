// git 工作树警告：任何把结果写出文件的命令，目标路径位于 git 工作树内时向标准错误输出警告。

import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { runCli, SAMPLE_APP } from './helpers/cli.mjs';

/**
 * 造一个带 .git 标记的临时目录，模拟 git 工作树。
 * @returns {Promise<string>} 临时目录路径
 */
async function makeGitTree() {
  const root = await mkdtemp(join(tmpdir(), 'anti-rea-git-'));
  await mkdir(join(root, '.git'), { recursive: true });
  return root;
}

test('输出路径位于 git 工作树内时向标准错误输出警告', async () => {
  const gitTree = await makeGitTree();
  try {
    const outPath = join(gitTree, 'audit.json');
    const result = await runCli(['audit', SAMPLE_APP, '--json', '--out', outPath]);
    assert.equal(result.code, 0);
    assert.match(result.stderr, /git 工作树/);
    assert.match(result.stderr, /警告/);
  } finally {
    await rm(gitTree, { recursive: true, force: true });
  }
});

test('输出路径不在 git 工作树内时不输出警告', async () => {
  const plain = await mkdtemp(join(tmpdir(), 'anti-rea-plain-'));
  try {
    const outPath = join(plain, 'audit.json');
    const result = await runCli(['audit', SAMPLE_APP, '--json', '--out', outPath]);
    assert.equal(result.code, 0);
    assert.ok(!result.stderr.includes('git 工作树'), `不应出现警告，实际标准错误：${result.stderr}`);
  } finally {
    await rm(plain, { recursive: true, force: true });
  }
});

test('加固命令的写出路径位于 git 工作树内时同样警告', async () => {
  const gitTree = await makeGitTree();
  try {
    const auditPath = join(gitTree, 'audit.json');
    await writeFile(auditPath, (await runCli(['audit', SAMPLE_APP, '--json'])).stdout, 'utf8');
    const result = await runCli(['harden', SAMPLE_APP, '--from', auditPath, '--out', join(gitTree, 'hardened.bin')]);
    assert.equal(result.code, 0);
    assert.match(result.stderr, /git 工作树/);
    const occurrences = result.stderr.split('git 工作树').length - 1;
    assert.equal(occurrences, 1, '同一路径只应警告一次');
  } finally {
    await rm(gitTree, { recursive: true, force: true });
  }
});
