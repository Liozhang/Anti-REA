// package.json 契约：模块格式、零依赖、测试脚本与入口文件。

import assert from 'node:assert/strict';
import { readFile, stat } from 'node:fs/promises';
import { test } from 'node:test';

import { CLI_ENTRY, MCP_ENTRY, REPO_ROOT } from './helpers/cli.mjs';

const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));

test('package.json 使用 ESM 模块格式', () => {
  assert.equal(packageJson.type, 'module');
});

test('package.json 的运行时依赖为空', () => {
  assert.deepEqual(packageJson.dependencies ?? {}, {});
  assert.equal(Object.keys(packageJson.dependencies ?? {}).length, 0);
});

test('scripts.test 是 node --test', () => {
  assert.equal(packageJson.scripts?.test, 'node --test');
});

test('引擎要求 Node.js 22 及以上', () => {
  assert.match(String(packageJson.engines?.node), />=\s*22/);
});

test('两个入口文件都存在且是普通文件', async () => {
  for (const entry of [CLI_ENTRY, MCP_ENTRY]) {
    const info = await stat(entry);
    assert.equal(info.isFile(), true, `${entry} 应为普通文件`);
  }
});

test('bin 字段指向两个入口', () => {
  assert.equal(packageJson.bin?.['anti-rea'], 'bin/anti-rea.js');
  assert.equal(packageJson.bin?.['anti-rea-mcp'], 'bin/anti-rea-mcp.js');
});

test('仓库根没有被测试写入多余文件', async () => {
  // 只读检查：确认仓库根仍只有既有的说明文档与新建的骨架目录。
  const { readdir } = await import('node:fs/promises');
  const names = await readdir(REPO_ROOT);
  for (const expected of ['README.md', 'package.json', 'bin', 'src', 'tests', 'scripts', 'docs']) {
    assert.ok(names.includes(expected), `仓库根缺少 ${expected}`);
  }
});
