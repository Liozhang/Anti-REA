// 夹具稳定性：每个已提交夹具的 sha256 与清单记录一致，保证测试跑的是固定真实字节。
// 覆盖三条路径：
//   正常输入   清单登记的夹具全部存在、摘要一致，构造器输出与已提交字节逐字节相同
//   畸形输入   构造器输出与磁盘字节不一致、清单登记了不存在的文件、出现未登记的散落文件
//   部分读取   不适用：本用例只校验字节与登记关系，不读取制品内容

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, readdir, stat } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import { FIXTURE_SPECS, fixtureSpecById } from '../src/fixtures/index.mjs';
import { BYTE_FIXTURES, buildFixtureBytes } from './fixtures/build.mjs';
import { runNode } from './helpers/cli.mjs';

const FIXTURES_DIR = fileURLToPath(new URL('./fixtures/', import.meta.url));
const manifest = JSON.parse(await readFile(new URL('./fixtures/manifest.json', import.meta.url), 'utf8'));

test('夹具清单登记了全部已提交夹具，没有待生成项', () => {
  assert.equal(manifest.schema, 'anti-rea.fixture-manifest/1');
  const entries = Object.entries(manifest.fixtures);
  assert.ok(entries.length >= 23, `登记项过少：${entries.length}`);
  const committed = entries.filter(([, value]) => typeof value === 'string');
  const pending = entries.filter(([, value]) => value === null);
  assert.equal(pending.length, 0, '字节级夹具已全部生成，清单不应再有 null 摘要');
  assert.equal(committed.length, entries.length, '每个登记项都必须是 sha256 摘要');
  for (const [relativePath, digest] of committed) {
    assert.match(digest, /^[0-9a-f]{64}$/, `摘要格式不正确：${relativePath}`);
  }
});

test('每个已提交夹具的 sha256 与清单记录一致', async () => {
  for (const [relativePath, expected] of Object.entries(manifest.fixtures)) {
    if (typeof expected !== 'string') {
      continue;
    }
    const url = new URL(join('fixtures', relativePath), import.meta.url);
    const info = await stat(url).catch(() => null);
    assert.notEqual(info, null, `清单登记的夹具不存在：${relativePath}`);
    const digest = createHash('sha256').update(await readFile(url)).digest('hex');
    assert.equal(digest, expected, `夹具摘要与清单不一致：${relativePath}`);
  }
});

test('构造器输出与已提交夹具逐字节一致（确定性）', () => {
  const built = buildFixtureBytes();
  assert.equal(built.length, BYTE_FIXTURES.length);
  for (const fixture of built) {
    assert.ok(fixture.bytes.length > 0, `夹具 ${fixture.path} 生成了空文件`);
    const expected = manifest.fixtures[fixture.path];
    assert.equal(typeof expected, 'string', `夹具 ${fixture.path} 未登记到清单`);
    assert.equal(
      createHash('sha256').update(fixture.bytes).digest('hex'),
      expected,
      `构造器输出与清单记录不一致：${fixture.path}`,
    );
  }
});

test('夹具目录里没有未登记到清单的散落文件', async () => {
  const registered = new Set(Object.keys(manifest.fixtures));
  const found = [];
  const queue = [FIXTURES_DIR];
  while (queue.length > 0) {
    const current = queue.shift();
    for (const dirent of await readdir(current, { withFileTypes: true })) {
      const absolute = join(current, dirent.name);
      if (dirent.isDirectory()) {
        queue.push(absolute);
        continue;
      }
      if (!dirent.isFile() || dirent.name === 'manifest.json' || dirent.name === 'build.mjs') {
        continue;
      }
      const relativePath = relative(FIXTURES_DIR, absolute).split(sep).join('/');
      if (!registered.has(relativePath)) {
        found.push(relativePath);
      }
    }
  }
  assert.deepEqual(found, [], '夹具目录出现未登记文件，应补登记或删除');
});

test('夹具规格登记表与构建登记表一致', () => {
  for (const fixture of BYTE_FIXTURES) {
    const spec = fixtureSpecById(fixture.id);
    assert.notEqual(spec, null, `构建登记表里的 ${fixture.id} 在规格表里没有对应项`);
    assert.equal(spec.path, fixture.path, `${fixture.id} 的路径不一致`);
    assert.equal(spec.container, fixture.container, `${fixture.id} 的容器标识不一致`);
    assert.equal(spec.status, 'committed', `${fixture.id} 应标记为已提交`);
  }
  for (const spec of FIXTURE_SPECS) {
    if (spec.id === 'sample-app') {
      continue;
    }
    assert.ok(
      BYTE_FIXTURES.some((fixture) => fixture.id === spec.id),
      `规格表里的 ${spec.id} 没有对应构造器`,
    );
  }
});

test('夹具规格登记表覆盖 v1 九类格式与两类范围外格式', () => {
  for (const container of ['elf', 'pe', 'mach-o', 'zip', 'gguf', 'safetensors', 'pyc', 'beam']) {
    assert.ok(
      FIXTURE_SPECS.some((spec) => spec.container === container),
      `夹具规格缺少 ${container}`,
    );
  }
  assert.ok(FIXTURE_SPECS.some((spec) => spec.container === 'unsupported'), '夹具规格应含范围外格式');
});

test('夹具规格登记表把 sample-app 标记为已提交', () => {
  const sampleApp = fixtureSpecById('sample-app');
  assert.equal(sampleApp?.status, 'committed');
  assert.equal(sampleApp?.container, 'directory');
});

test('node tests/fixtures/build.mjs --check 退出码为 0', async () => {
  const result = await runNode([join('tests', 'fixtures', 'build.mjs'), '--check']);
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /已提交夹具校验通过/);
});

test('夹具目录本身可定位', async () => {
  const info = await stat(new URL('fixtures/sample-app/README.md', import.meta.url));
  assert.equal(info.isFile(), true);
  assert.ok(FIXTURES_DIR.length > 0);
});
