// 静态检查：零依赖与模块格式、模板目录不误报、夹具不参与检查、不导入子进程相关模块。
// 检查范围严格限定为 src/ 与 bin/ 下的 .mjs/.js/.cjs 文件，逐文件扫描 import 与 require 源。

import assert from 'node:assert/strict';
import { mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';
import { test } from 'node:test';

import { REPO_ROOT } from './helpers/cli.mjs';

/** 参与静态检查的目录。 */
const SCAN_ROOTS = ['src', 'bin'];

/** 参与静态检查的扩展名。 */
const SCAN_EXTENSIONS = ['.mjs', '.js', '.cjs'];

/** import 与 require 的来源模式。 */
const SPECIFIER_PATTERNS = [
  /\bimport\s+[^;'"]*?\sfrom\s*['"]([^'"]+)['"]/g,
  /\bimport\s*['"]([^'"]+)['"]/g,
  /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  /\bexport\s+[^;'"]*?\sfrom\s*['"]([^'"]+)['"]/g,
  /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
];

/** 允许的来源前缀：Node.js 内置模块与仓库内相对路径。 */
const ALLOWED_PREFIXES = ['node:', './', '../', '/'];

/** 子进程与工作线程相关模块，src/ 与 bin/ 一律不得导入。 */
const SUBPROCESS_MODULES = ['node:child_process', 'node:worker_threads', 'child_process', 'worker_threads'];

/**
 * 枚举目录下的源文件。
 * @param {string} root 目录绝对路径
 * @returns {Promise<string[]>} 文件绝对路径，已排序
 */
async function listSourceFiles(root) {
  const found = [];
  const queue = [root];
  while (queue.length > 0) {
    const current = queue.shift();
    for (const dirent of await readdir(current, { withFileTypes: true })) {
      const absolute = join(current, dirent.name);
      if (dirent.isDirectory()) {
        queue.push(absolute);
        continue;
      }
      if (dirent.isFile() && SCAN_EXTENSIONS.includes(dirent.name.slice(dirent.name.lastIndexOf('.')))) {
        found.push(absolute);
      }
    }
  }
  return found.sort();
}

/**
 * 扫描一份源码，返回其中的模块来源列表。
 * @param {string} source 源码文本
 * @returns {string[]} 模块来源
 */
function scanSpecifiers(source) {
  const specifiers = [];
  for (const pattern of SPECIFIER_PATTERNS) {
    pattern.lastIndex = 0;
    let match = pattern.exec(source);
    while (match !== null) {
      specifiers.push(match[1]);
      match = pattern.exec(source);
    }
  }
  return specifiers;
}

test('src/ 与 bin/ 的源码只引用 node: 前缀模块或仓库内相对路径', async () => {
  const offenders = [];
  for (const root of SCAN_ROOTS) {
    for (const file of await listSourceFiles(resolve(REPO_ROOT, root))) {
      const source = await readFile(file, 'utf8');
      for (const specifier of scanSpecifiers(source)) {
        if (!ALLOWED_PREFIXES.some((prefix) => specifier.startsWith(prefix))) {
          offenders.push(`${relative(REPO_ROOT, file)} -> ${specifier}`);
        }
      }
    }
  }
  assert.deepEqual(offenders, [], '出现非 node: 前缀的引用即视为零依赖被破坏');
});

test('仓库根 templates/ 下含 import 行的模板不参与检查', async () => {
  const templatesDir = resolve(REPO_ROOT, 'templates');
  await mkdir(templatesDir, { recursive: true });
  const templatePath = join(templatesDir, 'static-check-canary.template.js');
  await writeFile(templatePath, "import probe from 'third-party-package';\nexport default probe;\n", 'utf8');
  try {
    const source = await readFile(templatePath, 'utf8');
    const specifiers = scanSpecifiers(source);
    assert.deepEqual(specifiers, ['third-party-package']);

    // 检查范围只含 src/ 与 bin/，因此该文件不会被扫描到。
    const scanned = [];
    for (const root of SCAN_ROOTS) {
      scanned.push(...(await listSourceFiles(resolve(REPO_ROOT, root))));
    }
    assert.ok(!scanned.includes(templatePath), 'templates/ 不应进入静态检查范围');
    const offenders = [];
    for (const file of scanned) {
      const text = await readFile(file, 'utf8');
      for (const specifier of scanSpecifiers(text)) {
        if (!ALLOWED_PREFIXES.some((prefix) => specifier.startsWith(prefix))) {
          offenders.push(`${relative(REPO_ROOT, file)} -> ${specifier}`);
        }
      }
    }
    assert.deepEqual(offenders, []);
  } finally {
    await rm(templatePath, { force: true });
  }
});

test('tests/fixtures/ 下的文件不参与静态检查', async () => {
  const fixturesDir = resolve(REPO_ROOT, 'tests', 'fixtures');
  const canary = join(fixturesDir, 'static-check-canary.mjs');
  await writeFile(canary, "import thing from 'not-a-real-package';\nexport default thing;\n", 'utf8');
  try {
    const scanned = [];
    for (const root of SCAN_ROOTS) {
      scanned.push(...(await listSourceFiles(resolve(REPO_ROOT, root))));
    }
    assert.ok(!scanned.some((file) => file.startsWith(fixturesDir)), 'fixtures/ 不应进入静态检查范围');
  } finally {
    await rm(canary, { force: true });
  }
});

test('src/ 与 bin/ 不导入子进程与工作线程相关模块', async () => {
  const offenders = [];
  for (const root of SCAN_ROOTS) {
    for (const file of await listSourceFiles(resolve(REPO_ROOT, root))) {
      const source = await readFile(file, 'utf8');
      for (const specifier of scanSpecifiers(source)) {
        if (SUBPROCESS_MODULES.includes(specifier)) {
          offenders.push(`${relative(REPO_ROOT, file)} -> ${specifier}`);
        }
      }
    }
  }
  assert.deepEqual(offenders, [], '读取全部在进程内完成，不得启动子进程');
});
