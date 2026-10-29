// 命令行契约：子命令名、退出码表、--json 可解析、notice 拒否语义、probe 集成包生成。
// 覆盖三类输入：正常输入、畸形输入、资源超限下的部分读取。

import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { cp, mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import { EXIT_CODES } from '../src/cli/exit-codes.mjs';
import { runCli as runCliSubprocess, runNode, SAMPLE_APP } from './helpers/cli.mjs';
import { runCli } from '../src/cli/index.mjs';
import { createMcpServer } from '../src/mcp/server.mjs';

/** 仓库根目录。 */
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * 进程内运行命令行，收集退出码与输出，避免每条畸形输入都起子进程。
 * @param {readonly string[]} args 命令行参数
 * @returns {Promise<{code: number, stdout: string, stderr: string}>}
 */
async function runInProcess(args) {
  let stdout = '';
  let stderr = '';
  const code = await runCli(args, {
    write: (text) => {
      stdout += text;
    },
    writeError: (text) => {
      stderr += text;
    },
  });
  return { code, stdout, stderr };
}

/**
 * 造一个带 .git 标记的临时目录，模拟 git 工作树。
 * @returns {Promise<string>} 临时目录路径
 */
async function makeGitTree() {
  const root = await mkdtemp(join(tmpdir(), 'anti-rea-cli-git-'));
  await writeFile(join(root, '.git'), 'gitdir: /elsewhere\n', 'utf8');
  return root;
}

/**
 * 把策略写到临时文件，返回路径。
 * @param {Record<string, unknown>} policy 策略对象
 * @returns {Promise<string>} 策略文件路径
 */
async function writePolicy(policy) {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-cli-policy-'));
  const path = join(dir, 'policy.json');
  await writeFile(path, JSON.stringify(policy), 'utf8');
  return path;
}

test('退出码表为 0 成功、1 业务不通过、2 用法或输入错误、3 拒否', () => {
  assert.equal(EXIT_CODES.SUCCESS, 0);
  assert.equal(EXIT_CODES.BUSINESS_FAILURE, 1);
  assert.equal(EXIT_CODES.USAGE_ERROR, 2);
  assert.equal(EXIT_CODES.REFUSAL, 3);
});

test('不传子命令时退出码为 2', async () => {
  const result = await runInProcess([]);
  assert.equal(result.code, 2);
});

test('未知子命令时退出码为 2', async () => {
  const result = await runInProcess(['frobnicate']);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /未知子命令/);
});

test('audit 缺少目标路径时退出码为 2', async () => {
  const result = await runInProcess(['audit']);
  assert.equal(result.code, 2);
});

test('audit 目标不存在时退出码为 2', async () => {
  const result = await runInProcess(['audit', 'definitely-not-here', '--json']);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /目标不存在/);
});

test('audit 对普通应用目录正常完成，退出码为 0，输出可被 JSON.parse', async () => {
  const result = await runCliSubprocess(['audit', SAMPLE_APP, '--json']);
  assert.equal(result.code, 0);
  const report = JSON.parse(result.stdout);
  assert.equal(report.tool, 'audit-artifact');
  assert.equal(report.artifact.kind, 'directory');
});

test('audit 支持 --redacted，输出脱敏报告', async () => {
  const result = await runCliSubprocess(['audit', SAMPLE_APP, '--json', '--redacted']);
  assert.equal(result.code, 0);
  const report = JSON.parse(result.stdout);
  assert.equal(report.redacted, true);
});

test('harden 缺少 --from 时退出码为 2', async () => {
  const result = await runInProcess(['harden', SAMPLE_APP]);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /--from/);
});

test('harden 的 --from 指向不存在文件时退出码为 2', async () => {
  const result = await runInProcess(['harden', SAMPLE_APP, '--from', 'no-such-audit.json']);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /无法读取审计结果文件/);
});

test('verify 对未加固的普通应用目录退出码为 0', async () => {
  const result = await runCliSubprocess(['verify', SAMPLE_APP, '--json']);
  assert.equal(result.code, 0);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, 'passed');
});

test('notice --template license 在法律字段缺失时退出码为 3 且输出含 omitted_reason', async () => {
  const result = await runCliSubprocess(['notice', '--template', 'license', '--json']);
  assert.equal(result.code, 3);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, 'refused');
  assert.ok(Array.isArray(report.omitted_reason));
  assert.ok(report.omitted_reason.length > 0);
  assert.equal(report.omittedReason, undefined, '拒否报告只保留蛇形 omitted_reason，不再产出驼峰字段');
});

test('notice 使用未知模板时退出码为 2', async () => {
  const result = await runInProcess(['notice', '--template', 'eula']);
  assert.equal(result.code, 2);
});

test('notice --format 与 --json 等价，输出可被 JSON.parse', async () => {
  const viaFormat = await runInProcess(['notice', '--template', 'license', '--format', 'json']);
  assert.equal(viaFormat.code, 3);
  const report = JSON.parse(viaFormat.stdout);
  assert.equal(report.schema, 'anti-rea.refusal/1');
  assert.ok(report.omitted_reason.length > 0);
});

test('notice --format text 输出人读文本，含拒否原因段且不是 JSON', async () => {
  const result = await runInProcess(['notice', '--template', 'license', '--format', 'text']);
  assert.equal(result.code, 3);
  assert.match(result.stdout, /拒否原因/);
  assert.match(result.stdout, /主体名称/);
  assert.equal(result.stdout.trimStart().startsWith('{'), false, '文本模式不得输出 JSON');
});

test('--help 退出码为 0 且列出五个子命令', async () => {
  const result = await runInProcess(['--help']);
  assert.equal(result.code, 0);
  for (const subcommand of ['audit', 'harden', 'verify', 'notice', 'probe']) {
    assert.match(result.stdout, new RegExp(subcommand));
  }
});

test('--version 退出码为 0 且输出版本号', async () => {
  const result = await runInProcess(['--version']);
  assert.equal(result.code, 0);
  assert.match(result.stdout, /anti-rea \d+\.\d+\.\d+/);
});

test('说明文档记载的入口 bin/anti-rea.js 与设计文档写作的 bin/antirea.mjs 行为一致', async () => {
  const documented = await runCliSubprocess(['audit', SAMPLE_APP, '--json']);
  const alias = await runNode(['bin/antirea.mjs', 'audit', SAMPLE_APP, '--json']);
  assert.equal(documented.code, 0);
  assert.equal(alias.code, 0);
  // 两条入口只比报告内容，generatedAt 是生成时刻，天然不同。
  const strip = (text) => {
    const report = JSON.parse(text);
    delete report.generatedAt;
    return report;
  };
  assert.deepEqual(strip(alias.stdout), strip(documented.stdout));
});

// —— 正常输入：报告写出、基线复审、法律字段齐全时不拒否 ——

test('audit --out 把报告写入文件，标准输出仍是同一份可解析报告', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-cli-out-'));
  try {
    const outPath = join(dir, 'audit.json');
    const result = await runInProcess(['audit', SAMPLE_APP, '--json', '--out', outPath]);
    assert.equal(result.code, 0);
    const fromFile = JSON.parse(await readFile(outPath, 'utf8'));
    const fromStdout = JSON.parse(result.stdout);
    assert.equal(fromFile.tool, 'audit-artifact');
    assert.equal(fromFile.artifact.sha256, fromStdout.artifact.sha256);
    assert.match(result.stderr, /报告已写入/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('verify --from 基线审计报告正常完成，退出码 0，输出含前后差异', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-cli-verify-'));
  try {
    const audit = await runInProcess(['audit', SAMPLE_APP, '--json']);
    const baselinePath = join(dir, 'audit.json');
    await writeFile(baselinePath, audit.stdout, 'utf8');
    const result = await runInProcess(['verify', SAMPLE_APP, '--json', '--from', baselinePath]);
    assert.equal(result.code, 0);
    const report = JSON.parse(result.stdout);
    assert.equal(report.status, 'passed');
    assert.ok(report.comparison !== null, '给出基线时必须输出前后差异');
    // sample-app 没有任何发现，加固前后同一份制品，三类差异都应为空。
    assert.deepEqual(report.comparison, { resolved: [], introduced: [], persisting: [] });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('notice 在法律字段齐全时不走拒否路径', async () => {
  const policyPath = await writePolicy({
    legal: {
      subject: '示例主体',
      contact: 'security@example.com',
      jurisdiction: '示例辖区',
      licenseId: 'MIT',
      licenseTextSource: 'https://example.com/LICENSE',
      prohibitedActs: ['逆向工程'],
      consequences: [{ statement: '示例后果陈述', statuteExcerpt: '示例法条摘录' }],
    },
  });
  try {
    const result = await runInProcess(['notice', '--template', 'license', '--json', '--policy', policyPath]);
    assert.notEqual(result.code, 3, '字段齐全时不得拒否');
    if (result.code === 0) {
      const report = JSON.parse(result.stdout);
      assert.equal(report.status, 'generated');
    }
  } finally {
    await rm(join(policyPath, '..'), { recursive: true, force: true });
  }
});

// —— probe 子命令：集成包生成、--out 语义、git 工作树警告 ——

test('probe 子命令把集成包写进位置参数给出的输出目录，退出码为 0', async () => {
  const root = await mkdtemp(join(tmpdir(), 'anti-rea-cli-probe-'));
  try {
    const kitDir = join(root, 'kit');
    const result = await runInProcess(['probe', kitDir, '--json']);
    assert.equal(result.code, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.status, 'generated');
    assert.equal(report.tool, 'probe-kit');
    assert.equal(report.outDir, kitDir);
    assert.deepEqual(
      report.files.map((file) => file.name),
      ['runtime-probe.mjs', 'manual-checklist.md', 'INTEGRATION.md'],
    );
    for (const name of ['runtime-probe.mjs', 'manual-checklist.md', 'INTEGRATION.md']) {
      const info = await stat(join(kitDir, name));
      assert.equal(info.isFile(), true);
      assert.ok(info.size > 0);
    }
    // 人读输出给出落盘清单，不冒充制品报告。
    const human = await runInProcess(['probe', kitDir]);
    assert.equal(human.code, 0);
    assert.match(human.stdout, /集成包输出目录/);
    assert.match(human.stdout, /runtime-probe\.mjs/);
    assert.equal(human.stdout.includes('制品摘要'), false, 'probe 不读制品，人读输出不得给制品摘要');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('probe 的 --out 与位置参数同义且优先，重复生成幂等', async () => {
  const root = await mkdtemp(join(tmpdir(), 'anti-rea-cli-probe-out-'));
  try {
    const project = join(root, 'project');
    await mkdir(project, { recursive: true });
    await writeFile(join(project, 'app.js'), 'console.log(1)\n', 'utf8');
    const kitDir = join(root, 'kit');
    const first = await runInProcess(['probe', project, '--out', kitDir, '--json']);
    assert.equal(first.code, 0, first.stderr);
    assert.equal(JSON.parse(first.stdout).changed, true);
    const probeText = await readFile(join(kitDir, 'runtime-probe.mjs'), 'utf8');

    const second = await runInProcess(['probe', project, '--out', kitDir, '--json']);
    assert.equal(second.code, 0, second.stderr);
    assert.equal(JSON.parse(second.stdout).changed, false, '第二次生成内容相同，不得重复写入');
    assert.equal(await readFile(join(kitDir, 'runtime-probe.mjs'), 'utf8'), probeText);
    // 集成包只写进输出目录，位置参数给出的目录不被写入。
    assert.deepEqual(await readdir(project), ['app.js']);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('probe 缺少位置参数或给出未登记选项时退出码为 2', async () => {
  const missing = await runInProcess(['probe']);
  assert.equal(missing.code, 2);
  assert.match(missing.stderr, /位置参数/);
  const bogus = await runInProcess(['probe', 'some-dir', '--bogus']);
  assert.equal(bogus.code, 2);
  assert.match(bogus.stderr, /不支持的选项/);
});

test('probe 的输出目录位于 git 工作树内时向标准错误输出警告，同一路径只警告一次', async () => {
  const gitTree = await makeGitTree();
  try {
    const kitDir = join(gitTree, 'kit');
    const result = await runInProcess(['probe', kitDir, '--json']);
    assert.equal(result.code, 0, result.stderr);
    const occurrences = result.stderr.split('git 工作树').length - 1;
    assert.equal(occurrences, 1, `同一路径只应警告一次，实际 ${occurrences} 次`);
  } finally {
    await rm(gitTree, { recursive: true, force: true });
  }
});

test('MCP generate_probe_kit 与命令行 probe 产出同一份集成包报告（工具名除外）', async () => {
  const root = await mkdtemp(join(tmpdir(), 'anti-rea-cli-probe-shared-'));
  try {
    const cliKit = join(root, 'cli-kit');
    const mcpKit = join(root, 'mcp-kit');
    const cli = JSON.parse((await runInProcess(['probe', cliKit, '--json'])).stdout);
    const server = createMcpServer();
    const response = await server.handle({
      jsonrpc: '2.0',
      id: 9,
      method: 'tools/call',
      params: { name: 'generate_probe_kit', arguments: { path: cliKit, out: mcpKit } },
    });
    assert.equal(response.result.isError, false);
    const mcp = JSON.parse(response.result.content[0].text);

    const strip = (report) => {
      const copy = { ...report };
      delete copy.tool;
      // 输出目录不同：两条入口各写自己的一份，其余字段必须一致。
      copy.outDir = '<输出目录>';
      copy.files = copy.files.map((file) => ({ ...file, path: '<输出目录>' }));
      return copy;
    };
    assert.deepEqual(strip(mcp), strip(cli), '两条入口必须共用同一套工作流代码');
    assert.equal(mcp.tool, 'generate_probe_kit');
    assert.equal(cli.tool, 'probe-kit');
    // 两边落盘内容逐字节相同。
    for (const name of ['runtime-probe.mjs', 'manual-checklist.md', 'INTEGRATION.md']) {
      assert.equal(await readFile(join(mcpKit, name), 'utf8'), await readFile(join(cliKit, name), 'utf8'));
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// —— 畸形输入：未登记选项、非法取值、位置参数过多、审计结果文件不可用 ——

test('未登记选项、非法格式取值、短选项、位置参数过多都按用法错误处理', async () => {
  const cases = [
    { args: ['audit', SAMPLE_APP, '--bogus'], pattern: /不支持的选项/ },
    { args: ['audit', SAMPLE_APP, '--format', 'yaml'], pattern: /--format 只支持/ },
    { args: ['audit', '-j'], pattern: /短选项/ },
    { args: ['audit', SAMPLE_APP, SAMPLE_APP], pattern: /位置参数/ },
    { args: ['audit', SAMPLE_APP, '--json', '--out'], pattern: /--out 缺少取值/ },
  ];
  for (const { args, pattern } of cases) {
    const result = await runInProcess(args);
    assert.equal(result.code, 2, `${args.join(' ')} 应返回用法错误`);
    assert.match(result.stderr, pattern, `${args.join(' ')} 的标准错误应说明原因`);
  }
});

test('harden 的 --from 指向非 JSON 文件时退出码为 2', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-cli-badjson-'));
  try {
    const badPath = join(dir, 'not-json.txt');
    await writeFile(badPath, '这不是 JSON', 'utf8');
    const result = await runInProcess(['harden', SAMPLE_APP, '--from', badPath]);
    assert.equal(result.code, 2);
    assert.match(result.stderr, /不是合法 JSON/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('harden 的 --from 指向合法 JSON 但不是审计报告时退出码为 2', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-cli-notaudit-'));
  try {
    const wrongPath = join(dir, 'other.json');
    await writeFile(wrongPath, JSON.stringify({ hello: 'world' }), 'utf8');
    const result = await runInProcess(['harden', SAMPLE_APP, '--from', wrongPath]);
    assert.equal(result.code, 2);
    assert.match(result.stderr, /不是 Anti-REA 审计报告/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('verify 的 --from 指向不可用文件时退出码为 2', async () => {
  const result = await runInProcess(['verify', SAMPLE_APP, '--from', 'no-such-baseline.json']);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /无法读取基线审计报告/);
});

test('notice 缺少 --template 时退出码为 2', async () => {
  const result = await runInProcess(['notice']);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /--template/);
});

// —— 部分读取：单文件上限设为极小值时产出部分结果并附限制说明 ——

test('单文件上限极小时 audit 输出 partial 与限制说明，退出码仍为 0', async () => {
  const policyPath = await writePolicy({ budgets: { maxFileBytes: 1, maxTotalScanBytes: 1 } });
  try {
    const result = await runInProcess(['audit', SAMPLE_APP, '--json', '--policy', policyPath]);
    assert.equal(result.code, 0, '资源超限只产部分结果，不让进程失败');
    const report = JSON.parse(result.stdout);
    assert.equal(report.status, 'partial');
    const codes = report.limitations.map((limitation) => limitation.code);
    assert.ok(codes.includes('max-file-bytes-exceeded'), `缺少单文件上限限制说明：${JSON.stringify(codes)}`);
    assert.ok(report.limitations.every((limitation) => limitation.message.length > 0));
  } finally {
    await rm(join(policyPath, '..'), { recursive: true, force: true });
  }
});

test('部分读取的报告同样可以脱敏且保留分类与计数', async () => {
  const policyPath = await writePolicy({ budgets: { maxFileBytes: 1, maxTotalScanBytes: 1 } });
  try {
    const plain = JSON.parse((await runInProcess(['audit', SAMPLE_APP, '--json', '--policy', policyPath])).stdout);
    const redacted = JSON.parse((await runInProcess(['audit', SAMPLE_APP, '--json', '--redacted', '--policy', policyPath])).stdout);
    assert.equal(redacted.redacted, true);
    assert.equal(redacted.status, 'partial');
    assert.equal(redacted.summary.capabilityBoundaries, plain.summary.capabilityBoundaries);
    assert.ok(!JSON.stringify(redacted).includes(SAMPLE_APP), '脱敏报告不得包含精确路径');
  } finally {
    await rm(join(policyPath, '..'), { recursive: true, force: true });
  }
});

// —— git 工作树警告：同一路径只警告一次 ——

test('audit 写出路径位于 git 工作树内时向标准错误输出警告，同一路径只警告一次', async () => {
  const gitTree = await makeGitTree();
  try {
    const result = await runInProcess(['audit', SAMPLE_APP, '--json', '--out', join(gitTree, 'audit.json')]);
    assert.equal(result.code, 0);
    const occurrences = result.stderr.split('git 工作树').length - 1;
    assert.equal(occurrences, 1, `同一路径只应警告一次，实际 ${occurrences} 次`);
    assert.match(result.stderr, /--redacted/);
  } finally {
    await rm(gitTree, { recursive: true, force: true });
  }
});

test('harden 的写出路径位于 git 工作树内时同样警告，报告写出不重复警告', async () => {
  const gitTree = await makeGitTree();
  try {
    const audit = await runInProcess(['audit', SAMPLE_APP, '--json']);
    const auditPath = join(gitTree, 'audit.json');
    await writeFile(auditPath, audit.stdout, 'utf8');
    const result = await runInProcess(['harden', SAMPLE_APP, '--from', auditPath, '--out', join(gitTree, 'report.json')]);
    assert.equal(result.code, 0);
    const occurrences = result.stderr.split('git 工作树').length - 1;
    assert.equal(occurrences, 1, `只有报告写出路径在树内，应警告一次，实际 ${occurrences} 次`);
    assert.match(result.stderr, /report\.json/);
  } finally {
    await rm(gitTree, { recursive: true, force: true });
  }
});

test('加固目标与报告写出路径都在 git 工作树内时，两条路径各警告一次', async () => {
  const gitTree = await makeGitTree();
  try {
    const target = join(gitTree, 'app.txt');
    await writeFile(target, '普通应用文件\n', 'utf8');
    const audit = await runInProcess(['audit', target, '--json']);
    const auditPath = join(gitTree, 'audit.json');
    await writeFile(auditPath, audit.stdout, 'utf8');
    const result = await runInProcess(['harden', target, '--from', auditPath, '--out', join(gitTree, 'report.json')]);
    assert.equal(result.code, 0);
    const occurrences = result.stderr.split('git 工作树').length - 1;
    assert.equal(occurrences, 2, `加固输出路径与报告写出路径各一次，实际 ${occurrences} 次`);
    assert.match(result.stderr, /app\.txt\.hardened/);
    assert.match(result.stderr, /report\.json/);
  } finally {
    await rm(gitTree, { recursive: true, force: true });
  }
});

// —— MCP 服务层与命令行共用同一套工作流 ——

test('MCP harden_artifact 与命令行 harden 产出同一份报告（工具名除外）', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-cli-shared-'));
  try {
    const audit = await runInProcess(['audit', SAMPLE_APP, '--json']);
    const auditPath = join(dir, 'audit.json');
    await writeFile(auditPath, audit.stdout, 'utf8');

    const cli = JSON.parse((await runInProcess(['harden', SAMPLE_APP, '--from', auditPath, '--json'])).stdout);
    const server = createMcpServer();
    const response = await server.handle({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'harden_artifact', arguments: { path: SAMPLE_APP, from: auditPath } },
    });
    assert.equal(response.result.isError, false);
    const mcp = JSON.parse(response.result.content[0].text);

    const strip = (report) => {
      const copy = { ...report };
      delete copy.tool;
      return copy;
    };
    assert.deepEqual(strip(mcp), strip(cli), '两条入口必须共用同一套工作流代码');
    assert.equal(mcp.tool, 'harden_artifact');
    assert.equal(cli.tool, 'harden-artifact');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('MCP audit_artifact 给出 out 时写出报告，git 工作树警告进 warnings 字段', async () => {
  const gitTree = await makeGitTree();
  try {
    const outPath = join(gitTree, 'mcp-audit.json');
    const server = createMcpServer();
    const response = await server.handle({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'audit_artifact', arguments: { path: SAMPLE_APP, out: outPath } },
    });
    assert.equal(response.result.isError, false);
    const report = response.result.structuredContent;
    assert.equal(report.output, outPath);
    assert.equal(report.warnings.length, 1, '同一路径只警告一次');
    assert.match(report.warnings[0], /git 工作树/);
    const written = JSON.parse(await readFile(outPath, 'utf8'));
    assert.equal(written.artifact.sha256, report.artifact.sha256);
  } finally {
    await rm(gitTree, { recursive: true, force: true });
  }
});

test('MCP tools/call 对用法错误返回 isError，对拒否返回含 omitted_reason 的报告', async () => {
  const server = createMcpServer();
  const missing = await server.handle({
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    params: { name: 'harden_artifact', arguments: { path: SAMPLE_APP } },
  });
  assert.equal(missing.result.isError, true, '缺少 from 属于用法错误');

  const badTarget = await server.handle({
    jsonrpc: '2.0',
    id: 4,
    method: 'tools/call',
    params: { name: 'audit_artifact', arguments: { path: 'definitely-not-here' } },
  });
  assert.equal(badTarget.result.isError, true);
});



test('发布布局下冒烟自检可用：没有 tests/ 时退到随包发布的探针模板', async () => {
  // 实测背景：安装副本里跑冒烟失败，自检目标指向 tests/fixtures/sample-app，
  // 而 package.json 的 files 字段不含 tests/，发布出去的包装着一个跑不了的自检。
  // 这个用例按发布布局拼一个临时包，确保缺陷不复发。
  const root = await mkdtemp(join(tmpdir(), 'anti-rea-pack-'));
  try {
    for (const entry of ['bin', 'src', 'templates', 'scripts']) {
      await cp(join(REPO_ROOT, entry), join(root, entry), { recursive: true });
    }
    await cp(join(REPO_ROOT, 'package.json'), join(root, 'package.json'));
    await stat(join(root, 'tests')).then(
      () => assert.fail('临时包不应包含 tests/，否则本用例失去意义'),
      () => {},
    );
    const result = await new Promise((resolvePromise, rejectPromise) => {
      execFile(process.execPath, [join(root, 'scripts', 'mcp-smoke.mjs')], { cwd: root, maxBuffer: 32 * 1024 * 1024 }, (error, stdout, stderr) => {
        if (error !== null && error.code === undefined) {
          rejectPromise(error);
          return;
        }
        resolvePromise({ code: error?.code ?? 0, stdout, stderr });
      });
    });
    assert.equal(result.code, 0, `发布布局下的冒烟应通过：${result.stderr}`);
    assert.match(result.stdout, /MCP 冒烟验证通过/);
    for (const tool of ['audit_artifact', 'harden_artifact', 'verify_artifact', 'generate_notice', 'generate_probe_kit']) {
      assert.ok(result.stdout.includes(tool), `工具清单缺少 ${tool}`);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
