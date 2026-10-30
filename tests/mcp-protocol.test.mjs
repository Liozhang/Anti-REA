// MCP 协议：标准输入输出传输、initialize 握手、tools/list、tools/call。
// 进程内驱动服务实例，另用一个子进程握手用例确认 bin/anti-rea-mcp.js 可独立启动。
// 覆盖三类输入：正常输入、畸形输入、部分读取（传输分帧与资源上限产出的部分结果）。

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';

import { createMcpServer, serveOverStdio } from '../src/mcp/server.mjs';
import { TOOL_NAMES } from '../src/mcp/tools.mjs';
import { MCP_ENTRY, REPO_ROOT, SAMPLE_APP } from './helpers/cli.mjs';

/** 法律字段齐全的策略夹具，供 generate_notice 成功路径使用。 */
const COMPLETE_POLICY = join(REPO_ROOT, 'tests', 'notice', 'fixtures', 'complete-policy.json');

test('initialize 返回协议版本、能力与服务标识', async () => {
  const server = createMcpServer();
  const response = await server.handle({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'test', version: '0.0.0' } },
  });
  assert.equal(response.id, 1);
  assert.equal(response.error, undefined);
  assert.equal(response.result.protocolVersion, '2024-11-05');
  assert.equal(response.result.serverInfo.name, 'anti-rea');
  assert.deepEqual(response.result.capabilities.tools, { listChanged: false });
});

test('initialize 在客户端请求不受支持版本时回落到最新受支持版本', async () => {
  const server = createMcpServer();
  const response = await server.handle({
    jsonrpc: '2.0',
    id: 2,
    method: 'initialize',
    params: { protocolVersion: '1999-01-01' },
  });
  assert.equal(response.result.protocolVersion, '2025-06-18');
});

test('tools/list 返回五个工具，名称与命令行子命令一一对应', async () => {
  const server = createMcpServer();
  const response = await server.handle({ jsonrpc: '2.0', id: 3, method: 'tools/list' });
  const names = response.result.tools.map((tool) => tool.name);
  assert.deepEqual(names, ['audit_artifact', 'harden_artifact', 'verify_artifact', 'generate_notice', 'generate_probe_kit']);
  assert.deepEqual(names, [...TOOL_NAMES]);
  for (const tool of response.result.tools) {
    assert.equal(typeof tool.description, 'string');
    assert.equal(tool.inputSchema.type, 'object');
  }
});

test('tools/call 调用 audit_artifact 成功并返回可解析报告', async () => {
  const server = createMcpServer();
  const response = await server.handle({
    jsonrpc: '2.0',
    id: 4,
    method: 'tools/call',
    params: { name: 'audit_artifact', arguments: { path: SAMPLE_APP } },
  });
  assert.equal(response.error, undefined);
  assert.equal(response.result.isError, false);
  const text = response.result.content.find((item) => item.type === 'text').text;
  const report = JSON.parse(text);
  assert.equal(report.tool, 'audit_artifact');
  assert.equal(report.artifact.kind, 'directory');
});

test('tools/call 调用 generate_notice 在法律字段缺失时返回含 omitted_reason 的拒否报告', async () => {
  const server = createMcpServer();
  const response = await server.handle({
    jsonrpc: '2.0',
    id: 5,
    method: 'tools/call',
    params: { name: 'generate_notice', arguments: { template: 'license' } },
  });
  // 拒否按失败信号返回：此前 isError 为 false，协议层看起来像成功，代理会以为
  // 声明已经生成。报告本身一个字段不少地送回，调用方看得到缺什么。
  assert.equal(response.result.isError, true);
  const report = JSON.parse(response.result.content[0].text);
  assert.equal(report.status, 'refused');
  assert.ok(report.omitted_reason.length > 0);
  assert.equal(report.omittedReason, undefined, '拒否报告只保留蛇形 omitted_reason');
});

test('tools/call 调用 generate_probe_kit 生成集成包，out 指输出目录', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-mcp-probe-'));
  try {
    const kitDir = join(dir, 'kit');
    const server = createMcpServer();
    const response = await server.handle({
      jsonrpc: '2.0',
      id: 9,
      method: 'tools/call',
      params: { name: 'generate_probe_kit', arguments: { path: dir, out: kitDir } },
    });
    assert.equal(response.result.isError, false, response.result.content[0].text);
    const report = JSON.parse(response.result.content[0].text);
    assert.equal(report.tool, 'generate_probe_kit');
    assert.equal(report.status, 'generated');
    assert.equal(report.outDir, resolve(kitDir));
    const names = report.files.map((file) => file.name);
    for (const name of ['runtime-probe.mjs', 'manual-checklist.md', 'INTEGRATION.md']) {
      assert.ok(names.includes(name), `集成包报告应登记产物 ${name}`);
      const info = await stat(join(kitDir, name));
      assert.ok(info.isFile() && info.size > 0, `产物应落盘：${name}`);
    }
    // out 是集成包目录，报告不写进目录，目录里只有集成包三份产物。
    assert.deepEqual(await readdir(kitDir), ['INTEGRATION.md', 'manual-checklist.md', 'runtime-probe.mjs']);
    // output 与 path 两个名字等价。
    for (const key of ['output', 'path']) {
      const other = join(dir, `kit-${key}`);
      const via = await server.handle({
        jsonrpc: '2.0',
        id: 10,
        method: 'tools/call',
        params: { name: 'generate_probe_kit', arguments: { [key]: other } },
      });
      assert.equal(via.result.isError, false, `${key} 应被当作输出目录`);
      assert.equal(JSON.parse(via.result.content[0].text).outDir, resolve(other));
    }
    // 一个目录名都没给时按用法错误处理。
    const missing = await server.handle({
      jsonrpc: '2.0',
      id: 11,
      method: 'tools/call',
      params: { name: 'generate_probe_kit', arguments: {} },
    });
    assert.equal(missing.result.isError, true);
    assert.equal(JSON.parse(missing.result.content[0].text).error.exitCode, 2);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('tools/call 使用未知工具名时标记为错误', async () => {
  const server = createMcpServer();
  const response = await server.handle({
    jsonrpc: '2.0',
    id: 6,
    method: 'tools/call',
    params: { name: 'delete_everything', arguments: {} },
  });
  assert.equal(response.result.isError, true);
});

test('未知方法返回 METHOD_NOT_FOUND', async () => {
  const server = createMcpServer();
  const response = await server.handle({ jsonrpc: '2.0', id: 7, method: 'resources/list' });
  assert.equal(response.error.code, -32601);
});

test('通知不产生响应', async () => {
  const server = createMcpServer();
  const response = await server.handle({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} });
  assert.equal(response, null);
});

test('ping 返回空结果', async () => {
  const server = createMcpServer();
  const response = await server.handle({ jsonrpc: '2.0', id: 8, method: 'ping' });
  assert.deepEqual(response.result, {});
});

test('bin/anti-rea-mcp.js 可作为子进程完成握手并调用一次 audit_artifact', async () => {
  const child = spawn(process.execPath, [MCP_ENTRY], { cwd: REPO_ROOT, stdio: ['pipe', 'pipe', 'pipe'] });
  const pending = new Map();
  let buffer = '';
  let stderrText = '';
  child.stderr.on('data', (chunk) => {
    stderrText += String(chunk);
  });
  child.stdout.on('data', (chunk) => {
    buffer += String(chunk);
    let index = buffer.indexOf('\n');
    while (index !== -1) {
      const line = buffer.slice(0, index).trim();
      buffer = buffer.slice(index + 1);
      if (line !== '') {
        const message = JSON.parse(line);
        const waiter = pending.get(message.id);
        if (waiter !== undefined) {
          pending.delete(message.id);
          waiter(message);
        }
      }
      index = buffer.indexOf('\n');
    }
  });

  /**
   * 发送请求并等待响应。
   * @param {string} method 方法名
   * @param {Record<string, unknown>} params 参数
   * @returns {Promise<Record<string, unknown>>}
   */
  function request(method, params) {
    const id = pending.size + 1;
    return new Promise((resolvePromise, rejectPromise) => {
      const timer = setTimeout(() => rejectPromise(new Error(`等待 ${method} 超时：${stderrText}`)), 15000);
      pending.set(id, (message) => {
        clearTimeout(timer);
        resolvePromise(message);
      });
      child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
    });
  }

  try {
    const init = await request('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '0.0.0' } });
    assert.equal(init.result.serverInfo.name, 'anti-rea');
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} })}\n`);
    const list = await request('tools/list', {});
    assert.equal(list.result.tools.length, 5);
    const call = await request('tools/call', { name: 'audit_artifact', arguments: { path: SAMPLE_APP } });
    assert.equal(call.result.isError, false);
    const report = JSON.parse(call.result.content[0].text);
    assert.equal(report.tool, 'audit_artifact');
  } finally {
    child.stdin.end();
    child.kill();
  }
});

test('冒烟脚本存在且可读', async () => {
  const text = await readFile(join(REPO_ROOT, 'scripts', 'mcp-smoke.mjs'), 'utf8');
  assert.match(text, /initialize/);
  assert.match(text, /tools\/list/);
  assert.match(text, /audit_artifact/);
});

// —— 正常输入（补充）——

test('tools/call 的 format 为 text 时返回人读文本', async () => {
  const server = createMcpServer();
  const response = await server.handle({
    jsonrpc: '2.0',
    id: 20,
    method: 'tools/call',
    params: { name: 'audit_artifact', arguments: { path: SAMPLE_APP, format: 'text' } },
  });
  assert.equal(response.result.isError, false);
  const text = response.result.content.find((item) => item.type === 'text').text;
  assert.match(text, /^工具：audit_artifact/);
  assert.match(text, /状态：/);
  assert.match(text, /制品摘要：/);
});

test('tools/call 的 redacted 为 true 时返回脱敏报告，隐去精确路径', async () => {
  const server = createMcpServer();
  const plain = await server.handle({
    jsonrpc: '2.0',
    id: 21,
    method: 'tools/call',
    params: { name: 'audit_artifact', arguments: { path: SAMPLE_APP } },
  });
  const redacted = await server.handle({
    jsonrpc: '2.0',
    id: 22,
    method: 'tools/call',
    params: { name: 'audit_artifact', arguments: { path: SAMPLE_APP, redacted: true } },
  });
  const plainReport = JSON.parse(plain.result.content[0].text);
  const redactedReport = JSON.parse(redacted.result.content[0].text);
  assert.equal(redactedReport.redacted, true);
  assert.equal(redactedReport.artifact.path, undefined, '脱敏报告不得带精确路径');
  assert.notEqual(plainReport.artifact.path, undefined, '未脱敏报告应带精确路径，否则本用例无从对比');
  assert.equal(redactedReport.artifact.sha256, plainReport.artifact.sha256, '脱敏不改变制品摘要');
  for (const finding of redactedReport.findings) {
    assert.equal(finding.evidence, undefined, '脱敏报告不得带证据偏移与摘录');
    assert.equal(finding.mitigation, undefined, '脱敏报告不得带缓解措施对应关系');
  }
});

test('tools/call 的 out 把报告写出到文件', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-mcp-out-'));
  try {
    const outPath = join(dir, 'audit.json');
    const server = createMcpServer();
    const response = await server.handle({
      jsonrpc: '2.0',
      id: 23,
      method: 'tools/call',
      params: { name: 'audit_artifact', arguments: { path: SAMPLE_APP, out: outPath } },
    });
    const report = JSON.parse(response.result.content[0].text);
    assert.equal(report.output, resolve(outPath));
    const written = JSON.parse(await readFile(outPath, 'utf8'));
    assert.equal(written.tool, 'audit_artifact');
    assert.equal(written.artifact.sha256, report.artifact.sha256);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('out 位于 git 工作树内时，警告收进报告的 warnings 字段', async () => {
  const gitTree = await mkdtemp(join(tmpdir(), 'anti-rea-mcp-git-'));
  try {
    await mkdir(join(gitTree, '.git'), { recursive: true });
    const outPath = join(gitTree, 'audit.json');
    const server = createMcpServer();
    const response = await server.handle({
      jsonrpc: '2.0',
      id: 24,
      method: 'tools/call',
      params: { name: 'audit_artifact', arguments: { path: SAMPLE_APP, out: outPath } },
    });
    const report = JSON.parse(response.result.content[0].text);
    assert.ok(Array.isArray(report.warnings), 'git 工作树警告应收进报告 warnings 字段');
    assert.ok(report.warnings.some((warning) => warning.includes('git 工作树')), `实际 warnings：${JSON.stringify(report.warnings)}`);
  } finally {
    await rm(gitTree, { recursive: true, force: true });
  }
});

test('generate_notice 字段齐全时成功，out 写出的文件是声明文档且不含工具引用与加固状态暗示', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-mcp-notice-'));
  try {
    const outPath = join(dir, 'NOTICE.md');
    const server = createMcpServer();
    const response = await server.handle({
      jsonrpc: '2.0',
      id: 25,
      method: 'tools/call',
      params: { name: 'generate_notice', arguments: { template: 'license', policy: COMPLETE_POLICY, out: outPath } },
    });
    assert.equal(response.result.isError, false);
    const report = JSON.parse(response.result.content[0].text);
    assert.equal(report.status, 'generated');
    assert.equal(report.output, resolve(outPath), 'generate_notice 的 out 指声明文件路径');
    const notice = await readFile(outPath, 'utf8');
    assert.match(notice, /^# 许可与禁止逆向声明/, 'out 写出的应是声明文档，不是报告 JSON');
    assert.ok(notice.includes('示例主体'), '声明应包含用户提供的真实主体字段');
    for (const token of ['anti-rea', 'antirea', '加固', 'harden', 'mitigation', '缓解', 'audit', '审计', 'verify', '复审', 'omitted_reason', 'requires_resign']) {
      assert.ok(!notice.toLowerCase().includes(token), `声明文档不得出现 ${token}`);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// —— 畸形输入 ——

test('非对象消息返回 INVALID_REQUEST', async () => {
  const server = createMcpServer();
  for (const message of ['a string', 42, null, true, [1, 2]]) {
    const response = await server.handle(message);
    assert.equal(response.error?.code, -32600, `消息 ${JSON.stringify(message)} 应判 INVALID_REQUEST`);
  }
});

test('缺少 method 字段的请求返回 INVALID_REQUEST', async () => {
  const server = createMcpServer();
  const response = await server.handle({ jsonrpc: '2.0', id: 30, params: {} });
  assert.equal(response.error.code, -32600);
  assert.equal(response.id, 30);
});

test('通知一律不应答：initialize、ping、tools/list、tools/call 省略 id 时不产生响应', async () => {
  const server = createMcpServer();
  const methods = [
    { method: 'initialize', params: { protocolVersion: '2025-06-18' } },
    { method: 'ping', params: {} },
    { method: 'tools/list', params: {} },
    { method: 'tools/call', params: { name: 'audit_artifact', arguments: { path: SAMPLE_APP } } },
  ];
  for (const { method, params } of methods) {
    const response = await server.handle({ jsonrpc: '2.0', method, params });
    assert.equal(response, null, `${method} 作为通知不应应答`);
  }
});

test('带 id 的 notifications/ 方法返回 METHOD_NOT_FOUND', async () => {
  const server = createMcpServer();
  const response = await server.handle({ jsonrpc: '2.0', id: 31, method: 'notifications/initialized', params: {} });
  assert.equal(response.error.code, -32601);
});

test('id 为 null 的请求仍按请求应答', async () => {
  const server = createMcpServer();
  const response = await server.handle({ jsonrpc: '2.0', id: null, method: 'ping' });
  assert.deepEqual(response.result, {});
  assert.equal(response.id, null);
});

test('tools/call 的 arguments 不是对象时标记为错误', async () => {
  const server = createMcpServer();
  for (const arguments_ of [[], 'path', 42]) {
    const response = await server.handle({
      jsonrpc: '2.0',
      id: 32,
      method: 'tools/call',
      params: { name: 'audit_artifact', arguments: arguments_ },
    });
    assert.equal(response.result.isError, true, `arguments 为 ${JSON.stringify(arguments_)} 时应判错误`);
  }
});

test('tools/call 的 params 不是对象时标记为错误', async () => {
  const server = createMcpServer();
  const response = await server.handle({ jsonrpc: '2.0', id: 33, method: 'tools/call', params: 'oops' });
  assert.equal(response.result.isError, true);
});

test('tools/call 缺少必填参数时标记为错误并给出用法错误', async () => {
  const server = createMcpServer();
  const response = await server.handle({
    jsonrpc: '2.0',
    id: 34,
    method: 'tools/call',
    params: { name: 'audit_artifact', arguments: {} },
  });
  assert.equal(response.result.isError, true);
  const described = JSON.parse(response.result.content[0].text);
  assert.equal(described.error.exitCode, 2, '缺少目标路径是用法错误');
});

test('generate_notice 使用未知模板时标记为错误', async () => {
  const server = createMcpServer();
  const response = await server.handle({
    jsonrpc: '2.0',
    id: 35,
    method: 'tools/call',
    params: { name: 'generate_notice', arguments: { template: 'eula' } },
  });
  assert.equal(response.result.isError, true);
  const described = JSON.parse(response.result.content[0].text);
  assert.equal(described.error.exitCode, 2);
});

test('策略文件不是合法 JSON 时标记为错误', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-mcp-policy-'));
  try {
    const policyPath = join(dir, 'broken.json');
    await writeFile(policyPath, '{ 不是合法 JSON', 'utf8');
    const server = createMcpServer();
    const response = await server.handle({
      jsonrpc: '2.0',
      id: 36,
      method: 'tools/call',
      params: { name: 'audit_artifact', arguments: { path: SAMPLE_APP, policy: policyPath } },
    });
    assert.equal(response.result.isError, true);
    const described = JSON.parse(response.result.content[0].text);
    assert.equal(described.error.exitCode, 2);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// —— 部分读取与资源上限 ——

test('标准输入输出传输：一条消息拆成多段写入仍能正确应答', async () => {
  const lines = await serveWithChunks([
    '{"jsonrpc":"2.0",',
    '"id":41,"method"',
    ':"ping"}\n',
  ]);
  assert.equal(lines.length, 1);
  assert.deepEqual(JSON.parse(lines[0]), { jsonrpc: '2.0', id: 41, result: {} });
});

test('标准输入输出传输：一段数据里的多条消息与空行全部应答', async () => {
  const lines = await serveWithInput([
    '',
    '{"jsonrpc":"2.0","id":42,"method":"ping"}',
    '   ',
    '{"jsonrpc":"2.0","id":43,"method":"ping"}',
  ]);
  assert.equal(lines.length, 2);
  assert.equal(JSON.parse(lines[0]).id, 42);
  assert.equal(JSON.parse(lines[1]).id, 43);
});

test('标准输入输出传输：非法 JSON 行返回 PARSE_ERROR，后续行继续处理', async () => {
  const lines = await serveWithInput(['{oops', '{"jsonrpc":"2.0","id":44,"method":"ping"}']);
  assert.equal(lines.length, 2);
  assert.equal(JSON.parse(lines[0]).error.code, -32700);
  assert.deepEqual(JSON.parse(lines[1]).result, {});
});

test('标准输入输出传输：通知不产生响应', async () => {
  const lines = await serveWithInput([
    '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}',
    '{"jsonrpc":"2.0","method":"initialize"}',
  ]);
  assert.deepEqual(lines, []);
});

test('报表字节上限让报告文本截断并附限制说明，调用本身不算失败', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-mcp-truncate-'));
  try {
    const policyPath = join(dir, 'tiny-report.json');
    await writeFile(policyPath, JSON.stringify({ budgets: { maxReportBytes: 96 } }), 'utf8');
    const server = createMcpServer();
    const response = await server.handle({
      jsonrpc: '2.0',
      id: 45,
      method: 'tools/call',
      params: { name: 'audit_artifact', arguments: { path: SAMPLE_APP, policy: policyPath } },
    });
    assert.equal(response.result.isError, false, '产部分结果不是调用失败');
    const text = response.result.content[0].text;
    assert.ok(text.endsWith('…[报表已达到策略字节上限，内容已截断]'), `实际结尾：${text.slice(-48)}`);
    assert.ok(Buffer.byteLength(text, 'utf8') <= 96, `截断后仍应受上限约束，实际 ${Buffer.byteLength(text, 'utf8')} 字节`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('单文件字节上限让审计产部分结果并附限制说明', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-mcp-partial-'));
  try {
    const policyPath = join(dir, 'tiny-file.json');
    await writeFile(policyPath, JSON.stringify({ budgets: { maxFileBytes: 16 } }), 'utf8');
    const server = createMcpServer();
    const response = await server.handle({
      jsonrpc: '2.0',
      id: 46,
      method: 'tools/call',
      params: { name: 'audit_artifact', arguments: { path: SAMPLE_APP, policy: policyPath } },
    });
    assert.equal(response.result.isError, false);
    const report = JSON.parse(response.result.content[0].text);
    assert.equal(report.status, 'partial');
    assert.ok(report.limitations.some((limitation) => limitation.code === 'max-file-bytes-exceeded'), `实际限制说明：${JSON.stringify(report.limitations.map((l) => l.code))}`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// —— 退出码折算 ——

test('verify_artifact 对结构损坏的制品折算为 isError（退出码 1）', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-mcp-verify-'));
  try {
    // 20 字节的 ELF：魔数与 e_ident 齐备，但不足 64 位 ELF 头所需的 64 字节，容器结构不可解析。
    const elfPath = join(dir, 'truncated.elf');
    await writeFile(elfPath, Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]), Buffer.alloc(12, 0)]));
    const server = createMcpServer();
    const response = await server.handle({
      jsonrpc: '2.0',
      id: 47,
      method: 'tools/call',
      params: { name: 'verify_artifact', arguments: { path: elfPath } },
    });
    assert.equal(response.result.isError, true, '复审不通过（退出码 1）应折算为 isError');
    const report = JSON.parse(response.result.content[0].text);
    assert.equal(report.status, 'failed');
    assert.ok(report.checks.some((check) => check.family === 'container-parse' && check.status === 'failed'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('harden_artifact 缺少审计结果文件时折算为 isError（退出码 2）', async () => {
  const server = createMcpServer();
  const response = await server.handle({
    jsonrpc: '2.0',
    id: 48,
    method: 'tools/call',
    params: { name: 'harden_artifact', arguments: { path: SAMPLE_APP } },
  });
  assert.equal(response.result.isError, true);
  const described = JSON.parse(response.result.content[0].text);
  assert.equal(described.error.exitCode, 2);
});

// —— 传输辅助 ——

/**
 * 在注入的流上运行服务：按行写完全部输入后关闭标准输入，返回全部输出行。
 * @param {readonly string[]} lines 输入行，不含换行符
 * @returns {Promise<string[]>} 输出行，不含换行符
 */
async function serveWithInput(lines) {
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const chunks = [];
  stdout.on('data', (chunk) => {
    chunks.push(String(chunk));
  });
  const done = serveOverStdio({ stdin, stdout });
  for (const line of lines) {
    stdin.write(`${line}\n`);
  }
  stdin.end();
  await done;
  return chunks.join('').split('\n').filter((line) => line !== '');
}

/**
 * 在注入的流上运行服务：按数据段写入，段与段之间让出事件循环，模拟一条消息被拆成多段送达。
 * @param {readonly string[]} chunks 数据段，可含部分行
 * @returns {Promise<string[]>} 输出行，不含换行符
 */
async function serveWithChunks(chunks) {
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const out = [];
  stdout.on('data', (chunk) => {
    out.push(String(chunk));
  });
  const done = serveOverStdio({ stdin, stdout });
  for (const chunk of chunks) {
    stdin.write(chunk);
    await new Promise((resolvePromise) => {
      setImmediate(resolvePromise);
    });
  }
  stdin.end();
  await done;
  return out.join('').split('\n').filter((line) => line !== '');
}
