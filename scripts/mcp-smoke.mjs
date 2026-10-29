#!/usr/bin/env node
// MCP 冒烟验证：以子进程方式启动 MCP 服务，跑通最小可用路径。
// 步骤：initialize 握手 -> notifications/initialized -> tools/list -> 调用一次 audit_artifact。
// 全部成功时退出码为 0；任一步失败时向标准错误输出原因并退出码 1。
//
// 用法：node scripts/mcp-smoke.mjs

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '..');
const SERVER_ENTRY = resolve(REPO_ROOT, 'bin', 'anti-rea-mcp.js');
// 自检目标：仓库检出优先用测试夹具；安装副本没有 tests/ 目录（files 字段不含它），
// 退到随包发布的探针模板。两种布局下冒烟都必须跑通，否则发布出去的包装着跑不了的自检。
const REPO_SAMPLE_APP = resolve(REPO_ROOT, 'tests', 'fixtures', 'sample-app');
const PACKAGED_SAMPLE = resolve(REPO_ROOT, 'templates', 'probe-kit', 'runtime-probe.template.mjs');
const SAMPLE_APP = existsSync(REPO_SAMPLE_APP) ? REPO_SAMPLE_APP : PACKAGED_SAMPLE;

/** 期望见到的工具名，五个工具一个都不能少。 */
const EXPECTED_TOOLS = Object.freeze([
  'audit_artifact',
  'harden_artifact',
  'verify_artifact',
  'generate_notice',
  'generate_probe_kit',
]);

/** 单步等待上限，毫秒。 */
const STEP_TIMEOUT_MS = 20000;

/** 整体超时，毫秒。 */
const TOTAL_TIMEOUT_MS = 60000;

/**
 * 主流程。
 * @returns {Promise<number>} 退出码
 */
async function main() {
  const child = spawn(process.execPath, [SERVER_ENTRY], {
    cwd: REPO_ROOT,
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  let stderrText = '';
  child.stderr.on('data', (chunk) => {
    stderrText += String(chunk);
  });

  const pending = new Map();
  let buffer = '';
  child.stdout.on('data', (chunk) => {
    buffer += String(chunk);
    let newline = buffer.indexOf('\n');
    while (newline !== -1) {
      const line = buffer.slice(0, newline).trim();
      buffer = buffer.slice(newline + 1);
      if (line !== '') {
        dispatch(line);
      }
      newline = buffer.indexOf('\n');
    }
  });

  /**
   * 把一行输出分派给等待中的请求。
   * @param {string} line 一行 JSON-RPC 消息
   */
  function dispatch(line) {
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      return;
    }
    const waiter = pending.get(message.id);
    if (waiter !== undefined) {
      pending.delete(message.id);
      waiter(message);
    }
  }

  /**
   * 发送请求并等待响应。
   * @param {string} method 方法名
   * @param {Record<string, unknown>} params 参数
   * @returns {Promise<Record<string, unknown>>} 响应对象
   */
  function request(method, params) {
    const id = pending.size + 1;
    const payload = JSON.stringify({ jsonrpc: '2.0', id, method, params });
    return new Promise((resolvePromise, rejectPromise) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        rejectPromise(new Error(`等待 ${method} 响应超时`));
      }, STEP_TIMEOUT_MS);
      pending.set(id, (message) => {
        clearTimeout(timer);
        resolvePromise(message);
      });
      child.stdin.write(`${payload}\n`);
    });
  }

  /**
   * 发送通知，不等待响应。
   * @param {string} method 方法名
   * @param {Record<string, unknown>} params 参数
   */
  function notify(method, params) {
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method, params })}\n`);
  }

  /**
   * 断言一条请求拿到了成功结果。
   * @param {string} step 步骤名
   * @param {Record<string, unknown>} response 响应
   * @returns {Record<string, unknown>} result 字段
   */
  function expectOk(step, response) {
    if (response.error !== undefined) {
      throw new Error(`${step} 返回错误：${JSON.stringify(response.error)}`);
    }
    if (response.result === undefined) {
      throw new Error(`${step} 没有返回 result 字段`);
    }
    return response.result;
  }

  try {
    const init = expectOk(
      'initialize',
      await request('initialize', {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'anti-rea-mcp-smoke', version: '0.1.1' },
      }),
    );
    assert(typeof init.protocolVersion === 'string' && init.protocolVersion !== '', 'initialize 未返回 protocolVersion');
    assert(init.serverInfo?.name === 'anti-rea', `initialize 返回的 serverInfo.name 不是 anti-rea：${JSON.stringify(init.serverInfo)}`);
    process.stdout.write(`握手成功：协议版本 ${init.protocolVersion}，服务 ${init.serverInfo.name} ${init.serverInfo.version}\n`);

    notify('notifications/initialized', {});

    const list = expectOk('tools/list', await request('tools/list', {}));
    const names = (list.tools ?? []).map((tool) => tool.name);
    for (const expected of EXPECTED_TOOLS) {
      assert(names.includes(expected), `tools/list 缺少工具 ${expected}，实际返回 ${JSON.stringify(names)}`);
    }
    process.stdout.write(`工具清单完整：${names.join('、')}\n`);

    const call = expectOk(
      'tools/call audit_artifact',
      await request('tools/call', {
        name: 'audit_artifact',
        arguments: { path: SAMPLE_APP },
      }),
    );
    assert(call.isError !== true, `audit_artifact 调用失败：${JSON.stringify(call)}`);
    const text = (call.content ?? []).find((item) => item.type === 'text')?.text;
    assert(typeof text === 'string' && text !== '', 'audit_artifact 没有返回文本内容');
    const report = JSON.parse(text);
    assert(report.tool === 'audit_artifact', `audit_artifact 返回的报告 tool 字段异常：${report.tool}`);
    assert(report.artifact?.sha256 !== undefined, 'audit_artifact 返回的报告缺少制品摘要');
    assert(Array.isArray(report.capabilityBoundaries), 'audit_artifact 返回的报告缺少能力边界条目');
    process.stdout.write(`审计调用成功：制品 ${report.artifact.sha256.slice(0, 16)}…，能力边界 ${report.capabilityBoundaries.length} 项\n`);

    process.stdout.write('MCP 冒烟验证通过\n');
    return 0;
  } catch (error) {
    process.stderr.write(`MCP 冒烟验证失败：${error instanceof Error ? error.message : String(error)}\n`);
    if (stderrText.trim() !== '') {
      process.stderr.write(`服务标准错误输出：\n${stderrText}`);
    }
    return 1;
  } finally {
    child.stdin.end();
    child.kill();
  }
}

/**
 * 断言辅助。
 * @param {boolean} condition 条件
 * @param {string} message 失败说明
 */
function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

const timer = setTimeout(() => {
  process.stderr.write(`MCP 冒烟验证超过整体超时 ${TOTAL_TIMEOUT_MS} 毫秒\n`);
  process.exit(1);
}, TOTAL_TIMEOUT_MS);

process.exitCode = await main();
clearTimeout(timer);
