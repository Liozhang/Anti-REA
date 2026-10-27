// MCP 服务层：标准输入输出传输的 JSON-RPC 2.0 服务。
// 实现 initialize、tools/list、tools/call 三个方法，另接受 ping 与 notifications/initialized。
// 服务层只负责协议与错误折算，五个工具与命令行共用同一套工作流代码。

import { createInterface } from 'node:readline';

import { describeError } from '../errors.mjs';
import { handleToolCall } from './handlers.mjs';
import { latestProtocolVersion, MCP_PROTOCOL_VERSIONS, SERVER_INFO, toolList } from './tools.mjs';

/** JSON-RPC 错误码。 */
export const JSON_RPC_ERRORS = Object.freeze({
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
});

/**
 * 创建 MCP 服务实例。服务与传输解耦，测试可在进程内直接驱动。
 * @returns {{handle: Function, protocolVersion: string, serverInfo: object}}
 */
export function createMcpServer() {
  /**
   * 处理一条 JSON-RPC 消息。
   * 通知（客户端省略 id）一律不应答：JSON-RPC 2.0 与 MCP 协议都要求通知不产生响应，
   * 对 initialize 这类方法应答出一个没有 id 字段的对象反而是畸形响应。
   * @param {unknown} message 解析后的消息
   * @returns {Promise<Record<string, unknown> | null>} 响应；通知返回 null
   */
  async function handle(message) {
    if (message === null || typeof message !== 'object' || Array.isArray(message)) {
      return errorResponse(undefined, JSON_RPC_ERRORS.INVALID_REQUEST, '请求必须是 JSON-RPC 对象');
    }
    const request = message;
    const id = request.id;
    const isNotification = id === undefined;
    const method = typeof request.method === 'string' ? request.method : '';

    if (isNotification) {
      return null;
    }

    if (method === '') {
      return errorResponse(id, JSON_RPC_ERRORS.INVALID_REQUEST, '缺少 method 字段');
    }

    switch (method) {
      case 'initialize':
        return result(id, initializeResult(request.params));
      case 'ping':
        return result(id, {});
      case 'tools/list':
        return result(id, { tools: toolList() });
      case 'tools/call':
        return result(id, await handleToolCall(request.params));
      default:
        // 走到这里的一定是带 id 的请求：通知已在上面统一返回 null。
        // 未知方法一律应答 METHOD_NOT_FOUND，包括名字以 notifications/ 开头却带了 id 的畸形请求——
        // 对带 id 的请求保持沉默会让客户端一直等待响应。
        return errorResponse(id, JSON_RPC_ERRORS.METHOD_NOT_FOUND, `不支持的方法：${method}`);
    }
  }

  /**
   * 构造 initialize 结果。客户端请求的协议版本在支持列表内时原样回应该版本。
   * @param {Record<string, unknown> | undefined} params 请求参数
   * @returns {Record<string, unknown>}
   */
  function initializeResult(params) {
    const requested = typeof params?.protocolVersion === 'string' ? params.protocolVersion : undefined;
    const protocolVersion = requested !== undefined && MCP_PROTOCOL_VERSIONS.includes(requested) ? requested : latestProtocolVersion();
    return {
      protocolVersion,
      capabilities: { tools: { listChanged: false } },
      serverInfo: SERVER_INFO,
    };
  }

  return { handle, serverInfo: SERVER_INFO };
}

/**
 * 构造成功响应。
 * @param {unknown} id 请求标识
 * @param {unknown} result 结果
 * @returns {Record<string, unknown>}
 */
function result(id, value) {
  return { jsonrpc: '2.0', id, result: value };
}

/**
 * 构造错误响应。
 * @param {unknown} id 请求标识
 * @param {number} code 错误码
 * @param {string} message 错误说明
 * @returns {Record<string, unknown>}
 */
function errorResponse(id, code, message) {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

/**
 * 在标准输入输出上运行服务，直到标准输入关闭。
 * @param {{stdin?: NodeJS.ReadableStream, stdout?: NodeJS.WritableStream}} [io] 传输注入，便于测试
 * @returns {Promise<void>}
 */
export async function serveOverStdio(io = {}) {
  const stdin = io.stdin ?? process.stdin;
  const stdout = io.stdout ?? process.stdout;
  const server = createMcpServer();
  const readline = createInterface({ input: stdin, terminal: false });

  for await (const line of readline) {
    const trimmed = line.trim();
    if (trimmed === '') {
      continue;
    }
    let message;
    try {
      message = JSON.parse(trimmed);
    } catch {
      stdout.write(`${JSON.stringify(errorResponse(undefined, JSON_RPC_ERRORS.PARSE_ERROR, '请求不是合法 JSON'))}\n`);
      continue;
    }
    let response;
    try {
      response = await server.handle(message);
    } catch (error) {
      const described = describeError(error);
      response = errorResponse(message?.id, JSON_RPC_ERRORS.INTERNAL_ERROR, described.message);
    }
    if (response !== null) {
      stdout.write(`${JSON.stringify(response)}\n`);
    }
  }
}
