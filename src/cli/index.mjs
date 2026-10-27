// 命令行入口：子命令分发与统一退出码表。
// 本文件只做分发与错误折算，工作流在 workflows.mjs 与 src/ 各模块中，MCP 服务层共用。

import { readFile } from 'node:fs/promises';

import { AntireaError, RefusalError, describeError } from '../errors.mjs';
import { EXIT_CODES, EXIT_CODE_LABELS } from './exit-codes.mjs';
import { parseArgs } from './args.mjs';
import { commandAudit, commandHarden, commandNotice, commandProbe, commandVerify } from './commands.mjs';
import { buildRefusalReport, createTreeWarner } from './workflows.mjs';
import { USAGE } from './usage.mjs';

/** 子命令到工作流的映射。 */
const COMMANDS = Object.freeze({
  audit: commandAudit,
  harden: commandHarden,
  verify: commandVerify,
  notice: commandNotice,
  probe: commandProbe,
});

/**
 * 读取包版本，用于 --version。
 * @returns {Promise<string>}
 */
async function readVersion() {
  try {
    const url = new URL('../../package.json', import.meta.url);
    const text = await readFile(url, 'utf8');
    return JSON.parse(text).version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

/**
 * 运行命令行。
 * @param {readonly string[]} argv 进程参数，不含 node 与脚本路径
 * @param {{write?: Function, writeError?: Function}} [io] 输出注入，便于测试
 * @returns {Promise<number>} 退出码
 */
export async function runCli(argv, io = {}) {
  const out = io.write ?? ((text) => process.stdout.write(text));
  const err = io.writeError ?? ((text) => process.stderr.write(text));
  const warnTree = createTreeWarner((message) => err(`${message}\n`));
  const context = { io: { write: out, writeError: err }, warnTree };

  const parsed = parseArgs(argv);
  if (!parsed.ok) {
    err(`${parsed.errors.join('\n')}\n\n${USAGE}`);
    return EXIT_CODES.USAGE_ERROR;
  }
  if (parsed.help) {
    out(USAGE);
    return EXIT_CODES.SUCCESS;
  }
  if (parsed.version) {
    out(`anti-rea ${await readVersion()}\n`);
    return EXIT_CODES.SUCCESS;
  }

  const command = COMMANDS[parsed.subcommand];
  if (command === undefined) {
    err(`未知子命令：${parsed.subcommand || '（未提供）'}\n\n${USAGE}`);
    return EXIT_CODES.USAGE_ERROR;
  }
  try {
    return await command({
      ...context,
      target: parsed.positionals[0] ?? '',
      options: parsed.options,
    });
  } catch (error) {
    if (error instanceof RefusalError) {
      const report = buildRefusalReport({ tool: parsed.subcommand, omitted_reason: error.omittedReason });
      out(`${JSON.stringify(report, null, 2)}\n`);
      err(`${error.message}\n`);
      return EXIT_CODES.REFUSAL;
    }
    const described = describeError(error);
    err(`错误（${EXIT_CODE_LABELS[described.exitCode] ?? described.exitCode}）：${described.message}\n`);
    if (!(error instanceof AntireaError) && error instanceof Error && error.stack !== undefined) {
      err(`${error.stack}\n`);
    }
    return described.exitCode;
  }
}
