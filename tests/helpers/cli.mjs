// 测试辅助：定位仓库根、运行命令行子进程、汇总输出。

import { execFile } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));

/** 仓库根目录。 */
export const REPO_ROOT = resolve(HERE, '..', '..');

/** 命令行入口。 */
export const CLI_ENTRY = resolve(REPO_ROOT, 'bin', 'anti-rea.js');

/** MCP 服务入口。 */
export const MCP_ENTRY = resolve(REPO_ROOT, 'bin', 'anti-rea-mcp.js');

/** 端到端夹具目录。 */
export const SAMPLE_APP = resolve(REPO_ROOT, 'tests', 'fixtures', 'sample-app');

/**
 * 运行命令行，收集退出码与输出。
 * @param {readonly string[]} args 命令行参数
 * @returns {Promise<{code: number, stdout: string, stderr: string}>}
 */
export function runCli(args) {
  return new Promise((resolvePromise, rejectPromise) => {
    execFile(
      process.execPath,
      [CLI_ENTRY, ...args],
      { cwd: REPO_ROOT, maxBuffer: 32 * 1024 * 1024 },
      (error, stdout, stderr) => {
        if (error !== null && error.code === undefined) {
          rejectPromise(error);
          return;
        }
        resolvePromise({ code: error?.code ?? 0, stdout, stderr });
      },
    );
  });
}

/**
 * 运行仓库内任意脚本。
 * @param {readonly string[]} args 命令行参数
 * @returns {Promise<{code: number, stdout: string, stderr: string}>}
 */
export function runNode(args) {
  return new Promise((resolvePromise, rejectPromise) => {
    execFile(process.execPath, args, { cwd: REPO_ROOT, maxBuffer: 32 * 1024 * 1024 }, (error, stdout, stderr) => {
      if (error !== null && error.code === undefined) {
        rejectPromise(error);
        return;
      }
      resolvePromise({ code: error?.code ?? 0, stdout, stderr });
    });
  });
}
