// 包版本号的单一来源。
// 命令行 --version 与 MCP 服务标识此前各取一次：命令行每次读 package.json，
// MCP 把版本号硬编码在工具定义里。两处漂移时没有任何测试拦截，服务会报出
// 与命令行不同的版本。这里统一到 package.json，读取失败时回落，不让版本号
// 搞垮启动。

import { readFileSync } from 'node:fs';

/**
 * 读取 package.json 的版本号。读取或解析失败时回落 '0.0.0'：
 * 版本号取不到不该让整个工具不可用。
 * @returns {string} 版本号
 */
function readPackageVersion() {
  try {
    const text = readFileSync(new URL('../package.json', import.meta.url), 'utf8');
    return JSON.parse(text).version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

/** 包版本号，供命令行与 MCP 服务标识共用。 */
export const PACKAGE_VERSION = readPackageVersion();
