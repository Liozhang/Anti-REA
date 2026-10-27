#!/usr/bin/env node
// Anti-REA 命令行入口。
// 接口以仓库根 README.md 与 docs/readme/README_zh.md 为准，两份文档与实现必须逐字一致。

import { runCli } from '../src/cli/index.mjs';

// 使用 process.exitCode 而非 process.exit，让标准输出先冲刷完再退出。
process.exitCode = await runCli(process.argv.slice(2));
