#!/usr/bin/env node
// Anti-REA 命令行入口的别名。
// 仓库根 README.md 与 docs/readme/README_zh.md 记载的入口是 bin/anti-rea.js；
// 设计文档的验收条目写作 bin/antirea.mjs。这里提供一个等价的别名，两条路径行为完全一致。

import { runCli } from '../src/cli/index.mjs';

process.exitCode = await runCli(process.argv.slice(2));
