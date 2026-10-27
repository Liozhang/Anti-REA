#!/usr/bin/env node
// Anti-REA MCP 服务入口：标准输入输出传输。
// 注册方式见仓库根 README.md 与 docs/readme/README_zh.md。

import { serveOverStdio } from '../src/mcp/server.mjs';

await serveOverStdio();
