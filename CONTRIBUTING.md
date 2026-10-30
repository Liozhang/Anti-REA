# Contributing to Anti-REA

# 参与 Anti-REA 开发

Issues and pull requests are welcome. This document covers development setup, the
checks that gate a change, and the conventions the test suite enforces.

欢迎提交 issue 与 pull request。本文说明开发环境、改动前必须通过的检查，以及测试套件强制守住的约定。

## Development setup / 开发环境

Anti-REA is zero-dependency Node.js. There is nothing to install and no build step:

Anti-REA 是零依赖的 Node.js 项目，没有需要安装的依赖，也没有构建步骤：

```bash
node --version          # 要求 22 或更高
node --test             # 运行全部测试
node scripts/mcp-smoke.mjs
node tests/fixtures/build.mjs --check
```

Every check must pass before a change is ready. The suite currently stands at 560
tests, all passing, plus the MCP smoke handshake and the fixture digest check.

上述检查全部通过，一项改动才算就绪。当前套件 566 项测试全部通过，外加 MCP 冒烟握手与夹具摘要核对。

## Checks that gate a change / 改动门禁

| Check | Command | What it protects |
| --- | --- | --- |
| Full test suite | `node --test` | Behaviour contracts of every module |
| MCP smoke | `node scripts/mcp-smoke.mjs` | The stdio handshake and the five-tool surface |
| Fixture registration | `node tests/fixtures/build.mjs --check` | Committed fixtures still match their pinned digests |
| Probe subcommand | `node bin/anti-rea.js probe <dir>` | The generated integration package still builds |

| 检查 | 命令 | 保护什么 |
| --- | --- | --- |
| 完整测试套件 | `node --test` | 每个模块的行为契约 |
| MCP 冒烟 | `node scripts/mcp-smoke.mjs` | stdio 握手与五个工具的表面 |
| 夹具登记 | `node tests/fixtures/build.mjs --check` | 已提交夹具与登记的摘要仍然一致 |
| 探针子命令 | `node bin/anti-rea.js probe <目录>` | 生成的集成包仍能构建 |

## Conventions the suite enforces / 测试套件守住的约定

- **Zero runtime dependencies.** Only Node.js built-in modules. A new dependency is
  a design change, not an implementation detail.
  **零运行时依赖。** 只使用 Node.js 内置模块。新增依赖属于设计变更，不是实现细节。
- **Closed vocabularies.** Layer identifiers, tool identifiers, mitigation
  identifiers and severities live in `src/audit/layer-defs.mjs` and
  `src/audit/finding.mjs`. A value outside the vocabulary fails at construction
  time, not at report time. Register new values there.
  **封闭词表。** 层标识、工具标识、缓解措施编号与严重度集中在 `src/audit/layer-defs.mjs` 与 `src/audit/finding.mjs`。词表外的取值在构造时就会失败，而不是等到出报告。新取值在那里登记。
- **Every finding carries evidence.** A finding without an evidence range, the
  reader that would consume it, and a stated reader limitation is rejected.
  **每条发现都带证据。** 没有证据范围、没有会消费它的读取器、没有读取器限制说明的发现会被拒绝。
- **Skipped means explained.** A mitigation that cannot be applied is reported as
  skipped with its reason. Silent skips are treated as defects.
  **跳过必须说明。** 无法施加的措施以"跳过并附原因"报告。静默跳过视为缺陷。
- **Deterministic tests.** No randomness, no wall-clock reads, no network. Fixtures
  are constructed byte by byte and pinned by digest in
  `tests/fixtures/manifest.json`; regenerate them with
  `tests/fixtures/build.mjs` and commit the manifest together with the bytes.
  **确定性测试。** 不用随机数、不读时钟、不联网。夹具逐字节构造，摘要登记在 `tests/fixtures/manifest.json`；用 `tests/fixtures/build.mjs` 重新生成，字节与清单一起提交。
- **Do not weaken assertions to improve a baseline.** A failing test is either a
  defect to fix or a contract to change deliberately, with the reason stated in the
  commit message.
  **不得为了让基线好看而弱化断言。** 失败的测试要么是要修的缺陷，要么是要显式变更的契约，原因写进提交信息。
- **Language.** Source comments and commit messages are written in Chinese. The
  README defaults to English with translations under `docs/readme/`; keep the two in
  sync when a section changes.
  **语言。** 源码注释与提交信息用中文。README 默认英文，翻译放在 `docs/readme/`；章节有变动时两者同步更新。

## Reporting a bug / 报告缺陷

Open an issue with your Node version, the target type, the exact command you ran,
and the output. If the report concerns a security vulnerability in Anti-REA itself,
follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

开 issue 时请附上 Node 版本、目标类型、你执行的确切命令和输出。如果问题涉及 Anti-REA 自身的安全漏洞，请按 [SECURITY.md](SECURITY.md) 的方式处理，不要开公开 issue。
