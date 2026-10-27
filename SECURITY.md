# Security Policy

# 安全政策

## Scope / 报告范围

Anti-REA is a defensive tool. It reads artifacts you point it at, writes `.hardened`
copies beside them, and never runs the target. Reports are welcome for
vulnerabilities in Anti-REA itself:

Anti-REA 是防御性工具。它读取你指定的制品，在旁写出 `.hardened` 副本，从不运行目标。欢迎报告 Anti-REA 自身的安全漏洞：

- **Unsafe file handling.** Path traversal, overwriting the original artifact
  instead of writing a copy, or following symlinks when reading a directory.
  **不安全的文件处理。** 路径穿越、覆写原件而非写出副本、读取目录时跟随符号链接。
- **Unbounded resource use.** A malformed artifact that causes unbounded
  allocation, an infinite loop, or a crash with a stack trace instead of a skipped
  entry with a stated reason.
  **无界资源使用。** 畸形制品导致无界分配、死循环，或抛出栈轨迹而不是"跳过并附原因"。
- **MCP server defects.** Protocol handling, tool argument validation, or output
  that leaks paths or bytes the report contract says it should redact.
  **MCP 服务缺陷。** 协议处理、工具参数校验，或输出泄露了报告契约承诺脱敏的路径与字节。
- **Supply chain.** The project has zero runtime dependencies; a proposed
  dependency is a design change and is reviewed as one.
  **供应链。** 本项目零运行时依赖；新增依赖属于设计变更，按设计变更审查。

## Out of scope / 不在范围内

- Documented design limits. The README's Known limits section states what this
  tool does not do; those limits are not vulnerabilities.
  **文档写明的设计边界。** README"已知限制"一节写明了本工具不做什么；那些边界不是漏洞。
- Audit false negatives. A format or credential family the readers do not cover
  yet is a coverage gap and belongs in a regular issue.
  **审计漏报。** 读取器尚未覆盖的格式或凭据家族属于覆盖缺口，请开普通 issue。
- "It does not stop a determined reverse engineer." That is the stated design
  position, not a defect.
  **"它拦不住下定决心的逆向者"。** 这是写明的设计立场，不是缺陷。

## How to report / 报告方式

Use GitHub private vulnerability reporting on this repository
(**Security → Report a vulnerability**). Do not open a public issue for a
vulnerability in Anti-REA itself.

请使用本仓库的 GitHub 私密漏洞报告功能（**Security → Report a vulnerability**）。Anti-REA 自身的安全漏洞不要开公开 issue。

Include the Anti-REA commit, your Node version and host, the artifact that triggers
the problem, and the command you ran. Do not attach a real user artifact; a minimal
reproduction is enough.

请附上 Anti-REA 的提交号、Node 版本与主机、触发问题的制品，以及你执行的命令。不要附带真实的用户制品，给出最小复现即可。

## Response / 响应

Acknowledgement within 7 days, an assessment within 30 days, and a fix or a
documented decision before the next release. You will be credited in the release
notes unless you prefer otherwise.

7 天内确认收到，30 天内给出评估，在下一次发布前修复或给出书面结论。除非你另有要求，修复会记入发布说明并署名。
