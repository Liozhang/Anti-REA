# templates/

反运行时观察集成包的模板目录。

## 用途

`src/probe-kit` 生成的运行期自检代码片段与人工检查清单统一放在这里。
模板文件在 `templates/probe-kit/` 下，由 `buildProbeKit` 读取、替换占位符后写进调用方给出的输出目录。

模板清单：

| 模板 | 产出 | 内容 |
| --- | --- | --- |
| `probe-kit/runtime-probe.template.mjs` | `runtime-probe.mjs` | 运行期自检代码片段（Node.js ESM 目标，零依赖） |
| `probe-kit/manual-checklist.template.md` | `manual-checklist.md` | 人工检查清单 |
| `probe-kit/integration-notes.template.md` | `INTEGRATION.md` | 集成方式说明：接入步骤、响应模式、例外清单与限制说明 |

每个模板的首行与末行各有一条完整性标记（`anti-rea-probe-template` 与
`anti-rea-probe-template-end`）。生成时逐份校验：缺起始标记或结束标记即判定模板不完整，
拒绝生成，不写半个集成包。标记行不进入产出文件。

## 边界

- 生成的内容是可嵌入的检测代码与检查清单，默认只输出集成包，不自动改动制品。
- 默认响应是记录并继续；是否拒绝由策略显式开启，并配例外清单与多迹象联合判定。
- 不得生成任何伪装成系统或操作者指令的文本，也不得试图覆盖分析代理的既有规则。
- 本目录在静态依赖检查范围之外：检查只扫 `src/` 与 `bin/` 下的 `.mjs`、`.js`、`.cjs` 文件，
  因此模板里出现 `import` 行不会被判为引入第三方依赖。
