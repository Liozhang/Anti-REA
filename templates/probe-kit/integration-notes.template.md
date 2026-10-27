<!-- anti-rea-probe-template: integration-notes v1 -->
# 集成方式说明

本集成包只输出可嵌入的检测代码片段与人工检查清单，不自动改动制品本身。
是否把检测接入你们的软件、接在哪里，由你们决定。

产物文件：

{{FILE_LIST}}

## 接入步骤

1. 把 `runtime-probe.mjs` 放进你们的项目（Node.js 22 及以上的 ESM 模块，零依赖）。
2. 在进程入口处 `import { createRuntimeProbe } from './runtime-probe.mjs';`，
   先 `const probe = createRuntimeProbe();`，再调用 `probe.check();`。
   `check()` 的返回值是本次判定结果，默认只记录在内存里，用 `probe.records()` 读取。
3. 需要上报时传 `onObservation` 回调；需要拒绝时传 `onRefuse` 回调。
4. 按 `manual-checklist.md` 逐项人工核对，把结论写进运营留痕。

## 响应模式

当前响应模式：{{RESPONSE_MODE}}（拒绝开关：{{REFUSAL_ENABLED_TEXT}}）

- `report-only`：只记录与上报，然后继续运行。这是默认模式。
- `report-and-refuse`：多迹象联合判定命中后拒绝继续。该模式必须由策略显式开启，
  判定阈值默认为 {{SIGNAL_THRESHOLD}} 个独立迹象；单项迹象从不触发拒绝。

## 例外清单

当前例外：{{EXCEPTIONS_TEXT}}

这些环境变量名或会话标记存在时，对应的检查项被抑制，避免持续集成与远程执行场景误伤。
用户自填的例外默认抑制 `env-write-marker` 与 `pseudo-terminal-signs` 两项，
需要更细的抑制范围请直接改生成代码里的 `EXCEPTION_SUPPRESSES`。

## 拒绝动作的实现约束

- 默认拒绝动作是抛出可捕获的 `ProbeRefusalError`：不是崩溃，不清数据，更不是静默失败。
- 请用 `onRefuse` 接入你们自己的处理路径（提示、退出、降级），不要改成删除数据或无提示退出。

## 限制说明

- 当前版本只生成 Node.js（ESM）目标的检测代码片段，其他语言需按同一判定逻辑移植。
- 检测只提高成本，不能阻止有准备的分析者改写探针。
- Chromium 系进程会覆盖初始环境内存，环境变量归属无法验证。
- Windows 对环境变量名做大小写折叠，例外匹配已按平台折叠比较。
- 伪终端迹象在持续集成与远程执行场景下本身就会误报，只能靠联合判定与例外清单缓解。
- `traced-state` 只在 Linux 可检查；`inspector-port` 只覆盖启动时挂接的检查器。
- 自检代码本身成为新的可分析面，不要在生成的代码里写入任何秘密。
<!-- anti-rea-probe-template-end: integration-notes -->
