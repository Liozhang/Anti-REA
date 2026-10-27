<!-- anti-rea-probe-template: manual-checklist v1 -->
# 人工检查清单（反运行时观察层）

本清单是运行期自检代码的人工补充。自动检查覆盖不到的部分由这里列出，
逐项确认后请把结论记录到你们的运营留痕里。

当前响应模式：{{RESPONSE_MODE}}
当前例外清单：{{EXCEPTIONS_TEXT}}

## 按检查项的人工核对

{{CHECK_ITEMS}}

## 与自动检查无关的人工项

{{MANUAL_ITEMS}}

## 限制说明

- 当前版本只生成 Node.js（ESM）目标的检测代码片段，其他语言需按同一判定逻辑移植。
- 检测只提高成本，不能阻止有准备的分析者改写探针。
- Chromium 系进程会覆盖初始环境内存，环境变量归属无法验证。
- Windows 对环境变量名做大小写折叠，例外匹配已按平台折叠比较。
- 伪终端迹象在持续集成与远程执行场景下本身就会误报，只能靠联合判定与例外清单缓解。
- `traced-state` 只在 Linux 可检查 `/proc/self/status` 的 `TracerPid`；`inspector-port` 只覆盖启动时挂接的检查器。
- 自检代码本身成为新的可分析面，不要在生成的代码里写入任何秘密。
<!-- anti-rea-probe-template-end: manual-checklist -->
