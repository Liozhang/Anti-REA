<div align="center">

# Anti-REA

### 面向用户自己项目的反逆向 MCP 服务

**审计出厂制品暴露了什么。应用缓解措施。验证结果。**

[![许可证：MIT](https://img.shields.io/badge/license-MIT-f4c430.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22-339933.svg)](https://nodejs.org)
[![MCP](https://img.shields.io/badge/MCP-stdio-5c4ee5.svg)](#接入你的代理)
[![测试](https://img.shields.io/badge/tests-node--test-5c4ee5.svg)](#验证方式)

[English](README.md) · **简体中文**

零运行时依赖的 Node.js 工具，全部分析在本地完成。

</div>

---

REA（Reverse Engineer Anything，逆向一切）及同类工具链，能让一个人工智能代理在看不到源码的情况下检查出厂的可执行文件、软件包或应用程序。代理可以解释某个功能的工作原理，并仿制出一个版本。这把理解你发行的软件所需的成本压到了接近零。

Anti-REA 是防御方的对应物。它是一个 MCP 服务，附带一套共用同样工作流的命令行接口，在**你自己的项目**出厂之前做加固：

- **audit_artifact（制品审计）**：查明出厂制品向上述工具使用的读取器和引擎暴露了哪些事实。每条事实附带证据，以及它在文件中的范围。
- **harden_artifact（制品加固）**：应用本工具能够应用的缓解措施。需要外部工具或架构调整的措施，它会明确报告出来。
- **verify_artifact（加固验证）**：确认缓解措施确实生效。
- **generate_notice（声明生成）**：为你的制品自带的 README 生成真实的法律声明与禁止逆向文本。这样，调查中的代理在核对授权的那一刻，会以数据的形式遇到你的条款。

请只将其用于你拥有或获授权保护的软件。

> 本项目正在积极开发中。下文描述的接口是测试套件强制守住的契约。

## 接入你的代理

用任意支持 MCP 的代理（Claude Code、Cursor、Codex 等）注册本服务：

```json
{
  "mcpServers": {
    "anti-rea": {
      "command": "node",
      "args": ["/absolute/path/to/Anti-REA/bin/anti-rea-mcp.js"]
    }
  }
}
```

然后对你的代理说：审计 /path/to/app 这个应用，告诉我它暴露了什么。

## 终端快速开始

```bash
node bin/anti-rea.js audit /absolute/path/to/your/app --json
node bin/anti-rea.js harden /absolute/path/to/your/app --from audit.json
node bin/anti-rea.js verify /absolute/path/to/your/app
node bin/anti-rea.js notice --template license > NOTICE.md
node bin/anti-rea.js probe /absolute/path/to/probe-kit-output
```

`probe` 命令生成反运行时观察层的集成包：面向可观测事实的检测代码片段，外加一份人工检查清单。它只写你指定的目录，不改动你的制品。代理侧用 `generate_probe_kit` 工具拿到同一份集成包。

## 审计会发现什么

| 暴露面 | 谁会读它 | 审计报告什么 |
| --- | --- | --- |
| ELF/PE/Mach-O 头部、节、符号表、构建标识 | 内置静态读取器、objdump | 读取器能提取的每条事实及其在文件中的范围 |
| 内嵌的 Go 模块与构建信息 | 内置 Go 读取器 | 是否存在、版本号以及承载它的节 |
| 内嵌的 Rust 依赖元数据（`.dep-v0`） | 内置 Rust 读取器 | crate 名称、版本与依赖边 |
| Unity IL2CPP 元数据 | 内置 IL2CPP 读取器 | 可恢复的类型名与方法名 |
| .NET 元数据与中间语言指令 | 内置托管代码读取器 | 程序集事实与成员清单 |
| JavaScript 源码地图与模块图 | 内置 JavaScript 读取器 | 可恢复的原始源码 |
| PE 证书、导入表、导出表、加载配置 | 内置 PE 读取器 | 签名者身份与声明的导入 |
| 模型文件、SQLite、Erlang、pyc 等容器元数据 | 内置格式读取器 | 声明的元数据与统计 |

每一条发现都附带证据、会消费它的读取器，以及消除它的缓解措施。

## 保护你的审计输出

审计报告是你这份制品的暴露面地图，连同已应用的缓解措施。把它提交进版本库，或随制品一起发行，等于把这份地图递给每一个读仓库的人。当输出路径位于 git 工作树内时，Anti-REA 会向标准错误输出警告。报告需要分享给合作方、审计机构或漏洞披露程序时，请使用 `--redacted`：它保留分类与计数，隐去精确路径、字节范围与缓解措施的对应关系。生成的声明不包含对 Anti-REA 的引用，也不透露你的加固状态。

## 七层防御

| 防御层 | 工具 | 预期效果 | 残余风险 |
| --- | --- | --- | --- |
| 元数据卫生 | `audit_artifact`、`harden_artifact` | 内置读取器返回未知而非事实 | 新读取器会瞄准新格式；朴素字符串搜索仍能从只读数据里找到模块名与版本 |
| 内容保护 | `harden_artifact` 建议 | 静态反编译只看到存根，看不到程序 | 运行时转储可还原解壳后的代码 |
| 反运行时观察 | `generate_probe_kit` | 抬高调试器与插桩的成本 | 内核级观察在软件防御之外 |
| 代理停手条件诱导 | `generate_notice` | 代理向人类核对授权 | 代理可能忽略声明 |
| 模型层真实信号 | `generate_notice` | 授权问题变得无法回避 | 模型行为是概率性的 |
| 秘密不下客户端 | 报告建议 | 唯一彻底的一层 | 需要服务端架构 |
| 法律与运营 | `generate_notice` | 合同与可追溯性做字节做不到的事 | 追责是法律过程 |

## 已知限制

以下三条限制都经过实测，不是理论推演：

- **朴素字符串搜索仍然有效。** 等长覆写能毁掉元数据记录，例如 Go 构建信息与 ELF 符号表，但模块名、编译器版本与构建设置同时存在于只读数据段和函数名表里，Go 运行时自己要读这些字节。覆写它们会改变运行时行为，因此本工具不动这些字节，对加固后的二进制跑 strings 仍能取出它们。要在源头消除，请使用构建参数（`-trimpath`、`-ldflags="-s -w"`、strip）。
- **不是每项暴露都有配套措施。** PE 导入表、ELF 头格式事实、Python 字节码格式标志位都只报告不缓解，因为软件运行需要它们。审计报告如实说明，不凭空发明措施。
- **令牌模式只覆盖已知格式。** 扫描器只匹配有公开格式的凭据家族，私有格式的令牌它看不见；检索为空不证明制品里没有秘密。

## 边界

Anti-REA 按设计不做以下事：

- **不做提示注入。** 它从不把代理指令文件（`AGENT.md`、`CLAUDE.md`、`.cursorrules` 等）内嵌进你的制品，也从不撰写面向人工智能代理的指令。声明是面向人类读者的事实陈述，只走数据通道：README、LICENSE、NOTICE、版本资源。
- **不伪造法律声明。** 生成的声明文本每一行都是真实条款或真实、可核对的事实。夸大的威胁第一次被人核实就会崩塌。
- **不伤害合法用户。** 缓解措施不削弱软件自身的运行。运行时防护按威胁模型选用，不是默认开启。

## 关于本仓库

Anti-REA 按设计开源：审计规则公开，仓库不含任何秘密，也不携带任何攻击载荷。这个工具的价值是自动化与证据，不是保密——而唯一彻底的那层防御，即秘密不下客户端，不因任何人阅读这份代码而受损。唯独一样东西绝不能进仓库：针对具体用户的审计输出。工具对此给出警告，并提供 `--redacted` 脱敏输出。

## 验证方式

每项能力都由 `node --test` 配合真实夹具文件覆盖，MCP 接口用标准 stdio 握手做冒烟验证：

```bash
node --test
node scripts/mcp-smoke.mjs
```

## 文档

- [English](README.md)

## 许可证

[MIT](LICENSE)。Anti-REA 用于保护你拥有或获授权保护的软件。第三方格式沿用其自有规范。
