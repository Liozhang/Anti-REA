// 命令行帮助文本。
// 文本中出现的接口与两份说明文档保持一致，改接口必须先改文档再改这里。

import { SUBCOMMAND_SPECS } from './args.mjs';

/** 用法说明。 */
export const USAGE = `Anti-REA：面向自有软件的离线审计与加固工具

用法：
  node bin/anti-rea.js <子命令> [参数]

子命令：
  audit <目录或文件> --json          审计制品暴露面；正常完成（包括发现暴露）时退出码为 0
  audit <目录或文件> --redacted      输出脱敏报告：保留分类与计数，隐去精确路径、字节范围与缓解措施对应关系
  harden <目录或文件> --from <审计结果.json>
                                     应用元数据层缓解措施，保留原件备份
  verify <目录或文件>                复审，确认缓解生效
  notice --template license          在标准输出生成许可与禁止逆向的声明模板，只含真实字段
  probe <输出目录>                   生成反运行时观察集成包：检测代码片段与人工检查清单，不改动制品

通用选项：
  --json                            以 JSON 输出报告
  --format <json|text>              输出格式，等价于 --json 与默认文本
  --policy <路径>                   策略文件，决定层开关、法律字段与资源预算
  --out <路径>                      把报告写入文件；目标路径位于 git 工作树内时向标准错误输出警告
                                    （probe 例外：--out 是集成包输出目录，与位置参数同义且优先，不写报告文件）
  --help                            显示本帮助
  --version                         显示版本

退出码：
  0  成功（审计正常完成，包括发现暴露；加固施加成功；复审通过；声明生成成功）
  1  业务不通过（复审未通过且已回滚；工作流步骤未实现）
  2  用法或输入错误
  3  拒否（例如生成声明时法律字段缺失，未改动制品）

示例：
  node bin/anti-rea.js audit /absolute/path/to/your/app --json
  node bin/anti-rea.js harden /absolute/path/to/your/app --from audit.json
  node bin/anti-rea.js verify /absolute/path/to/your/app
  node bin/anti-rea.js notice --template license > NOTICE.md
  node bin/anti-rea.js probe /absolute/path/to/kit --json
`;

/**
 * 生成某个子命令的用法片段。
 * @param {string} subcommand 子命令名
 * @returns {string}
 */
export function subcommandUsage(subcommand) {
  const spec = SUBCOMMAND_SPECS[subcommand];
  if (spec === undefined) {
    return USAGE;
  }
  const flags = Object.keys(spec.options).map((name) => `--${name}`).join(' ');
  const positional = spec.positionalLabel === '' ? '' : ` ${spec.positionalLabel}`;
  return `用法：node bin/anti-rea.js ${subcommand}${positional} [${flags}]\n`;
}
