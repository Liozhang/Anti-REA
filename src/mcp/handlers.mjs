// MCP 工具调用处理：把 tools/call 分发到与命令行共用的工作流。
// 本文件只做协议适配：参数取自 tools/call，工作流一律走 src/cli/workflows.mjs，不另写一份逻辑。
// 退出码到 MCP 结果的折算：
//   0 成功          -> isError 为 false，报告作为文本内容返回
//   1 业务不通过    -> isError 为 true
//   2 用法或输入错误 -> isError 为 true
//   3 拒否          -> isError 为 true，拒否报告同样带回：status 为 refused，
//                       omitted_reason 点名缺失的字段。拒绝不是成功——按成功信号返回，
//                       代理会以为声明已经生成，而它一个字节都没写。

import { resolve } from 'node:path';

import { RefusalError, describeError } from '../errors.mjs';
import { renderTextReport, serializeReport } from '../report/serialize.mjs';
import { renderProbeKitText } from '../probe-kit/index.mjs';
import {
  buildRefusalReport,
  createTreeWarner,
  loadPolicyFor,
  runAuditWorkflow,
  runHardenWorkflow,
  runNoticeWorkflow,
  runProbeWorkflow,
  runVerifyWorkflow,
  writeReportFile,
} from '../cli/workflows.mjs';
import { toolByName } from './tools.mjs';

/**
 * 处理 tools/call。
 * @param {Record<string, unknown> | undefined} params 请求参数，含 name 与 arguments
 * @returns {Promise<{content: Array<{type: string, text: string}>, isError: boolean, structuredContent?: Record<string, unknown>}>}
 */
export async function handleToolCall(params) {
  const name = typeof params?.name === 'string' ? params.name : '';
  const tool = toolByName(name);
  if (tool === null) {
    return {
      content: [
        {
          type: 'text',
          text: `未知工具：${name || '（未提供）'}，可用工具为 audit_artifact、harden_artifact、verify_artifact、generate_notice、generate_probe_kit`,
        },
      ],
      isError: true,
    };
  }
  const args = params?.arguments ?? {};
  if (args === null || typeof args !== 'object' || Array.isArray(args)) {
    return { content: [{ type: 'text', text: 'arguments 必须是对象' }], isError: true };
  }

  // git 工作树警告在 MCP 侧没有标准错误通道，收进报告的 warnings 字段，同一路径只记一次。
  const warnings = [];
  const warnTree = createTreeWarner((message) => warnings.push(message));

  try {
    const policy = await loadPolicyFor(args.policy);
    const { report, exitCode } = await runWorkflow(name, args, policy, warnTree);
    // 定稿顺序：先经警告器（让 git 工作树警告有机会进报告），补 output 与 warnings，
    // 再序列化文本，最后写出。写出的文件与返回给调用方的文本因此逐字节一致。
    const outputPath = await planReportOutput(name, args, warnTree);
    // harden 报告的 output 字段由工作流填写（未写入制品时为 null），不被报告路径覆盖。
    if (outputPath !== null && report.output === undefined) {
      report.output = outputPath;
    }
    if (warnings.length > 0) {
      report.warnings = [...warnings];
    }
    const text = textOf(name, report, args, policy);
    if (outputPath !== null) {
      await writeReportFile(outputPath, text, warnTree);
    }
    return {
      content: [{ type: 'text', text }],
      isError: exitCode !== 0,
      structuredContent: report,
    };
  } catch (error) {
    if (error instanceof RefusalError) {
      const report = buildRefusalReport({ tool: name, omitted_reason: error.omittedReason });
      const outputPath = await planReportOutput(name, args, warnTree);
      if (outputPath !== null) {
        report.output = outputPath;
      }
      if (warnings.length > 0) {
        report.warnings = [...warnings];
      }
      const text = textOf(name, report, args, {});
      if (outputPath !== null) {
        await writeReportFile(outputPath, text, warnTree);
      }
      return {
        content: [{ type: 'text', text }],
        // 拒否按失败信号返回：报告连同 omitted_reason 一起送回，调用方既看得到
        // 缺什么，也不会把拒否误判成一次成功的调用。
        isError: true,
        structuredContent: report,
      };
    }
    const described = describeError(error);
    return {
      content: [{ type: 'text', text: JSON.stringify({ error: described }, null, 2) }],
      isError: true,
    };
  }
}

/**
 * 按工具名跑对应工作流，返回报告与退出码。
 * @param {string} name 工具名
 * @param {Record<string, unknown>} args 工具参数
 * @param {Record<string, unknown>} policy 已载入策略
 * @param {(outputPath: string) => Promise<boolean>} warnTree git 工作树警告器
 * @returns {Promise<{report: Record<string, unknown>, exitCode: number}>}
 */
async function runWorkflow(name, args, policy, warnTree) {
  switch (name) {
    case 'audit_artifact': {
      const report = await runAuditWorkflow({
        target: String(args.path),
        policy,
        toolName: name,
        redacted: args.redacted === true,
      });
      return { report, exitCode: 0 };
    }
    case 'harden_artifact': {
      // 加固产物的写出路径取目标同目录加固定后缀；out 只决定报告写到哪里，与命令行一致。
      const report = await runHardenWorkflow({
        target: String(args.path),
        from: args.from,
        policy,
        toolName: name,
        warnTree,
      });
      return { report, exitCode: 0 };
    }
    case 'verify_artifact': {
      const result = await runVerifyWorkflow({
        target: String(args.path),
        from: args.from,
        policy,
        toolName: name,
      });
      return { report: result.report, exitCode: result.exitCode };
    }
    case 'generate_notice': {
      const report = await runNoticeWorkflow({
        template: String(args.template),
        policy,
        toolName: name,
        outPath: typeof args.out === 'string' && args.out !== '' ? args.out : undefined,
        warnTree,
      });
      return { report, exitCode: 0 };
    }
    case 'generate_probe_kit': {
      // 集成包输出目录：out、output、path 三个名字等价，按此顺序取先给出者，与命令行 --out 优先于位置参数一致。
      const outDir = firstString(args.out, args.output, args.path);
      const report = await runProbeWorkflow({ outDir, policy, toolName: name, warnTree });
      return { report, exitCode: 0 };
    }
    default:
      throw new RangeError(`未接线的工具：${name}`);
  }
}

/**
 * 取第一个非空字符串参数，全部不是非空字符串时返回 undefined。
 * @param {...unknown} values 候选参数值
 * @returns {string | undefined}
 */
function firstString(...values) {
  for (const value of values) {
    if (typeof value === 'string' && value !== '') {
      return value;
    }
  }
  return undefined;
}

/**
 * 报告文本：默认 JSON（与既有 MCP 行为一致），format 为 text 时渲染人读文本。
 * generate_notice 例外：它的交付物是声明文档，format 为 text 时直接给出声明全文，
 * 不让报告元数据替换掉声明本身。generate_probe_kit 同理：交付物是集成包本身，
 * format 为 text 时给集成包落盘清单，与命令行 probe 的人读输出同一份渲染。
 * @param {string} name 工具名
 * @param {Record<string, unknown>} report 报告对象
 * @param {Record<string, unknown>} args 工具参数
 * @param {Record<string, unknown>} policy 策略，用于报表字节上限
 * @returns {string}
 */
function textOf(name, report, args, policy) {
  if (name === 'generate_notice' && args.format === 'text' && typeof report.notice === 'string') {
    return report.notice;
  }
  // 只在报告确实是集成包报告时走集成包文本：拒否报告没有 outDir，落回通用渲染，“拒否原因”段才不会丢。
  if (name === 'generate_probe_kit' && args.format === 'text' && typeof report.outDir === 'string') {
    return renderProbeKitText(report);
  }
  if (args.format === 'text') {
    return renderTextReport(report);
  }
  return serializeReport(report, { policy });
}

/**
 * 定稿前的输出路径规划：解析 out 并先经 git 工作树警告器。
 * generate_notice 例外：它的 out 已由工作流当作声明文件路径消费（runNoticeWorkflow 的 outPath），
 * 声明文档就是该工具的交付物；再把报告 JSON 写出到同一路径会把声明覆盖掉。
 * 因此 generate_notice 的报告只经 content 返回，不落盘。
 * generate_probe_kit 同理：它的 out（含 output、path）是集成包输出目录，目录里放的是集成包文件，
 * 把报告写进那个目录会与交付物混在一起；报告只经 content 返回，不落盘。
 * @param {string} name 工具名
 * @param {Record<string, unknown>} args 工具参数
 * @param {(outputPath: string) => Promise<boolean>} warnTree git 工作树警告器
 * @returns {Promise<string | null>} 解析后的报告写出路径；不写报告时为 null
 */
async function planReportOutput(name, args, warnTree) {
  if (name === 'generate_notice' || name === 'generate_probe_kit') {
    return null;
  }
  if (typeof args.out !== 'string' || args.out === '') {
    return null;
  }
  const resolved = resolve(args.out);
  await warnTree(resolved);
  return resolved;
}
