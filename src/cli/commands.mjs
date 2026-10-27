// 五个子命令的工作流分发。
// 业务逻辑全部在 workflows.mjs，命令行与 MCP 服务共用同一套代码；
// 本文件只做命令行侧的参数适配、报告输出与退出码折算。

import { RefusalError } from '../errors.mjs';
import { resolve } from 'node:path';

import { loadPolicyFor } from './workflows.mjs';
import { renderTextReport, serializeReport } from '../report/serialize.mjs';
import { renderProbeKitText } from '../probe-kit/index.mjs';
import {
  HARDEN_REPORT_SCHEMA,
  REFUSAL_REPORT_SCHEMA,
  buildRefusalReport,
  createTreeWarner,
  runAuditWorkflow,
  runHardenWorkflow,
  runNoticeWorkflow,
  runProbeWorkflow,
  runVerifyWorkflow,
  writeReportFile,
} from './workflows.mjs';

export { HARDEN_REPORT_SCHEMA, REFUSAL_REPORT_SCHEMA };

/**
 * 判断是否以 JSON 输出。
 * @param {Record<string, string | boolean>} options 已解析选项
 * @returns {boolean}
 */
function wantsJson(options) {
  return options.json === true || options.format === 'json';
}

/**
 * 取当前命令行的 git 工作树警告器，同一路径只警告一次。
 * @param {{io: {writeError: Function}, warnTree?: Function}} ctx
 * @returns {Function}
 */
function treeWarnerOf(ctx) {
  ctx.warnTree ??= createTreeWarner((message) => ctx.io.writeError(`${message}\n`));
  return ctx.warnTree;
}

/**
 * 输出报告：按需写文件，并把同一份内容送到标准输出。
 * @param {{io: {write: Function, writeError: Function}, options: Record<string, unknown>, warnTree?: Function}} ctx
 * @param {{report: Record<string, unknown>, asJson: boolean, policy: Record<string, unknown>}} input
 */
async function emitReport(ctx, { report, asJson, policy }) {
  const text = asJson ? serializeReport(report, { policy }) : renderTextReport(report);
  if (typeof ctx.options.out === 'string' && ctx.options.out !== '') {
    const written = await writeReportFile(ctx.options.out, text, treeWarnerOf(ctx));
    ctx.io.writeError(`报告已写入 ${written}\n`);
  }
  ctx.io.write(asJson ? `${text}\n` : text);
}

/**
 * audit 子命令：审计制品暴露面。
 * 正常完成（包括发现暴露）时退出码为 0，仅在操作失败时非零。
 * @param {{target: string, options: Record<string, string | boolean>, io: object, warnTree?: Function}} ctx
 * @returns {Promise<number>} 退出码
 */
export async function commandAudit(ctx) {
  const policy = await loadPolicyFor(ctx.options.policy);
  const report = await runAuditWorkflow({
    target: ctx.target,
    policy,
    redacted: ctx.options.redacted === true,
  });
  await emitReport(ctx, { report, asJson: wantsJson(ctx.options), policy });
  return 0;
}

/**
 * harden 子命令：按审计结果施加缓解措施。
 * 骨架阶段可施加的集合为空，输出空施加清单与逐条跳过原因，不改动制品。
 * 加固产物的写出路径取目标同目录加固定后缀；--out 只决定报告写到哪里，两者分别警告。
 * @param {{target: string, options: Record<string, string | boolean>, io: object, warnTree?: Function}} ctx
 * @returns {Promise<number>} 退出码
 */
export async function commandHarden(ctx) {
  const policy = await loadPolicyFor(ctx.options.policy);
  const report = await runHardenWorkflow({
    target: ctx.target,
    from: ctx.options.from,
    policy,
    warnTree: treeWarnerOf(ctx),
  });
  await emitReport(ctx, { report, asJson: wantsJson(ctx.options), policy });
  return 0;
}

/**
 * verify 子命令：复审，确认缓解生效。
 * @param {{target: string, options: Record<string, string | boolean>, io: object, warnTree?: Function}} ctx
 * @returns {Promise<number>} 退出码 0 通过、1 不通过
 */
export async function commandVerify(ctx) {
  const policy = await loadPolicyFor(ctx.options.policy);
  const result = await runVerifyWorkflow({
    target: ctx.target,
    from: ctx.options.from,
    policy,
  });
  await emitReport(ctx, { report: result.report, asJson: wantsJson(ctx.options), policy });
  return result.exitCode;
}

/**
 * notice 子命令：生成许可与禁止逆向的声明模板。
 * 只含真实字段；字段缺失时产出含 omitted_reason 的拒否报告并返回退出码 3。
 * 声明文档是交付物：给出 --out 时由工作流落盘，标准输出按模式给出声明文本（人读）或报告（JSON）。
 * 报告不写进 --out：那会把刚落盘的声明文档覆盖成报告。
 * @param {{target: string, options: Record<string, string | boolean>, io: object, warnTree?: Function}} ctx
 * @returns {Promise<number>} 退出码
 */
export async function commandNotice(ctx) {
  const policy = await loadPolicyFor(ctx.options.policy);
  const template = String(ctx.options.template);
  const outPath = typeof ctx.options.out === 'string' && ctx.options.out !== '' ? ctx.options.out : null;
  try {
    const report = await runNoticeWorkflow({
      template,
      policy,
      ...(outPath === null ? {} : { outPath }),
      warnTree: treeWarnerOf(ctx),
    });
    if (wantsJson(ctx.options)) {
      ctx.io.write(`${serializeReport(report, { policy })}\n`);
    } else {
      ctx.io.write(report.notice);
    }
    if (outPath !== null) {
      ctx.io.writeError(`声明已写入 ${resolve(outPath)}\n`);
    }
    return 0;
  } catch (error) {
    if (!(error instanceof RefusalError)) {
      throw error;
    }
    const report = buildRefusalReport({ tool: 'notice', omitted_reason: error.omittedReason, extra: { template } });
    await emitReport(ctx, { report, asJson: wantsJson(ctx.options), policy });
    return 3;
  }
}

/**
 * probe 子命令：生成反运行时观察集成包。
 * 位置参数是集成包输出目录，--out 与它同义且优先：同时给出时以 --out 为准，
 * 因为集成包与具体制品无关（不读制品、不改动制品），位置参数此时只是缺省输出目录。
 * --out 已经是集成包目录，报告因此只送标准输出，不再另写报告文件。
 * 输出目录位于 git 工作树内时由警告器向标准错误提示，同一路径只警告一次。
 * @param {{target: string, options: Record<string, string | boolean>, io: object, warnTree?: Function}} ctx
 * @returns {Promise<number>} 退出码
 */
export async function commandProbe(ctx) {
  const policy = await loadPolicyFor(ctx.options.policy);
  const outDir = typeof ctx.options.out === 'string' && ctx.options.out !== '' ? ctx.options.out : ctx.target;
  const report = await runProbeWorkflow({ outDir, policy, warnTree: treeWarnerOf(ctx) });
  if (wantsJson(ctx.options)) {
    ctx.io.write(`${serializeReport(report, { policy })}\n`);
  } else {
    ctx.io.write(renderProbeKitText(report));
  }
  return 0;
}
