// 共用工作流：命令行与 MCP 服务唯一的一套业务路径。
// 命令行只做参数解析与退出码折算，MCP 服务只做协议适配，两者都调用这里的函数。
// 铁律：任何工作流步骤不得在两处各写一份，改行为只改这里，两条入口同时生效。

import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import { auditArtifact, assertAuditReport } from '../audit/engine.mjs';
import { identifyArtifact } from '../container/identify.mjs';
import { RefusalError, UsageError } from '../errors.mjs';
import { generateNotice, inspectLegalFields } from '../notice/index.mjs';
import { loadPolicy } from '../policy/schema.mjs';
import { buildProbeKit } from '../probe-kit/index.mjs';
import { redactReport } from '../report/redact.mjs';
import { applyMitigations, DEFAULT_OUTPUT_SUFFIX } from '../transforms/index.mjs';
import { verifyArtifact } from '../verify/index.mjs';
import { gitTreeWarning, isInsideGitWorkTree } from './git-tree.mjs';

/** 加固报告模式版本。 */
export const HARDEN_REPORT_SCHEMA = 'anti-rea.harden-report/1';

/** 拒否报告模式版本。凡拒否必产出含 omitted_reason 的报告。 */
export const REFUSAL_REPORT_SCHEMA = 'anti-rea.refusal/1';

/** 声明报告模式版本。 */
export const NOTICE_REPORT_SCHEMA = 'anti-rea.notice/1';

/**
 * 构造拒否报告。命令行与 MCP 服务共用同一结构，调用方只补自己的工具名与附加字段。
 * 字段名是蛇形 omitted_reason：报告是对外契约，两条入口与说明文档都用这一个拼写。
 * @param {{tool: string, omitted_reason: readonly string[], extra?: Record<string, unknown>}} input
 * @returns {Record<string, unknown>}
 */
export function buildRefusalReport({ tool, omitted_reason, extra = {} }) {
  return {
    schema: REFUSAL_REPORT_SCHEMA,
    tool,
    status: 'refused',
    omitted_reason: [...omitted_reason],
    ...extra,
  };
}

/**
 * 造一个 git 工作树警告器：同一路径只警告一次。
 * 命令行把警告送标准错误，MCP 服务把警告收进报告的 warnings 字段，语义一致。
 * @param {(message: string) => void} emit 警告出口
 * @returns {(outputPath: string) => Promise<boolean>} 是否真的警告了
 */
export function createTreeWarner(emit) {
  const warned = new Set();
  return async function warnIfInGitTree(outputPath) {
    const resolved = resolve(outputPath);
    if (warned.has(resolved)) {
      return false;
    }
    warned.add(resolved);
    if (await isInsideGitWorkTree(resolved)) {
      emit(gitTreeWarning(resolved));
      return true;
    }
    return false;
  };
}

/**
 * 把报告文本写出到文件。目标路径位于 git 工作树内时先经警告器提示，同一路径只警告一次。
 * @param {string} outputPath 输出路径
 * @param {string} text 报告文本
 * @param {(outputPath: string) => Promise<boolean>} warnTree 警告器
 * @returns {Promise<string>} 实际写出的绝对路径
 */
export async function writeReportFile(outputPath, text, warnTree) {
  const resolved = resolve(outputPath);
  await warnTree(resolved);
  await writeFile(resolved, text, 'utf8');
  return resolved;
}

/**
 * 读取并校验审计结果文件，作为加固输入或复审基线。
 * @param {unknown} fromPath 审计结果文件路径
 * @param {string} label 人读标签，用于错误信息
 * @returns {Promise<Record<string, unknown>>} 校验通过的审计报告
 */
export async function readAuditReportFile(fromPath, label = '审计结果文件') {
  if (typeof fromPath !== 'string' || fromPath.trim() === '') {
    throw new UsageError(`缺少${label}路径：请用 --from 给出加固前产出的审计报告`);
  }
  const auditPath = resolve(fromPath);
  let text;
  try {
    text = await readFile(auditPath, 'utf8');
  } catch (error) {
    throw new UsageError(`无法读取${label}：${auditPath}`, { cause: String(error) });
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new UsageError(`${label}不是合法 JSON：${auditPath}`, { cause: String(error) });
  }
  try {
    return assertAuditReport(parsed);
  } catch (error) {
    throw new UsageError(`${label}不是 Anti-REA 审计报告：${auditPath}（${error.message}）`, {
      cause: String(error),
    });
  }
}

/**
 * 审计工作流：只读清点制品暴露面，按需脱敏。
 * 正常完成（包括发现暴露）不抛错，由调用方决定退出码 0。
 * @param {{target: string, policy?: Record<string, unknown>, toolName?: string, redacted?: boolean}} input
 * @returns {Promise<Record<string, unknown>>} 审计报告（可脱敏）
 */
export async function runAuditWorkflow({ target, policy = {}, toolName = 'audit-artifact', redacted = false }) {
  const report = await auditArtifact(target, { policy, toolName });
  return redacted === true ? redactReport(report) : report;
}

/**
 * 加固工作流：按审计结果派生缓解措施并施加。
 * 入口是 transforms 的批量施加 applyMitigations：读一次、按序施加、写出一次；
 * 签名门控、PE CheckSum 重算、幂等判定（本次产出与已存在输出逐字节相同不算改动）
 * 都由批量结果给出，工作流不再自己逐发现循环。
 * 文件目标整体一次批量施加；目录目标按条目逐个施加，每个条目写自己的 <条目>.hardened，
 * 发现按 evidence.path（条目相对路径）分到条目。两条路径都不改原件。
 * 模型层重布局要把许可元数据写进制品：法律字段不齐时在施加开始前即拒否（退出码 3），
 * 不写入任何字节；批量结果里若仍带拒理由，同样折成退出码 3。
 * 写入后自动跑一次结构复审，结果进报告的 review 字段；复审自身出错记 pending，不冒充通过。
 * 原件永不改动：加固产物写在独立路径，回滚即删除这些文件。
 * outputPath 是文件目标的加固产物写出路径，默认取目标同目录加固定后缀；它与调用方的报告写出路径（--out）是两条路径，
 * 各自位于 git 工作树内时都要经警告器提示，两条入口行为一致。
 * @param {{
 *   target: string,
 *   from: unknown,
 *   policy?: Record<string, unknown>,
 *   toolName?: string,
 *   outputPath?: string,
 *   warnTree?: (outputPath: string) => Promise<boolean>,
 * }} input
 * @returns {Promise<Record<string, unknown>>} 加固报告
 */
export async function runHardenWorkflow({ target, from, policy = {}, toolName = 'harden-artifact', outputPath, warnTree }) {
  const auditReport = await readAuditReportFile(from);

  // 模型层重布局注入许可元数据：法律字段不齐时拒绝开始，而不是写出一半再拒。
  const needsLegalFields = auditReport.findings.some(
    (finding) => typeof finding.mitigation === 'string' && finding.mitigation.startsWith('model.'),
  );
  if (needsLegalFields) {
    const inspection = inspectLegalFields(policy);
    if (!inspection.complete) {
      throw new RefusalError(inspection.omittedReason);
    }
  }

  const identity = await identifyArtifact(target, policy);
  const defaultOutput = `${resolve(target)}${DEFAULT_OUTPUT_SUFFIX}`;
  const resolvedOutput = typeof outputPath === 'string' && outputPath !== '' ? resolve(outputPath) : defaultOutput;
  // 只有文件目标真的把加固产物写到 resolvedOutput：目录目标逐条目写 <条目>.hardened，
  // 那条“目标加后缀”的路径一个字节都不会落盘。警告一条不会写出的路径，
  // 等于提示一份不存在的暴露面，还会把同一次加固的警告次数算多，因此按目标类型分流：
  // 目录目标的每条产物路径由 applyPerEntry 各自经警告器提示。
  if (warnTree !== undefined && identity.kind === 'file') {
    await warnTree(resolvedOutput);
  }

  const rawBatch =
    identity.kind === 'directory'
      ? await applyPerEntry(identity, auditReport.findings, policy, warnTree)
      : await applyMitigations({ target, findings: auditReport.findings, policy, outputPath: resolvedOutput });
  // 统一两条路径的结果形状：目录分支已是聚合形状，文件分支按同一组字段折算。
  const batch = Array.isArray(rawBatch.outputs) ? rawBatch : normalizeFileBatch(rawBatch);

  // 双保险：个别施加函数自行拒写时会把拒理由带在结果里，这里统一折成退出码 3。
  // 施加结果里的字段名由 transforms 定（omittedReason），是内部结构；
  // 对外的拒否报告统一由 buildRefusalReport 产出蛇形 omitted_reason，两处不混用。
  const entryRefusal = [...batch.applied, ...batch.skipped].flatMap((entry) =>
    Array.isArray(entry.omittedReason) ? entry.omittedReason : [],
  );
  if (entryRefusal.length > 0) {
    throw new RefusalError(entryRefusal);
  }

  const review = await reviewAfterWrite(batch, auditReport, policy);

  return {
    schema: HARDEN_REPORT_SCHEMA,
    tool: toolName,
    status: batch.applied.length > 0 ? 'applied' : 'no-op',
    artifact: {
      kind: identity.kind,
      path: identity.path,
      sha256: identity.sha256,
      bytes: identity.bytes,
    },
    applied: batch.applied,
    skipped: batch.skipped,
    changed: batch.changed,
    wrote: batch.wrote,
    idempotent: batch.idempotent,
    requiresResign: batch.requiresResign,
    checksumRecomputed: batch.checksumRecomputed,
    review,
    rollback: {
      available: true,
      action: '原件未被改动，删除加固产物即可回退',
      output: batch.wrote === true ? batch.outputs : null,
    },
    output: batch.wrote === true ? batch.outputs[0] : null,
    outputNote: hardenOutputNote(batch),
    limitations: batch.limitations,
  };
}

/**
 * 把文件目标的批量施加结果折算成统一形状：字段与目录分支一致，
 * outputs 为写入的产物路径列表，entryOutputs 为 null 表示单文件（复审带基线比对）。
 * @param {Record<string, unknown>} raw applyMitigations 的返回
 * @returns {{applied: unknown[], skipped: unknown[], limitations: unknown[], changed: boolean, wrote: boolean, idempotent: boolean, requiresResign: boolean, checksumRecomputed: boolean, outputs: string[], entryOutputs: null}}
 */
function normalizeFileBatch(raw) {
  const outputs = raw.wrote === true && typeof raw.artifact?.outputPath === 'string' ? [raw.artifact.outputPath] : [];
  return {
    applied: raw.applied,
    skipped: raw.skipped,
    limitations: raw.limitations,
    changed: raw.changed,
    wrote: raw.wrote,
    idempotent: raw.idempotent,
    requiresResign: raw.requiresResign,
    checksumRecomputed: raw.checksumRecomputed,
    outputs,
    entryOutputs: null,
  };
}

/**
 * 目录目标逐条目施加：发现按 evidence.path（条目相对路径）分到条目，
 * 每个条目一次批量施加，产物写 <条目>.hardened。没有可施加发现的条目不读不写。
 * 聚合字段与 applyMitigations 的返回一致，供加固报告直接引用。
 * @param {Record<string, unknown>} identity identifyArtifact 的结果（kind 为 directory）
 * @param {readonly Record<string, unknown>[]} findings 审计发现
 * @param {Record<string, unknown>} policy 策略
 * @param {((outputPath: string) => Promise<boolean>) | undefined} warnTree git 工作树警告器
 * @returns {Promise<{applied: unknown[], skipped: unknown[], limitations: unknown[], changed: boolean, wrote: boolean, idempotent: boolean, requiresResign: boolean, checksumRecomputed: boolean, outputs: string[], entryOutputs: Array<{relativePath: string, outputPath: string, applied: unknown[]}>}>}
 */
async function applyPerEntry(identity, findings, policy, warnTree) {
  const byEntry = new Map();
  for (const finding of findings) {
    const key = finding?.evidence?.path;
    if (typeof key !== 'string' || key === '') {
      continue;
    }
    const list = byEntry.get(key) ?? [];
    list.push(finding);
    byEntry.set(key, list);
  }

  const applied = [];
  const skipped = [];
  const limitations = [];
  const outputs = [];
  const entryOutputs = [];
  let changed = false;
  let wrote = false;
  let idempotent = false;
  let requiresResign = false;
  let checksumRecomputed = false;

  for (const entry of identity.entries) {
    const entryFindings = byEntry.get(entry.relativePath) ?? [];
    if (entryFindings.length === 0) {
      continue;
    }
    const entryOutput = `${entry.absolutePath}${DEFAULT_OUTPUT_SUFFIX}`;
    if (warnTree !== undefined) {
      await warnTree(entryOutput);
    }
    const batch = await applyMitigations({
      target: entry.absolutePath,
      findings: entryFindings,
      policy,
      outputPath: entryOutput,
    });
    applied.push(...batch.applied);
    skipped.push(...batch.skipped);
    limitations.push(...batch.limitations);
    if (batch.changed === true) changed = true;
    if (batch.wrote === true) {
      wrote = true;
      outputs.push(entryOutput);
      entryOutputs.push({ relativePath: entry.relativePath, outputPath: entryOutput, applied: batch.applied });
    }
    if (batch.idempotent === true) idempotent = true;
    if (batch.requiresResign === true) requiresResign = true;
    if (batch.checksumRecomputed === true) checksumRecomputed = true;
  }

  return { applied, skipped, limitations, changed, wrote, idempotent, requiresResign, checksumRecomputed, outputs, entryOutputs };
}

/**
 * 写入后复审：对每个写入的加固产物重跑结构检查（容器解析、签名、校验和、必需集）。
 * 复审自身出错记 pending 并说明原因，不冒充通过，也不让已完成的施加结果丢失。
 * @param {Record<string, unknown>} batch 施加聚合结果（文件或目录两条路径的统一形状）
 * @param {Record<string, unknown>} auditReport 加固前的基线审计报告
 * @param {Record<string, unknown>} policy 策略
 * @returns {Promise<Record<string, unknown>>} 复审小结
 */
async function reviewAfterWrite(batch, auditReport, policy) {
  if (batch.wrote !== true) {
    return { passed: true, status: 'not-run', note: '本次未写入任何字节，无需复审' };
  }
  const targets = Array.isArray(batch.entryOutputs)
    ? batch.entryOutputs.map((item) => ({ path: item.outputPath, applied: item.applied, label: item.relativePath }))
    : [{ path: batch.outputs[0], applied: batch.applied, label: null }];
  const entries = [];
  for (const target of targets) {
    try {
      const result = await verifyArtifact(target.path, {
        policy,
        // 文件目标用整份基线比对；目录条目只用结构检查，基线是整目录的报告，逐条目比对齐不准。
        ...(target.label === null ? { baseline: auditReport } : {}),
        applied: target.applied,
        toolName: 'harden-artifact',
      });
      entries.push({
        ...(target.label === null ? {} : { entry: target.label }),
        passed: result.exitCode === 0,
        status: result.report.status,
        note:
          result.exitCode === 0
            ? '复审通过：结构健全，未伤害合法用户依赖的结构'
            : '复审未完全通过：放行前请按复审报告逐项核对',
      });
    } catch (error) {
      entries.push({
        ...(target.label === null ? {} : { entry: target.label }),
        passed: false,
        status: 'error',
        note: `复审未能完成：${error instanceof Error ? error.message : String(error)}`,
      });
    }
  }
  const passed = entries.every((entry) => entry.passed);
  return {
    passed,
    status: passed ? 'passed' : entries.some((entry) => entry.status === 'error') ? 'error' : 'failed',
    note: passed
      ? entries.length === 1
        ? entries[0].note
        : `${entries.length} 个加固产物全部复审通过`
      : '有加固产物复审未通过或未能完成，详见各条目结论',
    ...(entries.length === 1 ? {} : { entries }),
  };
}

/**
 * 加固产物的输出说明，按施加结果的三种终态分别措辞。
 * @param {Record<string, unknown>} batch 施加聚合结果
 * @returns {string}
 */
function hardenOutputNote(batch) {
  if (batch.wrote === true) {
    return `已写入加固后制品：${batch.outputs.join('、')}`;
  }
  if (batch.idempotent === true) {
    return '本次产出与已存在的加固产物逐字节相同，未重复写入';
  }
  return '没有可施加的缓解措施，未写入任何文件，原件未被改动';
}

/**
 * 复审工作流：重跑审计、与基线比对、做结构健全性检查。
 * @param {{target: string, from?: unknown, policy?: Record<string, unknown>, toolName?: string}} input
 * @returns {Promise<{exitCode: number, report: Record<string, unknown>}>} exitCode 0 通过、1 不通过
 */
export async function runVerifyWorkflow({ target, from, policy = {}, toolName = 'verify-artifact' }) {
  let baseline = null;
  if (typeof from === 'string' && from !== '') {
    baseline = await readAuditReportFile(from, '基线审计报告');
  }
  return await verifyArtifact(target, { policy, baseline, toolName });
}

/**
 * 声明工作流：按真实字段生成法律声明。
 * 法律字段缺失时抛 RefusalError，由调用方统一折成拒否报告；写出路径经警告器提示。
 * 声明文档文本随报告返回（notice 字段）：命令行人读模式直接输出它，
 * MCP 调用方不传 out 时也能从报告里拿到全文。给出 outPath 时声明文档由 generateNotice 落盘，
 * 报告本身不再写往该路径——那会把刚落盘的声明覆盖掉。
 * @param {{template: string, policy?: Record<string, unknown>, toolName?: string, outPath?: string, warnTree?: Function}} input
 * @returns {Promise<Record<string, unknown>>} 声明报告
 */
export async function runNoticeWorkflow({ template, policy = {}, toolName = 'notice', outPath, warnTree }) {
  const resolvedOut = typeof outPath === 'string' && outPath !== '' ? resolve(outPath) : null;
  if (resolvedOut !== null && warnTree !== undefined) {
    await warnTree(resolvedOut);
  }
  const generated = await generateNotice({ template, policy, outPath: resolvedOut ?? undefined });
  return {
    schema: NOTICE_REPORT_SCHEMA,
    tool: toolName,
    status: 'generated',
    template,
    output: resolvedOut,
    notice: generated.text,
  };
}

/**
 * 载入策略：未提供路径时返回默认策略。供两条入口共用，错误口径一致。
 * @param {unknown} policyPath 策略文件路径
 * @returns {Promise<Record<string, unknown>>}
 */
export async function loadPolicyFor(policyPath) {
  return await loadPolicy(typeof policyPath === 'string' && policyPath !== '' ? policyPath : undefined);
}

/**
 * 集成包工作流：生成反运行时观察集成包，与命令行、MCP 服务两条入口共用。
 * 生成方只往 outDir 写集成包文件，不读制品、不改动制品、不启动子进程、不发起网络请求；
 * outDir 位于 git 工作树内时先经警告器提示，同一路径只警告一次，两条入口行为一致。
 * toolName 按入口填写：命令行报 probe-kit，MCP 服务报 generate_probe_kit，与其余工作流同一口径。
 * @param {{
 *   outDir: string,
 *   policy?: Record<string, unknown>,
 *   toolName?: string,
 *   warnTree?: (outputPath: string) => Promise<boolean>,
 * }} input
 * @returns {Promise<Record<string, unknown>>} 集成包报告
 */
export async function runProbeWorkflow({ outDir, policy = {}, toolName = 'probe-kit', warnTree }) {
  const report = await buildProbeKit({ policy, outDir, warnTree });
  return toolName === 'probe-kit' ? report : { ...report, tool: toolName };
}
