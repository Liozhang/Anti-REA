// 审计引擎：把读取器输出归入七层封闭词表，给出严重度与缓解编号。
// 全部读取在进程内完成：不执行目标代码、不附加进程、不发起网络请求。
// 资源超限时产部分结果并附限制说明，进程不失败不超时。
//
// 引擎对读取器输出的三件事负责：
//   1. 归组   按 layer-defs 的七层词表归组，按层与严重度汇总
//   2. 把关   每条发现先过 assertFindingVocabulary，词表外取值转成限制说明而不是混进报告
//   3. 编号   汇总前按层顺序编号，编号在报告内唯一，可被施加记录引用
// 此外还负责识别阶段的遗漏：identifyArtifact 跳过的条目（不可读等原因）没有进入 entries，
// 引擎逐条把它们转成限制说明，口径与复审侧 verify-entry-skipped 一致。
// 少了这一步，报告里只会剩下“没有暴露”，部分结果就冒充了完整结论。

import { NotImplementedError, UsageError } from '../errors.mjs';
import { identifyArtifact } from '../container/identify.mjs';
import { isLayerEnabled } from '../policy/schema.mjs';
import { capabilityBoundaryFor, readersForContainer } from '../readers/index.mjs';
import { assertFindingVocabulary, numberFindings, summarizeFindings } from './finding.mjs';

/** 审计报告模式版本。 */
export const AUDIT_REPORT_SCHEMA = 'anti-rea.audit-report/1';

/**
 * 审计一个制品。
 * @param {string} target 目录或文件路径
 * @param {{
 *   policy?: Record<string, unknown>,
 *   toolName?: string,
 *   now?: () => Date,
 *   readers?: Record<string, readonly {id: string, formats: readonly string[], layers: readonly string[], purpose: string, read: Function}[]>,
 *   io?: {open?: Function, stat?: Function},
 * }} [options] toolName 供 MCP 层把报告标成调用方看到的名字；
 *   readers 是读取器表，键为容器标识；省略时用 src/readers 的登记表，供测试与调用方注入；
 *   io 是识别阶段的文件系统注入，键与 src/container/identify.mjs 一致，供测试构造不可读条目
 * @returns {Promise<Record<string, unknown>>} 审计报告
 */
export async function auditArtifact(target, options = {}) {
  const policy = options.policy ?? {};
  const identity = await identifyArtifact(target, policy, options.io ?? {});
  const readerTable = options.readers;

  const findings = [];
  const boundaryIndex = new Map();
  const containerCounts = new Map();
  const limitations = [];
  let partial = false;

  if (identity.truncated) {
    partial = true;
    limitations.push({
      code: 'max-files-exceeded',
      message: '目录条目数达到策略上限，未枚举的条目未参与本次审计',
      scope: 'artifact',
    });
  }

  // 识别阶段就不可读的条目没有进入 entries，逐条转成限制说明：
  // 静默跳过等于让“没有暴露”冒充结论，口径与复审侧 verify-entry-skipped 一致。
  for (const skipped of identity.skipped) {
    partial = true;
    limitations.push({
      code: 'audit-entry-skipped',
      message: `条目 ${skipped.relativePath} 在识别阶段即不可读（${skipped.reason}），本次没有提取到任何事实。该条目不等于没有暴露，只是本次没有参与审计`,
      scope: 'entry',
    });
  }

  for (const entry of identity.entries) {
    // 容器分类计数先于预算判定记录，保证超限条目也在报告里留下分类痕迹。
    containerCounts.set(entry.container.type, (containerCounts.get(entry.container.type) ?? 0) + 1);

    // 文件头读取量与摘要覆盖范围先于单文件上限记录：被跳过的条目同样要知道
    // 它的容器判定与摘要覆盖到了什么程度，否则“部分结果”会缺一半信息。
    if (entry.detectionLimited) {
      partial = true;
      limitations.push({
        code: 'detection-prefix-limited',
        message: '条目文件头读取量受单文件上限约束，容器判定可能不完整',
        scope: 'entry',
      });
    }
    if (entry.digestTruncated) {
      partial = true;
      limitations.push({
        code: 'digest-truncated',
        message: '累计扫描窗口耗尽，条目摘要未覆盖整个文件',
        scope: 'entry',
      });
    }
    if (entry.bytes > (policy.budgets?.maxFileBytes ?? Number.POSITIVE_INFINITY)) {
      partial = true;
      limitations.push({
        code: 'max-file-bytes-exceeded',
        message: '条目字节数超过单文件上限，未读取其内容',
        scope: 'entry',
      });
      continue;
    }

    const readers =
      readerTable === undefined ? readersForContainer(entry.container.type) : (readerTable[entry.container.type] ?? []);
    if (readers.length === 0) {
      const boundary = capabilityBoundaryFor(entry);
      if (boundary !== null) {
        // 同一能力边界按分类聚合，报告里给计数而不是逐条目重复同一条说明。
        const existing = boundaryIndex.get(boundary.id);
        if (existing === undefined) {
          boundaryIndex.set(boundary.id, { ...boundary, count: 1 });
        } else {
          existing.count += 1;
        }
      }
      continue;
    }

    const enabledReaders = readers.filter((reader) => reader.layers.some((layerId) => isLayerEnabled(policy, layerId)));
    if (enabledReaders.length === 0) {
      limitations.push({
        code: 'layer-disabled',
        message: `容器 ${entry.container.type} 的全部读取器所属层已被策略关闭，本次未提取任何事实`,
        scope: 'entry',
      });
      continue;
    }

    for (const reader of enabledReaders) {
      let result;
      try {
        result = await reader.read({ entry, policy, budgets: policy.budgets ?? {} });
      } catch (error) {
        if (!(error instanceof NotImplementedError)) {
          throw error;
        }
        limitations.push({
          code: 'reader-not-implemented',
          message: `读取器 ${reader.id} 尚未实现：${reader.purpose}。该条目不等于没有暴露，只是本次没有提取到事实`,
          scope: 'entry',
        });
        continue;
      }

      if (result?.findings !== undefined && !Array.isArray(result.findings)) {
        limitations.push({
          code: 'reader-error',
          message: `读取器 ${reader.id} 返回的 findings 不是数组，本次未纳入报告`,
          scope: 'entry',
        });
      }
      if (result?.limitations !== undefined && !Array.isArray(result.limitations)) {
        limitations.push({
          code: 'reader-error',
          message: `读取器 ${reader.id} 返回的 limitations 不是数组，本次未纳入报告`,
          scope: 'entry',
        });
      }

      for (const finding of Array.isArray(result?.findings) ? result.findings : []) {
        try {
          assertFindingVocabulary(finding);
        } catch (error) {
          // 读取器写错层名、严重度或缓解编号时，报告不收录这条发现，
          // 但必须留下限制说明：静默丢弃会让“没有暴露”冒充结论。
          limitations.push({
            code: 'finding-rejected',
            message: `读取器 ${reader.id} 提交的发现未通过词表校验：${error.message}。该条目不等于没有暴露，只是本次没有纳入报告`,
            scope: 'entry',
          });
          continue;
        }
        findings.push(finding);
      }
      for (const note of Array.isArray(result?.limitations) ? result.limitations : []) {
        limitations.push(note);
      }
    }
  }

  // 汇总前编号：编号按层内递增，读取顺序确定（目录条目按路径排序、读取器按登记顺序），
  // 因此同一制品两次审计得到同一组编号。
  numberFindings(findings);

  const summary = summarizeFindings(findings);
  const capabilityBoundaries = [...boundaryIndex.values()];
  const containers = [...containerCounts.entries()].map(([type, count]) => ({ type, count }));
  summary.byContainer = Object.fromEntries(containerCounts);
  const report = {
    schema: AUDIT_REPORT_SCHEMA,
    tool: options.toolName ?? 'audit-artifact',
    status: partial ? 'partial' : 'complete',
    artifact: {
      kind: identity.kind,
      path: identity.path,
      sha256: identity.sha256,
      bytes: identity.bytes,
      entryCount: identity.entries.length,
    },
    findings,
    capabilityBoundaries,
    containers,
    limitations,
    summary: {
      findings: summary.total,
      byLayer: summary.byLayer,
      bySeverity: summary.bySeverity,
      byContainer: summary.byContainer,
      capabilityBoundaries: capabilityBoundaries.length,
      limitations: limitations.length,
    },
    generatedAt: (options.now ?? (() => new Date()))().toISOString(),
  };

  if (identity.kind === 'file' && identity.entries.length === 1) {
    report.artifact.container = identity.entries[0].container.type;
  }
  return report;
}

/**
 * 校验审计结果文件能否作为加固输入。
 * @param {unknown} report 解析后的审计报告
 * @returns {Record<string, unknown>} 校验通过的报告
 */
export function assertAuditReport(report) {
  if (report === null || typeof report !== 'object' || Array.isArray(report)) {
    throw new UsageError('审计结果文件顶层必须是对象');
  }
  if (typeof report.schema !== 'string' || !report.schema.startsWith('anti-rea.audit-report/')) {
    throw new UsageError('审计结果文件不是 Anti-REA 审计报告：缺少 schema 字段');
  }
  if (!Array.isArray(report.findings)) {
    throw new UsageError('审计结果文件缺少 findings 数组');
  }
  return report;
}
