// 复审引擎：加固的安全门。
// 两件事：
//   1. 重跑审计并与基线比对，得出残留发现、新增发现、消失发现
//   2. 做结构健全性检查，共五个检查族：
//        container-parse         容器解析：头部与全部已声明表结构可遍历
//        signature-consistency   签名一致性：代码签名载荷范围在文件内（只观察不验证密码学信任）
//        checksum-consistency    校验和一致性：PE 可选头 CheckSum 重算值、ZIP 条目 CRC32 与中央目录项
//        pyc-flag-consistency    pyc 标志与哈希状态一致性：清零 source_hash 必须一并清除 check_source
//        required-sections       必需节完整性：按格式必需集逐项判定，已施加缓解清单中的项从必需集移除
//
// 判定语义里最重要的两条：
//   1. 没有失败且没有未决项才判 passed。看不到问题不等于通过：事实缺失、预算超限、
//      观察器无法解析一律记 pending，总体结论落到 partial，退出码 1——安全门不能自称通过。
//   2. 豁免只认施加记录。options.applied 显式给出时按它派生；只有基线时按“基线有、
//      本次没有”的消失发现反推已施加编号；两者都没有时必需集一项不免。

import { auditArtifact } from '../audit/engine.mjs';
import { SUPPORTED_CONTAINERS } from '../container/detect.mjs';
import { identifyArtifact } from '../container/identify.mjs';
import { budgetsOf } from '../policy/schema.mjs';
import { readEntryBytes } from '../readers/common.mjs';
import { analyzeByContainer, computePeChecksum } from '../signatures/index.mjs';
import { appliedMitigationIds, checkRequiredSet } from '../required-sets/index.mjs';
import { diffAuditsByKey } from '../report/diff.mjs';
import { inspectContainer } from './facts.mjs';

/** 复审报告模式版本。 */
export const VERIFY_REPORT_SCHEMA = 'anti-rea.verify-report/1';

/** 结构检查族封闭集合。 */
export const CHECK_FAMILIES = Object.freeze([
  'container-parse',
  'signature-consistency',
  'checksum-consistency',
  'pyc-flag-consistency',
  'required-sections',
]);

/** 单项检查结论的封闭集合。pending 表示本次无法判定，绝不当成通过。 */
export const CHECK_STATUSES = Object.freeze(['passed', 'failed', 'pending', 'not-applicable']);

/** 带签名观察器的容器：这些容器要做签名一致性检查。 */
const SIGNATURE_OBSERVER_CONTAINERS = Object.freeze(['elf', 'pe', 'mach-o', 'mach-o-fat', 'zip']);

/** 带校验和观察器的容器：这些容器要做校验和一致性检查。 */
const CHECKSUM_OBSERVER_CONTAINERS = Object.freeze(['pe', 'zip']);

/** 容器到适用检查族的映射。不适用该容器实际结构的族不出现在报告里，避免用噪音冒充覆盖。 */
// 每个受支持容器都必须出现在这里：读取失败或预算截断的错误路径要按这份清单逐族记
// pending，漏登记的容器会在那些路径上拿到 undefined 而崩溃。
export const FAMILIES_BY_CONTAINER = Object.freeze({
  elf: Object.freeze(['container-parse', 'signature-consistency', 'required-sections']),
  pe: Object.freeze(['container-parse', 'signature-consistency', 'checksum-consistency', 'required-sections']),
  'mach-o': Object.freeze(['container-parse', 'signature-consistency', 'required-sections']),
  'mach-o-fat': Object.freeze(['container-parse', 'signature-consistency', 'required-sections']),
  zip: Object.freeze(['container-parse', 'signature-consistency', 'checksum-consistency', 'required-sections']),
  gguf: Object.freeze(['container-parse', 'required-sections']),
  safetensors: Object.freeze(['container-parse', 'required-sections']),
  pyc: Object.freeze(['container-parse', 'pyc-flag-consistency', 'required-sections']),
  beam: Object.freeze(['container-parse', 'required-sections']),
  // DEX 没有登记的签名观察器，因此没有签名族；容器解析与必需集两项都适用。
  dex: Object.freeze(['container-parse', 'required-sections']),
});

/**
 * 复审一个制品。
 * @param {string} target 目录或文件路径
 * @param {{
 *   policy?: Record<string, unknown>,
 *   baseline?: Record<string, unknown> | null,
 *   applied?: unknown,
 *   toolName?: string,
 * }} [options] applied 是施加记录：编号字符串数组、带 mitigation 字段的对象数组，
 *   或含 applied 数组的加固报告；省略时按基线比对反推。baseline 是加固前的审计报告。
 * @returns {Promise<{exitCode: number, report: Record<string, unknown>}>}
 */
export async function verifyArtifact(target, options = {}) {
  const policy = options.policy ?? {};
  const budgets = budgetsOf(policy);
  const toolName = options.toolName ?? 'verify-artifact';

  // 复审自己跑一遍审计：与基线比对的“本次”一侧必须来自同一套读取器，而不是调用方转述。
  const current = await auditArtifact(target, { policy, toolName });
  // 结构检查需要逐条目字节，审计报告不携带字节，这里按同一策略重新识别一遍。
  const identity = await identifyArtifact(target, policy);
  const baseline = options.baseline ?? null;
  // 前后差异按稳定标识（层、分类、读取器）比对，一个标识一处暴露只列一次：
  // 同一标识多处落点（如静态与动态符号表）不逐次虚增残留项，只清其中一处也不算整处消失。
  const comparison = baseline === null || baseline === undefined ? null : diffAuditsByKey(baseline, current);
  const applied = resolveAppliedMitigations(options.applied, baseline, comparison);
  const checks = [];
  const limitations = [];
  const appliedIds = applied.mitigations;
  let outOfScope = 0;
  let requiresResign = false;

  for (const entry of identity.entries) {
    const containerType = entry.container.type;
    if (!SUPPORTED_CONTAINERS.includes(containerType)) {
      outOfScope += 1;
      continue;
    }
    const families = FAMILIES_BY_CONTAINER[containerType];
    let read;
    try {
      read = await readEntryBytes(entry, budgets);
    } catch (error) {
      // 复审期间条目变得不可读：不猜、不冒充通过，逐族记 pending 并留限制说明。
      const reason = `复审读取条目失败：${error instanceof Error ? error.message : String(error)}`;
      for (const family of families) {
        checks.push({ family, container: containerType, entry: entry.relativePath, status: 'pending', reason });
      }
      limitations.push({ code: 'verify-entry-unreadable', message: reason, scope: 'entry' });
      continue;
    }
    if (!read.complete) {
      // 部分读取：结构复审无法完成。这不是制品损坏的证据，只是本次判不了。
      const reason = `条目只读取前 ${read.bytesRead} 字节（共 ${read.fileSize} 字节），结构复审无法完成`;
      for (const family of families) {
        checks.push({ family, container: containerType, entry: entry.relativePath, status: 'pending', reason });
      }
      limitations.push({
        code: 'verify-read-truncated',
        message: `条目 ${entry.relativePath} 只读取前 ${read.bytesRead} 字节（共 ${read.fileSize} 字节），未覆盖部分没有做结构复审`,
        scope: 'entry',
      });
      continue;
    }

    const entryApplied = appliedIds;
    const entryChecks = checkEntry({ entry, containerType, bytes: read.bytes, policy, applied: entryApplied });
    for (const check of entryChecks) {
      if (check.detail?.requiresResign === true) {
        requiresResign = true;
      }
    }
    checks.push(...entryChecks);
  }

  for (const skipped of identity.skipped) {
    limitations.push({
      code: 'verify-entry-skipped',
      message: `条目 ${skipped.relativePath} 在识别阶段即不可读（${skipped.reason}），本次没有做结构复审`,
      scope: 'entry',
    });
  }
  if (outOfScope > 0) {
    limitations.push({
      code: 'verify-out-of-scope',
      message: `${outOfScope} 个条目不落入 v1 格式集（${SUPPORTED_CONTAINERS.join('、')}），没有容器结构可复审；这些条目的暴露面边界以审计报告的能力边界说明为准`,
      scope: 'artifact',
    });
  }

  const failed = checks.filter((check) => check.status === 'failed');
  const pending = checks.filter((check) => check.status === 'pending');
  const status = failed.length > 0 ? 'failed' : pending.length > 0 ? 'partial' : 'passed';
  const report = {
    schema: VERIFY_REPORT_SCHEMA,
    tool: toolName,
    status,
    artifact: current.artifact,
    checks,
    comparison,
    applied: { source: applied.source, mitigations: applied.mitigations },
    requiresResign,
    limitations,
    summary: {
      checks: checks.length,
      passed: checks.filter((check) => check.status === 'passed').length,
      failed: failed.length,
      pending: pending.length,
      notApplicable: checks.filter((check) => check.status === 'not-applicable').length,
      entriesInspected: checks.length === 0 ? 0 : new Set(checks.map((check) => check.entry)).size,
      outOfScopeEntries: outOfScope,
    },
  };
  return { exitCode: status === 'passed' ? 0 : 1, report };
}

/**
 * 对一个条目跑全部适用检查族。
 * @param {{entry: Record<string, unknown>, containerType: string, bytes: Buffer, policy: Record<string, unknown>, applied: string[]}} input
 * @returns {Array<Record<string, unknown>>} 检查记录列表
 */
function checkEntry({ entry, containerType, bytes, policy, applied }) {
  const base = { container: containerType, entry: entry.relativePath };
  const inspection = inspectContainer(containerType, bytes);
  if (inspection === null) {
    // 容器在 v1 格式集内却没有登记结构检查函数：判不了，不冒充通过。
    const reason = `容器 ${containerType} 没有登记的结构检查函数，本次无法判定`;
    return FAMILIES_BY_CONTAINER[containerType].map((family) => ({ ...base, family, status: 'pending', reason }));
  }
  const records = [];

  // 1. 容器解析。
  records.push({
    ...base,
    family: 'container-parse',
    status: inspection.parse.parseable ? 'passed' : 'failed',
    reason: inspection.parse.parseable
      ? `容器结构可解析：${inspection.parse.structures.join('、')}`
      : `容器结构解析失败：${inspection.parse.reason}`,
  });

  // 2. 签名一致性。
  if (SIGNATURE_OBSERVER_CONTAINERS.includes(containerType)) {
    records.push(signatureCheck(base, containerType, bytes, policy, applied));
  }

  // 3. 校验和一致性。
  if (CHECKSUM_OBSERVER_CONTAINERS.includes(containerType)) {
    records.push(checksumCheck(base, containerType, bytes));
  }

  // 4. pyc 标志与哈希状态一致性。
  if (containerType === 'pyc') {
    records.push(pycFlagCheck(base, inspection));
  }

  // 5. 必需节完整性（含按施加记录派生的豁免）。
  records.push(requiredSectionsCheck(base, containerType, inspection.facts, applied));

  return records;
}

/**
 * 签名一致性检查：只观察不验证密码学信任。
 * 检得出的不一致是“签名载荷范围超出文件长度”；检不出的（签名与字节是否匹配）不在静态可判定范围内，
 * 因此检出签名且施加过缓解措施时标记 requiresResign，由用户用自有签名身份重新签名后放行。
 * @param {Record<string, unknown>} base 检查记录基础字段
 * @param {string} containerType 容器标识
 * @param {Buffer} bytes 制品字节
 * @param {Record<string, unknown>} policy 策略
 * @param {readonly string[]} applied 制品级已施加缓解编号，见 resolveAppliedMitigations
 * @returns {Record<string, unknown>} 检查记录
 */
function signatureCheck(base, containerType, bytes, policy, applied) {
  const observations = analyzeByContainer(bytes, containerType, { policy });
  const observation = observations[0];
  if (observation === undefined) {
    return { ...base, family: 'signature-consistency', status: 'not-applicable', reason: '该容器没有登记的签名观察器' };
  }
  if (!observation.parseable) {
    // 观察器解析不了制品：结构失败由容器解析检查族判定，这里只记无法判定，不重复计失败。
    return {
      ...base,
      family: 'signature-consistency',
      status: 'pending',
      reason: `签名观察器无法解析该制品：${observation.limitation}。结构是否损坏由容器解析检查族判定`,
      detail: { observer: observation.observer },
    };
  }
  if (observation.signatureDetected !== true) {
    return {
      ...base,
      family: 'signature-consistency',
      status: 'not-applicable',
      reason: signatureAbsentReason(observation.observer),
      detail: { observer: observation.observer },
    };
  }
  const range = signatureRangeOf(observation, bytes.length);
  const detail = { observer: observation.observer };
  let reason = range.reason;
  if (!range.ok) {
    return { ...base, family: 'signature-consistency', status: 'failed', reason, detail };
  }
  if (applied.length > 0) {
    // 施加记录显示制品的字节被缓解措施改过：签名是否仍匹配不在静态可判定范围内，只能标记。
    detail.requiresResign = true;
    reason += `；施加记录显示已施加 ${applied.length} 项缓解措施，签名可能已失效，须由用户用自有签名身份重新签名后放行`;
  }
  return { ...base, family: 'signature-consistency', status: 'passed', reason, detail };
}

/**
 * 未检出签名机制时的检查理由，按观察器给出具体说明。
 * @param {string} observer 观察器标识
 * @returns {string}
 */
function signatureAbsentReason(observer) {
  if (observer === 'zip-entry-crc32') {
    return 'ZIP 没有代码签名机制可验（APK 签名方案不在 v1 范围）；条目一致性由校验和一致性检查族负责';
  }
  if (observer === 'elf-note') {
    return '未检出代码签名机制；ELF note 为构建标识等元数据，不构成签名门，改写 note 内容走必需集豁免';
  }
  return '未检出代码签名机制，本次不做签名一致性判定';
}

/**
 * 判定签名载荷范围是否在文件内。
 * @param {Record<string, unknown>} observation 观察结果
 * @param {number} fileLength 文件字节数
 * @returns {{ok: boolean, reason: string}}
 */
function signatureRangeOf(observation, fileLength) {
  if (observation.observer === 'pe-security-and-checksum') {
    const directory = observation.securityDirectory;
    const end = (directory.fileOffset ?? 0) + directory.size;
    return end <= fileLength
      ? { ok: true, reason: `检出 PE 安全目录（Authenticode 签名），证书表范围 [${directory.fileOffset}, ${end}) 在文件内` }
      : { ok: false, reason: `PE 安全目录声明范围 [${directory.fileOffset}, ${end}) 超出文件长度 ${fileLength}，签名载荷不完整` };
  }
  if (observation.observer === 'mach-o-code-signature') {
    const signed = observation.slices.filter((slice) => slice.hasCodeSignature);
    for (const slice of signed) {
      // 胖二进制分片的 dataoff 相对分片起点，瘦二进制分片起点为 0。
      const end = slice.offset + slice.codeSignature.dataoff + slice.codeSignature.datasize;
      if (end > fileLength) {
        return { ok: false, reason: `分片 ${slice.offset} 的 LC_CODE_SIGNATURE 声明范围超出文件长度 ${fileLength}，签名载荷不完整` };
      }
    }
    return { ok: true, reason: `检出 LC_CODE_SIGNATURE，${signed.length} 个分片带签名，签名载荷范围均在文件内` };
  }
  return { ok: true, reason: '观察器未声明签名载荷范围，本次只登记存在性' };
}

/**
 * 校验和一致性检查：PE 可选头 CheckSum 与重算值比对，ZIP 条目 CRC32 与中央目录项比对。
 * @param {Record<string, unknown>} base 检查记录基础字段
 * @param {string} containerType 容器标识
 * @param {Buffer} bytes 制品字节
 * @returns {Record<string, unknown>} 检查记录
 */
function checksumCheck(base, containerType, bytes) {
  const observations = analyzeByContainer(bytes, containerType, { policy: {} });
  const observation = observations[0];
  if (observation === undefined) {
    return { ...base, family: 'checksum-consistency', status: 'not-applicable', reason: '该容器没有登记的校验和观察器' };
  }
  if (!observation.parseable) {
    return {
      ...base,
      family: 'checksum-consistency',
      status: 'pending',
      reason: `校验和观察器无法解析该制品：${observation.limitation}。结构是否损坏由容器解析检查族判定`,
      detail: { observer: observation.observer },
    };
  }
  if (observation.observer === 'pe-security-and-checksum') {
    if (observation.checksum.nonZero !== true) {
      return {
        ...base,
        family: 'checksum-consistency',
        status: 'not-applicable',
        reason: '可选头 CheckSum 为零，该制品没有可验的校验和机制',
        detail: { observer: observation.observer, value: observation.checksum.value },
      };
    }
    const recomputed = computePeChecksum(bytes, observation.checksum.fieldOffset);
    const consistent = recomputed === observation.checksum.value;
    return {
      ...base,
      family: 'checksum-consistency',
      status: consistent ? 'passed' : 'failed',
      reason: consistent
        ? `可选头 CheckSum 与重算值一致（0x${recomputed.toString(16)}）`
        : `可选头 CheckSum 与重算值不一致：存储 0x${observation.checksum.value.toString(16)}，重算 0x${recomputed.toString(16)}。等长改写后未同帧重算，或制品在写入后又被改动`,
      detail: { observer: observation.observer, stored: observation.checksum.value, recomputed },
    };
  }
  // ZIP 条目 CRC32。
  if (observation.entries.length === 0) {
    return {
      ...base,
      family: 'checksum-consistency',
      status: 'not-applicable',
      reason: '没有可枚举的 ZIP 条目，没有校验和可验',
      detail: { observer: observation.observer },
    };
  }
  const inconsistent = observation.entries.filter((entry) => entry.consistent === false).map((entry) => entry.name);
  const scanModes = [...new Set(observation.entries.map((entry) => entry.methodName))].join('、');
  return {
    ...base,
    family: 'checksum-consistency',
    status: observation.allCrcConsistent === true ? 'passed' : 'failed',
    reason:
      observation.allCrcConsistent === true
        ? `逐条目 CRC32 与中央目录项一致（${observation.entries.length} 条，压缩方法 ${scanModes}）`
        : `${inconsistent.length} 个条目的 CRC32 与数据重算值不一致（${inconsistent.join('、')}）：改写条目数据后未同帧重算，或制品被改动`,
    detail: { observer: observation.observer, inconsistentEntries: inconsistent },
  };
}

/**
 * pyc 标志与哈希状态一致性检查。
 * 规则只有一条：hash_based 置位而源哈希清零时，check_source 必须一并清除，
 * 否则运行期会拿着全零哈希核对源文件——标志与哈希状态不一致。
 * @param {Record<string, unknown>} base 检查记录基础字段
 * @param {Record<string, unknown>} inspection 容器检查结果
 * @returns {Record<string, unknown>} 检查记录
 */
function pycFlagCheck(base, inspection) {
  const state = inspection.flagState;
  if (state === null || state.readable !== true) {
    return {
      ...base,
      family: 'pyc-flag-consistency',
      status: 'pending',
      reason: '文件不足 16 字节，读不到标志位与源哈希字段，标志与哈希状态本次没有覆盖',
    };
  }
  if (state.hashBased !== true) {
    return {
      ...base,
      family: 'pyc-flag-consistency',
      status: 'not-applicable',
      reason: '该制品不是 hash_based，没有源哈希字段可核对；时间戳制式的头字段由必需集覆盖',
    };
  }
  if (state.checkSource === true && state.sourceHashZero === true) {
    return {
      ...base,
      family: 'pyc-flag-consistency',
      status: 'failed',
      reason: 'check_source 标志置位但源文件哈希已清零，标志与哈希状态不一致：运行期会拿全零哈希核对源文件',
    };
  }
  if (state.checkSource === false && state.sourceHashZero === true) {
    return {
      ...base,
      family: 'pyc-flag-consistency',
      status: 'passed',
      reason: '源文件哈希已清零且 check_source 一并清除，与 metadata.pyc-source-hash-clear 的预期状态一致',
    };
  }
  return {
    ...base,
    family: 'pyc-flag-consistency',
    status: 'passed',
    reason: `hash_based 制品带非零源哈希，check_source ${state.checkSource ? '已置位' : '未置位'}，标志位与哈希状态一致`,
  };
}

/**
 * 必需节完整性检查：按格式必需集逐项判定，已施加缓解清单中的项从必需集移除。
 * @param {Record<string, unknown>} base 检查记录基础字段
 * @param {string} containerType 容器标识
 * @param {Record<string, unknown>} facts 结构事实表
 * @param {readonly string[]} applied 制品级已施加缓解编号，见 resolveAppliedMitigations
 * @returns {Record<string, unknown>} 检查记录
 */
function requiredSectionsCheck(base, containerType, facts, applied) {
  const result = checkRequiredSet(containerType, facts, applied);
  const detail = {
    schema: result.schema,
    required: result.required,
    exempted: result.exempted,
    failedItems: result.items.filter((item) => item.status === 'failed').map((item) => item.id),
    unverifiedItems: result.items.filter((item) => item.status === 'unverified').map((item) => item.id),
    summary: result.summary,
  };
  const statusOf = {
    passed: 'passed',
    failed: 'failed',
    partial: 'pending',
    'not-applicable': 'not-applicable',
  };
  const reasonOf = {
    passed: `必需集 ${result.summary.total} 项全部可解析（${result.exempted.length} 项按施加记录豁免）`,
    failed: `必需集有 ${result.summary.failed} 项不可解析：${detail.failedItems.join('、')}。缓解措施破坏了合法用户依赖的结构`,
    partial: `必需集有 ${result.summary.unverified} 项未提供结构事实（${detail.unverifiedItems.join('、')}），本次不判定通过`,
    'not-applicable': result.reason ?? '该容器没有登记必需集，本次不适用',
  };
  return {
    ...base,
    family: 'required-sections',
    status: statusOf[result.status],
    reason: reasonOf[result.status],
    detail,
  };
}

/**
 * 解析已施加缓解记录，得出制品级编号清单。
 * 豁免按整件生效，不按条目细分，理由有两条：
 *   1. 典型流程里加固产物写在 <目标>.hardened，基线审计发现的 evidence.path 与复审条目
 *      路径天然对不上，按条目匹配会在唯一真实的流程上失效；
 *   2. 反推依据是“基线有、本次没有”的消失发现：键（层、分类、读取器）消失意味着
 *      该暴露在整件范围内不再被任何读取器看到，整件生效与观察到的现象一致。
 *      键仍在（同一标识还有别处落点）时不算消失，据此不派生豁免。
 * 两种来源：
 *   explicit        调用方显式给出施加记录，按 appliedMitigationIds 归一化
 *   baseline-diff   只有基线时，按消失发现的 mitigation 编号反推已施加措施
 *   none            两者都没有，任何项都不豁免
 * 出处记录在报告的 applied.source 字段里，供运营留痕核对。
 * @param {unknown} explicit 显式施加记录
 * @param {Record<string, unknown> | null} baseline 基线审计报告
 * @param {{resolved: unknown[]} | null} comparison 按稳定标识的比对结果，见 diffAuditsByKey
 * @returns {{source: string, mitigations: string[]}}
 */
function resolveAppliedMitigations(explicit, baseline, comparison) {
  if (explicit !== undefined && explicit !== null) {
    return { source: 'explicit', mitigations: appliedMitigationIds(explicit) };
  }
  if (baseline !== null && baseline !== undefined) {
    const mitigations = [];
    const seen = new Set();
    for (const finding of comparison?.resolved ?? []) {
      const id = finding?.mitigation;
      if (typeof id !== 'string' || id === '' || seen.has(id)) {
        continue;
      }
      seen.add(id);
      mitigations.push(id);
    }
    return { source: 'baseline-diff', mitigations };
  }
  return { source: 'none', mitigations: [] };
}
