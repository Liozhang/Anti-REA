// 报告脱敏：保留分类与计数，隐去精确路径、字节范围与缓解措施对应关系。
// 用于把报告分享给合作方、审计机构或漏洞披露程序的场景。
// 脱敏是单向的：脱敏后的报告不能反向还原路径，因此不能替代原件留档。
//
// 隐去路径靠两道 scrub，缺一不可：
//   1. 精确 scrub。制品路径与全部证据路径（含裸文件名）来自报告自身，
//      先替换它们，覆盖“路径字段被删了但自由文本里还留着”的情况；
//   2. 形态 scrub。限制说明是自由文本，读取器出错时会把条目相对路径写进
//      消息（见 src/readers/common.mjs 的 reader-error 分支），这类路径
//      在报告其他地方没有踪迹，只能按路径形态识别：词首是根（盘符、
//      '/'、'./'、'../'），或末段带短扩展名。'elf/pe/mach-o'、'和/或'
//      这类非路径斜杠两种形态都不命中，不误伤。

/** 路径被隐去后的占位符。 */
const REDACTED_PATH = '（路径已脱敏）';

/** 路径形态：词首为根，或末段带短扩展名；只在词首起算，不吞掉半个词。 */
const PATH_TOKEN = /(?<![^\s])(?:(?:\.{1,2}|[A-Za-z]:)?[\\/][^\s]*|[^\s]*[\\/][^\s]*\.[A-Za-z0-9]{1,8}(?![A-Za-z0-9]))/g;

/**
 * 收集需要精确替换的路径串：制品路径、全部证据路径（各带裸文件名），
 * 以及复审报告里逐条目检查与跳过记录中的条目路径。
 * 后两类整条替换、不带裸文件名：条目路径已经够短，再拆裸文件名只会
 * 增加把普通词汇当成路径误伤的概率。
 * 长串优先替换，避免 '/a/b/c' 被裸名 'c' 抢先替换后留下残缺路径。
 * @param {Record<string, unknown>} report 原始报告
 * @returns {string[]}
 */
function scrubTargetsOf(report) {
  const targets = new Set();
  const add = (value) => {
    if (typeof value !== 'string' || value === '') {
      return;
    }
    targets.add(value);
    const base = value.split(/[\\/]/).pop();
    if (base !== undefined && base !== '') {
      targets.add(base);
    }
  };
  const addWhole = (value) => {
    if (typeof value === 'string' && value !== '') {
      targets.add(value);
    }
  };
  add(report?.artifact?.path);
  for (const finding of Array.isArray(report?.findings) ? report.findings : []) {
    add(finding?.evidence?.path);
  }
  // 复审报告的 checks 与 skipped 携带条目路径，脱敏时整块丢弃；
  // 但它们可能已被写进 limitations 的自由文本，这里先把路径收进来。
  for (const check of Array.isArray(report?.checks) ? report.checks : []) {
    addWhole(check?.entry);
  }
  for (const skipped of Array.isArray(report?.skipped) ? report.skipped : []) {
    addWhole(skipped?.relativePath);
  }
  return [...targets].sort((left, right) => right.length - left.length);
}

/**
 *  scrub 一段自由文本：先精确替换已知路径，再按形态替换残余路径样串。
 * @param {string} text 原始文本
 * @param {readonly string[]} targets 精确路径串，长串优先
 * @returns {string}
 */
function scrubText(text, targets) {
  if (typeof text !== 'string' || text === '') {
    return text;
  }
  let out = text;
  for (const target of targets) {
    out = out.split(target).join(REDACTED_PATH);
  }
  return out.replace(PATH_TOKEN, REDACTED_PATH);
}

/**
 * 脱敏一份审计或复审报告。
 * 隐去内容：
 *   artifact.path              精确路径
 *   findings[].evidence        精确路径、字节范围与摘录
 *   findings[].mitigation      缓解措施对应关系
 *   limitations[].message      自由文本里可能夹带的条目路径
 * 保留内容：
 *   制品摘要、字节数、容器类型、逐层逐严重度计数、分类名、能力边界分类与限制说明
 * @param {Record<string, unknown>} report 原始报告
 * @returns {Record<string, unknown>} 脱敏后的报告，原对象不被修改
 */
export function redactReport(report) {
  const targets = scrubTargetsOf(report);
  const findings = (Array.isArray(report?.findings) ? report.findings : []).map((finding) => ({
    layer: finding.layer,
    severity: finding.severity,
    category: finding.category,
    reader: finding.reader,
  }));

  const boundaries = (Array.isArray(report?.capabilityBoundaries) ? report.capabilityBoundaries : []).map((boundary) => ({
    id: boundary.id,
    label: scrubText(boundary.label, targets),
    reason: scrubText(boundary.reason, targets),
    count: boundary.count ?? 1,
  }));

  const limitations = (Array.isArray(report?.limitations) ? report.limitations : []).map((limitation) => ({
    code: limitation.code,
    message: scrubText(limitation.message, targets),
    scope: limitation.scope,
  }));

  const redacted = {
    schema: report.schema,
    tool: report.tool,
    status: report.status,
    redacted: true,
    artifact: {
      kind: report.artifact?.kind,
      sha256: report.artifact?.sha256,
      bytes: report.artifact?.bytes,
      entryCount: report.artifact?.entryCount,
    },
    findings,
    capabilityBoundaries: boundaries,
    containers: report.containers ?? [],
    limitations,
    summary: report.summary ?? {},
  };
  if (report.artifact?.container !== undefined) {
    redacted.artifact.container = report.artifact.container;
  }
  if (report.generatedAt !== undefined) {
    redacted.generatedAt = report.generatedAt;
  }
  if (report.comparison !== undefined) {
    redacted.comparison = redactComparison(report.comparison);
  }
  if (report.requiresResign === true) {
    // 需要重新签名是与路径无关的安全信号：分享脱敏报告时丢掉它，
    // 收件方可能把未重新签名的制品直接放行，因此保留。
    redacted.requiresResign = true;
  }
  return redacted;
}

/**
 * 脱敏前后差异比对结果，同样隐去路径与字节范围。
 * @param {Record<string, unknown> | null} comparison
 * @returns {Record<string, unknown> | null}
 */
function redactComparison(comparison) {
  if (comparison === null) {
    return null;
  }
  const count = (list) => (Array.isArray(list) ? list.length : 0);
  return {
    resolved: count(comparison.resolved),
    introduced: count(comparison.introduced),
    persisting: count(comparison.persisting),
  };
}

/**
 * 判断一份报告是否已脱敏。
 * @param {Record<string, unknown>} report
 * @returns {boolean}
 */
export function isRedacted(report) {
  return report?.redacted === true;
}
