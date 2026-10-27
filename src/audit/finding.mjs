// 发现模型：审计输出的最小单元。
// 每条发现都带编号、证据、会消费它的读取器、读取器自身声明限制，以及建议的缓解措施编号。
// 编号、层、严重度、缓解编号四样全部取自封闭词表：读取器可以写错，报告不行。

import { LAYER_IDS, SEVERITY_IDS, TOOL_IDS } from './layer-defs.mjs';

/** 缓解措施编号封闭集合。编号在报告与施加记录之间传递。 */
export const MITIGATION_IDS = Object.freeze([
  'metadata.go-buildinfo-inline-overwrite',
  'metadata.go-buildinfo-pointer-overwrite',
  'metadata.go-buildinfo-writable-region-overwrite',
  'metadata.go-buildinfo-macho-rw-overwrite',
  'metadata.go-buildinfo-pe-characteristics-overwrite',
  'metadata.rust-dep-section-overwrite',
  'metadata.elf-symtab-clear',
  'metadata.elf-build-id-note-overwrite',
  'metadata.pe-debug-directory-overwrite',
  'metadata.pyc-source-hash-clear',
  'content.data-segment-overwrite',
  'runtime.probe-integration-package',
  'model.safetensors-metadata-relayout',
  'model.gguf-metadata-relayout',
  'secret.token-placeholder-overwrite',
]);

/**
 * 生成发现编号。编号在同一份报告内唯一，格式为层内递增。
 * @param {string} layerId 层标识
 * @param {number} index 层内序号，从 1 开始
 * @returns {string}
 */
export function findingId(layerId, index) {
  if (!LAYER_IDS.includes(layerId)) {
    throw new RangeError(`层标识不在封闭词表内：${layerId}`);
  }
  if (!Number.isSafeInteger(index) || index < 0) {
    throw new RangeError(`发现序号必须是非负整数：${String(index)}`);
  }
  return `F-${layerId}-${String(index).padStart(4, '0')}`;
}

/**
 * 给一批发现按层顺序编号，直接写回 finding.id 并返回同一数组。
 * 审计引擎在汇总前调用：编号在报告内唯一、可被施加记录引用。
 * 入参必须先过 assertFindingVocabulary，否则编号会落在词表外。
 * @param {Array<Record<string, unknown>>} findings 发现列表
 * @returns {Array<Record<string, unknown>>} 同一数组
 */
export function numberFindings(findings) {
  const counters = new Map();
  for (const finding of findings) {
    const next = (counters.get(finding.layer) ?? 0) + 1;
    counters.set(finding.layer, next);
    finding.id = findingId(finding.layer, next);
  }
  return findings;
}

/**
 * 校验一条发现的结构与词表取值。读取器输出先过这一关才进报告：
 * 层、严重度、缓解编号必须取自封闭词表，证据必须带路径。
 * 校验不过时抛 RangeError 或 TypeError，由审计引擎转成限制说明，不让审计失败。
 * @param {unknown} finding 待校验的发现
 * @returns {Record<string, unknown>} 校验通过的发现
 */
export function assertFindingVocabulary(finding) {
  if (finding === null || typeof finding !== 'object' || Array.isArray(finding)) {
    throw new TypeError('发现必须是对象');
  }
  if (!LAYER_IDS.includes(finding.layer)) {
    throw new RangeError(`层标识不在封闭词表内：${String(finding.layer)}`);
  }
  if (!SEVERITY_IDS.includes(finding.severity)) {
    throw new RangeError(`严重度不在封闭词表内：${String(finding.severity)}`);
  }
  for (const field of ['title', 'category', 'reader']) {
    if (typeof finding[field] !== 'string' || finding[field] === '') {
      throw new RangeError(`发现缺少字段 ${field}，或该字段不是非空字符串`);
    }
  }
  if (typeof finding.readerLimitation !== 'string') {
    throw new RangeError('发现缺少字段 readerLimitation，或该字段不是字符串');
  }
  const evidence = finding.evidence;
  if (evidence === null || typeof evidence !== 'object' || Array.isArray(evidence)) {
    throw new RangeError('发现缺少 evidence 对象');
  }
  if (typeof evidence.path !== 'string' || evidence.path === '') {
    throw new RangeError('发现缺少 evidence.path');
  }
  if (evidence.byteRange !== undefined && evidence.byteRange !== null) {
    const range = evidence.byteRange;
    if (!Array.isArray(range) || range.length !== 2 || !range.every((value) => Number.isFinite(value) && value >= 0)) {
      throw new RangeError('发现的 evidence.byteRange 必须是两个非负数字');
    }
  }
  if (finding.mitigation !== undefined && finding.mitigation !== null && !MITIGATION_IDS.includes(finding.mitigation)) {
    throw new RangeError(`缓解措施编号不在已登记集合内：${String(finding.mitigation)}`);
  }
  return finding;
}

/**
 * 构造一条发现，并在构造时校验层、严重度与工具标识是否在词表内。
 * @param {{
 *   layer: string,
 *   severity: string,
 *   title: string,
 *   category: string,
 *   evidence: {path: string, byteRange?: [number, number], excerpt?: string},
 *   reader: string,
 *   readerLimitation: string,
 *   mitigation?: string,
 *   detail?: Record<string, unknown>
 * }} input
 * @returns {Record<string, unknown>}
 */
export function createFinding(input) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('发现输入必须是对象');
  }
  if (input.evidence === null || typeof input.evidence !== 'object' || Array.isArray(input.evidence)) {
    throw new TypeError('发现输入缺少 evidence 对象');
  }
  const finding = {
    layer: input.layer,
    severity: input.severity,
    title: input.title,
    category: input.category,
    evidence: {
      path: input.evidence.path,
      byteRange: input.evidence.byteRange ?? null,
      excerpt: input.evidence.excerpt ?? null,
    },
    reader: input.reader,
    readerLimitation: input.readerLimitation,
    mitigation: input.mitigation ?? null,
  };
  if (input.detail !== undefined) {
    finding.detail = input.detail;
  }
  // 构造时统一过词表关：层、严重度、缓解编号、证据路径有一项越界就不放行。
  assertFindingVocabulary(finding);
  return finding;
}

/**
 * 按层与严重度汇总发现，供报告的分类与计数使用。
 * 词表封闭：汇总只承认词表内的层与严重度，词表外取值抛 RangeError，
 * 而不是悄悄多出一个计数键——那会让“按层汇总恰好覆盖七层”的约定失效。
 * @param {Array<Record<string, unknown>>} findings 发现列表
 * @returns {{total: number, byLayer: Record<string, number>, bySeverity: Record<string, number>}}
 */
export function summarizeFindings(findings) {
  const byLayer = {};
  const bySeverity = {};
  for (const layerId of LAYER_IDS) {
    byLayer[layerId] = 0;
  }
  for (const severity of SEVERITY_IDS) {
    bySeverity[severity] = 0;
  }
  for (const finding of findings) {
    if (!LAYER_IDS.includes(finding.layer)) {
      throw new RangeError(`层标识不在封闭词表内：${String(finding.layer)}`);
    }
    if (!SEVERITY_IDS.includes(finding.severity)) {
      throw new RangeError(`严重度不在封闭词表内：${String(finding.severity)}`);
    }
    byLayer[finding.layer] += 1;
    bySeverity[finding.severity] += 1;
  }
  return { total: findings.length, byLayer, bySeverity };
}

export { LAYER_IDS, SEVERITY_IDS, TOOL_IDS };
