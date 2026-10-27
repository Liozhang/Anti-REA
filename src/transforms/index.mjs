// 缓解措施实现：transforms 模块出口。
// 分两类写入性质，每项都声明功能风险与签名影响：
//   等长覆写   保持文件长度与全部偏移不变，结构性安全
//   重布局写入 整体重新序列化、按原对齐规则重排，并重跑全部格式校验
// 另有一类只生成集成包、不改动制品：反运行时观察集成包由 probe-kit 生成，本模块遇到它时
// 明确跳过并附原因，不静默跳过，也不在 transforms 里另写一份生成逻辑。
//
// 加固引擎（harden 工作流）的入口是 applyMitigations：读一次、按序施加、写出一次，
// 返回的批量结果带 applied、skipped、changed、requiresResign、checksumRecomputed 与制品摘要，
// 供加固报告直接引用。逐个发现调用登记表上的 apply 也能得到正确字节：同一进程内同一对
// 输入输出路径会复用工作缓冲区，后一次施加叠在前一次的结果上，不会互相覆盖；
// 跨进程的每次调用都从制品原件重新读起，不把磁盘上已存在的输出当成输入。
//
// 全部读取与写入都在进程内完成：不启动目标、不附加进程、不发起网络请求，只用 Node.js 内置模块。

import { createHash } from 'node:crypto';
import { readFile as readFileFs, stat as statFs, writeFile as writeFileFs } from 'node:fs/promises';

import { NotImplementedError, UsageError } from '../errors.mjs';
import { MITIGATION_IDS } from '../audit/finding.mjs';
import {
  clearElfBuildIdNotes,
  clearElfSymtab,
  clearPycSourceHash,
  overwriteDataSegmentRange,
  overwriteGoBuildinfo,
  overwritePeDebugDirectoryPaths,
  overwriteRustDepSection,
  overwriteTokenPlaceholder,
} from './equal-length.mjs';
import { evaluateSignatureGate, recomputePeChecksumInPlace } from './gate.mjs';
import { writeGgufMetadata, writeSafetensorsMetadata } from './relayout.mjs';

/** 批量施加结果模式版本。 */
export const TRANSFORM_BATCH_SCHEMA = 'anti-rea.transform-batch/1';

/** 加固产物默认后缀：与目标同目录，避免覆盖原件。 */
export const DEFAULT_OUTPUT_SUFFIX = '.hardened';

/**
 * 逐发现施加用的进程内工作缓冲区：键为“输入路径加输出路径”。
 * 存在的意义是让按发现循环的调用方（每发现调一次 apply）也能得到组合后的正确字节：
 * 同一次运行里的后一次施加叠在前一次的结果上。跨进程不复用，每次从制品原件读起，
 * 因此磁盘上已存在的输出永远不会被当成输入，旧输出不会污染新一次加固。
 */
const WORKING_BUFFERS = new Map();

/** 工作缓冲区条数上限，超出按插入顺序淘汰最旧一条，避免长任务无限占用内存。 */
const WORKING_BUFFER_LIMIT = 256;

/** 缓解措施编号到写入性质的映射。 */
const TRANSFORM_KINDS = Object.freeze({
  'metadata.go-buildinfo-inline-overwrite': 'equal-length-overwrite',
  'metadata.go-buildinfo-pointer-overwrite': 'equal-length-overwrite',
  'metadata.go-buildinfo-writable-region-overwrite': 'equal-length-overwrite',
  'metadata.go-buildinfo-macho-rw-overwrite': 'equal-length-overwrite',
  'metadata.go-buildinfo-pe-characteristics-overwrite': 'equal-length-overwrite',
  'metadata.rust-dep-section-overwrite': 'equal-length-overwrite',
  'metadata.elf-symtab-clear': 'equal-length-overwrite',
  'metadata.elf-build-id-note-overwrite': 'equal-length-overwrite',
  'metadata.pe-debug-directory-overwrite': 'equal-length-overwrite',
  'metadata.pyc-source-hash-clear': 'equal-length-overwrite',
  'content.data-segment-overwrite': 'equal-length-overwrite',
  'runtime.probe-integration-package': 'generated-integration-package',
  'model.safetensors-metadata-relayout': 'relayout-write',
  'model.gguf-metadata-relayout': 'relayout-write',
  'secret.token-placeholder-overwrite': 'equal-length-overwrite',
});

/** 缓解措施编号到字节级施加函数的映射。探针集成包没有字节级实现，单独走拒写路径。 */
const BYTE_TRANSFORMS = Object.freeze({
  'metadata.go-buildinfo-inline-overwrite': (buffer, finding) => overwriteGoBuildinfo(buffer, finding),
  'metadata.go-buildinfo-pointer-overwrite': (buffer, finding) => overwriteGoBuildinfo(buffer, finding),
  'metadata.go-buildinfo-writable-region-overwrite': (buffer, finding) => overwriteGoBuildinfo(buffer, finding),
  'metadata.go-buildinfo-macho-rw-overwrite': (buffer, finding) => overwriteGoBuildinfo(buffer, finding),
  'metadata.go-buildinfo-pe-characteristics-overwrite': (buffer, finding) => overwriteGoBuildinfo(buffer, finding),
  'metadata.rust-dep-section-overwrite': (buffer, finding, context) => overwriteRustDepSection(buffer, finding, context.container),
  'metadata.elf-symtab-clear': (buffer, finding) => clearElfSymtab(buffer, finding),
  'metadata.elf-build-id-note-overwrite': (buffer) => clearElfBuildIdNotes(buffer),
  'metadata.pe-debug-directory-overwrite': (buffer) => overwritePeDebugDirectoryPaths(buffer),
  'metadata.pyc-source-hash-clear': (buffer) => clearPycSourceHash(buffer),
  'content.data-segment-overwrite': (buffer, finding) => overwriteDataSegmentRange(buffer, finding),
  'secret.token-placeholder-overwrite': (buffer, finding, context) => overwriteTokenPlaceholder(buffer, finding, context.container),
  'model.safetensors-metadata-relayout': (buffer, finding, context) => writeSafetensorsMetadata(buffer, context),
  'model.gguf-metadata-relayout': (buffer, finding, context) => writeGgufMetadata(buffer, context),
});

/**
 * 缓解措施登记表。字段：
 *   id              措施编号，与审计发现的 mitigation 字段对应
 *   kind            写入性质
 *   layer           所属层标识
 *   containers      适用容器；空数组表示不按容器限定
 *   functionalRisk  对合法用户的功能风险说明
 *   signatureImpact 对签名与校验和的影响
 *   applyToBuffer   字节级施加，同步函数，返回 {ok, buffer, ranges, notes, relayout?, zip?} 或 {ok:false, reason}
 *   apply           文件级施加，异步函数，读入、施加、写出，返回施加结果记录
 */
export const TRANSFORM_REGISTRY = Object.freeze(
  MITIGATION_IDS.map((id) =>
    Object.freeze({
      id,
      kind: TRANSFORM_KINDS[id],
      layer: layerOfMitigation(id),
      containers: containersOfMitigation(id),
      functionalRisk: functionalRiskOf(id),
      signatureImpact: signatureImpactOf(id),
      applyToBuffer: byteTransformOf(id),
      apply: async (input) => {
        // 没有字节级实现的措施在文件级入口上明确抛 NotImplementedError，
        // 让按“逐个发现施加”组织的调用方照旧走“跳过并附原因”的路径。
        if (BYTE_TRANSFORMS[id] === undefined) {
          throw new NotImplementedError(`transforms/${id}`, '施加逻辑尚未实现');
        }
        return await applyMitigation({ ...input, finding: input.finding, policy: input.policy ?? {} });
      },
    }),
  ),
);

/**
 * 按编号取缓解措施。
 * @param {string} mitigationId 措施编号
 * @returns {Record<string, unknown> | null}
 */
export function transformById(mitigationId) {
  return TRANSFORM_REGISTRY.find((transform) => transform.id === mitigationId) ?? null;
}

/**
 * 列出全部缓解措施的元数据，不暴露任何施加函数。
 * @returns {readonly Record<string, unknown>[]}
 */
export function listTransforms() {
  return TRANSFORM_REGISTRY.map(({ apply, applyToBuffer, ...metadata }) => Object.freeze(metadata));
}

/**
 * 按写入性质取缓解措施。
 * @param {'equal-length-overwrite' | 'relayout-write' | 'generated-integration-package'} kind
 * @returns {readonly Record<string, unknown>[]}
 */
export function transformsOfKind(kind) {
  return TRANSFORM_REGISTRY.filter((transform) => transform.kind === kind);
}

/**
 * 批量施加缓解措施：加固引擎的唯一入口。
 * 先按资源预算确认文件可读，再整体评估签名门控，然后按发现顺序逐项施加到同一份工作缓冲区，
 * 最后一次性写出。任何一项定位不到目标都只记“跳过并附原因”，不影响其余项；
 * 门控不允许或超出单文件上限时全部跳过，且不写出任何字节。
 * @param {{
 *   target: string,
 *   findings: readonly Record<string, unknown>[],
 *   policy?: Record<string, unknown>,
 *   outputPath?: string,
 *   inputPath?: string,
 *   metadata?: Record<string, string | string[]>,
 *   compose?: boolean,
 *   io?: {readFile?: Function, writeFile?: Function, stat?: Function},
 * }} input compose 为真时按进程内工作缓冲区组合多项措施，仅供逐发现施加入口使用
 * @returns {Promise<Record<string, unknown>>} 批量施加结果
 */
export async function applyMitigations(input) {
  const target = input.target;
  if (typeof target !== 'string' || target.trim() === '') {
    throw new TypeError('applyMitigations 需要目标文件路径');
  }
  const inputPath = typeof input.inputPath === 'string' && input.inputPath !== '' ? input.inputPath : target;
  const outputPath = typeof input.outputPath === 'string' && input.outputPath !== '' ? input.outputPath : `${target}${DEFAULT_OUTPUT_SUFFIX}`;
  const read = input.io?.readFile ?? readFileFs;
  const write = input.io?.writeFile ?? writeFileFs;
  const statPath = input.io?.stat ?? statFs;
  const findings = Array.isArray(input.findings) ? input.findings : [];
  const compose = input.compose === true;
  const cacheKey = `${inputPath}\u0000${outputPath}`;

  // 资源预算：单文件上限与审计同一口径。超限时不读取内容，全部发现记跳过并附限制说明。
  const maxFileBytes = input.policy?.budgets?.maxFileBytes;
  if (typeof maxFileBytes === 'number' && Number.isFinite(maxFileBytes)) {
    const info = await statPath(inputPath).catch(() => null);
    const fileSize = info === null ? null : Number(info.size);
    if (fileSize !== null && fileSize > maxFileBytes) {
      return budgetExceededResult({
        inputPath,
        outputPath,
        fileSize,
        maxFileBytes,
        findings,
      });
    }
  }

  let original;
  try {
    original = compose && WORKING_BUFFERS.has(cacheKey) ? WORKING_BUFFERS.get(cacheKey) : await read(inputPath);
  } catch (error) {
    throw new UsageError(`无法读取目标文件：${inputPath}`, { cause: String(error) });
  }
  const inputBytes = Buffer.isBuffer(original) ? original : Buffer.from(original);
  const state = { buffer: Buffer.from(inputBytes) };
  state.gate = evaluateSignatureGate(state.buffer, input.policy ?? {});

  const applied = [];
  const skipped = [];
  const limitations = [];
  // 重布局写入是整体重新序列化，同一文件同一编号只施加一次：
  // 模型文件上“元数据键值”与“张量索引”两类发现映射同一编号，重复施加会堆重复键。
  const relayoutDone = new Set();
  for (const finding of findings) {
    const mitigationId = typeof finding?.mitigation === 'string' ? finding.mitigation : null;
    const transform = mitigationId === null ? null : transformById(mitigationId);
    if (transform !== null && transform.kind === 'relayout-write' && relayoutDone.has(mitigationId)) {
      skipped.push({
        mitigation: mitigationId,
        finding: typeof finding?.id === 'string' ? finding.id : null,
        kind: transform.kind,
        layer: transform.layer,
        status: 'skipped',
        changed: false,
        reason: `重布局写入 ${mitigationId} 已在本批次内施加过一次，整体重新序列化只做一次`,
        notes: [],
      });
      continue;
    }
    const outcome = applyOne(state, finding, input.policy ?? {}, input.metadata);
    if (outcome.status === 'applied') {
      applied.push(outcome);
      if (transform !== null && transform.kind === 'relayout-write') {
        relayoutDone.add(mitigationId);
      }
    } else {
      skipped.push(outcome);
    }
  }

  // PE CheckSum 重算放在全部覆写之后：校验和覆盖整份文件，早算等于白算。
  let checksum = null;
  if (state.gate.recomputeChecksum && !state.buffer.equals(inputBytes)) {
    const recomputed = recomputePeChecksumInPlace(state.buffer);
    if (recomputed !== null) {
      checksum = recomputed;
    } else {
      limitations.push('策略允许重算 PE CheckSum，但改写后的字节里定位不到 CheckSum 字段，本次未重算');
    }
  }

  // 组合模式把本次结果记回工作缓冲区：同一进程内下一次施加从这里接着改。
  if (compose) {
    WORKING_BUFFERS.set(cacheKey, state.buffer);
    if (WORKING_BUFFERS.size > WORKING_BUFFER_LIMIT) {
      const oldest = WORKING_BUFFERS.keys().next().value;
      WORKING_BUFFERS.delete(oldest);
    }
  }

  const existing = await tryRead(outputPath, read);
  const identicalToExisting = existing !== null && existing.equals(state.buffer);
  // 改动的定义与加固报告一致：本次产出与已存在输出逐字节相同时不算改动。
  const changed = !state.buffer.equals(inputBytes) && !identicalToExisting;
  const wrote = changed && !identicalToExisting;
  if (wrote) {
    await write(outputPath, state.buffer);
  }

  const notes = [];
  for (const entry of [...applied, ...skipped]) {
    for (const note of entry.notes ?? []) {
      notes.push(note);
    }
  }
  for (const observation of state.gate.observations) {
    if (typeof observation.limitation === 'string' && observation.limitation !== '') {
      limitations.push(observation.limitation);
    }
  }

  return {
    schema: TRANSFORM_BATCH_SCHEMA,
    status: applied.length > 0 ? 'applied' : 'no-op',
    tool: 'harden-artifact',
    artifact: {
      kind: 'file',
      inputPath,
      outputPath: wrote || identicalToExisting ? outputPath : null,
      bytesBefore: inputBytes.length,
      bytesAfter: state.buffer.length,
      sha256Before: createHash('sha256').update(inputBytes).digest('hex'),
      sha256After: createHash('sha256').update(state.buffer).digest('hex'),
    },
    container: state.gate.container,
    gate: {
      allowed: state.gate.allowed,
      reason: state.gate.reason,
      requiresResign: state.gate.requiresResign,
      recomputeChecksum: state.gate.recomputeChecksum,
    },
    applied,
    skipped,
    changed,
    wrote,
    idempotent: identicalToExisting,
    requiresResign: state.gate.requiresResign && applied.length > 0,
    checksumRecomputed: checksum !== null,
    checksum,
    notes,
    limitations,
  };
}

/**
 * 单项施加：读入目标、施加一项措施、写出到输出路径。
 * 默认输出路径取目标同目录加固定后缀。同一进程内对同一对输入输出路径的多次调用会组合：
 * 后一次施加叠在前一次的结果上，因此按发现循环调用也能得到叠加全部措施的字节。
 * 跨进程的每次调用都从制品原件读起，磁盘上已存在的输出不会被当成输入。
 * @param {{
 *   target: string,
 *   finding: Record<string, unknown>,
 *   policy?: Record<string, unknown>,
 *   outputPath?: string,
 *   inputPath?: string,
 *   metadata?: Record<string, string | string[]>,
 *   io?: {readFile?: Function, writeFile?: Function, stat?: Function},
 * }} input
 * @returns {Promise<Record<string, unknown>>} 批量施加结果（只含一项）
 */
export async function applyMitigation(input) {
  return await applyMitigations({ ...input, findings: [input.finding], compose: true });
}

/**
 * 构造单文件超限时的批量结果：不读取内容、不写出字节，全部发现记跳过并附限制说明。
 * @param {{inputPath: string, outputPath: string, fileSize: number, maxFileBytes: number, findings: readonly Record<string, unknown>[]}} input
 * @returns {Record<string, unknown>}
 */
function budgetExceededResult({ inputPath, outputPath, fileSize, maxFileBytes, findings }) {
  const reason = `条目字节数 ${fileSize} 超过单文件上限 ${maxFileBytes}，未读取其内容，本次没有施加任何措施`;
  return {
    schema: TRANSFORM_BATCH_SCHEMA,
    status: 'no-op',
    tool: 'harden-artifact',
    artifact: {
      kind: 'file',
      inputPath,
      outputPath: null,
      bytesBefore: fileSize,
      bytesAfter: fileSize,
      sha256Before: null,
      sha256After: null,
    },
    container: 'unknown',
    gate: { allowed: false, reason, requiresResign: false, recomputeChecksum: false },
    applied: [],
    skipped: findings.map((finding) => ({
      mitigation: typeof finding?.mitigation === 'string' ? finding.mitigation : null,
      finding: typeof finding?.id === 'string' ? finding.id : null,
      kind: null,
      layer: null,
      status: 'skipped',
      changed: false,
      reason,
      notes: [],
    })),
    changed: false,
    wrote: false,
    idempotent: false,
    requiresResign: false,
    checksumRecomputed: false,
    checksum: null,
    notes: [],
    limitations: [{ code: 'max-file-bytes-exceeded', message: reason, scope: 'artifact' }],
  };
}

/**
 * 对工作缓冲区施加一项措施。
 * @param {{buffer: Buffer, gate: Record<string, unknown>}} state 可变工作状态
 * @param {Record<string, unknown>} finding 审计发现
 * @param {Record<string, unknown>} policy 策略
 * @param {Record<string, string | string[]> | undefined} metadata 模型层元数据内容
 * @returns {Record<string, unknown>} 单项结果
 */
function applyOne(state, finding, policy, metadata) {
  const mitigationId = typeof finding?.mitigation === 'string' && finding.mitigation !== '' ? finding.mitigation : null;
  const transform = mitigationId === null ? null : transformById(mitigationId);
  const base = {
    mitigation: mitigationId,
    finding: typeof finding?.id === 'string' ? finding.id : null,
    kind: transform?.kind ?? null,
    layer: transform?.layer ?? null,
    status: 'skipped',
    changed: false,
    reason: null,
    notes: [],
  };
  if (mitigationId === null) {
    return { ...base, reason: '该发现未标注缓解措施编号，无法派生施加项' };
  }
  if (transform === null) {
    return { ...base, reason: '该编号不在已登记的缓解措施表内' };
  }
  if (transform.kind === 'generated-integration-package') {
    return {
      ...base,
      reason: '反运行时观察集成包由 probe-kit 生成，默认只输出集成包、不改动制品本身，本次不施加',
    };
  }
  if (transform.containers.length > 0 && !transform.containers.includes(state.gate.container)) {
    return { ...base, reason: `该措施适用于 ${transform.containers.join('、')}，当前制品容器为 ${state.gate.container}` };
  }
  if (!state.gate.allowed) {
    return { ...base, reason: state.gate.reason ?? '签名或校验和门控不允许改写' };
  }

  let outcome;
  try {
    outcome = transform.applyToBuffer(state.buffer, finding, { policy, metadata, container: state.gate.container });
  } catch (error) {
    if (error instanceof NotImplementedError) {
      return { ...base, reason: error.message };
    }
    return { ...base, reason: `施加时遇到意外错误：${String(error?.message ?? error)}` };
  }
  if (outcome === null || typeof outcome !== 'object' || outcome.ok !== true) {
    const skipped = { ...base, reason: typeof outcome?.reason === 'string' ? outcome.reason : '施加函数没有返回可用的结果' };
    // 法律字段缺失一类拒由要原样带给调用方：加固引擎靠它把退出码折成 3。
    if (Array.isArray(outcome?.omittedReason) && outcome.omittedReason.length > 0) {
      skipped.omittedReason = [...outcome.omittedReason];
    }
    return skipped;
  }
  if (!Buffer.isBuffer(outcome.buffer)) {
    return { ...base, reason: '施加函数没有返回缓冲区，拒绝写出' };
  }
  if (outcome.buffer.length !== state.buffer.length && transform.kind === 'equal-length-overwrite') {
    // 等长覆写改变了文件长度，说明实现坏了：宁可跳过，也不写出长度被破坏的制品。
    return { ...base, reason: '等长覆写改变了文件长度，本次拒绝写出' };
  }

  // 逐项改动按字节判定：重复施加同一措施时缓冲区不变，这一项就不算改动。
  const changed = !outcome.buffer.equals(state.buffer);
  state.buffer = outcome.buffer;
  const result = {
    ...base,
    status: 'applied',
    changed,
    notes: Array.isArray(outcome.notes) ? [...outcome.notes] : [],
    overwrittenRanges: Array.isArray(outcome.ranges) ? outcome.ranges.map(([from, to]) => [from, to]) : [],
  };
  if (outcome.relayout !== undefined) {
    result.relayout = outcome.relayout;
  }
  if (outcome.zip !== undefined) {
    result.zip = outcome.zip;
  }
  if (Array.isArray(outcome.omittedReason) && outcome.omittedReason.length > 0) {
    result.omittedReason = [...outcome.omittedReason];
  }
  return result;
}

/**
 * 尝试读取已存在的输出文件；读不到时返回 null。
 * @param {string} outputPath
 * @param {Function} read
 * @returns {Promise<Buffer | null>}
 */
async function tryRead(outputPath, read) {
  try {
    const existing = await read(outputPath);
    return Buffer.isBuffer(existing) ? existing : Buffer.from(existing);
  } catch {
    return null;
  }
}

/**
 * 取字节级施加函数。没有实现的那一项在施加时抛 NotImplementedError，
 * 由加固引擎转成“跳过并附原因”，不静默跳过。
 * @param {string} id 措施编号
 * @returns {Function}
 */
function byteTransformOf(id) {
  const implementation = BYTE_TRANSFORMS[id];
  if (implementation !== undefined) {
    return implementation;
  }
  return function notImplemented() {
    throw new NotImplementedError(`transforms/${id}`, '施加逻辑尚未实现');
  };
}

/** @param {string} id @returns {string} */
function layerOfMitigation(id) {
  if (id.startsWith('metadata.')) {
    return 'metadata-hygiene';
  }
  if (id.startsWith('content.')) {
    return 'content-protection';
  }
  if (id.startsWith('runtime.')) {
    return 'runtime-observation-resistance';
  }
  if (id.startsWith('model.')) {
    return 'model-truthful-signals';
  }
  return 'secret-minimization';
}

/** @param {string} id @returns {readonly string[]} */
function containersOfMitigation(id) {
  if (id.startsWith('metadata.go-buildinfo-') && (id.endsWith('inline-overwrite') || id.endsWith('pointer-overwrite') || id.endsWith('writable-region-overwrite'))) {
    return Object.freeze(['elf']);
  }
  if (id.includes('macho')) {
    return Object.freeze(['mach-o', 'mach-o-fat']);
  }
  if (id.includes('pe-')) {
    return Object.freeze(['pe']);
  }
  if (id.includes('elf-')) {
    return Object.freeze(['elf']);
  }
  if (id.includes('pyc')) {
    return Object.freeze(['pyc']);
  }
  if (id.includes('zip')) {
    return Object.freeze(['zip']);
  }
  if (id.includes('safetensors')) {
    return Object.freeze(['safetensors']);
  }
  if (id.includes('gguf')) {
    return Object.freeze(['gguf']);
  }
  if (id.includes('rust-dep')) {
    return Object.freeze(['elf', 'mach-o']);
  }
  if (id === 'secret.token-placeholder-overwrite') {
    // 令牌扫描由全部八类读取器做，覆写在能保持结构完好的容器上施加。
    // pyc、gguf、beam 三类的令牌都在长度前缀的原始字节里，按命中长度清零不破坏各自结构。
    // safetensors 只报告不覆写：令牌在 JSON 头内，填零会引入原始控制字符，使 JSON 头解析失败。
    return Object.freeze(['elf', 'pe', 'mach-o', 'mach-o-fat', 'zip', 'pyc', 'gguf', 'beam']);
  }
  if (id === 'content.data-segment-overwrite') {
    return Object.freeze(['elf', 'pe', 'mach-o']);
  }
  return Object.freeze([]);
}

/** @param {string} id @returns {string} */
function functionalRiskOf(id) {
  if (id === 'metadata.pyc-source-hash-clear') {
    return '清零 source_hash 会同时清除 check_source 标志，否则标志与哈希状态不一致；清零后按名核对源文件的机制失效';
  }
  if (id === 'runtime.probe-integration-package') {
    return '生成的是可嵌入的检测代码片段与人工检查清单，不改动制品本身，需用户自行集成';
  }
  if (id.startsWith('model.')) {
    return '重布局写入会整体重新序列化，必须按原对齐规则重排并重跑全部格式校验；元数据可被再次剥离，不构成技术屏障';
  }
  if (id === 'metadata.elf-symtab-clear') {
    return '清零符号表只让按名检索失败，地址级枚举仍可用；动态符号表是运行期必需数据，一律拒改';
  }
  if (id === 'metadata.elf-build-id-note-overwrite') {
    return '清零构建标识只让按标识匹配调试信息与符号服务器失效，note 结构与制品可加载性不变；标识仍可作为制品指纹被人为记录后继续使用';
  }
  if (id === 'metadata.rust-dep-section-overwrite') {
    return '只覆写节头里的节名与节类型，压缩载荷仍可被裸检索原样提取';
  }
  if (id === 'metadata.pe-debug-directory-overwrite') {
    return '只覆写符号文件路径字节，调试目录结构与数据目录项未改动';
  }
  if (id === 'secret.token-placeholder-overwrite') {
    return '占位覆写只覆盖模式命中的字节，任意自创令牌不在覆盖内；检索为空不证明制品里没有秘密；safetensors 的令牌在 JSON 头内，填零会使头解析失败，该类只报告不覆写';
  }
  if (id === 'content.data-segment-overwrite') {
    return '等长覆写保持文件长度与全部偏移不变，但只覆盖给出的字节区间，区间外仍可被直接检索';
  }
  return '等长覆写保持文件长度与全部偏移不变，不改变制品可加载性';
}

/** @param {string} id @returns {string} */
function signatureImpactOf(id) {
  if (id === 'runtime.probe-integration-package') {
    return '不写入制品，无签名影响';
  }
  if (id.includes('pe-')) {
    return '可能触及 PE 安全目录与可选头 CheckSum，命中后默认跳过改写；策略允许重算时等长重算 CheckSum';
  }
  if (id.includes('macho')) {
    return '可能触及 LC_CODE_SIGNATURE，命中后默认跳过改写';
  }
  if (id === 'secret.token-placeholder-overwrite') {
    return 'ZIP 存储条目覆写后同帧重算 CRC32；其余容器等长覆写不改变偏移，但改写字节仍会使既有校验和失效';
  }
  if (id === 'metadata.elf-symtab-clear') {
    return '可能触及 ELF note，命中后需走必需集豁免';
  }
  if (id === 'metadata.elf-build-id-note-overwrite') {
    return '只清零 note 描述符字节，note 结构与文件长度不变，但改写字节仍会使既有校验和失效';
  }
  if (id.startsWith('model.')) {
    return '重布局写入改变文件长度与偏移，签名制品必须重新签名';
  }
  return '等长覆写不改变文件长度与偏移，但改写字节仍会使既有校验和失效';
}
