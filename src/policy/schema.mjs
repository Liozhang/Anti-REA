// 策略文件模式与校验。
// 策略是 JSON 文件，决定七层开关、法律真实字段、资源预算、签名改动许可与反观察响应模式。
// 本模块只做模式与校验，不在策略里预设任何法律字段的取值：字段必须由用户填写真实内容。
//
// 三条约束贯穿全文件：
//   1. 类型与缺失分开。validatePolicy 只校验类型与结构，类型错误是用法错误（退出码 2）；
//      字段是否齐备由 notice 模块按 LEGAL_FIELD_SPEC 判定，缺失走拒否（退出码 3）。
//      两者不可互相替代：把缺失当成类型错误，会让用户以为改个格式就能通过；
//      把类型错误当成缺失，会放过畸形文件。
//   2. 封闭词表在文件关口强制。层标识取自 audit/layer-defs 的七层封闭词表，
//      用户写错层名时在载入文件这一道抛用法错误，不静默关闭一个不存在的层。
//   3. 资源上限用于产部分结果。上限的意义是超限时给出部分结果与限制说明，
//      不让进程失败或超时，因此预算值只允许非负整数，非法值在载入时即被拒绝。

import { readFile } from 'node:fs/promises';

import { LAYER_IDS } from '../audit/layer-defs.mjs';
import { UsageError } from '../errors.mjs';

/** 策略模式版本，随字段增补而递增。 */
export const POLICY_SCHEMA_VERSION = 1;

/** 资源预算默认值。上限存在的意义是超限时产部分结果并附限制说明，而不是让进程失败或超时。 */
export const DEFAULT_BUDGETS = Object.freeze({
  /** 单文件读取上限，字节。 */
  maxFileBytes: 64 * 1024 * 1024,
  /** 累计扫描窗口，字节。 */
  maxTotalScanBytes: 1024 * 1024 * 1024,
  /** 报表字节上限。 */
  maxReportBytes: 8 * 1024 * 1024,
  /** 嵌套深度上限，例如 ZIP 内再嵌 ZIP。 */
  maxNestingDepth: 8,
  /** 目录目标一次枚举的最大文件数。 */
  maxFiles: 5000,
});

/** 预算字段的人读名。错误信息里带上，用户不必猜键名含义；未登记的键不给名，按开放扩展点处理。 */
const BUDGET_LABELS = Object.freeze({
  maxFileBytes: '单文件上限',
  maxTotalScanBytes: '累计扫描窗口',
  maxReportBytes: '报表字节上限',
  maxNestingDepth: '嵌套深度',
  maxFiles: '目录枚举文件数上限',
});

/** 法律字段模式。任何一项缺失都会让声明生成走拒否路径。 */
export const LEGAL_FIELD_SPEC = Object.freeze([
  { key: 'subject', label: '主体名称', kind: 'string' },
  { key: 'contact', label: '联系渠道', kind: 'string' },
  { key: 'jurisdiction', label: '司法辖区', kind: 'string' },
  { key: 'licenseId', label: '许可标识', kind: 'string' },
  { key: 'licenseTextSource', label: '许可文本来源', kind: 'string' },
  { key: 'prohibitedActs', label: '禁止行为清单', kind: 'string[]' },
  { key: 'consequences', label: '后果陈述', kind: 'consequence[]' },
]);

/** 后果陈述单项的字段名。缺 statuteExcerpt 即拒写该段，齐备性判定在 notice 模块。 */
const CONSEQUENCE_STRING_FIELDS = Object.freeze(['statement', 'statuteExcerpt']);

/** 反观察响应模式。默认只记录与上报，拒绝行为必须由策略显式开启。 */
export const OBSERVATION_MODES = Object.freeze(['report-only', 'report-and-refuse']);

/** 反观察例外的默认清单为空：已知持续集成变量与远程 Shell 会话的基线清单由 probe-kit 提供，这里只放用户自填项。 */
export const DEFAULT_OBSERVATION_EXCEPTIONS = Object.freeze([]);

/** 默认策略：层全部开启，法律字段全部为空，预算取默认值，签名改动一律不允许。 */
export const DEFAULT_POLICY = Object.freeze({
  schemaVersion: POLICY_SCHEMA_VERSION,
  layers: Object.freeze({}),
  legal: Object.freeze({
    subject: '',
    contact: '',
    jurisdiction: '',
    licenseId: '',
    licenseTextSource: '',
    prohibitedActs: Object.freeze([]),
    consequences: Object.freeze([]),
  }),
  budgets: DEFAULT_BUDGETS,
  signatures: Object.freeze({
    /** 检测到代码签名或校验和机制的制品是否允许改写。默认否。 */
    allowRewriteSigned: false,
    /** PE 可选头 CheckSum 非零时是否允许等长重算。默认否，无法重算时按签名制品同等对待。 */
    allowChecksumRecompute: false,
  }),
  observation: Object.freeze({
    mode: 'report-only',
    /** 反观察响应是否拒绝继续运行。默认否，且只在 report-and-refuse 模式下可开启。 */
    refusalEnabled: false,
    exceptions: DEFAULT_OBSERVATION_EXCEPTIONS,
  }),
});

/**
 * 深合并默认策略与用户策略，用户取值优先。
 * 数组整体替换，不逐项合并：禁止行为清单与例外清单由用户一次给全，避免默认项与用户项混在一起难以审阅。
 * @param {Record<string, unknown>} base
 * @param {Record<string, unknown>} override
 * @returns {Record<string, unknown>}
 */
function mergePolicy(base, override) {
  const result = { ...base };
  for (const [key, value] of Object.entries(override)) {
    const current = result[key];
    if (value !== null && typeof value === 'object' && !Array.isArray(value) && current !== null && typeof current === 'object' && !Array.isArray(current)) {
      result[key] = mergePolicy(current, value);
    } else {
      result[key] = value;
    }
  }
  return result;
}

/**
 * 深冻结合并后的策略。策略是只读事实来源，任何模块都不应在运行时改写它；
 * 冻结让误改写当场报错，而不是把一处改动扩散到后续全部调用。
 * @template T
 * @param {T} value 待冻结值
 * @returns {T} 原值
 */
function deepFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) {
    return value;
  }
  for (const nested of Object.values(value)) {
    deepFreeze(nested);
  }
  return Object.freeze(value);
}

/**
 * 去掉 JSON 文本开头的字节顺序标记。Windows 编辑器存出的 UTF-8 文件常带标记，
 * 带标记的合法 JSON 不应被判成畸形文件。
 * @param {unknown} text 读取到的文本
 * @returns {string}
 */
function stripBom(text) {
  const source = typeof text === 'string' ? text : String(text ?? '');
  return source.charCodeAt(0) === 0xfeff ? source.slice(1) : source;
}

/**
 * 断言某节存在时必须是无 null 的普通对象。数组与标量一律拒绝：
 * 把节写成数组或标量时，逐字段校验会一条都不报，畸形策略会被当成合法策略放行。
 * @param {Record<string, unknown>} candidate 待校验策略
 * @param {string} key 节名
 */
function assertPlainSection(candidate, key) {
  const value = candidate[key];
  if (value !== undefined && value !== null && (typeof value !== 'object' || Array.isArray(value))) {
    throw new UsageError(`策略 ${key} 必须是对象`);
  }
}

/**
 * 校验策略结构。字段类型不符时抛 UsageError，对应退出码 2。
 * 未知键一律保留：结构校验不替用户决定哪些键有意义，层标识的封闭性在载入文件的关口单独校验。
 * @param {unknown} policy 待校验策略
 * @returns {Record<string, unknown>} 校验通过的策略
 */
export function validatePolicy(policy) {
  if (policy === null || typeof policy !== 'object' || Array.isArray(policy)) {
    throw new UsageError('策略文件顶层必须是对象');
  }
  const candidate = policy;
  if (candidate.schemaVersion !== undefined && candidate.schemaVersion !== POLICY_SCHEMA_VERSION) {
    throw new UsageError(`策略 schemaVersion 不支持：${String(candidate.schemaVersion)}，当前支持 ${POLICY_SCHEMA_VERSION}`);
  }
  for (const section of ['layers', 'legal', 'budgets', 'signatures', 'observation']) {
    assertPlainSection(candidate, section);
  }

  for (const [key, value] of Object.entries(candidate.layers ?? {})) {
    if (typeof value !== 'boolean') {
      throw new UsageError(`策略 layers.${key} 必须是布尔值：true 开启该层，false 关闭该层`);
    }
  }

  for (const [key, value] of Object.entries(candidate.budgets ?? {})) {
    const label = BUDGET_LABELS[key];
    const suffix = label === undefined ? '' : `（${label}）`;
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
      throw new UsageError(`策略 budgets.${key}${suffix} 必须是非负有限数字`);
    }
    if (!Number.isInteger(value)) {
      throw new UsageError(`策略 budgets.${key}${suffix} 必须是非负有限数字，且为整数字节数`);
    }
  }

  for (const key of ['allowRewriteSigned', 'allowChecksumRecompute']) {
    const value = candidate.signatures?.[key];
    if (value !== undefined && typeof value !== 'boolean') {
      throw new UsageError(`策略 signatures.${key} 必须是布尔值`);
    }
  }

  const observation = candidate.observation ?? {};
  const mode = observation.mode;
  if (mode !== undefined && !OBSERVATION_MODES.includes(mode)) {
    throw new UsageError(`策略 observation.mode 只支持：${OBSERVATION_MODES.join('、')}`);
  }
  const refusalEnabled = observation.refusalEnabled;
  if (refusalEnabled !== undefined && typeof refusalEnabled !== 'boolean') {
    throw new UsageError('策略 observation.refusalEnabled 必须是布尔值');
  }
  if (observation.exceptions !== undefined) {
    if (!Array.isArray(observation.exceptions)) {
      throw new UsageError('策略 observation.exceptions 必须是字符串数组，每项为一个环境变量名或会话标记');
    }
    for (const [index, item] of observation.exceptions.entries()) {
      if (typeof item !== 'string' || item.trim() === '') {
        throw new UsageError(`策略 observation.exceptions[${index}] 必须是非空字符串`);
      }
    }
  }
  // 模式与拒绝开关必须一致：拒绝行为只在 report-and-refuse 模式下可开启，
  // 声明了该模式就必须显式打开开关。两者矛盾时策略自身无法回答“到底拒不拒绝”，按用法错误拒绝。
  const effectiveMode = mode ?? DEFAULT_POLICY.observation.mode;
  const effectiveRefusal = refusalEnabled ?? DEFAULT_POLICY.observation.refusalEnabled;
  if (effectiveRefusal !== (effectiveMode === 'report-and-refuse')) {
    throw new UsageError('策略 observation.refusalEnabled 与 observation.mode 必须一致：拒绝行为只在 report-and-refuse 模式下可开启，且开启时必须声明该模式');
  }

  const legal = candidate.legal ?? {};
  for (const field of LEGAL_FIELD_SPEC) {
    const value = legal[field.key];
    if (value === undefined) {
      continue;
    }
    if (field.kind === 'string' && typeof value !== 'string') {
      throw new UsageError(`策略 legal.${field.key} 必须是字符串`);
    }
    if (field.kind === 'string[]') {
      if (!Array.isArray(value)) {
        throw new UsageError(`策略 legal.${field.key} 必须是字符串数组`);
      }
      for (const [index, item] of value.entries()) {
        if (typeof item !== 'string') {
          throw new UsageError(`策略 legal.${field.key}[${index}] 必须是字符串`);
        }
      }
    }
    if (field.kind === 'consequence[]' && !Array.isArray(value)) {
      throw new UsageError('策略 legal.consequences 必须是数组，每项含 statement 与 statuteExcerpt');
    }
  }
  for (const [index, consequence] of (legal.consequences ?? []).entries()) {
    if (consequence === null || typeof consequence !== 'object' || Array.isArray(consequence)) {
      throw new UsageError('策略 legal.consequences 每项必须是对象');
    }
    for (const key of CONSEQUENCE_STRING_FIELDS) {
      const value = consequence[key];
      if (value !== undefined && typeof value !== 'string') {
        throw new UsageError(`策略 legal.consequences[${index}].${key} 必须是字符串`);
      }
    }
  }
  return candidate;
}

/**
 * 层标识封闭性校验，只在载入策略文件时执行。
 * 用户写错层名必须落到用法错误：放行一个不存在的层名，用户会以为关掉了某一层，
 * 而实际上那一层仍在审计与加固范围内。结构校验（validatePolicy）原样保留未知键，
 * 供进程内传入的策略对象携带扩展键。
 * @param {Record<string, unknown>} policy 已过结构校验的策略
 */
function assertKnownLayerKeys(policy) {
  for (const key of Object.keys(policy.layers ?? {})) {
    if (!LAYER_IDS.includes(key)) {
      throw new UsageError(`策略 layers.${key} 不是已登记的层标识，可用层为：${LAYER_IDS.join('、')}`);
    }
  }
}

/**
 * 载入策略：读取文件、校验、与默认值合并。未提供路径时返回默认策略。
 * 载入文件时额外强制层标识封闭词表；返回的策略已深冻结，调用方不得改写。
 * @param {string | undefined} policyPath 策略文件路径
 * @param {{readFile?: (path: string) => Promise<string>}} [io] 读取注入，便于测试
 * @returns {Promise<Record<string, unknown>>}
 */
export async function loadPolicy(policyPath, io = {}) {
  const read = io.readFile ?? readFile;
  if (!policyPath) {
    return deepFreeze(mergePolicy(DEFAULT_POLICY, {}));
  }
  let text;
  try {
    text = await read(policyPath, 'utf8');
  } catch (error) {
    throw new UsageError(`无法读取策略文件：${policyPath}`, { cause: String(error) });
  }
  let parsed;
  try {
    parsed = JSON.parse(stripBom(text));
  } catch (error) {
    throw new UsageError(`策略文件不是合法 JSON：${policyPath}`, { cause: String(error) });
  }
  const validated = validatePolicy(parsed);
  assertKnownLayerKeys(validated);
  return deepFreeze(mergePolicy(DEFAULT_POLICY, validated));
}

/**
 * 取资源预算，缺失字段回落到默认值。
 * 非法值（非数字、负数、非有限值）一律忽略并回落默认值：预算被污染时按默认上限运行，
 * 比把污染值传进读取路径导致崩溃更接近“产部分结果”的约定。
 * 未登记的预算键若是合法数字则原样透传，留给后续读取器扩展。
 * @param {Record<string, unknown>} policy
 * @returns {typeof DEFAULT_BUDGETS}
 */
export function budgetsOf(policy) {
  const merged = { ...DEFAULT_BUDGETS };
  for (const [key, value] of Object.entries(policy?.budgets ?? {})) {
    if (typeof value === 'number' && Number.isFinite(value) && value >= 0) {
      merged[key] = Math.floor(value);
    }
  }
  return merged;
}

/**
 * 判断某防御层是否开启。未显式关闭的层默认开启。
 * 词表外标识同样返回开启：审计要的是多看而不是少看，少看一层的代价由调用方按层开关决定。
 * @param {Record<string, unknown>} policy
 * @param {string} layerId 层标识
 * @returns {boolean}
 */
export function isLayerEnabled(policy, layerId) {
  const layers = policy?.layers ?? {};
  const value = layers[layerId];
  return value === undefined ? true : value === true;
}

/**
 * 解析全部七层的开关，键为层标识，值为布尔。词表外层标识不出现在结果里。
 * @param {Record<string, unknown>} policy
 * @returns {Readonly<Record<string, boolean>>}
 */
export function resolveLayers(policy) {
  const resolved = {};
  for (const layerId of LAYER_IDS) {
    resolved[layerId] = isLayerEnabled(policy, layerId);
  }
  return Object.freeze(resolved);
}

/**
 * 列出策略开启的层标识，顺序与封闭词表一致。
 * @param {Record<string, unknown>} policy
 * @returns {readonly string[]}
 */
export function enabledLayerIds(policy) {
  return Object.freeze(LAYER_IDS.filter((layerId) => isLayerEnabled(policy, layerId)));
}

/**
 * 列出策略关闭的层标识，顺序与封闭词表一致。
 * @param {Record<string, unknown>} policy
 * @returns {readonly string[]}
 */
export function disabledLayerIds(policy) {
  return Object.freeze(LAYER_IDS.filter((layerId) => !isLayerEnabled(policy, layerId)));
}

/**
 * 取反观察响应策略：响应模式、是否拒绝、例外清单。
 * 非法值回落默认值（只记录与上报、不拒绝、无例外），与 budgetsOf 同一口径。
 * @param {Record<string, unknown>} policy
 * @returns {{mode: string, refusalEnabled: boolean, exceptions: readonly string[]}}
 */
export function observationPolicyOf(policy) {
  const section = policy?.observation ?? {};
  const mode = OBSERVATION_MODES.includes(section.mode) ? section.mode : DEFAULT_POLICY.observation.mode;
  const refusalEnabled = section.refusalEnabled === true;
  const exceptions = Array.isArray(section.exceptions)
    ? section.exceptions.filter((item) => typeof item === 'string' && item.trim() !== '')
    : [];
  return Object.freeze({ mode, refusalEnabled, exceptions: Object.freeze([...exceptions]) });
}
