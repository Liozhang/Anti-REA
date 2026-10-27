// 按格式的必需集数据与豁免规则。
// verify 按必需集校验：已施加缓解清单中的节与字段从必需集移除，其余必须保持可解析。
//
// 本文件提供三条规则：
//   1. deriveExemptions    从施加记录派生豁免，必需集按项划分成“仍然必须可解析”与“已豁免”两部分
//   2. exemptionsFor       上面那条规则按容器取数后的便捷入口
//   3. checkRequiredSet    按结构事实逐项判定：可解析、不可解析、不适用、未提供事实
//
// 复审接入方式：verify 先取该容器登记的全部必需项编号（requiredItemsOf），
// 由读取器或自身解析产出以必需项编号为键的结构事实表，再调用 checkRequiredSet。
// 事实表缺项即判 unverified，不因为“没看到问题”就判通过；未提供事实会让总体结论落到 partial。

import { UsageError } from '../errors.mjs';
import { REQUIRED_SETS, REQUIRED_SET_SCHEMA } from './sets.mjs';

export { REQUIRED_ITEM_KINDS, REQUIRED_SETS, REQUIRED_SET_SCHEMA, REQUIRED_SET_STATUS, requiredItemsOf } from './sets.mjs';

/** 结构事实判定用的封闭状态集合。 */
export const REQUIRED_ITEM_STATUS = Object.freeze(['passed', 'failed', 'unverified', 'exempted']);

/** 必需集总体判定的封闭状态集合。 */
export const REQUIRED_SET_VERDICT = Object.freeze(['passed', 'partial', 'failed', 'not-applicable']);

/**
 * 取某容器对应的必需集；容器不在表内时返回 null，由调用方记为不适用。
 * @param {string} containerType 容器标识
 * @returns {Record<string, unknown> | null}
 */
export function requiredSetFor(containerType) {
  return REQUIRED_SETS[containerType] ?? null;
}

/**
 * 把施加记录折算成编号清单。
 * 接受三种形状：编号字符串数组、带 mitigation 字段的对象数组（加固报告的 applied 字段）、
 * 含 applied 数组的报告对象。没有 applied 字段时视为没有施加任何措施。
 * @param {unknown} appliedRecord 施加记录
 * @returns {string[]} 缓解措施编号
 */
export function appliedMitigationIds(appliedRecord) {
  if (appliedRecord === null || appliedRecord === undefined) {
    return [];
  }
  if (Array.isArray(appliedRecord)) {
    return normalizeNameList(appliedRecord, '已施加缓解清单');
  }
  if (typeof appliedRecord === 'object') {
    if (appliedRecord.applied === undefined) {
      return [];
    }
    return normalizeNameList(appliedRecord.applied, '施加记录的 applied 字段');
  }
  throw new UsageError('施加记录必须是数组，或含 applied 数组的对象');
}

/**
 * 从施加记录派生必需集豁免。
 * 规则：已施加缓解清单中列名的节与字段，从必需集移除；其余必须保持可解析。
 * 匹配按两项进行：必需项编号本身，以及该项 exemptedBy 登记的缓解措施编号。
 * @param {unknown} appliedMitigations 已施加的缓解措施编号、加固报告的 applied 记录或报告对象
 * @param {unknown} requiredItems 该格式的必需项清单，可为编号字符串或必需项对象
 * @returns {{required: string[], exempted: string[], unmatched: string[]}}
 */
export function deriveExemptions(appliedMitigations, requiredItems) {
  const items = normalizeItems(requiredItems);
  const applied = appliedMitigationIds(appliedMitigations);
  const appliedSet = new Set(applied);

  const required = [];
  const exempted = [];
  const known = new Set();
  for (const item of items) {
    const names = [item.id, ...item.exemptedBy];
    for (const name of names) {
      known.add(name);
    }
    if (names.some((name) => appliedSet.has(name))) {
      exempted.push(item.id);
    } else {
      required.push(item.id);
    }
  }
  const unmatched = [...appliedSet].filter((name) => !known.has(name));
  return { required, exempted, unmatched };
}

/**
 * 按容器派生豁免，是 deriveExemptions 取好必需集后的便捷入口。
 * 容器没有登记必需集时返回 not-applicable，不抛错、不冒充通过。
 * @param {unknown} appliedMitigations 已施加的缓解措施编号或施加记录
 * @param {string} containerType 容器标识
 * @returns {{container: string, status: string, required: string[], exempted: string[], unmatched: string[]}}
 */
export function exemptionsFor(appliedMitigations, containerType) {
  const set = requiredSetFor(containerType);
  if (set === null) {
    return {
      container: String(containerType),
      status: 'not-applicable',
      reason: `容器 ${String(containerType)} 没有登记必需集，本次不适用`,
      required: [],
      exempted: [],
      unmatched: [],
    };
  }
  const { required, exempted, unmatched } = deriveExemptions(appliedMitigations, set.items);
  return { container: containerType, status: set.status, required, exempted, unmatched };
}

/**
 * 按结构事实逐项校验必需集。
 * @param {string} containerType 容器标识
 * @param {unknown} facts 结构事实表，键为必需项编号；缺项按未提供事实处理
 * @param {unknown} appliedMitigations 已施加的缓解措施编号或施加记录，用于派生豁免
 * @returns {{
 *   container: string, schema: string, status: string, required: string[], exempted: string[],
 *   items: Array<{id: string, kind: string, label: string, status: string, reason: string}>,
 *   summary: {total: number, passed: number, failed: number, unverified: number, exempted: number},
 *   limitations: Array<{code: string, scope: string, message: string}>
 * }}
 */
export function checkRequiredSet(containerType, facts, appliedMitigations) {
  const set = requiredSetFor(containerType);
  if (set === null) {
    return {
      container: String(containerType),
      schema: REQUIRED_SET_SCHEMA,
      status: 'not-applicable',
      reason: `容器 ${String(containerType)} 没有登记必需集，本次不适用`,
      required: [],
      exempted: [],
      items: [],
      summary: { total: 0, passed: 0, failed: 0, unverified: 0, exempted: 0 },
      limitations: [],
    };
  }
  if (facts !== null && facts !== undefined && (typeof facts !== 'object' || Array.isArray(facts))) {
    throw new UsageError('结构事实必须是对象，键为必需项编号');
  }
  const factTable = facts ?? {};
  const { exempted } = deriveExemptions(appliedMitigations, set.items);
  const exemptedSet = new Set(exempted);

  const items = [];
  const limitations = [];
  const counts = { total: set.items.length, passed: 0, failed: 0, unverified: 0, exempted: 0 };
  for (const item of set.items) {
    if (exemptedSet.has(item.id)) {
      counts.exempted += 1;
      items.push({
        id: item.id,
        kind: item.kind,
        label: item.label,
        status: 'exempted',
        reason: '已施加的缓解措施覆盖该项，按施加记录从必需集移除',
      });
      continue;
    }
    const verdict = evaluateFact(item, factTable[item.id]);
    counts[verdict.status] += 1;
    items.push({ id: item.id, kind: item.kind, label: item.label, status: verdict.status, reason: verdict.reason });
    if (verdict.status === 'unverified') {
      limitations.push({ code: 'structure-facts-missing', scope: item.id, message: verdict.reason });
    }
  }

  const status = counts.failed > 0 ? 'failed' : counts.unverified > 0 ? 'partial' : 'passed';
  return {
    container: containerType,
    schema: REQUIRED_SET_SCHEMA,
    status,
    required: items.filter((item) => item.status !== 'exempted').map((item) => item.id),
    exempted: [...exempted],
    items,
    summary: counts,
    limitations,
  };
}

/**
 * 判定单项结构事实。
 * 事实形状：true 表示可解析；false 表示不可解析；
 * {parsed: true|false, reason?} 显式判定；{absent: true, reason?} 表示该制品不含此结构，按不适用处理；
 * 缺项或无法识别的形状判 unverified，并说明原因。
 * @param {Record<string, unknown>} item 必需项
 * @param {unknown} fact 该项的结构事实
 * @returns {{status: 'passed' | 'failed' | 'unverified', reason: string}}
 */
function evaluateFact(item, fact) {
  const name = `${item.label}（${item.id}）`;
  if (fact === undefined || fact === null) {
    return { status: 'unverified', reason: `复审未提供${name}的结构事实，本次不判定` };
  }
  if (fact === true) {
    return { status: 'passed', reason: '结构可解析' };
  }
  if (fact === false) {
    return { status: 'failed', reason: `${name}不可解析` };
  }
  if (typeof fact === 'object' && !Array.isArray(fact)) {
    if (fact.absent === true) {
      return {
        status: 'passed',
        reason: typeof fact.reason === 'string' && fact.reason !== '' ? fact.reason : '该制品不含此结构，按不适用处理',
      };
    }
    if (fact.parsed === true) {
      return {
        status: 'passed',
        reason: typeof fact.reason === 'string' && fact.reason !== '' ? fact.reason : '结构可解析',
      };
    }
    if (fact.parsed === false) {
      return {
        status: 'failed',
        reason: typeof fact.reason === 'string' && fact.reason !== '' ? fact.reason : `${name}不可解析`,
      };
    }
  }
  return { status: 'unverified', reason: `${name}的结构事实形状无法识别，本次不判定` };
}

/**
 * 归一化编号清单。null 与 undefined 视为空；其余必须是数组，且每项是编号字符串或带 mitigation 字段的对象。
 * @param {unknown} value 待归一化清单
 * @param {string} label 出错信息里的字段名
 * @returns {string[]}
 */
function normalizeNameList(value, label) {
  if (value === null || value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new UsageError(`${label}必须是数组`);
  }
  return value.map((entry, index) => {
    const name = nameOfEntry(entry);
    if (name === null) {
      throw new UsageError(`${label}第 ${index + 1} 项既不是编号字符串，也不是带 mitigation 字段的对象`);
    }
    return name;
  });
}

/**
 * 归一化必需项清单。字符串按编号处理；对象必须有字符串 id，exemptedBy 可选。
 * @param {unknown} value 待归一化清单
 * @returns {Array<{id: string, exemptedBy: string[]}>}
 */
function normalizeItems(value) {
  if (value === null || value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new UsageError('必需项清单必须是数组');
  }
  return value.map((entry, index) => {
    if (typeof entry === 'string' && entry.trim() !== '') {
      return { id: entry, exemptedBy: [] };
    }
    if (entry !== null && typeof entry === 'object' && !Array.isArray(entry)) {
      if (typeof entry.id !== 'string' || entry.id.trim() === '') {
        throw new UsageError(`必需项清单第 ${index + 1} 项缺少字符串 id 字段`);
      }
      return {
        id: entry.id,
        exemptedBy: normalizeNameList(entry.exemptedBy, `必需项 ${entry.id} 的 exemptedBy`),
      };
    }
    throw new UsageError(`必需项清单第 ${index + 1} 项既不是编号字符串，也不是带 id 字段的对象`);
  });
}

/**
 * 从清单项取编号：字符串原样返回，对象取 mitigation 或 id 字段。
 * @param {unknown} entry 清单项
 * @returns {string | null} 无法识别时返回 null
 */
function nameOfEntry(entry) {
  if (typeof entry === 'string') {
    return entry.trim() === '' ? null : entry;
  }
  if (entry !== null && typeof entry === 'object' && !Array.isArray(entry)) {
    for (const key of ['mitigation', 'id']) {
      const value = entry[key];
      if (typeof value === 'string' && value.trim() !== '') {
        return value;
      }
    }
  }
  return null;
}
