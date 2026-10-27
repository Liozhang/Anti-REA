// 法律声明模板渲染与统一拒否语义。
// 铁律：只消费策略中的真实字段，不代为声明任何未确认的事实。
// 每一句后果陈述必须附带用户提供的真实法条摘录；缺来源即拒写该段，并在报告里以 omitted_reason 记录。
// 统一拒否语义：只要出现 omitted_reason，即视为拒绝并返回非零退出码。
//
// 渲染边界（三条，各有对应用例）：
//   1. 文本只由策略 legal 节的真实字段拼成：主体名称、联系渠道、司法辖区、许可标识、许可文本来源、
//      禁止行为清单、后果陈述及其法条摘录。工具不补写未经用户确认的事实，也不生成法条编号。
//   2. 输出不得引用工具本身，不得透露加固、审计或缓解状态。模板自身的固定文字在渲染后自检，
//      自检只覆盖模板文字，用户自填的字段值不参与判定：那是用户自己的陈述，不是工具的表述。
//   3. 文本确定：同一策略渲染两次结果逐字节相同，不掺入时间戳、随机值或运行期结论。

import { writeFile } from 'node:fs/promises';

import { RefusalError, UsageError } from '../errors.mjs';
import { LEGAL_FIELD_SPEC } from '../policy/schema.mjs';

/** 声明模板封闭集合。 */
export const NOTICE_TEMPLATES = Object.freeze(['license']);

/** 生成的声明中不得出现对 Anti-REA 的引用，也不得透露加固状态。 */
export const NOTICE_CONTENT_RULES = Object.freeze([
  '只写用户提供的真实字段，不写工具的检出结论',
  '后果陈述逐条附带真实法条摘录，缺摘录即拒写该段',
  '不出现工具名、版本、审计结论或加固状态',
]);

/** 机器可读声明块的模式标识。刻意不含工具名：声明块随制品分发，不得引用工具自身。 */
export const NOTICE_BLOCK_SCHEMA = 'license-notice/1';

/**
 * 声明文本中不允许出现的表述，一律小写存放，比对时同取小写。
 * 分两类：工具自身的身份标识，以及加固与审计状态的暗示。
 * 用户自填字段值不参与这一判定，见 assertNoticeContentSafe 的说明。
 */
export const FORBIDDEN_NOTICE_TOKENS = Object.freeze([
  'anti-rea',
  'anti rea',
  'anti_rea',
  'antirea',
  '加固',
  'harden',
  'hardened',
  'hardening',
  'mitigation',
  '缓解',
  'audit',
  '审计',
  'verify',
  '复审',
  'redact',
  '脱敏',
  'omitted_reason',
  'omittedreason',
  'requires_resign',
  'requiresresign',
]);

/** 自检占位值：把用户字段全部换成同一占位串后渲染，结果里只剩模板自身的固定文字。取可打印字符，JSON 序列化后仍可按原串剔除。 */
const SELF_CHECK_FIELD = 'PLACEHOLDER';

/** 自检用的合法字段集合：取值全是占位串，形状与真实字段一一对应。 */
const SELF_CHECK_LEGAL = Object.freeze({
  subject: SELF_CHECK_FIELD,
  contact: SELF_CHECK_FIELD,
  jurisdiction: SELF_CHECK_FIELD,
  licenseId: SELF_CHECK_FIELD,
  licenseTextSource: SELF_CHECK_FIELD,
  prohibitedActs: Object.freeze([SELF_CHECK_FIELD]),
  consequences: Object.freeze([{ statement: SELF_CHECK_FIELD, statuteExcerpt: SELF_CHECK_FIELD }]),
});

/**
 * 校验策略中的法律字段是否齐全。
 * 类型错误不在这里判：策略载入时已按模式校验，此处只判齐备性，缺失走拒否（退出码 3）。
 * @param {Record<string, unknown>} policy 策略
 * @returns {{complete: boolean, omittedReason: string[]}}
 */
export function inspectLegalFields(policy) {
  const legal = policy?.legal ?? {};
  const omittedReason = [];
  for (const field of LEGAL_FIELD_SPEC) {
    const value = legal[field.key];
    if (field.kind === 'string') {
      if (typeof value !== 'string' || value.trim() === '') {
        omittedReason.push(`缺少${field.label}（legal.${field.key}）`);
      }
      continue;
    }
    if (!Array.isArray(value) || value.length === 0) {
      // 后果陈述整节缺失时也要把“每条必须附真实法条摘录”这条要求说清：
      // 用户补字段时得知道要补的是陈述加摘录两样，只补陈述仍然过不了拒否关口。
      omittedReason.push(
        field.kind === 'consequence[]'
          ? `缺少${field.label}（legal.${field.key}）：每条后果陈述都必须附带真实法条摘录`
          : `缺少${field.label}（legal.${field.key}）`,
      );
      continue;
    }
    if (field.kind === 'consequence[]') {
      for (const [index, consequence] of value.entries()) {
        const statement = typeof consequence?.statement === 'string' ? consequence.statement.trim() : '';
        const excerpt = typeof consequence?.statuteExcerpt === 'string' ? consequence.statuteExcerpt.trim() : '';
        if (statement === '') {
          omittedReason.push(`第 ${index + 1} 条后果陈述为空（legal.consequences[${index}].statement）`);
        }
        if (excerpt === '') {
          omittedReason.push(`第 ${index + 1} 条后果陈述缺少真实法条摘录（legal.consequences[${index}].statuteExcerpt）`);
        }
      }
      continue;
    }
    // string[]：逐项判非空字符串。清单里混进数字或空串时，那不是用户提供的真实字段，按缺失拒否。
    for (const [index, item] of value.entries()) {
      if (typeof item !== 'string' || item.trim() === '') {
        omittedReason.push(`第 ${index + 1} 项不是非空字符串（legal.${field.key}[${index}]）`);
      }
    }
  }
  return { complete: omittedReason.length === 0, omittedReason };
}

/**
 * 把字符串字段去空白，非字符串按空值处理。只做规整，不补内容。
 * @param {unknown} value
 * @returns {string}
 */
function trimmed(value) {
  return typeof value === 'string' ? value.trim() : '';
}

/**
 * 把禁止行为清单规整为去空白字符串数组。
 * @param {unknown} value
 * @returns {readonly string[]}
 */
function trimmedList(value) {
  if (!Array.isArray(value)) {
    return Object.freeze([]);
  }
  return Object.freeze(value.filter((item) => typeof item === 'string').map((item) => item.trim()));
}

/**
 * 把后果陈述规整为去空白对象数组。缺字段的项按空串处理，齐备性判定已由 inspectLegalFields 把关。
 * @param {unknown} value
 * @returns {readonly {statement: string, statuteExcerpt: string}[]}
 */
function trimmedConsequences(value) {
  if (!Array.isArray(value)) {
    return Object.freeze([]);
  }
  return Object.freeze(
    value
      .filter((item) => item !== null && typeof item === 'object')
      .map((item) => Object.freeze({ statement: trimmed(item.statement), statuteExcerpt: trimmed(item.statuteExcerpt) })),
  );
}

/**
 * 规整法律字段：去空白、冻结。入参可以是策略的 legal 节，也可以是已规整的结果。
 * @param {Record<string, unknown>} legal 法律字段节
 * @returns {Readonly<Record<string, unknown>>} 规整后的字段
 */
export function normalizeLegalFields(legal) {
  const source = legal ?? {};
  return Object.freeze({
    subject: trimmed(source.subject),
    contact: trimmed(source.contact),
    jurisdiction: trimmed(source.jurisdiction),
    licenseId: trimmed(source.licenseId),
    licenseTextSource: trimmed(source.licenseTextSource),
    prohibitedActs: trimmedList(source.prohibitedActs),
    consequences: trimmedConsequences(source.consequences),
  });
}

/**
 * 取策略中的真实法律字段。字段不齐时抛 RefusalError，调用方（例如加固阶段注入声明）据此走拒否。
 * @param {Record<string, unknown>} policy 策略
 * @returns {Readonly<Record<string, unknown>>} 规整后的法律字段
 */
export function requireLegalFields(policy) {
  const legal = policy?.legal ?? {};
  const inspection = inspectLegalFields({ legal });
  if (!inspection.complete) {
    throw new RefusalError(inspection.omittedReason);
  }
  return normalizeLegalFields(legal);
}

/**
 * 由规整后的字段造机器可读声明块。只放真实字段，不放任何工具侧结论。
 * @param {Record<string, unknown>} fields 规整后的法律字段
 * @returns {Record<string, unknown>} 机器可读声明块
 */
function noticeBlockOf(fields) {
  return {
    schema: NOTICE_BLOCK_SCHEMA,
    subject: fields.subject,
    contact: fields.contact,
    jurisdiction: fields.jurisdiction,
    license: { id: fields.licenseId, textSource: fields.licenseTextSource },
    prohibitedActs: [...fields.prohibitedActs],
    consequences: fields.consequences.map((consequence) => ({
      statement: consequence.statement,
      statuteExcerpt: consequence.statuteExcerpt,
    })),
    authorization: { subject: fields.subject, channel: fields.contact },
  };
}

/**
 * 造机器可读声明块。字段不齐时抛 RefusalError，不产出半成品。
 * @param {Record<string, unknown>} legal 策略的 legal 节
 * @returns {Record<string, unknown>} 机器可读声明块
 */
export function buildNoticeBlock(legal) {
  return noticeBlockOf(requireLegalFields({ legal }));
}

/**
 * 渲染 license 模板的声明文档。
 * 章节固定：出具主体与字段清单、许可、禁止行为、后果陈述（逐条附法条摘录）、授权申请、机器可读声明块。
 * 全部文字要么是固定措辞，要么是用户提供的真实字段；不生成法条编号，不写工具侧结论。
 * @param {Record<string, unknown>} legal 策略的 legal 节
 * @returns {string} 声明文档文本，以换行符结尾
 */
export function renderLicenseNotice(legal) {
  const fields = requireLegalFields({ legal });
  const lines = [];
  lines.push('# 许可与禁止逆向声明');
  lines.push('');
  lines.push(`本声明由 ${fields.subject} 出具。`);
  lines.push('');
  lines.push(`- 主体名称：${fields.subject}`);
  lines.push(`- 联系渠道：${fields.contact}`);
  lines.push(`- 司法辖区：${fields.jurisdiction}`);
  lines.push(`- 许可标识：${fields.licenseId}`);
  lines.push(`- 许可文本来源：${fields.licenseTextSource}`);
  lines.push('');
  lines.push('## 许可');
  lines.push('');
  lines.push(`本制品按 ${fields.licenseId} 许可发布，许可全文见 ${fields.licenseTextSource}。`);
  lines.push('');
  lines.push('## 禁止行为');
  lines.push('');
  lines.push(`未经 ${fields.subject} 书面许可，不得实施以下行为：`);
  lines.push('');
  for (const [index, act] of fields.prohibitedActs.entries()) {
    lines.push(`${index + 1}. ${act}`);
  }
  lines.push('');
  lines.push('## 后果陈述');
  lines.push('');
  lines.push(`以下后果陈述由 ${fields.subject} 提供，每条附 ${fields.subject} 给出的法条摘录，供逐条核对：`);
  lines.push('');
  for (const [index, consequence] of fields.consequences.entries()) {
    lines.push(`${index + 1}. ${consequence.statement}`);
    lines.push(`   - 法条摘录：${consequence.statuteExcerpt}`);
  }
  lines.push('');
  lines.push('## 授权申请');
  lines.push('');
  lines.push(`如需取得上述禁止行为中任一项的授权，请通过 ${fields.contact} 与 ${fields.subject} 联系。`);
  lines.push('');
  lines.push('## 机器可读声明块');
  lines.push('');
  lines.push('下面的 JSON 块与上文内容一致，供程序读取：');
  lines.push('');
  lines.push('```json');
  lines.push(JSON.stringify(noticeBlockOf(fields), null, 2));
  lines.push('```');
  lines.push('');
  return `${lines.join('\n')}\n`;
}

/**
 * 在文本中查找不允许出现的表述。纯函数，供渲染自检与测试共用。
 * @param {string} text 待查文本
 * @returns {string[]} 命中的表述，空数组表示干净
 */
export function findForbiddenTokens(text) {
  const lower = String(text ?? '').toLowerCase();
  return FORBIDDEN_NOTICE_TOKENS.filter((token) => lower.includes(token));
}

/**
 * 模板自身文字自检：把用户字段换成占位串后渲染，只查模板写死的固定文字。
 * 用户自填的字段值不参与判定——那是用户自己的陈述；工具要保证的是自己不说那些话。
 * 命中即拒否：宁可不生成，也不发出引用工具或透露加固状态的声明。
 * @returns {void}
 */
export function assertNoticeContentSafe() {
  const scaffold = renderLicenseNotice(SELF_CHECK_LEGAL).split(SELF_CHECK_FIELD).join(' ');
  const hits = findForbiddenTokens(scaffold);
  if (hits.length > 0) {
    throw new RefusalError([
      `声明模板自身出现不允许的表述：${hits.join('、')}。声明不得引用工具本身，也不得透露加固或审计状态`,
    ]);
  }
}

/**
 * 生成声明。
 * 模板名不认时抛 UsageError（退出码 2）；法律字段缺失时抛 RefusalError（退出码 3），
 * 且不产出任何声明文本、不写出任何文件。字段齐全后渲染文本，给出 outPath 时落盘。
 * @param {{template: string, policy: Record<string, unknown>, outPath?: string}} input
 * @returns {Promise<{template: string, text: string, block: Record<string, unknown>, output: string | null}>}
 */
export async function generateNotice(input) {
  const request = input ?? {};
  const template = request.template;
  if (typeof template !== 'string' || !NOTICE_TEMPLATES.includes(template)) {
    throw new UsageError(`不支持的声明模板：${String(template)}，可用模板为 ${NOTICE_TEMPLATES.join('、')}`);
  }
  const policy = request.policy;
  if (policy !== undefined && policy !== null && (typeof policy !== 'object' || Array.isArray(policy))) {
    throw new UsageError('策略必须是对象，法律字段位于策略的 legal 节');
  }

  const inspection = inspectLegalFields(policy ?? {});
  if (!inspection.complete) {
    throw new RefusalError(inspection.omittedReason);
  }

  // 模板自检放在渲染之前：模板自身的文字不允许出现工具身份或加固状态暗示。
  assertNoticeContentSafe();

  const legal = (policy ?? {}).legal ?? {};
  const text = renderLicenseNotice(legal);
  const block = buildNoticeBlock(legal);

  const outPath = typeof request.outPath === 'string' && request.outPath !== '' ? request.outPath : null;
  if (outPath !== null) {
    try {
      await writeFile(outPath, text, 'utf8');
    } catch (error) {
      throw new UsageError(`无法写出声明文件：${outPath}`, { cause: String(error) });
    }
  }

  return Object.freeze({ template, text, block, output: outPath });
}
