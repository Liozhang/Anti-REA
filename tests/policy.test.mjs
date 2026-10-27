// policy 模块测试：策略文件模式与校验。
// 覆盖三类输入：
//   正常输入   默认策略、完整合法策略文件、层开关解析、预算读取、签名许可、反观察策略
//   畸形输入   类型错误、结构错误、模式与开关矛盾、文件不存在、非 JSON、词表外层层名
//   部分读取   策略只填部分字段时其余回落默认值；单文件上限与报表字节上限设为极小值时产部分结果
// 另覆盖法律真实字段的拒否语义：缺主体、缺联系方式、后果陈述缺真实法条摘录三种策略都走到拒否。

import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { LAYER_IDS } from '../src/audit/layer-defs.mjs';
import { auditArtifact } from '../src/audit/engine.mjs';
import { serializeReport } from '../src/report/serialize.mjs';
import { readSignaturesPolicy } from '../src/signatures/policy.mjs';
import { RefusalError, UsageError } from '../src/errors.mjs';
import { generateNotice, inspectLegalFields } from '../src/notice/index.mjs';
import {
  DEFAULT_BUDGETS,
  DEFAULT_OBSERVATION_EXCEPTIONS,
  DEFAULT_POLICY,
  LEGAL_FIELD_SPEC,
  OBSERVATION_MODES,
  POLICY_SCHEMA_VERSION,
  budgetsOf,
  disabledLayerIds,
  enabledLayerIds,
  isLayerEnabled,
  loadPolicy,
  observationPolicyOf,
  resolveLayers,
  validatePolicy,
} from '../src/policy/index.mjs';
import { runCli, SAMPLE_APP } from './helpers/cli.mjs';

/**
 * 把策略写到临时文件，返回路径。调用方负责在 finally 里删除整个临时目录。
 * @param {Record<string, unknown> | string} policy 策略对象，或直接给定的文件文本
 * @returns {Promise<{path: string, dir: string}>}
 */
async function writePolicyFile(policy) {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-policy-mod-'));
  const path = join(dir, 'policy.json');
  await writeFile(path, typeof policy === 'string' ? policy : JSON.stringify(policy), 'utf8');
  return { path, dir };
}

/** 一份法律字段齐全的策略，notice 侧判定为 complete。 */
const COMPLETE_LEGAL = Object.freeze({
  subject: '示例主体',
  contact: 'security@example.com',
  jurisdiction: '示例辖区',
  licenseId: 'MIT',
  licenseTextSource: 'https://example.com/LICENSE',
  prohibitedActs: ['逆向工程'],
  consequences: Object.freeze([Object.freeze({ statement: '示例后果陈述', statuteExcerpt: '示例法条摘录' })]),
});

// —— 正常输入 ——

test('默认策略：层全部开启、法律字段全空、预算取默认值、签名一律不允许、反观察只记录', () => {
  assert.equal(POLICY_SCHEMA_VERSION, 1);
  assert.equal(DEFAULT_POLICY.schemaVersion, POLICY_SCHEMA_VERSION);
  assert.equal(DEFAULT_POLICY.budgets, DEFAULT_BUDGETS);
  assert.equal(DEFAULT_POLICY.observation.exceptions, DEFAULT_OBSERVATION_EXCEPTIONS);
  assert.equal(DEFAULT_OBSERVATION_EXCEPTIONS.length, 0);

  for (const [key, value] of Object.entries(DEFAULT_POLICY.legal)) {
    if (Array.isArray(value)) {
      assert.equal(value.length, 0, `legal.${key} 默认必须为空`);
    } else {
      assert.equal(value, '', `legal.${key} 默认必须为空字符串`);
    }
  }
  for (const field of LEGAL_FIELD_SPEC) {
    assert.ok(field.key.length > 0 && field.label.length > 0, `法律字段 ${field.key} 必须有人读名`);
  }
  assert.equal(LEGAL_FIELD_SPEC.length, 7);
});

test('默认策略下七层全部开启，且解析结果与封闭词表逐层一致', () => {
  const resolved = resolveLayers(DEFAULT_POLICY);
  assert.deepEqual(Object.keys(resolved).sort(), [...LAYER_IDS].sort());
  for (const layerId of LAYER_IDS) {
    assert.equal(resolved[layerId], true, `层 ${layerId} 默认应开启`);
    assert.equal(isLayerEnabled(DEFAULT_POLICY, layerId), true);
  }
  assert.deepEqual([...enabledLayerIds(DEFAULT_POLICY)], [...LAYER_IDS]);
  assert.deepEqual([...disabledLayerIds(DEFAULT_POLICY)], []);
});

test('未提供策略路径时 loadPolicy 返回默认策略', async () => {
  const policy = await loadPolicy(undefined);
  assert.deepEqual(resolveLayers(policy), resolveLayers(DEFAULT_POLICY));
  assert.deepEqual(budgetsOf(policy), { ...DEFAULT_BUDGETS });
  assert.equal(observationPolicyOf(policy).mode, 'report-only');
});

test('载入完整合法策略文件后各节按用户取值生效，未提供的字段回落默认值', async () => {
  const { path, dir } = await writePolicyFile({
    layers: { 'metadata-hygiene': false, 'content-protection': false },
    budgets: { maxFileBytes: 1024, maxNestingDepth: 2 },
    signatures: { allowRewriteSigned: true, allowChecksumRecompute: true },
    observation: { mode: 'report-and-refuse', refusalEnabled: true, exceptions: ['CI', 'SSH_CONNECTION'] },
    legal: COMPLETE_LEGAL,
  });
  try {
    const policy = await loadPolicy(path);

    // 层开关：显式关闭的两层为假，其余六层仍开启。
    const resolved = resolveLayers(policy);
    assert.equal(resolved['metadata-hygiene'], false);
    assert.equal(resolved['content-protection'], false);
    assert.deepEqual([...disabledLayerIds(policy)], ['metadata-hygiene', 'content-protection']);
    assert.equal(enabledLayerIds(policy).length, LAYER_IDS.length - 2);

    // 预算：提供的两项生效，未提供的三项保持默认。
    const budgets = budgetsOf(policy);
    assert.equal(budgets.maxFileBytes, 1024);
    assert.equal(budgets.maxNestingDepth, 2);
    assert.equal(budgets.maxTotalScanBytes, DEFAULT_BUDGETS.maxTotalScanBytes);
    assert.equal(budgets.maxReportBytes, DEFAULT_BUDGETS.maxReportBytes);
    assert.equal(budgets.maxFiles, DEFAULT_BUDGETS.maxFiles);

    // 签名许可：显式允许两项都为真。
    assert.deepEqual(readSignaturesPolicy(policy), { allowRewriteSigned: true, allowChecksumRecompute: true });

    // 反观察：模式、拒绝开关与例外清单全部生效。
    const observation = observationPolicyOf(policy);
    assert.equal(observation.mode, 'report-and-refuse');
    assert.equal(observation.refusalEnabled, true);
    assert.deepEqual([...observation.exceptions], ['CI', 'SSH_CONNECTION']);

    // 法律字段原样保留。
    assert.deepEqual(policy.legal.consequences, [{ statement: '示例后果陈述', statuteExcerpt: '示例法条摘录' }]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('签名改动许可与 CheckSum 重算许可默认拒绝，只有策略显式允许才放行', () => {
  assert.equal(readSignaturesPolicy(DEFAULT_POLICY).allowRewriteSigned, false);
  assert.equal(readSignaturesPolicy(DEFAULT_POLICY).allowChecksumRecompute, false);
  assert.equal(validatePolicy({ signatures: { allowRewriteSigned: true } }).signatures.allowRewriteSigned, true);
  assert.equal(readSignaturesPolicy({ signatures: { allowChecksumRecompute: true } }).allowChecksumRecompute, true);
});

test('法律字段类型齐全时结构校验通过，notice 侧判定为完整', () => {
  assert.doesNotThrow(() => validatePolicy({ legal: COMPLETE_LEGAL }));
  assert.equal(inspectLegalFields({ legal: COMPLETE_LEGAL }).complete, true);
});

// —— 畸形输入：类型与结构 ——

test('validatePolicy 拒绝顶层非对象与不支持的 schemaVersion', () => {
  assert.throws(() => validatePolicy('policy'), /顶层必须是对象/);
  assert.throws(() => validatePolicy(null), /顶层必须是对象/);
  assert.throws(() => validatePolicy([]), /顶层必须是对象/);
  assert.throws(() => validatePolicy({ schemaVersion: 99 }), /schemaVersion 不支持/);
  assert.doesNotThrow(() => validatePolicy({ schemaVersion: POLICY_SCHEMA_VERSION }));
});

test('validatePolicy 拒绝把节写成数组或标量', () => {
  for (const section of ['layers', 'legal', 'budgets', 'signatures', 'observation']) {
    assert.throws(() => validatePolicy({ [section]: [] }), new RegExp(`策略 ${section} 必须是对象`), `${section} 为数组应被拒绝`);
    assert.throws(() => validatePolicy({ [section]: 7 }), new RegExp(`策略 ${section} 必须是对象`), `${section} 为标量应被拒绝`);
  }
  // 节为 null 时按缺省处理，不报错。
  for (const section of ['layers', 'legal', 'budgets', 'signatures', 'observation']) {
    assert.doesNotThrow(() => validatePolicy({ [section]: null }));
  }
});

test('validatePolicy 拒绝非布尔的层开关值', () => {
  assert.throws(() => validatePolicy({ layers: { 'metadata-hygiene': 'no' } }), /layers\.metadata-hygiene 必须是布尔值/);
  assert.throws(() => validatePolicy({ layers: { 'content-protection': 1 } }), /layers\.content-protection 必须是布尔值/);
  assert.throws(() => validatePolicy({ layers: { 'content-protection': null } }), /layers\.content-protection 必须是布尔值/);
  assert.doesNotThrow(() => validatePolicy({ layers: { 'content-protection': false } }));
});

test('validatePolicy 拒绝非法预算值', () => {
  assert.throws(() => validatePolicy({ budgets: { maxFileBytes: -1 } }), /必须是非负有限数字/);
  assert.throws(() => validatePolicy({ budgets: { maxFileBytes: 'big' } }), /必须是非负有限数字/);
  assert.throws(() => validatePolicy({ budgets: { maxReportBytes: Number.NaN } }), /必须是非负有限数字/);
  assert.throws(() => validatePolicy({ budgets: { maxTotalScanBytes: Number.POSITIVE_INFINITY } }), /必须是非负有限数字/);
  assert.throws(() => validatePolicy({ budgets: { maxFileBytes: 1.5 } }), /必须是非负有限数字，且为整数字节数/);
  // 错误信息带上预算字段的人读名，用户不必猜键名含义。
  assert.throws(() => validatePolicy({ budgets: { maxFileBytes: -1 } }), /单文件上限/);
  assert.doesNotThrow(() => validatePolicy({ budgets: { maxFileBytes: 0 } }));
});

test('validatePolicy 拒绝非布尔的签名许可与非法观察模式', () => {
  assert.throws(() => validatePolicy({ signatures: { allowRewriteSigned: 'yes' } }), /signatures\.allowRewriteSigned 必须是布尔值/);
  assert.throws(() => validatePolicy({ signatures: { allowChecksumRecompute: 1 } }), /signatures\.allowChecksumRecompute 必须是布尔值/);
  assert.throws(() => validatePolicy({ observation: { mode: 'block-everything' } }), /observation\.mode 只支持/);
  assert.equal(OBSERVATION_MODES.length, 2);
  assert.doesNotThrow(() => validatePolicy({ observation: { mode: 'report-only' } }));
});

test('validatePolicy 拒绝非布尔拒绝开关与畸形例外清单', () => {
  assert.throws(() => validatePolicy({ observation: { refusalEnabled: 'true' } }), /observation\.refusalEnabled 必须是布尔值/);
  assert.throws(() => validatePolicy({ observation: { exceptions: 'CI' } }), /observation\.exceptions 必须是字符串数组/);
  assert.throws(() => validatePolicy({ observation: { exceptions: ['CI', ''] } }), /observation\.exceptions\[1\] 必须是非空字符串/);
  assert.throws(() => validatePolicy({ observation: { exceptions: ['CI', 7] } }), /observation\.exceptions\[1\] 必须是非空字符串/);
  assert.doesNotThrow(() => validatePolicy({ observation: { exceptions: ['CI'] } }));
});

test('validatePolicy 拒绝观察模式与拒绝开关互相矛盾', () => {
  // 声明了拒绝模式却没打开开关，策略自身回答不了“到底拒不拒绝”。
  assert.throws(() => validatePolicy({ observation: { mode: 'report-and-refuse' } }), /必须一致/);
  // 打开了开关却没声明拒绝模式，同样矛盾。
  assert.throws(() => validatePolicy({ observation: { refusalEnabled: true } }), /必须一致/);
  // 只记录模式搭配关闭开关，是默认组合，不报错。
  assert.doesNotThrow(() => validatePolicy({ observation: { mode: 'report-only', refusalEnabled: false } }));
  // 拒绝模式搭配打开开关，是显式开启拒绝的唯一合法形态。
  assert.doesNotThrow(() => validatePolicy({ observation: { mode: 'report-and-refuse', refusalEnabled: true } }));
});

test('validatePolicy 拒绝法律字段类型错误', () => {
  assert.throws(() => validatePolicy({ legal: '示例主体' }), /策略 legal 必须是对象/);
  assert.throws(() => validatePolicy({ legal: { subject: 7 } }), /legal\.subject 必须是字符串/);
  assert.throws(() => validatePolicy({ legal: { prohibitedActs: '逆向工程' } }), /legal\.prohibitedActs 必须是字符串数组/);
  assert.throws(() => validatePolicy({ legal: { prohibitedActs: ['逆向工程', 7] } }), /legal\.prohibitedActs\[1\] 必须是字符串/);
  assert.throws(() => validatePolicy({ legal: { consequences: { statement: 'x' } } }), /legal\.consequences 必须是数组/);
  assert.throws(() => validatePolicy({ legal: { consequences: ['缺对象'] } }), /legal\.consequences 每项必须是对象/);
  assert.throws(() => validatePolicy({ legal: { consequences: [{ statement: 7 }] } }), /legal\.consequences\[0\]\.statement 必须是字符串/);
  assert.throws(() => validatePolicy({ legal: { consequences: [{ statuteExcerpt: 7 }] } }), /legal\.consequences\[0\]\.statuteExcerpt 必须是字符串/);
  // 空字符串与缺失只影响齐备性判定（拒否），不影响结构校验。
  assert.doesNotThrow(() => validatePolicy({ legal: { subject: '', consequences: [{ statement: '' }] } }));
});

test('validatePolicy 原样保留词表外键，层标识封闭性在载入文件时强制', async () => {
  // 结构校验不做词表裁决：进程内传入的策略对象允许携带扩展键。
  const validated = validatePolicy({ layers: { 'not-a-layer': false } });
  assert.equal(validated.layers['not-a-layer'], false);

  // 载入文件时必须落到用法错误：放行一个不存在的层名，用户会以为关掉了某一层。
  const { path, dir } = await writePolicyFile({ layers: { 'not-a-layer': false } });
  try {
    await assert.rejects(() => loadPolicy(path), (error) => {
      assert.ok(error instanceof UsageError, '未知层名应抛 UsageError');
      assert.match(error.message, /not-a-layer 不是已登记的层标识/);
      assert.match(error.message, /metadata-hygiene/);
      return true;
    });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('loadPolicy 对不可读、非 JSON 与带字节顺序标记的文件分别处理', async () => {
  await assert.rejects(() => loadPolicy(join(tmpdir(), 'anti-rea-no-such-policy.json')), /无法读取策略文件/);

  const broken = await writePolicyFile('这不是 JSON');
  try {
    await assert.rejects(() => loadPolicy(broken.path), /不是合法 JSON/);
  } finally {
    await rm(broken.dir, { recursive: true, force: true });
  }

  // Windows 编辑器存出的 UTF-8 文件常带字节顺序标记，带标记的合法 JSON 必须能载入。
  const bom = await writePolicyFile(`\uFEFF${JSON.stringify({ layers: { 'content-protection': false } })}`);
  try {
    const policy = await loadPolicy(bom.path);
    assert.equal(policy.layers['content-protection'], false);
  } finally {
    await rm(bom.dir, { recursive: true, force: true });
  }
});

test('载入后的策略被深冻结，任何模块都不能在运行时改写它', async () => {
  const { path, dir } = await writePolicyFile({ budgets: { maxFileBytes: 1024 }, observation: { exceptions: ['CI'] } });
  try {
    const policy = await loadPolicy(path);
    assert.throws(() => {
      policy.budgets.maxFileBytes = 1;
    }, TypeError);
    assert.throws(() => {
      policy.observation.exceptions.push('SSH_CONNECTION');
    }, TypeError);
    assert.throws(() => {
      policy.layers['metadata-hygiene'] = false;
    }, TypeError);
    // 冻结不影响读取。
    assert.equal(budgetsOf(policy).maxFileBytes, 1024);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// —— 部分读取：只填部分字段，其余回落 ——

test('策略只填部分字段时，其余字段回落默认值', async () => {
  // 空对象是“只填部分字段”的极端形态：一个字段都不给，全部取默认值。
  const empty = await writePolicyFile({});
  try {
    const policy = await loadPolicy(empty.path);
    assert.deepEqual(resolveLayers(policy), resolveLayers(DEFAULT_POLICY));
    assert.deepEqual(budgetsOf(policy), { ...DEFAULT_BUDGETS });
    assert.equal(observationPolicyOf(policy).mode, 'report-only');
    assert.equal(inspectLegalFields(policy).complete, false);
  } finally {
    await rm(empty.dir, { recursive: true, force: true });
  }

  const onlyBudget = await writePolicyFile({ budgets: { maxFileBytes: 1 } });
  try {
    const policy = await loadPolicy(onlyBudget.path);
    assert.equal(budgetsOf(policy).maxFileBytes, 1);
    assert.equal(budgetsOf(policy).maxReportBytes, DEFAULT_BUDGETS.maxReportBytes);
    // 层开关没有出现，七层仍全部开启。
    assert.equal(enabledLayerIds(policy).length, LAYER_IDS.length);
    // 法律字段没有出现，仍全部为空，notice 侧判定为缺失。
    assert.equal(inspectLegalFields(policy).complete, false);
  } finally {
    await rm(onlyBudget.dir, { recursive: true, force: true });
  }

  const onlyObservation = await writePolicyFile({ observation: { exceptions: ['CI'] } });
  try {
    const observation = observationPolicyOf(await loadPolicy(onlyObservation.path));
    assert.deepEqual([...observation.exceptions], ['CI']);
    assert.equal(observation.mode, 'report-only');
    assert.equal(observation.refusalEnabled, false);
  } finally {
    await rm(onlyObservation.dir, { recursive: true, force: true });
  }
});

test('budgetsOf 对非法值回落默认值，对合法未知键原样透传', () => {
  const policy = {
    budgets: {
      maxFileBytes: 'big',
      maxReportBytes: -1,
      maxFiles: Number.NaN,
      maxNestingDepth: 3.7,
      maxZipEntryBytes: 2048,
    },
  };
  const budgets = budgetsOf(policy);
  assert.equal(budgets.maxFileBytes, DEFAULT_BUDGETS.maxFileBytes);
  assert.equal(budgets.maxReportBytes, DEFAULT_BUDGETS.maxReportBytes);
  assert.equal(budgets.maxFiles, DEFAULT_BUDGETS.maxFiles);
  assert.equal(budgets.maxNestingDepth, 3);
  assert.equal(budgets.maxZipEntryBytes, 2048);
  assert.deepEqual(budgetsOf(undefined), { ...DEFAULT_BUDGETS });
  assert.deepEqual(budgetsOf({}), { ...DEFAULT_BUDGETS });
});

test('单文件上限设为极小值时审计输出 partial 并附单文件上限限制说明', async () => {
  const policy = { ...DEFAULT_POLICY, budgets: { ...DEFAULT_BUDGETS, maxFileBytes: 1 } };
  const report = await auditArtifact(SAMPLE_APP, { policy });
  assert.equal(report.status, 'partial');
  const codes = report.limitations.map((limitation) => limitation.code);
  assert.ok(codes.includes('max-file-bytes-exceeded'), `缺少单文件上限限制说明：${JSON.stringify(codes)}`);
  assert.ok(report.limitations.every((limitation) => limitation.message.length > 0), '限制说明不得为空');
});

test('累计扫描窗口设为 0 时审计输出 partial 并附摘要截断限制说明', async () => {
  const policy = { ...DEFAULT_POLICY, budgets: { ...DEFAULT_BUDGETS, maxTotalScanBytes: 0 } };
  const report = await auditArtifact(SAMPLE_APP, { policy });
  assert.equal(report.status, 'partial');
  assert.ok(report.limitations.some((limitation) => limitation.code === 'digest-truncated'));
});

test('报表字节上限设为极小值时序列化结果被截断且不超过上限', async () => {
  const report = await auditArtifact(SAMPLE_APP, { policy: DEFAULT_POLICY });
  const limit = 400;
  const policy = { ...DEFAULT_POLICY, budgets: { ...DEFAULT_BUDGETS, maxReportBytes: limit } };
  const text = serializeReport(report, { policy });
  assert.ok(Buffer.byteLength(text, 'utf8') <= limit, '截断后的报表不得超过策略上限');
  assert.ok(text.includes('报表已达到策略字节上限') || JSON.parse(text.slice(0, text.lastIndexOf('\n') + 1)).truncated === true, '截断必须留下痕迹');

  // 上限宽裕时不做任何截断，报表完整可解析。
  const full = serializeReport(report, { policy: DEFAULT_POLICY });
  assert.equal(JSON.parse(full).summary.findings, report.summary.findings);
  assert.ok(!full.includes('报表已达到策略字节上限'));
});

// —— 法律真实字段的拒否语义 ——

test('缺主体、缺联系方式、后果陈述缺真实法条摘录三种策略都走到拒否', async () => {
  const cases = [
    { legal: { ...COMPLETE_LEGAL, subject: '' }, pattern: /主体名称/ },
    { legal: { ...COMPLETE_LEGAL, contact: '   ' }, pattern: /联系渠道/ },
    { legal: { ...COMPLETE_LEGAL, consequences: [{ statement: '示例后果陈述' }] }, pattern: /法条摘录/ },
    { legal: { ...COMPLETE_LEGAL, consequences: [{ statuteExcerpt: '示例法条摘录' }] }, pattern: /后果陈述为空/ },
  ];
  for (const [index, testCase] of cases.entries()) {
    const inspection = inspectLegalFields({ legal: testCase.legal });
    assert.equal(inspection.complete, false, `第 ${index + 1} 种策略不应判定为完整`);
    assert.ok(
      inspection.omittedReason.some((reason) => testCase.pattern.test(reason)),
      `第 ${index + 1} 种策略的 omittedReason 应说明缺什么：${JSON.stringify(inspection.omittedReason)}`,
    );
    await assert.rejects(
      () => generateNotice({ template: 'license', policy: { legal: testCase.legal } }),
      (error) => {
        assert.ok(error instanceof RefusalError, '字段缺失必须走拒否而不是其他错误');
        assert.ok(error.omittedReason.length > 0, '拒否必须逐条列出原因');
        return true;
      },
      `第 ${index + 1} 种策略应抛 RefusalError`,
    );
  }
});

test('notice 子命令在缺主体时退出码为 3 且输出含 omitted_reason', async () => {
  const { path, dir } = await writePolicyFile({ legal: { ...COMPLETE_LEGAL, subject: '' } });
  try {
    const result = await runCli(['notice', '--template', 'license', '--json', '--policy', path]);
    assert.equal(result.code, 3, '法律字段缺失必须返回拒否退出码');
    const report = JSON.parse(result.stdout);
    assert.equal(report.status, 'refused');
    // 对外契约字段是蛇形 omitted_reason，驼峰 omittedReason 明确不产出，
    // 见 tests/cli-contract.test.mjs、tests/notice.test.mjs 与 tests/mcp-protocol.test.mjs 的对应断言。
    assert.ok(Array.isArray(report.omitted_reason) && report.omitted_reason.length > 0, '拒否报告必须带原因清单');
    assert.ok(report.omitted_reason.some((reason) => reason.includes('主体名称')), '原因清单应点名缺失字段');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
