// notice 模块测试：法律声明模板渲染与统一拒否语义。
// 覆盖三类输入：
//   正常输入   字段齐全时渲染声明文档、机器可读声明块、写出文件、命令行与 MCP 两条入口正常完成
//   畸形输入   模板名不认、策略不是对象、写出路径不可用、各类法律字段缺失或类型不对
//   部分读取   部分字段齐全时只拒缺失项；后果陈述逐条判定，缺摘录的那条被点名
// 另覆盖内容边界：输出不引用工具自身、不透露加固状态、不写面向代理的指令式文本、不生成法条编号。

import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import { RefusalError, UsageError } from '../src/errors.mjs';
import { runCli as runCliSubprocess } from './helpers/cli.mjs';
import { runCli as runCliInProcess } from '../src/cli/index.mjs';
import { createMcpServer } from '../src/mcp/server.mjs';
import { LEGAL_FIELD_SPEC } from '../src/policy/schema.mjs';
import {
  FORBIDDEN_NOTICE_TOKENS,
  NOTICE_BLOCK_SCHEMA,
  NOTICE_CONTENT_RULES,
  NOTICE_TEMPLATES,
  assertNoticeContentSafe,
  buildNoticeBlock,
  findForbiddenTokens,
  generateNotice,
  inspectLegalFields,
  normalizeLegalFields,
  renderLicenseNotice,
  requireLegalFields,
} from '../src/notice/index.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, 'notice', 'fixtures');

/** 已提交夹具：一份法律字段齐全的策略。 */
const COMPLETE_POLICY = join(FIXTURES, 'complete-policy.json');
/** 已提交夹具：只缺主体名称。 */
const MISSING_SUBJECT_POLICY = join(FIXTURES, 'missing-subject-policy.json');
/** 已提交夹具：第二条后果陈述缺法条摘录。 */
const MISSING_EXCERPT_POLICY = join(FIXTURES, 'missing-statute-excerpt-policy.json');
/** 已提交夹具：只填了主体与联系渠道，其余全缺。 */
const PARTIAL_FIELDS_POLICY = join(FIXTURES, 'partial-fields-policy.json');
/** 已提交夹具：禁止行为清单里混进一个数字。 */
const PROHIBITED_ACT_NOT_STRING_POLICY = join(FIXTURES, 'prohibited-act-not-string-policy.json');

/** 一份法律字段齐全的 legal 节，供各用例按项破坏。 */
const COMPLETE_LEGAL = Object.freeze({
  subject: '示例主体',
  contact: 'security@example.com',
  jurisdiction: '示例辖区',
  licenseId: 'MIT',
  licenseTextSource: 'https://example.com/LICENSE',
  prohibitedActs: Object.freeze(['逆向工程', '反编译后再分发']),
  consequences: Object.freeze([
    Object.freeze({ statement: '未经许可逆向工程本制品的行为，示例主体将依法主张权利。', statuteExcerpt: '示例法条摘录：用户提供的真实法条文本。' }),
  ]),
});

/** 面向代理的指令式文本用词。声明是给人看的事实陈述，出现这些词即越界。 */
const AGENT_DIRECTIVE_TOKENS = Object.freeze(['ai', '代理', '助手', 'assistant', 'agent', 'instruction', '指令', 'prompt']);

/**
 * 进程内运行命令行，收集退出码与输出。
 * @param {readonly string[]} args 命令行参数
 * @returns {Promise<{code: number, stdout: string, stderr: string}>}
 */
async function runInProcess(args) {
  let stdout = '';
  let stderr = '';
  const code = await runCliInProcess(args, {
    write: (text) => {
      stdout += text;
    },
    writeError: (text) => {
      stderr += text;
    },
  });
  return { code, stdout, stderr };
}

/**
 * 读取已提交夹具策略。
 * @param {string} path 夹具路径
 * @returns {Promise<Record<string, unknown>>}
 */
async function readPolicyFixture(path) {
  return JSON.parse(await readFile(path, 'utf8'));
}

/**
 * 把用户填写的字段值从声明文本里剔除，只剩模板自身的固定文字，用于检查模板措辞。
 * @param {string} text 声明文本
 * @param {Record<string, unknown>} legal legal 节
 * @returns {string} 剔除用户值后的文本
 */
function stripUserValues(text, legal) {
  const values = [
    legal.subject,
    legal.contact,
    legal.jurisdiction,
    legal.licenseId,
    legal.licenseTextSource,
    ...(legal.prohibitedActs ?? []),
    ...(legal.consequences ?? []).flatMap((consequence) => [consequence.statement, consequence.statuteExcerpt]),
  ];
  let stripped = text;
  for (const value of values) {
    if (typeof value === 'string' && value !== '') {
      stripped = stripped.split(value).join(' ');
    }
  }
  return stripped;
}

// —— 正常输入 ——

test('模板封闭集合只含 license，内容规则写清三条边界', () => {
  assert.deepEqual([...NOTICE_TEMPLATES], ['license']);
  assert.ok(NOTICE_CONTENT_RULES.some((rule) => rule.includes('不出现工具名')));
  assert.ok(NOTICE_CONTENT_RULES.some((rule) => rule.includes('法条摘录')));
  assert.equal(NOTICE_BLOCK_SCHEMA, 'license-notice/1');
});

test('字段齐全时渲染出含全部真实字段的声明文档', async () => {
  const policy = await readPolicyFixture(COMPLETE_POLICY);
  const legal = policy.legal;
  const text = renderLicenseNotice(legal);

  // 五个字符串字段逐字出现。
  for (const field of ['subject', 'contact', 'jurisdiction', 'licenseId', 'licenseTextSource']) {
    assert.ok(text.includes(legal[field]), `声明应包含 ${field} 的原文：${legal[field]}`);
  }
  // 禁止行为逐条出现，且编号连续。
  for (const [index, act] of legal.prohibitedActs.entries()) {
    assert.ok(text.includes(`${index + 1}. ${act}`), `声明应逐条列出禁止行为：${act}`);
  }
  // 每条后果陈述都跟着自己的法条摘录。
  for (const [index, consequence] of legal.consequences.entries()) {
    assert.ok(text.includes(`${index + 1}. ${consequence.statement}`), '声明应逐条列出后果陈述');
    assert.ok(text.includes(`法条摘录：${consequence.statuteExcerpt}`), '每条后果陈述都应附法条摘录');
  }
  // 章节顺序固定，机器可读声明块在末尾。
  const order = ['## 许可', '## 禁止行为', '## 后果陈述', '## 授权申请', '## 机器可读声明块'].map((heading) =>
    text.indexOf(heading),
  );
  assert.deepEqual(order, [...order].sort((left, right) => left - right), '章节顺序应与模板一致');
  assert.ok(text.endsWith('\n'), '声明文档以换行符结尾');
});

test('机器可读声明块可被解析，字段与策略逐一相等', async () => {
  const policy = await readPolicyFixture(COMPLETE_POLICY);
  const text = renderLicenseNotice(policy.legal);
  const fenced = text.slice(text.indexOf('```json') + '```json'.length, text.lastIndexOf('```'));
  const block = JSON.parse(fenced);

  assert.equal(block.schema, NOTICE_BLOCK_SCHEMA);
  assert.equal(block.subject, policy.legal.subject);
  assert.equal(block.contact, policy.legal.contact);
  assert.equal(block.jurisdiction, policy.legal.jurisdiction);
  assert.equal(block.license.id, policy.legal.licenseId);
  assert.equal(block.license.textSource, policy.legal.licenseTextSource);
  assert.deepEqual(block.prohibitedActs, [...policy.legal.prohibitedActs]);
  assert.deepEqual(
    block.consequences,
    policy.legal.consequences.map((consequence) => ({ statement: consequence.statement, statuteExcerpt: consequence.statuteExcerpt })),
  );
  assert.equal(block.authorization.subject, policy.legal.subject);
  assert.equal(block.authorization.channel, policy.legal.contact);

  // 直接构造的块与文档内嵌的块一致。
  assert.deepEqual(buildNoticeBlock(policy.legal), block);
  assert.deepEqual(requireLegalFields(policy), normalizeLegalFields(policy.legal));
});

test('渲染确定：同一策略渲染两次逐字节相同', async () => {
  const policy = await readPolicyFixture(COMPLETE_POLICY);
  const first = renderLicenseNotice(policy.legal);
  const second = renderLicenseNotice(policy.legal);
  assert.equal(first, second);
  const firstRun = await generateNotice({ template: 'license', policy });
  const secondRun = await generateNotice({ template: 'license', policy });
  assert.equal(firstRun.text, secondRun.text);
  assert.equal(firstRun.text, first);
});

test('给出 outPath 时声明落盘，内容与返回文本一致，重复写出逐字节相同', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-notice-out-'));
  try {
    const policy = await readPolicyFixture(COMPLETE_POLICY);
    const outPath = join(dir, 'NOTICE.md');
    const result = await generateNotice({ template: 'license', policy, outPath });
    assert.equal(result.output, outPath);
    const written = await readFile(outPath);
    assert.equal(Buffer.compare(written, Buffer.from(result.text, 'utf8')), 0, '写出内容应与返回文本一致');

    await generateNotice({ template: 'license', policy, outPath });
    const rewritten = await readFile(outPath);
    assert.equal(Buffer.compare(rewritten, written), 0, '同一策略重复写出应逐字节相同');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('输出不引用工具自身，也不透露加固、审计或缓解状态', async () => {
  const policy = await readPolicyFixture(COMPLETE_POLICY);
  const result = await generateNotice({ template: 'license', policy });
  assert.deepEqual(findForbiddenTokens(result.text), [], `声明出现不允许的表述：${JSON.stringify(findForbiddenTokens(result.text))}`);
  assert.ok(!result.text.toLowerCase().includes('anti-rea'), '声明不得引用工具自身');
  assert.ok(!result.text.includes('加固'), '声明不得透露加固状态');
  assert.ok(!result.text.includes('审计'), '声明不得透露审计结论');
  assert.ok(!result.text.includes('缓解'), '声明不得透露缓解措施');
});

test('模板自身文字自检通过，且检查对违规表述有效', async () => {
  // 自检只覆盖模板写死的文字，正常模板必须通过。
  assert.doesNotThrow(() => assertNoticeContentSafe());

  // 检查本身有效：植入的违规表述必须被检出。
  const hits = findForbiddenTokens('本声明由 Anti-REA 生成，制品已完成加固与审计。');
  assert.ok(hits.includes('anti-rea'), '应检出工具身份标识');
  assert.ok(hits.includes('加固'), '应检出加固状态暗示');
  assert.ok(hits.includes('审计'), '应检出审计状态暗示');
});

test('模板措辞不含面向代理的指令式文本', async () => {
  // 用占位值渲染，只剩模板自身的固定文字。
  const scaffold = renderLicenseNotice({
    subject: 'S',
    contact: 'C',
    jurisdiction: 'J',
    licenseId: 'L',
    licenseTextSource: 'T',
    prohibitedActs: ['A'],
    consequences: [{ statement: 'ST', statuteExcerpt: 'SE' }],
  });
  const lower = scaffold.toLowerCase();
  for (const token of AGENT_DIRECTIVE_TOKENS) {
    assert.ok(!lower.includes(token.toLowerCase()), `模板文字不得出现面向代理的指令式用词：${token}`);
  }
  // 声明是事实陈述，不是给分析代理的指令。
  assert.ok(scaffold.includes('本声明由 S 出具。'));
});

test('用户自填的字段值不参与模板自检', async () => {
  // 自检只覆盖模板自身文字：用户自己的主体名称里出现工具字样时，
  // 那是用户自己的陈述，不由工具拒否；工具要保证的是自己不说那些话。
  const policy = { legal: { ...COMPLETE_LEGAL, subject: 'Anti-REA 示例主体' } };
  const result = await generateNotice({ template: 'license', policy });
  assert.ok(result.text.includes('Anti-REA 示例主体'), '用户自填字段应原样进入声明');
  assert.doesNotThrow(() => assertNoticeContentSafe());
});

test('剔除用户字段值后，模板文字不生成法条编号或法条名', async () => {
  const policy = await readPolicyFixture(COMPLETE_POLICY);
  const text = renderLicenseNotice(policy.legal);
  const scaffold = stripUserValues(text, policy.legal);
  assert.ok(!/《[^》]*》/.test(scaffold), '模板不得自行生成法条名');
  assert.ok(!/第\s*\d+\s*条/.test(scaffold), '模板不得自行生成法条编号');
});

test('命令行 notice 在字段齐全时退出码为 0 且输出可被 JSON.parse', async () => {
  const result = await runInProcess(['notice', '--template', 'license', '--json', '--policy', COMPLETE_POLICY]);
  assert.equal(result.code, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, 'generated');
  assert.equal(report.template, 'license');
  assert.equal(report.output, null);
});

test('命令行 notice --format json 与 --json 等价，--format text 输出人读文本', async () => {
  const viaFormat = await runInProcess(['notice', '--template', 'license', '--format', 'json', '--policy', MISSING_SUBJECT_POLICY]);
  assert.equal(viaFormat.code, 3, viaFormat.stderr);
  const report = JSON.parse(viaFormat.stdout);
  assert.equal(report.schema, 'anti-rea.refusal/1');
  assert.ok(report.omitted_reason.length > 0);

  const human = await runInProcess(['notice', '--template', 'license', '--format', 'text', '--policy', MISSING_SUBJECT_POLICY]);
  assert.equal(human.code, 3);
  assert.match(human.stdout, /拒否原因/);
  assert.match(human.stdout, /主体名称/);
  assert.equal(human.stdout.trimStart().startsWith('{'), false, '文本模式不得输出 JSON');
});

test('MCP generate_notice 在字段齐全时正常返回，缺失时返回含 omitted_reason 的拒否报告', async () => {
  const server = createMcpServer();
  const generated = await server.handle({
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: { name: 'generate_notice', arguments: { template: 'license', policy: COMPLETE_POLICY } },
  });
  assert.equal(generated.result.isError, false);
  const generatedReport = JSON.parse(generated.result.content[0].text);
  assert.equal(generatedReport.status, 'generated');

  const refused = await server.handle({
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/call',
    params: { name: 'generate_notice', arguments: { template: 'license', policy: MISSING_SUBJECT_POLICY } },
  });
  // 拒否按失败信号返回。此前这里断言 isError 为 false，理由是“拒否不是调用失败”；
  // 但代理按成功信号收到一份并没有生成的声明，正是本项目反复修的那类
  // “协议层看起来成功而实际没有”。报告连同 omitted_reason 一起送回，信息不减。
  assert.equal(refused.result.isError, true, '拒否不是成功，按失败信号返回');
  const refusedReport = JSON.parse(refused.result.content[0].text);
  assert.equal(refusedReport.status, 'refused');
  assert.ok(refusedReport.omitted_reason.some((reason) => reason.includes('主体名称')));
  assert.equal(refusedReport.omittedReason, undefined, '拒否报告只保留蛇形 omitted_reason');
});

// —— 畸形输入 ——

test('模板名不认或不是字符串时按用法错误处理', async () => {
  const policy = await readPolicyFixture(COMPLETE_POLICY);
  for (const template of ['eula', '', 'LICENSE', 42, undefined, null]) {
    await assert.rejects(
      () => generateNotice({ template, policy }),
      (error) => {
        assert.ok(error instanceof UsageError, `模板 ${String(template)} 应报用法错误`);
        assert.equal(error.code, 2);
        assert.match(error.message, /不支持的声明模板/);
        assert.match(error.message, /license/);
        return true;
      },
    );
  }
});

test('策略不是对象时按用法错误处理，不按拒否处理', async () => {
  for (const policy of ['legal', 42, true, ['legal']]) {
    await assert.rejects(
      () => generateNotice({ template: 'license', policy }),
      (error) => {
        assert.ok(error instanceof UsageError, `策略 ${JSON.stringify(policy)} 应报用法错误`);
        assert.equal(error.code, 2);
        return true;
      },
    );
  }
});

test('策略为 null 或缺省时按法律字段缺失拒否', async () => {
  for (const policy of [null, undefined]) {
    await assert.rejects(
      () => generateNotice({ template: 'license', policy }),
      (error) => {
        assert.ok(error instanceof RefusalError, '没有策略即没有真实字段，走拒否');
        assert.equal(error.code, 3);
        assert.equal(error.omittedReason.length, LEGAL_FIELD_SPEC.length, '应逐条点名全部缺失字段');
        return true;
      },
    );
  }
});

test('各类法律字段缺失或类型不对都走拒否，且理由点名缺失项', async () => {
  const cases = [
    { name: '缺主体', legal: { ...COMPLETE_LEGAL, subject: '' }, pattern: /主体名称/ },
    { name: '主体只有空白', legal: { ...COMPLETE_LEGAL, subject: '   ' }, pattern: /主体名称/ },
    { name: '缺联系渠道', legal: { ...COMPLETE_LEGAL, contact: '' }, pattern: /联系渠道/ },
    { name: '缺司法辖区', legal: { ...COMPLETE_LEGAL, jurisdiction: '' }, pattern: /司法辖区/ },
    { name: '缺许可标识', legal: { ...COMPLETE_LEGAL, licenseId: '' }, pattern: /许可标识/ },
    { name: '缺许可文本来源', legal: { ...COMPLETE_LEGAL, licenseTextSource: '' }, pattern: /许可文本来源/ },
    { name: '禁止行为为空数组', legal: { ...COMPLETE_LEGAL, prohibitedActs: [] }, pattern: /禁止行为清单/ },
    { name: '禁止行为不是数组', legal: { ...COMPLETE_LEGAL, prohibitedActs: '逆向工程' }, pattern: /禁止行为清单/ },
    { name: '禁止行为含非字符串项', legal: { ...COMPLETE_LEGAL, prohibitedActs: ['逆向工程', 7] }, pattern: /不是非空字符串/ },
    { name: '禁止行为含空串项', legal: { ...COMPLETE_LEGAL, prohibitedActs: ['逆向工程', '  '] }, pattern: /不是非空字符串/ },
    { name: '后果陈述为空数组', legal: { ...COMPLETE_LEGAL, consequences: [] }, pattern: /后果陈述/ },
    { name: '后果陈述缺法条摘录', legal: { ...COMPLETE_LEGAL, consequences: [{ statement: '示例后果陈述' }] }, pattern: /法条摘录/ },
    { name: '后果陈述为空', legal: { ...COMPLETE_LEGAL, consequences: [{ statuteExcerpt: '示例法条摘录' }] }, pattern: /后果陈述为空/ },
    { name: '法律节缺失', legal: undefined, pattern: /主体名称/ },
  ];
  for (const testCase of cases) {
    const policy = { legal: testCase.legal };
    const inspection = inspectLegalFields(policy);
    assert.equal(inspection.complete, false, `${testCase.name} 不应判定为完整`);
    await assert.rejects(
      () => generateNotice({ template: 'license', policy }),
      (error) => {
        assert.ok(error instanceof RefusalError, `${testCase.name} 必须走拒否而不是其他错误`);
        assert.equal(error.code, 3);
        assert.ok(Array.isArray(error.omittedReason) && error.omittedReason.length > 0, '拒否必须逐条列出原因');
        assert.ok(
          error.omittedReason.some((reason) => testCase.pattern.test(reason)),
          `${testCase.name} 的理由应点名缺失项：${JSON.stringify(error.omittedReason)}`,
        );
        return true;
      },
      `${testCase.name} 应抛 RefusalError`,
    );
  }
});

test('拒否时不产出声明文本，也不写出任何文件', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-notice-refuse-'));
  try {
    const outPath = join(dir, 'NOTICE.md');
    await assert.rejects(() => generateNotice({ template: 'license', policy: { legal: {} }, outPath }), RefusalError);
    const info = await stat(outPath).then(
      () => 'exists',
      () => 'missing',
    );
    assert.equal(info, 'missing', '拒否后不得留下任何声明文件');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('写出路径的父目录不存在时按用法错误处理，且不创建目录', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-notice-badout-'));
  try {
    const policy = await readPolicyFixture(COMPLETE_POLICY);
    const outPath = join(dir, 'no-such-dir', 'NOTICE.md');
    await assert.rejects(
      () => generateNotice({ template: 'license', policy, outPath }),
      (error) => {
        assert.ok(error instanceof UsageError, '写不出去属于输入错误');
        assert.equal(error.code, 2);
        assert.ok(error.message.includes(outPath), '错误信息应点名路径');
        return true;
      },
    );
    const created = await stat(join(dir, 'no-such-dir')).then(
      () => true,
      () => false,
    );
    assert.equal(created, false, '不得顺带创建目录');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('命令行对模板名不认返回用法错误，对类型错误的策略文件同样返回用法错误', async () => {
  const unknownTemplate = await runInProcess(['notice', '--template', 'eula']);
  assert.equal(unknownTemplate.code, 2);
  assert.match(unknownTemplate.stderr, /不支持的声明模板/);

  // 禁止行为清单里混进数字：策略载入时按类型错误拒绝（退出码 2），
  // 与 notice 侧按缺失拒否（退出码 3）是两道关口，互不替代。
  const typeError = await runInProcess(['notice', '--template', 'license', '--json', '--policy', PROHIBITED_ACT_NOT_STRING_POLICY]);
  assert.equal(typeError.code, 2);
  assert.match(typeError.stderr, /legal\.prohibitedActs\[1\] 必须是字符串/);

  // 绕过策略载入、直接进 notice 侧时，同一份字段按缺失拒否。
  const policy = await readPolicyFixture(PROHIBITED_ACT_NOT_STRING_POLICY);
  await assert.rejects(
    () => generateNotice({ template: 'license', policy }),
    (error) => {
      assert.ok(error instanceof RefusalError);
      assert.ok(error.omittedReason.some((reason) => reason.includes('legal.prohibitedActs[1]')));
      return true;
    },
  );
});

// —— 部分字段：只拒缺失项，逐条点名 ——

test('部分字段齐全时只拒缺失项，不点名已填字段', async () => {
  const policy = await readPolicyFixture(PARTIAL_FIELDS_POLICY);
  const inspection = inspectLegalFields(policy);
  assert.equal(inspection.complete, false);
  const joined = inspection.omittedReason.join('\n');
  for (const label of ['司法辖区', '许可标识', '许可文本来源', '禁止行为清单', '后果陈述']) {
    assert.ok(joined.includes(label), `应点名缺失的${label}`);
  }
  assert.ok(!/主体名称|联系渠道/.test(joined), '已填字段不应出现在拒否理由里');

  await assert.rejects(
    () => generateNotice({ template: 'license', policy }),
    (error) => {
      assert.ok(error instanceof RefusalError);
      assert.equal(error.omittedReason.length, 5, '只应列出五项缺失');
      return true;
    },
  );
});

test('后果陈述逐条判定：缺摘录的那条被点名，齐全的那条不被点名', async () => {
  const policy = await readPolicyFixture(MISSING_EXCERPT_POLICY);
  const inspection = inspectLegalFields(policy);
  assert.equal(inspection.complete, false);
  const joined = inspection.omittedReason.join('\n');
  assert.ok(joined.includes('第 2 条'), '应点名缺摘录的是第 2 条');
  assert.ok(joined.includes('legal.consequences[1].statuteExcerpt'), '应给出可定位的字段路径');
  assert.ok(!joined.includes('第 1 条'), '齐全的那条不应被点名');
});

// —— 命令行与 MCP 两条入口的拒否语义 ——

test('命令行 notice 缺主体时退出码为 3，输出含 omitted_reason 并点名缺失字段', async () => {
  const result = await runCliSubprocess(['notice', '--template', 'license', '--json', '--policy', MISSING_SUBJECT_POLICY]);
  assert.equal(result.code, 3);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, 'refused');
  assert.ok(Array.isArray(report.omitted_reason) && report.omitted_reason.length > 0, '拒否报告必须带原因清单');
  assert.ok(report.omitted_reason.some((reason) => reason.includes('主体名称')), '原因清单应点名缺失字段');
});

test('命令行 notice 不带策略时按默认策略拒否，理由覆盖全部法律字段', async () => {
  const result = await runCliSubprocess(['notice', '--template', 'license', '--json']);
  assert.equal(result.code, 3);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, 'refused');
  assert.equal(report.omitted_reason.length, LEGAL_FIELD_SPEC.length);
});

test('命令行 notice 缺少 --template 时退出码为 2', async () => {
  const result = await runInProcess(['notice']);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /--template/);
});

test('命令行 notice 的人读输出同样带拒否原因', async () => {
  // notice 的选项表现已登记 --format（取值 text 与 json，语义与 audit 一致）；
  // 不给 --json 也不给 --format 时默认输出人读文本。
  const result = await runCliSubprocess(['notice', '--template', 'license', '--policy', MISSING_SUBJECT_POLICY]);
  assert.equal(result.code, 3);
  assert.match(result.stdout, /拒否原因/);
  assert.match(result.stdout, /主体名称/);
});

test('临时策略文件写入后按文件路径走完整链路：拒否与生成各一次', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-notice-policy-'));
  try {
    const badPath = join(dir, 'bad.json');
    await writeFile(badPath, JSON.stringify({ legal: { ...COMPLETE_LEGAL, contact: '' } }), 'utf8');
    const bad = await runInProcess(['notice', '--template', 'license', '--json', '--policy', badPath]);
    assert.equal(bad.code, 3);
    assert.ok(JSON.parse(bad.stdout).omitted_reason.some((reason) => reason.includes('联系渠道')));

    const goodPath = join(dir, 'good.json');
    await writeFile(goodPath, JSON.stringify({ legal: COMPLETE_LEGAL }), 'utf8');
    const good = await runInProcess(['notice', '--template', 'license', '--json', '--policy', goodPath]);
    assert.equal(good.code, 0);
    assert.equal(JSON.parse(good.stdout).status, 'generated');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
