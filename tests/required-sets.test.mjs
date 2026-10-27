// required-sets 模块测试：必需集数据与豁免规则。
// 覆盖三类输入：正常输入（真实字节夹具上的基线与豁免派生）、
// 畸形输入（形状不合法的施加记录与事实表）、部分读取（事实表缺项与截断制品）。
//
// 结构事实由 tests/required-sets/extract-facts.mjs 从真实字节夹具提取，
// 它是读取器层的替身：只检验必需集真正依赖的结构，深度事实提取属 readers 模块职责。

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';

import { MITIGATION_IDS } from '../src/audit/finding.mjs';
import { SUPPORTED_CONTAINERS } from '../src/container/detect.mjs';
import { UsageError } from '../src/errors.mjs';
import {
  REQUIRED_ITEM_KINDS,
  REQUIRED_ITEM_STATUS,
  REQUIRED_SETS,
  REQUIRED_SET_SCHEMA,
  REQUIRED_SET_STATUS,
  REQUIRED_SET_VERDICT,
  appliedMitigationIds,
  checkRequiredSet,
  deriveExemptions,
  exemptionsFor,
  requiredItemsOf,
  requiredSetFor,
} from '../src/required-sets/index.mjs';
import { buildFixtures, digestFixtures } from './required-sets/build-fixtures.mjs';
import { extractFacts } from './required-sets/extract-facts.mjs';

const fixtures = buildFixtures();
const digests = digestFixtures(fixtures);

/** 记录的夹具摘要，保证测试跑的是固定真实字节。 */
const RECORDED_DIGESTS = Object.freeze({
  elf: 'c9643ac098936a685b85c4dda5b7bbf50dfcc2b38ea7b1d3a72efefc3a62f2ae',
  'elf-broken-program-headers': '00e21b0cbc695d0497efb08198c7cec1475d08817ef7b11688a77bb3e94f9146',
  pe: '962bd63bbaf078c8866c6874a8feb698c94c56e14c842e317f3acc0411b47d54',
  'pe-checksum-nonzero': '4540b98b15763af28cb8cdb6fd4fe907bd0bdb40b95cbb43cbf413ba048a8de3',
  'mach-o': '12311042d802495b51c8d1b712691c0163ef03a8d226602c6d726924ac025316',
  zip: '757dfa87046f5d20b0c2539e0a7368e7ac8e9a417d3e98d884833a2c82b50721',
  gguf: 'e6dcd369cec9c783fd1979e29c6634ca48810e63e9ac4738b9f81ed7473ac255',
  safetensors: '70304c712870442d4771ce597379e58e8c1b9b591a2495780779bcb726b6aee9',
  'safetensors-no-metadata': '093c4b223aebad441558da34ce1c10979f30fb0f481d9d5352e183c5eef32f41',
  pyc: 'e1d2aebb2fe4f47690d9caede62820110faa7a7cc381ea072c256dab2d996496',
  'pyc-hash-cleared': '1f43b7318c005cd8f5a827a4122903f5b0207ed05802779f6ffd3b59ed529b55',
  beam: '66a218952269cec33a95e05a3fcd39b68adde70d807cb4a77b3d6e0a08dca9a3',
});

/** 容器标识到夹具键的映射，每类格式至少一个真实字节夹具。 */
const CONTAINER_FIXTURES = Object.freeze({
  elf: 'elf',
  pe: 'pe',
  'mach-o': 'mach-o',
  zip: 'zip',
  gguf: 'gguf',
  safetensors: 'safetensors',
  pyc: 'pyc',
  beam: 'beam',
});

// ---------------------------------------------------------------------------
// 数据完整性
// ---------------------------------------------------------------------------

test('必需集覆盖 v1 全部容器标识，且不多登记', () => {
  assert.deepEqual(Object.keys(REQUIRED_SETS).sort(), [...SUPPORTED_CONTAINERS].sort());
  for (const container of SUPPORTED_CONTAINERS) {
    const set = REQUIRED_SETS[container];
    assert.equal(set.container, container);
    assert.equal(set.status, 'registered');
    assert.equal(set.schema ?? REQUIRED_SET_SCHEMA, REQUIRED_SET_SCHEMA);
    assert.ok(set.items.length > 0, `容器 ${container} 没有登记任何必需项`);
    assert.ok(typeof set.note === 'string' && set.note !== '');
  }
});

test('必需项编号全局唯一，类别在封闭词表内', () => {
  const seen = new Set();
  for (const [container, set] of Object.entries(REQUIRED_SETS)) {
    assert.ok(REQUIRED_SET_STATUS.includes(set.status), `容器 ${container} 的登记状态不在封闭集合内`);
    for (const item of set.items) {
      assert.ok(!seen.has(item.id), `必需项编号重复：${item.id}`);
      seen.add(item.id);
      assert.ok(REQUIRED_ITEM_KINDS.includes(item.kind), `必需项 ${item.id} 的类别 ${item.kind} 不在词表内`);
      assert.ok(typeof item.label === 'string' && item.label !== '');
      assert.ok(typeof item.requirement === 'string' && item.requirement !== '', `必需项 ${item.id} 缺少判定依据`);
      assert.ok(Array.isArray(item.exemptedBy));
    }
  }
});

test('判定状态落在封闭集合内', () => {
  const verdicts = new Set();
  const itemStatuses = new Set();
  for (const [container, fixtureKey] of Object.entries(CONTAINER_FIXTURES)) {
    const facts = extractFacts(container, fixtures[fixtureKey]);
    for (const applied of [[], ['metadata.elf-symtab-clear', 'metadata.pyc-source-hash-clear']]) {
      const result = checkRequiredSet(container, facts, applied);
      verdicts.add(result.status);
      for (const item of result.items) {
        itemStatuses.add(item.status);
      }
    }
  }
  verdicts.add(checkRequiredSet('il2cpp-metadata', {}, []).status);
  verdicts.add(checkRequiredSet('elf', null, []).status);
  for (const status of verdicts) {
    assert.ok(REQUIRED_SET_VERDICT.includes(status), `总体判定出现封闭集合外取值：${status}`);
  }
  for (const status of itemStatuses) {
    assert.ok(REQUIRED_ITEM_STATUS.includes(status), `单项判定出现封闭集合外取值：${status}`);
  }
  assert.ok(verdicts.has('passed'));
  assert.ok(itemStatuses.has('exempted'));
});

test('豁免登记的缓解编号全部在封闭集合内', () => {
  for (const [container, set] of Object.entries(REQUIRED_SETS)) {
    for (const item of set.items) {
      for (const mitigation of item.exemptedBy) {
        assert.ok(MITIGATION_IDS.includes(mitigation), `容器 ${container} 的 ${item.id} 登记了词表外缓解编号 ${mitigation}`);
      }
    }
  }
});

test('等长覆写类缓解与可豁免项一一对应', () => {
  const elf = REQUIRED_SETS.elf.items;
  const exemptedBy = (itemId) => elf.find((item) => item.id === itemId).exemptedBy;
  assert.deepEqual(exemptedBy('elf.section.symtab'), ['metadata.elf-symtab-clear']);
  assert.deepEqual(exemptedBy('elf.section.strtab'), ['metadata.elf-symtab-clear']);
  assert.ok(exemptedBy('elf.section.note').includes('metadata.elf-symtab-clear'));
  assert.ok(exemptedBy('elf.section.go-buildinfo').includes('metadata.go-buildinfo-inline-overwrite'));
  assert.ok(exemptedBy('elf.section.go-buildinfo').includes('metadata.go-buildinfo-pointer-overwrite'));
  assert.ok(exemptedBy('elf.section.go-buildinfo').includes('metadata.go-buildinfo-writable-region-overwrite'));
  assert.deepEqual(exemptedBy('elf.section.dep-v0'), ['metadata.rust-dep-section-overwrite']);
  assert.deepEqual(
    REQUIRED_SETS.pe.items.find((item) => item.id === 'pe.debug-directory').exemptedBy,
    ['metadata.pe-debug-directory-overwrite'],
  );
  assert.deepEqual(
    REQUIRED_SETS.pe.items.find((item) => item.id === 'pe.section.go-buildinfo').exemptedBy,
    ['metadata.go-buildinfo-pe-characteristics-overwrite'],
  );
  assert.deepEqual(
    REQUIRED_SETS['mach-o'].items.find((item) => item.id === 'mach-o.section.go-buildinfo').exemptedBy,
    ['metadata.go-buildinfo-macho-rw-overwrite'],
  );
  const pyc = REQUIRED_SETS.pyc.items;
  for (const itemId of ['pyc.source-hash', 'pyc.check-source-flag']) {
    assert.deepEqual(pyc.find((item) => item.id === itemId).exemptedBy, ['metadata.pyc-source-hash-clear']);
  }
});

test('模型层重布局写入不豁免任何必需项', () => {
  // 重布局写入后全部结构仍必须可解析，豁免只属于被覆写破坏的节与字段。
  for (const set of Object.values(REQUIRED_SETS)) {
    for (const item of set.items) {
      assert.ok(!item.exemptedBy.includes('model.safetensors-metadata-relayout'));
      assert.ok(!item.exemptedBy.includes('model.gguf-metadata-relayout'));
    }
  }
});

test('夹具字节确定，摘要与记录一致', () => {
  for (const [name, expected] of Object.entries(RECORDED_DIGESTS)) {
    assert.ok(fixtures[name] !== undefined, `缺少夹具 ${name}`);
    assert.equal(createHash('sha256').update(fixtures[name]).digest('hex'), expected, `夹具 ${name} 的字节发生变化`);
    assert.equal(digests[name], expected);
  }
});

// ---------------------------------------------------------------------------
// 豁免规则：正常输入
// ---------------------------------------------------------------------------

test('施加构建信息覆写后，ELF 必需集除该项外全部保留', () => {
  const result = deriveExemptions(['metadata.go-buildinfo-inline-overwrite'], REQUIRED_SETS.elf.items);
  assert.deepEqual(result.exempted, ['elf.section.go-buildinfo']);
  assert.equal(result.required.length, REQUIRED_SETS.elf.items.length - 1);
  assert.ok(!result.required.includes('elf.section.go-buildinfo'));
  assert.deepEqual(result.unmatched, []);
});

test('施加记录按对象形状识别，与编号数组等价', () => {
  const applied = [{ mitigation: 'metadata.go-buildinfo-pointer-overwrite', kind: 'equal-length-overwrite' }];
  assert.deepEqual(appliedMitigationIds(applied), ['metadata.go-buildinfo-pointer-overwrite']);
  assert.deepEqual(appliedMitigationIds({ applied }), ['metadata.go-buildinfo-pointer-overwrite']);
  const fromRecord = deriveExemptions({ applied }, REQUIRED_SETS.elf.items);
  const fromArray = deriveExemptions(['metadata.go-buildinfo-pointer-overwrite'], REQUIRED_SETS.elf.items);
  assert.deepEqual(fromRecord, fromArray);
});

test('符号表清零同时豁免符号表、字符串表与 note 三项', () => {
  const result = deriveExemptions(['metadata.elf-symtab-clear'], REQUIRED_SETS.elf.items);
  assert.deepEqual(result.exempted.sort(), ['elf.section.note', 'elf.section.strtab', 'elf.section.symtab']);
  assert.ok(result.required.includes('elf.program-headers'), '程序头不因符号表清零而豁免');
  assert.ok(result.required.includes('elf.section.dynsym'), '动态符号表不因静态符号表清零而豁免');
});

test('pyc 哈希清零同时豁免源哈希与 check_source 标志', () => {
  const result = deriveExemptions(['metadata.pyc-source-hash-clear'], REQUIRED_SETS.pyc.items);
  assert.deepEqual(result.exempted.sort(), ['pyc.check-source-flag', 'pyc.source-hash']);
  assert.ok(result.required.includes('pyc.magic'));
  assert.ok(result.required.includes('pyc.code-object'));
});

test('没有施加任何措施时不做任何豁免', () => {
  const result = deriveExemptions([], REQUIRED_SETS.elf.items);
  assert.deepEqual(result.exempted, []);
  assert.equal(result.required.length, REQUIRED_SETS.elf.items.length);
  assert.deepEqual(result.unmatched, []);
});

test('词表外的缓解编号进 unmatched，不影响必需集划分', () => {
  const result = deriveExemptions(['metadata.not-a-real-mitigation'], REQUIRED_SETS.elf.items);
  assert.deepEqual(result.exempted, []);
  assert.deepEqual(result.unmatched, ['metadata.not-a-real-mitigation']);
  assert.equal(result.required.length, REQUIRED_SETS.elf.items.length);
});

test('exemptionsFor 对未登记容器返回 not-applicable', () => {
  const result = exemptionsFor([], 'il2cpp-metadata');
  assert.equal(result.status, 'not-applicable');
  assert.deepEqual(result.required, []);
  assert.deepEqual(result.exempted, []);
  assert.match(result.reason, /没有登记必需集/);
});

test('appliedMitigationIds 接受三种形状，空记录视为没有施加', () => {
  assert.deepEqual(appliedMitigationIds(null), []);
  assert.deepEqual(appliedMitigationIds(undefined), []);
  assert.deepEqual(appliedMitigationIds([]), []);
  assert.deepEqual(appliedMitigationIds({}), []);
  assert.deepEqual(appliedMitigationIds({ skipped: [{ mitigation: 'x' }] }), []);
});

// ---------------------------------------------------------------------------
// 必需集校验：真实字节上的正常输入
// ---------------------------------------------------------------------------

test('未加固的 ELF 夹具全部必需项可解析', () => {
  const facts = extractFacts('elf', fixtures.elf);
  const result = checkRequiredSet('elf', facts, []);
  assert.equal(result.status, 'passed');
  assert.equal(result.summary.total, REQUIRED_SETS.elf.items.length);
  assert.equal(result.summary.failed, 0);
  assert.equal(result.summary.unverified, 0);
  assert.equal(result.summary.exempted, 0);
  assert.deepEqual(result.limitations, []);
});

test('清零 .go.buildinfo 后按施加记录派生豁免，其余必需项仍可解析', () => {
  // 对应验收标准：对清零 .go.buildinfo 后的 ELF 按施加记录派生豁免，
  // 断言必需集中除该项外全部保持可解析。
  const facts = extractFacts('elf', fixtures.elf);
  const applied = [{ mitigation: 'metadata.go-buildinfo-inline-overwrite' }];
  const result = checkRequiredSet('elf', facts, applied);
  assert.equal(result.status, 'passed');
  const item = result.items.find((entry) => entry.id === 'elf.section.go-buildinfo');
  assert.equal(item.status, 'exempted');
  assert.equal(result.summary.exempted, 1);
  for (const entry of result.items) {
    if (entry.id !== 'elf.section.go-buildinfo') {
      assert.equal(entry.status, 'passed', `${entry.id} 应保持可解析，实际为 ${entry.status}`);
    }
  }
});

test('豁免项缺失事实时不判 unverified，其余项照常判定', () => {
  const facts = extractFacts('elf', fixtures.elf);
  delete facts['elf.section.go-buildinfo'];
  const result = checkRequiredSet('elf', facts, ['metadata.go-buildinfo-inline-overwrite']);
  assert.equal(result.status, 'passed');
  assert.equal(result.summary.exempted, 1);
  assert.equal(result.summary.unverified, 0);
});

test('程序头被破坏的 ELF 判 failed，且只归因到程序头表', () => {
  const facts = extractFacts('elf', fixtures['elf-broken-program-headers']);
  const result = checkRequiredSet('elf', facts, []);
  assert.equal(result.status, 'failed');
  const failed = result.items.filter((item) => item.status === 'failed');
  assert.deepEqual(failed.map((item) => item.id), ['elf.program-headers']);
  assert.match(failed[0].reason, /越界/);
  assert.ok(result.items.every((item) => item.id !== 'elf.program-headers' || item.status === 'failed'));
});

test('v1 八类格式的夹具各自全部必需项可解析', () => {
  for (const [container, fixtureKey] of Object.entries(CONTAINER_FIXTURES)) {
    const facts = extractFacts(container, fixtures[fixtureKey]);
    const result = checkRequiredSet(container, facts, []);
    assert.equal(result.status, 'passed', `容器 ${container} 的必需集校验未通过：${JSON.stringify(result.items.filter((i) => i.status !== 'passed'))}`);
    assert.equal(result.summary.total, REQUIRED_SETS[container].items.length);
  }
});

test('PE 非零 CheckSum 制品的校验和字段仍可读', () => {
  const facts = extractFacts('pe', fixtures['pe-checksum-nonzero']);
  const checksum = facts['pe.optional-header.checksum'];
  assert.equal(checksum.parsed, true);
  const result = checkRequiredSet('pe', facts, []);
  assert.equal(result.status, 'passed');
});

test('safetensors 没有 __metadata__ 时按不适用处理，不影响其他项', () => {
  const facts = extractFacts('safetensors', fixtures['safetensors-no-metadata']);
  assert.equal(facts['safetensors.metadata'].absent, true);
  const result = checkRequiredSet('safetensors', facts, []);
  assert.equal(result.status, 'passed');
  assert.equal(result.items.find((item) => item.id === 'safetensors.metadata').status, 'passed');
});

test('pyc 未施加清零时源哈希与标志留在必需集内', () => {
  const facts = extractFacts('pyc', fixtures['pyc-hash-cleared']);
  const result = checkRequiredSet('pyc', facts, []);
  assert.equal(result.status, 'passed');
  for (const itemId of ['pyc.source-hash', 'pyc.check-source-flag']) {
    const item = result.items.find((entry) => entry.id === itemId);
    assert.equal(item.status, 'passed', `${itemId} 未施加缓解时应留在必需集内`);
  }
  const after = checkRequiredSet('pyc', facts, ['metadata.pyc-source-hash-clear']);
  assert.equal(after.status, 'passed');
  assert.equal(after.items.find((item) => item.id === 'pyc.source-hash').status, 'exempted');
  assert.equal(after.items.find((item) => item.id === 'pyc.check-source-flag').status, 'exempted');
});

// ---------------------------------------------------------------------------
// 部分读取
// ---------------------------------------------------------------------------

test('事实表缺项判 unverified，总体落到 partial 并附限制说明', () => {
  const facts = extractFacts('elf', fixtures.elf);
  const partial = { 'elf.elf-header': facts['elf.elf-header'], 'elf.program-headers': facts['elf.program-headers'] };
  const result = checkRequiredSet('elf', partial, []);
  assert.equal(result.status, 'partial');
  assert.equal(result.summary.failed, 0);
  assert.equal(result.summary.unverified, REQUIRED_SETS.elf.items.length - 2);
  assert.ok(result.limitations.length > 0);
  assert.equal(result.limitations[0].code, 'structure-facts-missing');
  for (const limitation of result.limitations) {
    assert.match(limitation.message, /复审未提供/);
  }
});

test('事实表为 null 时全部项判 unverified，不冒充通过', () => {
  const result = checkRequiredSet('elf', null, []);
  assert.equal(result.status, 'partial');
  assert.equal(result.summary.passed, 0);
  assert.equal(result.summary.unverified, REQUIRED_SETS.elf.items.length);
});

test('形状无法识别的事实判 unverified，不影响其他项判定', () => {
  const facts = extractFacts('elf', fixtures.elf);
  facts['elf.section.text'] = '看起来没问题';
  const result = checkRequiredSet('elf', facts, []);
  assert.equal(result.status, 'partial');
  assert.equal(result.items.find((item) => item.id === 'elf.section.text').status, 'unverified');
  assert.equal(result.items.find((item) => item.id === 'elf.program-headers').status, 'passed');
});

test('严重截断的制品不会让进程挂起，且不判通过', () => {
  for (const [container, fixtureKey] of Object.entries(CONTAINER_FIXTURES)) {
    const truncated = fixtures[fixtureKey].subarray(0, 8);
    const facts = extractFacts(container, truncated);
    const result = checkRequiredSet(container, facts, []);
    assert.notEqual(result.status, 'passed', `容器 ${container} 的严重截断制品不应判通过`);
    assert.ok(['failed', 'partial'].includes(result.status));
  }
});

test('半长截断的制品能给出判定，不抛错不超时', () => {
  for (const [container, fixtureKey] of Object.entries(CONTAINER_FIXTURES)) {
    const half = fixtures[fixtureKey].subarray(0, Math.floor(fixtures[fixtureKey].length / 2));
    const facts = extractFacts(container, half);
    const result = checkRequiredSet(container, facts, []);
    assert.ok(['passed', 'failed', 'partial'].includes(result.status), `容器 ${container} 的判定不在封闭集合内`);
    assert.equal(result.summary.total, REQUIRED_SETS[container].items.length);
  }
});

// ---------------------------------------------------------------------------
// 畸形输入
// ---------------------------------------------------------------------------

test('施加记录与必需项清单为 null 时按空处理', () => {
  assert.deepEqual(deriveExemptions(null, null), { required: [], exempted: [], unmatched: [] });
  assert.deepEqual(deriveExemptions(undefined, undefined), { required: [], exempted: [], unmatched: [] });
});

test('施加记录不是数组时抛用法错误', () => {
  assert.throws(() => deriveExemptions('metadata.elf-symtab-clear', []), UsageError);
  assert.throws(() => deriveExemptions(42, []), /必须是数组/);
  assert.throws(() => appliedMitigationIds(42), /必须是数组，或含 applied 数组的对象/);
});

test('施加记录含无法识别的条目时抛用法错误', () => {
  assert.throws(() => deriveExemptions([42], []), /既不是编号字符串/);
  assert.throws(() => deriveExemptions([{ reason: '没有编号' }], []), /既不是编号字符串/);
  assert.throws(() => deriveExemptions([''], []), /既不是编号字符串/);
});

test('必需项清单形状不合法时抛用法错误', () => {
  assert.throws(() => deriveExemptions([], 'elf.items'), /必需项清单必须是数组/);
  assert.throws(() => deriveExemptions([], [42]), /必需项清单第 1 项/);
  assert.throws(() => deriveExemptions([], [{ kind: 'section' }]), /缺少字符串 id/);
  assert.throws(() => deriveExemptions([], [{ id: 'elf.section.text', exemptedBy: 'x' }]), /exemptedBy必须是数组/);
});

test('必需项清单兼容编号字符串形状', () => {
  const result = deriveExemptions(['elf.program-headers'], ['elf.program-headers', 'elf.section-table']);
  assert.deepEqual(result.exempted, ['elf.program-headers']);
  assert.deepEqual(result.required, ['elf.section-table']);
  assert.deepEqual(result.unmatched, []);
});

test('容器不在必需集表内时判 not-applicable，不抛错', () => {
  const result = checkRequiredSet('il2cpp-metadata', {}, []);
  assert.equal(result.status, 'not-applicable');
  assert.deepEqual(result.items, []);
  assert.equal(result.summary.total, 0);
});

test('事实表形状不合法时抛用法错误', () => {
  assert.throws(() => checkRequiredSet('elf', '没有问题', []), UsageError);
  assert.throws(() => checkRequiredSet('elf', [], []), /结构事实必须是对象/);
});

test('requiredSetFor 与 requiredItemsOf 的取值一致', () => {
  for (const container of SUPPORTED_CONTAINERS) {
    assert.equal(requiredSetFor(container), REQUIRED_SETS[container]);
    assert.deepEqual(requiredItemsOf(container), REQUIRED_SETS[container].items);
  }
  assert.equal(requiredSetFor('il2cpp-metadata'), null);
  assert.deepEqual(requiredItemsOf('il2cpp-metadata'), []);
});
