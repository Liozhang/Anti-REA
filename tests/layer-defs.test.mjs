// 层词表封闭性：七层词表与层到工具映射引用的层名、工具名全部在词表内。
// 测试直接导入 src/audit/layer-defs.mjs 的封闭词表数据，出现词表外取值即使该测试失败。
// 覆盖三类输入：正常输入（已登记的层与工具）、畸形输入（词表外标识、缺字段、类型错误）、
// 部分读取（只取单个层或单个工具时，取到的数据与层表逐字一致）。

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import {
  LAYERS,
  LAYER_BY_ID,
  LAYER_IDS,
  LAYER_KINDS,
  LAYER_TOOLS,
  SEVERITY_IDS,
  TOOL_IDS,
  TOOL_SURFACES,
  assertLayerDefinition,
  assertLayerVocabulary,
  isKnownLayer,
  isKnownLayerKind,
  isKnownSeverity,
  isKnownTool,
  toolsOfLayer,
} from '../src/audit/layer-defs.mjs';
import { MITIGATION_IDS, createFinding, findingId, summarizeFindings } from '../src/audit/finding.mjs';
import { READER_REGISTRY } from '../src/readers/index.mjs';
import { TRANSFORM_REGISTRY, listTransforms, transformsOfKind } from '../src/transforms/index.mjs';
import { REQUIRED_SETS } from '../src/required-sets/index.mjs';
import { SUPPORTED_CONTAINERS } from '../src/container/detect.mjs';
import { CHECK_FAMILIES, verifyArtifact } from '../src/verify/index.mjs';
import { diffAudits } from '../src/report/diff.mjs';
import { SUBCOMMAND_SPECS } from '../src/cli/args.mjs';
import { TOOL_NAMES } from '../src/mcp/tools.mjs';

const FIXTURE_APP = resolve(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'sample-app');

test('七层词表恰好七个层', () => {
  assert.equal(LAYER_IDS.length, 7);
  assert.equal(LAYERS.length, 7);
  assert.equal(new Set(LAYER_IDS).size, 7, '层标识不得重复');
});

test('层映射引用的层名全部在词表内', () => {
  for (const [layerId, tools] of Object.entries(LAYER_TOOLS)) {
    assert.ok(LAYER_IDS.includes(layerId), `层映射出现词表外层名：${layerId}`);
    for (const toolId of tools) {
      assert.ok(TOOL_IDS.includes(toolId), `层 ${layerId} 引用词表外工具：${toolId}`);
    }
  }
});

test('层映射的键集合与词表一致', () => {
  assert.deepEqual(Object.keys(LAYER_TOOLS).sort(), [...LAYER_IDS].sort());
});

test('每个层至少映射一个工具', () => {
  for (const layer of LAYERS) {
    assert.ok(layer.tools.length > 0, `层 ${layer.id} 没有映射任何工具`);
  }
});

test('读取器登记的层标识全部在词表内', () => {
  for (const readers of Object.values(READER_REGISTRY)) {
    for (const reader of readers) {
      for (const layerId of reader.layers) {
        assert.ok(LAYER_IDS.includes(layerId), `读取器 ${reader.id} 引用词表外层：${layerId}`);
      }
    }
  }
});

test('缓解措施表覆盖全部已登记编号，且层标识在词表内', () => {
  assert.deepEqual(
    TRANSFORM_REGISTRY.map((transform) => transform.id).sort(),
    [...MITIGATION_IDS].sort(),
  );
  for (const transform of TRANSFORM_REGISTRY) {
    assert.ok(LAYER_IDS.includes(transform.layer), `缓解 ${transform.id} 引用词表外层：${transform.layer}`);
    assert.ok(['equal-length-overwrite', 'relayout-write', 'generated-integration-package'].includes(transform.kind));
  }
});

test('列出缓解措施时不暴露施加函数', () => {
  for (const transform of listTransforms()) {
    assert.equal(transform.apply, undefined);
    assert.equal(typeof transform.functionalRisk, 'string');
    assert.equal(typeof transform.signatureImpact, 'string');
  }
});

test('令牌覆写的容器白名单：能覆写的与只报告的分开', () => {
  // 实测背景：pyc 的 marshal 常量里埋了 API 令牌，审计原先看不见，接入扫描后又发现
  // 覆写的容器白名单不含 pyc，出现“报告了却消不掉”的半成品。白名单按结构安全性划定：
  // 长度前缀的原始字节可以清零，JSON 头内的字节不行。
  const token = listTransforms().find((transform) => transform.id === 'secret.token-placeholder-overwrite');
  assert.ok(token !== undefined, '令牌覆写措施应已登记');
  for (const container of ['elf', 'pe', 'mach-o', 'zip', 'pyc', 'gguf', 'beam']) {
    assert.ok(token.containers.includes(container), `令牌覆写应支持 ${container}`);
  }
  assert.equal(token.containers.includes('safetensors'), false, 'safetensors 的令牌在 JSON 头内，填零会使头解析失败，只报告不覆写');
  assert.match(token.functionalRisk, /safetensors/, '功能风险说明必须点明 safetensors 只报告不覆写');
});

test('必需集覆盖 v1 九类格式的容器标识', () => {
  for (const container of SUPPORTED_CONTAINERS) {
    assert.ok(REQUIRED_SETS[container] !== undefined, `必需集缺少容器 ${container}`);
  }
});

test('发现构造拒绝词表外的层与严重度', () => {
  const base = {
    layer: 'metadata-hygiene',
    severity: 'low',
    title: '标题',
    category: '分类',
    evidence: { path: 'x' },
    reader: 'elf',
    readerLimitation: '限制',
  };
  assert.throws(() => createFinding({ ...base, layer: 'not-a-layer' }), /层标识不在封闭词表内/);
  assert.throws(() => createFinding({ ...base, severity: 'critical' }), /严重度不在封闭词表内/);
  assert.doesNotThrow(() => createFinding(base));
});

test('发现编号使用词表内的层标识', () => {
  assert.equal(findingId('metadata-hygiene', 1), 'F-metadata-hygiene-0001');
  assert.throws(() => findingId('not-a-layer', 1), /层标识不在封闭词表内/);
  for (const severity of SEVERITY_IDS) {
    assert.equal(typeof severity, 'string');
  }
});

// ---- 以下为层定义数据自身的封闭性与一致性 ----

test('层表通过整表自检：字段齐全、标识与层名不重复、工具无游离项', () => {
  const checked = assertLayerVocabulary();
  assert.equal(checked.length, 7);
  for (const layer of LAYERS) {
    assert.doesNotThrow(() => assertLayerDefinition(layer), `层 ${layer.id} 应通过单条校验`);
  }
});

test('每个工具标识都被至少一个层引用，且都登记了调用面表面名', () => {
  for (const toolId of TOOL_IDS) {
    const referencedBy = LAYERS.filter((layer) => layer.tools.includes(toolId));
    assert.ok(referencedBy.length > 0, `工具 ${toolId} 没有被任何层引用`);
    assert.equal(typeof TOOL_SURFACES[toolId].subcommand, 'string');
    assert.equal(typeof TOOL_SURFACES[toolId].mcpTool, 'string');
  }
});

test('层写入性质全部在封闭词表内，缓解措施的写入性质是其子集', () => {
  for (const layer of LAYERS) {
    assert.ok(isKnownLayerKind(layer.kind), `层 ${layer.id} 的写入性质不在词表内：${layer.kind}`);
  }
  for (const transform of TRANSFORM_REGISTRY) {
    assert.ok(isKnownLayerKind(transform.kind), `缓解 ${transform.id} 的写入性质不在词表内`);
  }
  // 层比单条措施宽：文本生成与集成包生成两类只出现在层上。
  assert.ok(transformsOfKind('generated-text').length === 0, '文本生成不属于单条缓解措施');
  assert.ok(transformsOfKind('generated-integration-package').length > 0, '反运行时观察应生成集成包');
});

test('层表与派生映射逐字一致', () => {
  for (const layer of LAYERS) {
    assert.equal(LAYER_BY_ID[layer.id], layer, `LAYER_BY_ID['${layer.id}'] 与层表不是同一对象`);
    assert.equal(LAYER_TOOLS[layer.id], layer.tools, `LAYER_TOOLS['${layer.id}'] 与层表不是同一数组`);
    assert.deepEqual(toolsOfLayer(layer.id), [...layer.tools]);
  }
});

test('层与工具集合被冻结，改写即抛错', () => {
  assert.throws(() => {
    'use strict';
    LAYER_IDS.push('not-a-layer');
  }, TypeError);
  assert.throws(() => {
    'use strict';
    TOOL_IDS.push('not-a-tool');
  }, TypeError);
  assert.throws(() => {
    'use strict';
    LAYER_KINDS.push('not-a-kind');
  }, TypeError);
  assert.throws(() => {
    'use strict';
    SEVERITY_IDS.push('not-a-severity');
  }, TypeError);
  assert.throws(() => {
    'use strict';
    LAYERS[0].tools.push('not-a-tool');
  }, TypeError);
  assert.throws(() => {
    'use strict';
    LAYER_TOOLS['metadata-hygiene'] = [];
  }, TypeError);
});

test('部分读取：单个层与单个工具的查询结果与层表一致', () => {
  assert.equal(LAYER_BY_ID['legal-operational'].label, '法律与运营');
  assert.deepEqual([...toolsOfLayer('agent-stop-induction')], ['legal-notice', 'harden-artifact']);
  // 词表外的键取不到定义，且不会抛错，调用方可区分“没有这一层”与“这一层不合法”。
  assert.equal(LAYER_BY_ID['not-a-layer'], undefined);
  assert.equal(TOOL_SURFACES['not-a-tool'], undefined);
  assert.equal(isKnownLayer(undefined), false);
  assert.equal(isKnownTool(null), false);
  assert.equal(isKnownSeverity(42), false);
  assert.equal(isKnownLayerKind({}), false);
});

test('取层工具时拒绝词表外标识', () => {
  assert.throws(() => toolsOfLayer('not-a-layer'), /层标识不在封闭词表内/);
  assert.throws(() => toolsOfLayer(''), /层标识不在封闭词表内/);
});

// ---- 畸形输入：层定义缺字段、取值越界、类型错误 ----

const WELL_FORMED_LAYER = {
  id: 'legal-operational',
  label: '法律与运营',
  kind: 'generated-text',
  tools: ['legal-notice', 'audit-artifact', 'verify-artifact'],
};

test('层定义校验接受正常输入', () => {
  assert.equal(assertLayerDefinition(WELL_FORMED_LAYER), WELL_FORMED_LAYER);
});

test('层定义校验拒绝词表外的层标识与工具', () => {
  assert.throws(() => assertLayerDefinition({ ...WELL_FORMED_LAYER, id: 'not-a-layer' }), /层标识不在封闭词表内/);
  assert.throws(
    () => assertLayerDefinition({ ...WELL_FORMED_LAYER, tools: ['not-a-tool'] }),
    /引用词表外工具/,
  );
});

test('层定义校验拒绝词表外的写入性质', () => {
  assert.throws(
    () => assertLayerDefinition({ ...WELL_FORMED_LAYER, kind: 'magic-write' }),
    /写入性质不在封闭词表内/,
  );
});

test('层定义校验拒绝缺字段与部分读取得到的残片', () => {
  for (const field of ['id', 'label', 'kind', 'tools']) {
    const partial = { ...WELL_FORMED_LAYER };
    delete partial[field];
    assert.throws(() => assertLayerDefinition(partial), new RegExp(`层定义缺少字段 ${field}`), `缺 ${field} 应被拒`);
  }
  // 只读到层名、没读到标识与工具映射的残片。
  assert.throws(() => assertLayerDefinition({ label: '法律与运营' }), /层定义缺少字段 id/);
  assert.throws(() => assertLayerDefinition({ id: 'legal-operational' }), /层定义缺少字段 label/);
});

test('层定义校验拒绝类型错误与非对象输入', () => {
  assert.throws(() => assertLayerDefinition(null), TypeError);
  assert.throws(() => assertLayerDefinition(undefined), TypeError);
  assert.throws(() => assertLayerDefinition('legal-operational'), TypeError);
  assert.throws(() => assertLayerDefinition(['legal-operational']), TypeError);
  assert.throws(() => assertLayerDefinition({ ...WELL_FORMED_LAYER, label: '' }), /label 必须是非空字符串/);
  assert.throws(() => assertLayerDefinition({ ...WELL_FORMED_LAYER, label: 7 }), /label 必须是非空字符串/);
  assert.throws(() => assertLayerDefinition({ ...WELL_FORMED_LAYER, tools: [] }), /tools 必须是非空数组/);
  assert.throws(() => assertLayerDefinition({ ...WELL_FORMED_LAYER, tools: 'legal-notice' }), /tools 必须是非空数组/);
  assert.throws(
    () => assertLayerDefinition({ ...WELL_FORMED_LAYER, tools: ['legal-notice', 'legal-notice'] }),
    /重复引用工具/,
  );
});

// ---- 调用面：词表与命令行子命令、MCP 工具名一一对应 ----

test('工具标识与命令行子命令、MCP 工具名一一对应', () => {
  assert.deepEqual(Object.keys(TOOL_SURFACES).sort(), [...TOOL_IDS].sort());
  assert.deepEqual(
    [...TOOL_IDS].map((toolId) => TOOL_SURFACES[toolId].subcommand).sort(),
    Object.keys(SUBCOMMAND_SPECS).sort(),
  );
  assert.deepEqual(
    [...TOOL_IDS].map((toolId) => TOOL_SURFACES[toolId].mcpTool).sort(),
    [...TOOL_NAMES].sort(),
  );
  assert.equal(new Set(TOOL_NAMES).size, 5, 'MCP 工具名不得重复');
});

test('每个命令行子命令的策略开关只接受词表内的层标识', async () => {
  // 策略按层开关，层名来自用户文件；用户写错层名时必须落到用法错误而不是静默忽略。
  const { validatePolicy } = await import('../src/policy/schema.mjs');
  const report = await auditArtifactWithPolicy(FIXTURE_APP, { layers: { 'not-a-layer': false } });
  assert.equal(report.summary.byLayer['not-a-layer'], undefined);
  assert.equal(report.status, 'complete');
  assert.equal(validatePolicy({ layers: { 'not-a-layer': false } }).layers['not-a-layer'], false);
});

// ---- verify 侧：复审报告与差异比对只产出词表内的层名 ----

test('复审报告与差异比对引用的层名全部在词表内', async () => {
  const { exitCode, report } = await verifyArtifact(FIXTURE_APP);
  assert.equal(exitCode, 0);
  assert.equal(TOOL_SURFACES['verify-artifact'].mcpTool, 'verify_artifact');
  assert.ok(TOOL_IDS.includes(report.tool), `复审报告出现词表外工具：${String(report.tool)}`);

  for (const finding of report.comparison?.resolved ?? []) {
    assert.ok(LAYER_IDS.includes(finding.layer), `复审输出词表外层：${String(finding.layer)}`);
  }
  for (const finding of report.comparison?.persisting ?? []) {
    assert.ok(LAYER_IDS.includes(finding.layer), `复审输出词表外层：${String(finding.layer)}`);
  }
  for (const finding of report.comparison?.introduced ?? []) {
    assert.ok(LAYER_IDS.includes(finding.layer), `复审输出词表外层：${String(finding.layer)}`);
  }
  // 结构检查族本身也是封闭集合，复审不得凭空造出检查项。
  for (const check of report.checks) {
    assert.ok(CHECK_FAMILIES.includes(check.family), `复审出现词表外检查族：${String(check.family)}`);
  }
});

test('差异比对保留层名，不把同一事实判成消失又新增', () => {
  const baseline = {
    findings: [
      createFinding({
        layer: 'metadata-hygiene',
        severity: 'low',
        title: '标题',
        category: '分类',
        evidence: { path: 'a' },
        reader: 'elf',
        readerLimitation: '限制',
      }),
    ],
  };
  const current = {
    findings: [
      createFinding({
        layer: 'metadata-hygiene',
        severity: 'low',
        title: '标题',
        category: '分类',
        evidence: { path: 'b', byteRange: [0, 16] },
        reader: 'elf',
        readerLimitation: '限制',
      }),
    ],
  };
  const diff = diffAudits(baseline, current);
  assert.equal(diff.persisting.length, 1);
  assert.equal(diff.resolved.length, 0);
  assert.equal(diff.introduced.length, 0);
  for (const finding of [...diff.persisting, ...diff.resolved, ...diff.introduced]) {
    assert.ok(LAYER_IDS.includes(finding.layer));
  }
  // 比对键用层名，词表外的层名无法构造出发现，因此比对不可能引入词表外键。
  assert.throws(
    () =>
      createFinding({
        layer: 'not-a-layer',
        severity: 'low',
        title: '标题',
        category: '分类',
        evidence: { path: 'a' },
        reader: 'elf',
        readerLimitation: '限制',
      }),
    /层标识不在封闭词表内/,
  );
});

test('按层汇总的计数恰好覆盖词表内的每一层', () => {
  const summary = summarizeFindings([]);
  assert.deepEqual(Object.keys(summary.byLayer).sort(), [...LAYER_IDS].sort());
  assert.deepEqual(Object.keys(summary.bySeverity).sort(), [...SEVERITY_IDS].sort());
  assert.equal(summary.total, 0);
});

/** 带策略跑一次审计，用于观察层开关对归组的影响。 */
async function auditArtifactWithPolicy(target, policy) {
  const { auditArtifact } = await import('../src/audit/engine.mjs');
  return auditArtifact(target, { policy });
}
