// 七层封闭词表与层到工具的映射。
// 本模块是数据模块，审计归组、缓解编号与封闭词表测试共同导入同一份数据。
// 词表封闭：任何层标识、工具标识、写入性质或严重度都只能取自已登记的集合，
// 出现词表外取值即视为缺陷，由 assertLayerDefinition 在数据侧、由 finding 构造在输出侧双重把关。

/** 层标识封闭集合。 */
export const LAYER_IDS = Object.freeze([
  'metadata-hygiene',
  'content-protection',
  'runtime-observation-resistance',
  'agent-stop-induction',
  'model-truthful-signals',
  'secret-minimization',
  'legal-operational',
]);

/** 工具标识封闭集合。命令行子命令与 MCP 工具名各有表面名，经 TOOL_SURFACES 与这里的标识一一对应。 */
export const TOOL_IDS = Object.freeze([
  'audit-artifact',
  'harden-artifact',
  'verify-artifact',
  'legal-notice',
  'probe-kit',
]);

/** 严重度封闭集合。 */
export const SEVERITY_IDS = Object.freeze(['info', 'low', 'medium', 'high']);

/**
 * 层写入性质封闭集合。
 * 层是措施族，性质比单条缓解措施宽：等长覆写与重布局写入之外，
 * 还有只生成文本或生成集成包、不改动制品本身的两类。
 */
export const LAYER_KINDS = Object.freeze([
  'equal-length-overwrite',
  'relayout-write',
  'generated-text',
  'generated-integration-package',
]);

/** 层定义的必备字段。缺任一字段即视为不完整的层定义。 */
const LAYER_FIELDS = Object.freeze(['id', 'label', 'kind', 'tools']);

/**
 * 层定义。字段：
 *   id      层标识，词表内取值
 *   label   层名，与两份说明文档中的七层防御表一致
 *   tools   该层涉及的工具标识，全部在 TOOL_IDS 内
 *   kind    该层的写入性质：只读清点、等长覆写、重布局写入或文本生成
 */
export const LAYERS = Object.freeze([
  {
    id: 'metadata-hygiene',
    label: '元数据卫生',
    kind: 'equal-length-overwrite',
    tools: Object.freeze(['audit-artifact', 'harden-artifact', 'verify-artifact']),
  },
  {
    id: 'content-protection',
    label: '内容保护',
    kind: 'equal-length-overwrite',
    tools: Object.freeze(['audit-artifact', 'harden-artifact', 'verify-artifact']),
  },
  {
    id: 'runtime-observation-resistance',
    label: '反运行时观察',
    kind: 'generated-integration-package',
    tools: Object.freeze(['audit-artifact', 'harden-artifact', 'probe-kit']),
  },
  {
    id: 'agent-stop-induction',
    label: '代理停手诱导',
    kind: 'generated-text',
    tools: Object.freeze(['legal-notice', 'harden-artifact']),
  },
  {
    id: 'model-truthful-signals',
    label: '模型层真实信号',
    kind: 'relayout-write',
    tools: Object.freeze(['legal-notice', 'harden-artifact', 'verify-artifact']),
  },
  {
    id: 'secret-minimization',
    label: '秘密不下客户端',
    kind: 'equal-length-overwrite',
    tools: Object.freeze(['audit-artifact', 'harden-artifact', 'verify-artifact']),
  },
  {
    id: 'legal-operational',
    label: '法律与运营',
    kind: 'generated-text',
    tools: Object.freeze(['legal-notice', 'audit-artifact', 'verify-artifact']),
  },
]);

/** 层标识到层定义的映射。 */
export const LAYER_BY_ID = Object.freeze(Object.fromEntries(LAYERS.map((layer) => [layer.id, layer])));

/** 层到工具映射，键为层标识，值为工具标识数组。 */
export const LAYER_TOOLS = Object.freeze(Object.fromEntries(LAYERS.map((layer) => [layer.id, layer.tools])));

/**
 * 工具标识到调用面表面名的映射。
 * 同一套工作流代码同时服务命令行与 MCP：命令行子命令是 audit、harden、verify、notice、probe，
 * MCP 工具名是 audit_artifact、harden_artifact、verify_artifact、generate_notice、generate_probe_kit。
 * 映射写在这里，调用面改名时只需改一处，词表封闭性测试会同时校验两侧。
 */
export const TOOL_SURFACES = Object.freeze(
  Object.freeze({
    'audit-artifact': Object.freeze({ subcommand: 'audit', mcpTool: 'audit_artifact' }),
    'harden-artifact': Object.freeze({ subcommand: 'harden', mcpTool: 'harden_artifact' }),
    'verify-artifact': Object.freeze({ subcommand: 'verify', mcpTool: 'verify_artifact' }),
    'legal-notice': Object.freeze({ subcommand: 'notice', mcpTool: 'generate_notice' }),
    'probe-kit': Object.freeze({ subcommand: 'probe', mcpTool: 'generate_probe_kit' }),
  }),
);

/**
 * 判断层标识是否在词表内。
 * @param {string} layerId
 * @returns {boolean}
 */
export function isKnownLayer(layerId) {
  return LAYER_IDS.includes(layerId);
}

/**
 * 判断工具标识是否在词表内。
 * @param {string} toolId
 * @returns {boolean}
 */
export function isKnownTool(toolId) {
  return TOOL_IDS.includes(toolId);
}

/**
 * 判断写入性质是否在词表内。
 * @param {string} kind
 * @returns {boolean}
 */
export function isKnownLayerKind(kind) {
  return LAYER_KINDS.includes(kind);
}

/**
 * 判断严重度是否在词表内。
 * @param {string} severity
 * @returns {boolean}
 */
export function isKnownSeverity(severity) {
  return SEVERITY_IDS.includes(severity);
}

/**
 * 取某层涉及的工具标识。词表外标识抛 RangeError，交由调用方转成用法错误。
 * @param {string} layerId 层标识
 * @returns {readonly string[]}
 */
export function toolsOfLayer(layerId) {
  const layer = LAYER_BY_ID[layerId];
  if (layer === undefined) {
    throw new RangeError(`层标识不在封闭词表内：${layerId}`);
  }
  return layer.tools;
}

/**
 * 校验一条层定义：字段齐全、取值全部在词表内、工具不重复。
 * 新增或修改层定义的代码路径必须先过这一关，词表才谈得上封闭。
 * @param {Record<string, unknown>} layer 待校验的层定义
 * @returns {Record<string, unknown>} 校验通过的层定义
 */
export function assertLayerDefinition(layer) {
  if (layer === null || typeof layer !== 'object' || Array.isArray(layer)) {
    throw new TypeError('层定义必须是对象');
  }
  for (const field of LAYER_FIELDS) {
    if (!Object.hasOwn(layer, field)) {
      throw new RangeError(`层定义缺少字段 ${field}`);
    }
  }
  if (!isKnownLayer(layer.id)) {
    throw new RangeError(`层标识不在封闭词表内：${String(layer.id)}`);
  }
  if (typeof layer.label !== 'string' || layer.label === '') {
    throw new RangeError(`层 ${String(layer.id)} 的 label 必须是非空字符串`);
  }
  if (!isKnownLayerKind(layer.kind)) {
    throw new RangeError(`层 ${String(layer.id)} 的写入性质不在封闭词表内：${String(layer.kind)}`);
  }
  if (!Array.isArray(layer.tools) || layer.tools.length === 0) {
    throw new RangeError(`层 ${String(layer.id)} 的 tools 必须是非空数组`);
  }
  const seen = new Set();
  for (const toolId of layer.tools) {
    if (!isKnownTool(toolId)) {
      throw new RangeError(`层 ${String(layer.id)} 引用词表外工具：${String(toolId)}`);
    }
    if (seen.has(toolId)) {
      throw new RangeError(`层 ${String(layer.id)} 重复引用工具：${String(toolId)}`);
    }
    seen.add(toolId);
  }
  return layer;
}

/**
 * 校验整张层表：逐条过 assertLayerDefinition，且层标识、层名、工具标识均不重复，
 * TOOL_SURFACES 与 TOOL_IDS 一一对应。词表封闭性测试与启动自检都调这一函数。
 * @returns {readonly Record<string, unknown>[]} 校验通过的层定义数组
 */
export function assertLayerVocabulary() {
  const layerIds = new Set();
  const labels = new Set();
  const tools = new Set();
  for (const layer of LAYERS) {
    assertLayerDefinition(layer);
    if (layerIds.has(layer.id)) {
      throw new RangeError(`层标识重复：${layer.id}`);
    }
    if (labels.has(layer.label)) {
      throw new RangeError(`层名重复：${layer.label}`);
    }
    layerIds.add(layer.id);
    labels.add(layer.label);
    for (const toolId of layer.tools) {
      tools.add(toolId);
    }
  }
  if (layerIds.size !== LAYER_IDS.length) {
    throw new RangeError('层标识集合与层表不一致');
  }
  const surfaces = Object.keys(TOOL_SURFACES);
  if (surfaces.length !== TOOL_IDS.length) {
    throw new RangeError('工具表面名映射与工具标识集合不一致');
  }
  for (const toolId of TOOL_IDS) {
    if (!Object.hasOwn(TOOL_SURFACES, toolId)) {
      throw new RangeError(`工具 ${toolId} 没有登记调用面表面名`);
    }
    if (!tools.has(toolId)) {
      throw new RangeError(`工具 ${toolId} 没有被任何层引用，属于游离词表项`);
    }
  }
  return LAYERS;
}
