// policy 模块出口。
// 策略是命令行与 MCP 服务共用的只读事实来源：层开关、法律真实字段、资源预算、
// 签名改动许可与反观察响应模式全部从这里读，两个入口不各写一份。
export {
  POLICY_SCHEMA_VERSION,
  DEFAULT_POLICY,
  DEFAULT_BUDGETS,
  DEFAULT_OBSERVATION_EXCEPTIONS,
  LEGAL_FIELD_SPEC,
  OBSERVATION_MODES,
  validatePolicy,
  loadPolicy,
  budgetsOf,
  isLayerEnabled,
  resolveLayers,
  enabledLayerIds,
  disabledLayerIds,
  observationPolicyOf,
} from './schema.mjs';
