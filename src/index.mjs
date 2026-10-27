// Anti-REA 公共出口。按设计文档的模块划分汇总，便于命令行层、MCP 服务层与测试共同引用。
//
// 模块职责一句话说明：
//   cli            命令行入口与五个子命令分发，执行统一退出码表
//   container      只读容器识别与镜像解析，按魔数分发，只检查字节
//   readers        八类格式的事实读取器，每条发现附限制说明
//   signatures     签名与校验和观察器，只观察不验证密码学信任
//   audit          发现模型与审计引擎，按七层封闭词表归组
//   policy         策略文件模式与校验，含资源预算
//   transforms     缓解措施实现，分等长覆写与重布局写入两类
//   verify         复审引擎，从施加记录派生必需集豁免
//   notice         法律声明模板渲染与统一拒否语义
//   probe-kit      反运行时观察集成包生成，默认只输出集成包
//   fixtures       夹具规格登记表
//   report         机器可读报告的序列化、脱敏与前后差异比对
//   mcp            MCP 服务层，标准输入输出传输

export { EXIT_CODES, EXIT_CODE_LABELS } from './cli/exit-codes.mjs';
export {
  AntireaError,
  UsageError,
  BusinessError,
  RefusalError,
  NotImplementedError,
  describeError,
} from './errors.mjs';

export { detectContainer, SUPPORTED_CONTAINERS } from './container/detect.mjs';
export { identifyArtifact } from './container/identify.mjs';

export { READER_REGISTRY, readersForContainer } from './readers/index.mjs';
export { SIGNATURE_OBSERVERS } from './signatures/index.mjs';

export { LAYERS, LAYER_IDS, LAYER_TOOLS, SEVERITY_IDS, TOOL_IDS } from './audit/layer-defs.mjs';
export { createFinding, findingId, summarizeFindings, MITIGATION_IDS } from './audit/finding.mjs';
export { auditArtifact } from './audit/engine.mjs';

export { DEFAULT_POLICY, loadPolicy, validatePolicy } from './policy/index.mjs';
export { TRANSFORM_REGISTRY, listTransforms } from './transforms/index.mjs';
export { verifyArtifact } from './verify/index.mjs';
export { generateNotice, NOTICE_TEMPLATES } from './notice/index.mjs';
export { buildProbeKit } from './probe-kit/index.mjs';
export { FIXTURE_SPECS } from './fixtures/index.mjs';

export { serializeReport, renderTextReport } from './report/serialize.mjs';
export { redactReport } from './report/redact.mjs';
export { diffAudits } from './report/diff.mjs';

export { TOOL_DEFINITIONS, MCP_PROTOCOL_VERSIONS, SERVER_INFO } from './mcp/tools.mjs';
export { createMcpServer } from './mcp/server.mjs';
