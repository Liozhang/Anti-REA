// MCP 工具定义：五个工具的名称、说明与输入模式。
// 工具名与命令行子命令一一对应，且与两份说明文档中列出的接口逐字一致。

/** 服务标识。 */
export const SERVER_INFO = Object.freeze({
  name: 'anti-rea',
  version: '0.1.2',
  title: 'Anti-REA',
});

/** 支持的 MCP 协议版本，按从新到旧排列。 */
export const MCP_PROTOCOL_VERSIONS = Object.freeze(['2025-06-18', '2025-03-26', '2024-11-05']);

/**
 * 取最新支持的协议版本，用于客户端请求了不受支持版本时的回落。
 * @returns {string}
 */
export function latestProtocolVersion() {
  return MCP_PROTOCOL_VERSIONS[0];
}

/** 制品路径参数模式，audit、harden、verify 三个工具共用。 */
const ARTIFACT_PATH_PROPERTY = Object.freeze({
  type: 'string',
  description: '要处理的制品路径，可以是单个文件或目录。只处理用户显式提供的本地路径。',
});

/** 策略文件参数模式，五个工具共用。 */
const POLICY_PROPERTY = Object.freeze({
  type: 'string',
  description: '策略文件路径，决定层开关、法律真实字段与资源预算。省略时使用默认策略。',
});

/** 报告写出路径。audit、harden、verify 三个工具的 out 指报告文件。 */
const OUT_PATH_PROPERTY = Object.freeze({
  type: 'string',
  description: '报告写出路径。目标路径位于 git 工作树内时，服务会提示风险。',
});

/** 声明文件写出路径。generate_notice 的 out 指声明文档本身，不是报告路径。 */
const NOTICE_OUT_PATH_PROPERTY = Object.freeze({
  type: 'string',
  description: '声明文件写出路径，写出的内容是许可与禁止逆向声明文档。目标路径位于 git 工作树内时，服务会提示风险。',
});

/**
 * 集成包输出目录。generate_probe_kit 与制品无关（不读制品、不改动制品），
 * 三个名字等价，同时给出时按 out、output、path 的顺序取先给出者，与命令行 --out 优先于位置参数一致。
 */
const PROBE_OUT_DIR_DESCRIPTION =
  '集成包输出目录，集成包文件只写进这个目录。与 out、output、path 三个名字等价，同时给出时按 out、output、path 的顺序取先给出者；目标路径位于 git 工作树内时，服务会提示风险。';

/**
 * 五个工具的定义。
 */
export const TOOL_DEFINITIONS = Object.freeze([
  Object.freeze({
    name: 'audit_artifact',
    title: '制品审计',
    description:
      '只读清点制品中可被静态提取的事实，逐条给出证据、限制说明与可对应的缓解措施编号。全部读取在进程内完成，不执行目标代码、不发起网络请求，并受资源预算约束。',
    inputSchema: Object.freeze({
      type: 'object',
      properties: Object.freeze({
        path: ARTIFACT_PATH_PROPERTY,
        policy: POLICY_PROPERTY,
        redacted: Object.freeze({
          type: 'boolean',
          description: '输出脱敏报告：保留分类与计数，隐去精确路径、字节范围与缓解措施对应关系。',
        }),
        format: Object.freeze({ type: 'string', enum: Object.freeze(['json', 'text']) }),
        out: OUT_PATH_PROPERTY,
      }),
      required: Object.freeze(['path']),
    }),
  }),
  Object.freeze({
    name: 'harden_artifact',
    title: '制品加固',
    description:
      '按策略对制品施加缓解措施，先写临时文件、复审通过后原子替换目标路径，失败删除临时文件并保留原件。检测到代码签名或校验和机制的制品默认跳过改写，由用户显式选择是否继续。',
    inputSchema: Object.freeze({
      type: 'object',
      properties: Object.freeze({
        path: ARTIFACT_PATH_PROPERTY,
        from: Object.freeze({
          type: 'string',
          description: '加固前产出的审计结果文件路径，用来派生要施加的缓解措施。',
        }),
        policy: POLICY_PROPERTY,
        out: OUT_PATH_PROPERTY,
      }),
      required: Object.freeze(['path', 'from']),
    }),
  }),
  Object.freeze({
    name: 'verify_artifact',
    title: '加固验证',
    description:
      '对加固后制品复审：重跑审计并与基线比较发现变化，同时做结构健全性与签名一致性检查，确认缓解措施没有破坏合法功能。',
    inputSchema: Object.freeze({
      type: 'object',
      properties: Object.freeze({
        path: ARTIFACT_PATH_PROPERTY,
        from: Object.freeze({
          type: 'string',
          description: '加固前产出的审计结果文件路径，作为比对基线。',
        }),
        policy: POLICY_PROPERTY,
        out: OUT_PATH_PROPERTY,
      }),
      required: Object.freeze(['path']),
    }),
  }),
  Object.freeze({
    name: 'generate_notice',
    title: '声明生成',
    description:
      '依据用户提供的真实字段生成许可与禁止逆向的法律声明模板。任何字段缺失或后果陈述缺法条摘录时，产出含 omitted_reason 的拒否报告。',
    inputSchema: Object.freeze({
      type: 'object',
      properties: Object.freeze({
        template: Object.freeze({
          type: 'string',
          enum: Object.freeze(['license']),
          description: '声明模板名，当前只支持 license。',
        }),
        policy: POLICY_PROPERTY,
        out: NOTICE_OUT_PATH_PROPERTY,
      }),
      required: Object.freeze(['template']),
    }),
  }),
  Object.freeze({
    name: 'generate_probe_kit',
    title: '集成包生成',
    description:
      '生成反运行时观察集成包：可嵌入的检测代码片段、人工检查清单与集成方式说明。只往输出目录写文件，不读取、不改动任何制品，也不启动子进程或发起网络请求；是否拒绝由策略显式开启。',
    inputSchema: Object.freeze({
      type: 'object',
      properties: Object.freeze({
        out: Object.freeze({ type: 'string', description: PROBE_OUT_DIR_DESCRIPTION }),
        output: Object.freeze({ type: 'string', description: PROBE_OUT_DIR_DESCRIPTION }),
        path: Object.freeze({ type: 'string', description: PROBE_OUT_DIR_DESCRIPTION }),
        policy: POLICY_PROPERTY,
      }),
      // 三个输出目录名字等价，任何一个都不是必填：全部省略时按用法错误处理。
      required: Object.freeze([]),
    }),
  }),
]);

/** 工具名封闭集合。 */
export const TOOL_NAMES = Object.freeze(TOOL_DEFINITIONS.map((tool) => tool.name));

/**
 * 取工具定义列表，供 tools/list 使用。
 * @returns {readonly Record<string, unknown>[]}
 */
export function toolList() {
  return TOOL_DEFINITIONS;
}

/**
 * 按名称取工具定义。
 * @param {string} name 工具名
 * @returns {Record<string, unknown> | null}
 */
export function toolByName(name) {
  return TOOL_DEFINITIONS.find((tool) => tool.name === name) ?? null;
}
