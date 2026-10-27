// 反运行时观察集成包生成。
// 行为风险最高的一层，因此默认只输出可嵌入的检测代码片段与人工检查清单，不自动改动制品。
// 默认响应是记录并继续；是否拒绝由策略显式开启，并配例外清单与多迹象联合判定。
// 模板统一放仓库根 templates/probe-kit/，在静态依赖检查范围之外：
// 检查只扫 src/ 与 bin/，模板里出现 import 行不会被判成引入第三方依赖。
//
// 三条边界贯穿全文件：
//   1. 不注入。生成的内容是可观测事实的检测代码与人工清单，
//      不写任何伪装成系统或操作者指令的文本，也不试图覆盖分析代理的既有规则。
//   2. 不改动制品。buildProbeKit 只往调用方给出的 outDir 写集成包文件，
//      不读制品、不写制品、不启动子进程、不发起网络请求。
//   3. 拒绝不由生成方决定。响应模式与例外清单取自策略，
//      生成代码的默认拒绝动作是可捕获的类型化错误，绝不实现为清数据、崩溃或静默失败。

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { LAYER_BY_ID } from '../audit/layer-defs.mjs';
import { UsageError } from '../errors.mjs';
import { observationPolicyOf, validatePolicy } from '../policy/schema.mjs';

/** 所属层标识。写入性质是 generated-integration-package：只生成集成包，不改动制品。 */
const LAYER_ID = 'runtime-observation-resistance';

/** 层定义取自七层封闭词表，缺失即视为词表被破坏，载入期就失败而不是等到运行期。 */
const LAYER = LAYER_BY_ID[LAYER_ID];
if (LAYER === undefined) {
  throw new RangeError(`层标识不在封闭词表内：${LAYER_ID}`);
}

/** 集成包报告模式版本。 */
export const PROBE_KIT_SCHEMA = 'anti-rea.probe-kit/1';

/** 检测项封闭集合。每一项都是可观测事实，不是行为指令。 */
export const PROBE_CHECKS = Object.freeze([
  { id: 'env-write-marker', label: '进程捕获写入的运行标识环境变量' },
  { id: 'pseudo-terminal-signs', label: '伪终端迹象：终端类型、窗口尺寸、会话首进程身份' },
  { id: 'injected-script-prefix', label: '注入脚本命名前缀' },
  { id: 'traced-state', label: '被跟踪状态' },
  { id: 'inspector-port', label: '检查器端口' },
]);

/** 默认例外清单：已知持续集成变量与远程 Shell 会话。 */
export const DEFAULT_PROBE_EXCEPTIONS = Object.freeze(['CI', 'GITHUB_ACTIONS', 'SSH_CONNECTION', 'SSH_TTY']);

/**
 * 基线例外到检查项的抑制映射。
 * 持续集成场景会批量设置环境变量并使用伪终端，远程 Shell 会话本身就长得像伪终端，
 * 这两类例外抑制的正是会在这些场景误报的检查项。
 */
export const DEFAULT_EXCEPTION_SUPPRESSES = Object.freeze({
  CI: Object.freeze(['env-write-marker', 'pseudo-terminal-signs']),
  GITHUB_ACTIONS: Object.freeze(['env-write-marker', 'pseudo-terminal-signs']),
  SSH_CONNECTION: Object.freeze(['pseudo-terminal-signs']),
  SSH_TTY: Object.freeze(['pseudo-terminal-signs']),
});

/** 用户自填例外的默认抑制范围。策略里的例外只有环境变量名或会话标记，按保守口径抑制环境与伪终端两项。 */
const USER_EXCEPTION_SUPPRESSES = Object.freeze(['env-write-marker', 'pseudo-terminal-signs']);

/** 联合判定阈值：同时命中的独立迹象达到本值才判定为观察到运行期观察。单项迹象从不触发拒绝。 */
export const DEFAULT_SIGNAL_THRESHOLD = 2;

/** 集成包内容清单。 */
export const PROBE_KIT_PARTS = Object.freeze([
  '检测代码片段（按目标语言分文件）',
  '人工检查清单',
  '响应模式说明：默认记录并继续，拒绝需策略显式开启',
  '集成方式说明：默认只输出集成包，不自动改动制品本身',
]);

/**
 * 集成包模板登记表。模板文件在仓库根 templates/probe-kit/，产出文件写在调用方给出的 outDir。
 * summary 用于集成方式说明里的产物清单，也是模板被截断时定位用的说明。
 */
export const PROBE_TEMPLATE_FILES = Object.freeze([
  Object.freeze({
    id: 'runtime-probe',
    template: 'runtime-probe.template.mjs',
    output: 'runtime-probe.mjs',
    summary: '运行期自检代码片段（Node.js ESM 目标，零依赖，可导入后调用）',
  }),
  Object.freeze({
    id: 'manual-checklist',
    template: 'manual-checklist.template.md',
    output: 'manual-checklist.md',
    summary: '人工检查清单：自动检查覆盖不到的部分，逐项人工核对',
  }),
  Object.freeze({
    id: 'integration-notes',
    template: 'integration-notes.template.md',
    output: 'INTEGRATION.md',
    summary: '集成方式说明：接入步骤、响应模式、例外清单与限制说明',
  }),
]);

/** 各检查项对应的人工核对步骤，写进人工检查清单。 */
const CHECK_MANUAL_STEPS = Object.freeze({
  'env-write-marker': '对照威胁模型核对环境变量清单：把捕获工具实际写入的变量名关键词补进 ENV_MARKER_KEYWORDS，删掉与业务重名的关键词。',
  'pseudo-terminal-signs': '人工核对父进程链与终端来源：确认会话首进程是预期的外壳或服务管理器；持续集成与远程执行场景先加例外，不要改判定逻辑。',
  'injected-script-prefix': '人工核对 NODE_OPTIONS、--require、--import 指向的脚本路径；业务自身脚本命名与前缀重合时改清单。',
  'traced-state': 'Linux 用 cat /proc/<pid>/status 查看 TracerPid；其他平台用外部调试器检测手段人工确认，生成代码不覆盖。',
  'inspector-port': '用 ss -ltnp 或 netstat -ano 检查 9229、9222 等调试端口是否处于监听；运行期另开的端口不在生成代码的检查范围内。',
});

/** 与自动检查无关的人工项，写进人工检查清单。 */
const MANUAL_STEPS = Object.freeze([
  '检查 LD_PRELOAD（Linux）、DYLD_INSERT_LIBRARIES（macOS）、AppInit_DLLs（Windows）是否被注入非预期库。',
  '核对服务管理器（systemd、launchd、Windows 服务）里的启动参数，确认没有额外挂接检查器或预加载脚本。',
  '确认观察结果的上报渠道与保留期限；记录用日志不要写入秘密。',
  '把本集成包自身纳入审计范围：自检代码也是可分析面，不要在生成的代码里写入任何凭据。',
  '定期复查关键词与前缀清单：捕获工具改名后，旧清单会漏报。',
]);

/** 生成内容的限制说明，随报告返回，也写进集成方式说明。 */
const KIT_LIMITATIONS = Object.freeze([
  '当前版本只生成 Node.js（ESM）目标的检测代码片段，其他语言需按同一判定逻辑移植。',
  '检测只提高成本，不能阻止有准备的分析者改写探针。',
  'Chromium 系进程会覆盖初始环境内存，环境变量归属无法验证。',
  'Windows 对环境变量名做大小写折叠，例外匹配已按平台折叠比较。',
  '伪终端迹象在持续集成与远程执行场景下本身就会误报，只能靠联合判定与例外清单缓解。',
  'traced-state 只在 Linux 可检查 /proc/self/status 的 TracerPid；inspector-port 只覆盖启动时挂接的检查器。',
  '自检代码本身成为新的可分析面，不要在生成的代码里写入任何秘密。',
]);

/** 占位符模式：{{大写标识}}。 */
const TOKEN_PATTERN = /\{\{\s*([A-Z0-9_]+)\s*\}\}/g;

/** 模板起始标记行。模板首行必须包含它，缺它即视为不完整。 */
function markerLine(id) {
  return `anti-rea-probe-template: ${id}`;
}

/** 模板结束标记行。模板最后一个非空行必须包含它，缺它即视为写入被中断。 */
function markerEndLine(id) {
  return `anti-rea-probe-template-end: ${id}`;
}

/** 默认模板目录：仓库根 templates/probe-kit/，与 src/probe-kit/ 相对定位，不依赖当前工作目录。 */
function defaultTemplatesDir() {
  return resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'templates', 'probe-kit');
}

/**
 * 合并例外清单：基线例外在前，用户自填例外在后，按名去重。
 * 基线清单由本模块提供（已知持续集成变量与远程 Shell 会话），策略里只放用户自填项。
 * @param {Record<string, unknown>} policy 策略
 * @returns {readonly string[]} 生效的例外清单
 */
export function effectiveProbeExceptions(policy = {}) {
  const { exceptions } = observationPolicyOf(policy);
  const merged = [...DEFAULT_PROBE_EXCEPTIONS];
  for (const name of exceptions) {
    if (!merged.includes(name)) {
      merged.push(name);
    }
  }
  return Object.freeze(merged);
}

/**
 * 按检查项生成人工核对条目。
 * @returns {string} markdown 列表
 */
function checklistItems() {
  return PROBE_CHECKS.map((check) => {
    const step = CHECK_MANUAL_STEPS[check.id] ?? '按威胁模型人工核对本项。';
    return `- \`${check.id}\`（${check.label}）：${step}`;
  }).join('\n');
}

/**
 * 生成集成包模板的替换上下文。键名即占位符名，模板里出现未登记的占位符会在渲染期报错。
 * @param {Record<string, unknown>} policy 已过结构校验的策略
 * @returns {Record<string, string>} 占位符上下文
 */
export function probeKitContext(policy = {}) {
  const observation = observationPolicyOf(policy);
  const exceptions = effectiveProbeExceptions(policy);
  const suppresses = {};
  for (const [name, checkIds] of Object.entries(DEFAULT_EXCEPTION_SUPPRESSES)) {
    suppresses[name] = [...checkIds];
  }
  for (const name of observation.exceptions) {
    if (!Object.hasOwn(suppresses, name)) {
      suppresses[name] = [...USER_EXCEPTION_SUPPRESSES];
    }
  }
  return {
    RESPONSE_MODE: observation.mode,
    REFUSAL_ENABLED: String(observation.refusalEnabled),
    REFUSAL_ENABLED_TEXT: observation.refusalEnabled ? '已开启' : '未开启',
    SIGNAL_THRESHOLD: String(DEFAULT_SIGNAL_THRESHOLD),
    EXCEPTION_LIST: JSON.stringify(exceptions),
    EXCEPTION_SUPPRESSES: JSON.stringify(suppresses),
    EXCEPTIONS_TEXT: exceptions.join('、'),
    CHECK_IDS: JSON.stringify(PROBE_CHECKS.map((check) => check.id)),
    CHECK_ITEMS: checklistItems(),
    MANUAL_ITEMS: MANUAL_STEPS.map((step) => `- ${step}`).join('\n'),
    FILE_LIST: PROBE_TEMPLATE_FILES.map((spec) => `- \`${spec.output}\`：${spec.summary}`).join('\n'),
  };
}

/**
 * 校验模板完整性：首行有起始标记，最后一个非空行有结束标记。
 * 写入被中断的模板（截断）在这一关拦下，不生成半个集成包。
 * @param {string} id 模板标识
 * @param {string} text 模板全文
 * @param {string} sourcePath 模板路径，用于错误信息
 */
function assertTemplateComplete(id, text, sourcePath) {
  if (typeof text !== 'string' || text === '') {
    throw new UsageError(`集成包模板为空或不可读：${sourcePath}`);
  }
  const lines = text.split('\n');
  const first = lines[0] ?? '';
  const last = lines.filter((line) => line.trim() !== '').at(-1) ?? '';
  if (!first.includes(markerLine(id))) {
    throw new UsageError(`集成包模板缺少起始标记，判定为不完整：${sourcePath}`);
  }
  if (!last.includes(markerEndLine(id))) {
    throw new UsageError(`集成包模板缺少结束标记，判定为写入被中断：${sourcePath}`);
  }
}

/**
 * 去掉模板的标记行。标记只是完整性校验用的元数据，不进入产出文件。
 * @param {string} id 模板标识
 * @param {string} text 渲染后的文本
 * @returns {string}
 */
function stripMarkerLines(id, text) {
  return text
    .split('\n')
    .filter((line) => !line.includes(markerLine(id)) && !line.includes(markerEndLine(id)))
    .join('\n');
}

/**
 * 渲染一份模板：先查占位符是否全部登记，再逐项替换，最后复查有没有漏网占位符。
 * 未登记占位符按用法错误处理：静默留下 {{TOKEN}} 会生成一份看起来正常实则缺配置的集成包。
 * @param {string} id 模板标识
 * @param {string} text 模板全文
 * @param {Record<string, string>} context 占位符上下文
 * @param {string} sourcePath 模板路径，用于错误信息
 * @returns {string} 渲染结果
 */
export function renderTemplate(id, text, context, sourcePath) {
  const unknown = new Set();
  for (const match of text.matchAll(TOKEN_PATTERN)) {
    if (!Object.hasOwn(context, match[1])) {
      unknown.add(match[1]);
    }
  }
  if (unknown.size > 0) {
    throw new UsageError(`集成包模板 ${id} 含未登记的占位符：${[...unknown].join('、')}（${sourcePath}）`);
  }
  const rendered = stripMarkerLines(
    id,
    text.replace(TOKEN_PATTERN, (whole, name) => context[name]),
  );
  const leftover = rendered.match(TOKEN_PATTERN);
  if (leftover !== null) {
    throw new UsageError(`集成包模板 ${id} 渲染后仍有未替换占位符：${leftover[1]}（${sourcePath}）`);
  }
  return rendered;
}

/**
 * 生成反运行时观察集成包。
 * 只往 outDir 写集成包文件，不改动任何制品；任何一项模板不完整都不落盘。
 * @param {{
 *   policy?: Record<string, unknown>,
 *   outDir: string,
 *   templatesDir?: string,
 *   io?: {readFile?: (path: string, encoding: string) => Promise<string>},
 *   warnTree?: (outputPath: string) => Promise<boolean>,
 * }} input policy 为策略对象（可省略，省略时取默认策略）；
 *   templatesDir 与 io 供测试注入；warnTree 是 git 工作树警告器，由调用方在集成包写出前调用
 * @returns {Promise<Record<string, unknown>>} 集成包报告
 */
export async function buildProbeKit(input = {}) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw new UsageError('集成包生成输入必须是对象：{ policy, outDir }');
  }
  const outDir = input.outDir;
  if (typeof outDir !== 'string' || outDir.trim() === '') {
    throw new UsageError('缺少输出目录：请用 outDir 给出集成包的写出目录');
  }
  const policyInput = input.policy;
  if (policyInput !== undefined && policyInput !== null && (typeof policyInput !== 'object' || Array.isArray(policyInput))) {
    throw new UsageError('策略必须是对象');
  }
  const policy = policyInput ?? {};
  // 结构校验：类型错误与“模式声明了拒绝却没开开关”这类矛盾都在这里落到用法错误。
  validatePolicy(policy);

  const layerEnabled = (policy.layers ?? {})[LAYER_ID];
  if (layerEnabled === false) {
    // 策略显式关闭了本层：不生成，也不写任何文件，把决定权交回调用方。
    return {
      schema: PROBE_KIT_SCHEMA,
      tool: 'probe-kit',
      status: 'skipped',
      layer: LAYER_ID,
      layerLabel: LAYER.label,
      parts: [...PROBE_KIT_PARTS],
      response: {
        mode: observationPolicyOf(policy).mode,
        refusalEnabled: observationPolicyOf(policy).refusalEnabled,
        signalThreshold: DEFAULT_SIGNAL_THRESHOLD,
        exceptions: effectiveProbeExceptions(policy),
      },
      checks: PROBE_CHECKS.map((check) => check.id),
      outDir: resolve(outDir),
      files: [],
      changed: false,
      skipReason: `策略关闭了层 ${LAYER_ID}（${LAYER.label}），本次未生成集成包，也未写入任何文件`,
      note: '本集成包只输出可嵌入的检测代码片段与人工检查清单，未改动任何制品。',
      limitations: [...KIT_LIMITATIONS],
    };
  }

  const templatesDir = typeof input.templatesDir === 'string' && input.templatesDir !== '' ? input.templatesDir : defaultTemplatesDir();
  const read = input.io?.readFile ?? readFile;
  const context = probeKitContext(policy);

  // 先渲染全部模板，任何一项不完整都不落盘：不写半个集成包。
  const rendered = [];
  for (const spec of PROBE_TEMPLATE_FILES) {
    const templatePath = join(templatesDir, spec.template);
    let text;
    try {
      text = await read(templatePath, 'utf8');
    } catch (error) {
      throw new UsageError(`无法读取集成包模板：${templatePath}`, { cause: String(error) });
    }
    assertTemplateComplete(spec.id, text, templatePath);
    rendered.push({ spec, text: renderTemplate(spec.id, text, context, templatePath) });
  }

  const resolvedOut = resolve(outDir);
  try {
    await mkdir(resolvedOut, { recursive: true });
  } catch (error) {
    throw new UsageError(`无法创建输出目录：${resolvedOut}`, { cause: String(error) });
  }
  if (typeof input.warnTree === 'function') {
    await input.warnTree(resolvedOut);
  }

  // 逐文件比对后再写：内容相同的文件不重写，第二次生成因此 changed 为 false。
  const files = [];
  let changed = false;
  for (const { spec, text } of rendered) {
    const target = join(resolvedOut, spec.output);
    const existing = await read(target, 'utf8').catch(() => null);
    if (existing !== text) {
      await writeFile(target, text, 'utf8');
      changed = true;
    }
    files.push({ name: spec.output, path: target, bytes: Buffer.byteLength(text, 'utf8') });
  }

  const observation = observationPolicyOf(policy);
  return {
    schema: PROBE_KIT_SCHEMA,
    tool: 'probe-kit',
    status: 'generated',
    layer: LAYER_ID,
    layerLabel: LAYER.label,
    parts: [...PROBE_KIT_PARTS],
    response: {
      mode: observation.mode,
      refusalEnabled: observation.refusalEnabled,
      signalThreshold: DEFAULT_SIGNAL_THRESHOLD,
      exceptions: effectiveProbeExceptions(policy),
    },
    checks: PROBE_CHECKS.map((check) => check.id),
    outDir: resolvedOut,
    files,
    changed,
    note: '本集成包只输出可嵌入的检测代码片段与人工检查清单，未改动任何制品；是否拒绝由策略显式开启。',
    limitations: [...KIT_LIMITATIONS],
  };
}

/**
 * 集成包报告的人读文本：落盘清单、响应模式与限制说明。
 * 报告的 outDir、files、response 等字段不在通用人读渲染器的覆盖范围内，
 * 两条入口的文本模式都用这一份渲染，不各写一份；缺字段时给“未知”占位，不抛错。
 * @param {Record<string, unknown>} report buildProbeKit 的返回
 * @returns {string}
 */
export function renderProbeKitText(report) {
  const lines = [];
  lines.push(`集成包输出目录：${report?.outDir ?? '未知'}`);
  const status = report?.status ?? '未知';
  const statusText = status === 'generated' ? '已生成' : status === 'skipped' ? '未生成' : status;
  lines.push(`状态：${statusText}`);
  if (typeof report?.skipReason === 'string' && report.skipReason !== '') {
    lines.push(`未生成原因：${report.skipReason}`);
  }
  const files = Array.isArray(report?.files) ? report.files : [];
  if (files.length > 0) {
    lines.push(`产物：${files.length} 份`);
    for (const file of files) {
      lines.push(`  ${file?.name ?? '（未标注文件名）'}（${file?.bytes ?? 0} 字节）：${file?.path ?? '未知'}`);
    }
  }
  const response = report?.response ?? {};
  const refusal = response.refusalEnabled === true ? '已开启' : '未开启';
  lines.push(`响应模式：${response.mode ?? '未知'}（拒绝${refusal}，联合判定阈值 ${response.signalThreshold ?? '未知'}）`);
  const exceptions = Array.isArray(response.exceptions) ? response.exceptions : [];
  lines.push(`例外清单：${exceptions.length > 0 ? exceptions.join('、') : '无'}`);
  if (typeof report?.note === 'string' && report.note !== '') {
    lines.push(report.note);
  }
  const limitations = Array.isArray(report?.limitations) ? report.limitations : [];
  if (limitations.length > 0) {
    lines.push(`限制说明：${limitations.length} 项`);
    for (const limitation of limitations) {
      lines.push(`  ${limitation}`);
    }
  }
  return `${lines.join('\n')}\n`;
}
