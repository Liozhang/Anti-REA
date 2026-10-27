// anti-rea-probe-template: runtime-probe v1
// 运行期自检代码片段（反运行时观察层集成包产物，默认响应为记录并继续）。
// 只读当前进程自身可观测的事实：环境变量、命令行、标准流属性、POSIX 跟踪状态。
// 不启动子进程、不附加进程、不发起网络请求、不读写他人内存。
// 集成方须知：默认拒绝动作是抛出可捕获的 ProbeRefusalError；
// 请用 onRefuse 接入你们自己的处理路径，不得改成清数据、崩溃或静默失败。

import { readFileSync } from 'node:fs';

/** 响应模式：report-only 只记录与上报；report-and-refuse 多迹象联合判定后拒绝继续。 */
export const RESPONSE_MODE = '{{RESPONSE_MODE}}';

/** 是否允许拒绝继续。只有响应模式为 report-and-refuse 时本值才为 true。 */
export const REFUSAL_ENABLED = {{REFUSAL_ENABLED}};

/** 联合判定阈值：同时命中的独立迹象达到本值才判定为观察到运行期观察。单项迹象从不触发拒绝。 */
export const SIGNAL_THRESHOLD = {{SIGNAL_THRESHOLD}};

/** 例外清单：这些环境变量名或会话标记存在时，抑制映射内的检查项，避免持续集成与远程执行误伤。 */
export const EXCEPTIONS = Object.freeze({{EXCEPTION_LIST}});

/** 例外到检查项的抑制映射：键为例外名，值为被抑制的检查项标识。 */
export const EXCEPTION_SUPPRESSES = Object.freeze({{EXCEPTION_SUPPRESSES}});

/** 环境变量名关键词：变量名大小写折叠后包含其中任一项，即为运行标识环境变量迹象。 */
export const ENV_MARKER_KEYWORDS = Object.freeze(['capture', 'observation', 'instrument', 'tracer']);

/** 注入脚本命名前缀：命令行或 NODE_OPTIONS 中的脚本文件名以此开头，即为注入脚本迹象。 */
export const SCRIPT_PREFIXES = Object.freeze(['inject', 'instrument', 'observer', 'capture-agent']);

/** 会话首进程名关键词：父进程名包含其中任一项，即为伪终端迹象（仅 Linux 可读父进程名）。 */
export const PARENT_NAME_KEYWORDS = Object.freeze(['script', 'capture', 'pty', 'observ', 'record']);

/** 检查项标识封闭集合，与集成包报告一致。 */
export const CHECK_IDS = Object.freeze({{CHECK_IDS}});

/** 拒绝动作的错误类型：可捕获，不是崩溃，也不清数据，更不是静默失败。 */
export class ProbeRefusalError extends Error {
  /**
   * @param {Record<string, unknown>} outcome 联合判定结果
   */
  constructor(outcome) {
    const hits = Array.isArray(outcome.hits) ? outcome.hits.join('、') : '';
    super(`运行期自检同时命中多个观察迹象（${hits}），按响应模式 ${String(outcome.mode)} 拒绝继续。这是制品自身的运行期自检结论，由集成方处理。`);
    this.name = 'ProbeRefusalError';
    this.outcome = outcome;
  }
}

/**
 * 默认文本读取：只读本地小文件（/proc 下的状态文件）。
 * @param {string} path 文件路径
 * @returns {string} 文件内容
 */
function defaultReadText(path) {
  return readFileSync(path, 'utf8');
}

/**
 * 判断环境变量是否存在。Windows 对环境变量名做大小写折叠，因此该平台按折叠后比较。
 * @param {Record<string, string | undefined>} env 环境变量
 * @param {string} name 变量名
 * @param {string} platform 平台标识
 * @returns {boolean}
 */
function envHas(env, name, platform) {
  if (Object.hasOwn(env, name)) {
    return true;
  }
  if (platform !== 'win32') {
    return false;
  }
  const lowered = name.toLowerCase();
  return Object.keys(env).some((key) => key.toLowerCase() === lowered);
}

/**
 * 检查进程捕获写入的运行标识环境变量。
 * @param {Record<string, string | undefined>} [env] 环境变量，测试与集成方可注入
 * @returns {Record<string, unknown>} 检查结果
 */
export function checkEnvWriteMarker(env = process.env) {
  const names = Object.keys(env);
  const matched = names.filter((name) => {
    const lowered = name.toLowerCase();
    return ENV_MARKER_KEYWORDS.some((keyword) => lowered.includes(keyword.toLowerCase()));
  });
  return {
    id: 'env-write-marker',
    hit: matched.length > 0,
    detail: matched.length > 0 ? `环境变量名命中运行标识关键词：${matched.join('、')}` : '未发现运行标识环境变量',
    limitation: 'Chromium 系进程会覆盖初始环境内存，变量归属无法验证；本项只提高成本，不构成屏障',
  };
}

/**
 * 读会话首进程名。只有 Linux 提供 /proc/<ppid>/comm，其他平台返回 null。
 * @param {number} ppid 父进程号
 * @param {(path: string) => string} readText 文本读取函数
 * @param {string} platform 平台标识
 * @returns {string | null} 进程名，读不到时为 null
 */
function readParentName(ppid, readText, platform) {
  if (platform !== 'linux') {
    return null;
  }
  try {
    const text = readText(`/proc/${String(ppid)}/comm`);
    const first = text.split('\n')[0]?.trim() ?? '';
    return first === '' ? null : first;
  } catch {
    return null;
  }
}

/**
 * 检查伪终端迹象：终端类型、窗口尺寸、会话首进程身份。
 * @param {Record<string, string | undefined>} [env] 环境变量
 * @param {{isTTY?: boolean, columns?: number, rows?: number}} [stream] 标准流，测试与集成方可注入
 * @param {number} [ppid] 父进程号
 * @param {(path: string) => string} [readText] 文本读取函数
 * @param {string} [platform] 平台标识，测试可注入
 * @returns {Record<string, unknown>} 检查结果
 */
export function checkPseudoTerminalSigns(env = process.env, stream = process.stdout, ppid = process.ppid, readText = defaultReadText, platform = process.platform) {
  const signs = [];
  const claimsTty = stream !== undefined && stream !== null && stream.isTTY === true;
  const term = typeof env.TERM === 'string' ? env.TERM : '';
  if (claimsTty && term === '') {
    signs.push('标准流声称是终端，但 TERM 为空');
  }
  const columns = stream?.columns;
  const rows = stream?.rows;
  if (claimsTty && (!Number.isFinite(columns) || columns <= 0 || !Number.isFinite(rows) || rows <= 0)) {
    signs.push('标准流声称是终端，但窗口尺寸无效');
  }
  const parentName = readParentName(ppid, readText, platform);
  if (parentName !== null) {
    const lowered = parentName.toLowerCase();
    if (PARENT_NAME_KEYWORDS.some((keyword) => lowered.includes(keyword))) {
      signs.push(`会话首进程名命中捕获工具命名：${parentName}`);
    }
  }
  return {
    id: 'pseudo-terminal-signs',
    hit: signs.length > 0,
    detail: signs.length > 0 ? signs.join('；') : '未发现伪终端迹象',
    limitation: '伪终端迹象在持续集成与远程执行场景下本身就会误报，只能靠联合判定与例外清单缓解；macOS 读不到会话首进程名',
  };
}

/**
 * 检查注入脚本命名前缀。
 * @param {readonly string[]} [argv] 进程参数
 * @param {Record<string, string | undefined>} [env] 环境变量
 * @returns {Record<string, unknown>} 检查结果
 */
export function checkInjectedScriptPrefix(argv = process.argv, env = process.env) {
  const candidates = [...argv];
  if (typeof env.NODE_OPTIONS === 'string' && env.NODE_OPTIONS !== '') {
    candidates.push(env.NODE_OPTIONS);
  }
  const matched = candidates.filter((entry) => {
    if (typeof entry !== 'string' || entry === '') {
      return false;
    }
    const base = entry.split(/[\\/]/).pop() ?? entry;
    const lowered = base.toLowerCase();
    return SCRIPT_PREFIXES.some((prefix) => lowered.startsWith(prefix.toLowerCase()));
  });
  return {
    id: 'injected-script-prefix',
    hit: matched.length > 0,
    detail: matched.length > 0 ? `脚本名命中注入命名前缀：${matched.join('、')}` : '未发现注入脚本命名前缀',
    limitation: '脚本命名只是约定，误报与漏报都可能；业务脚本命名与前缀重合时请改清单，不要改判定逻辑',
  };
}

/**
 * 检查被跟踪状态。只有 Linux 在进程内可读 /proc/self/status 的 TracerPid。
 * @param {(path: string) => string} [readText] 文本读取函数
 * @param {string} [platform] 平台标识，测试可注入
 * @returns {Record<string, unknown>} 检查结果
 */
export function checkTracedState(readText = defaultReadText, platform = process.platform) {
  if (platform !== 'linux') {
    return {
      id: 'traced-state',
      hit: false,
      detail: '当前平台不提供进程内可读的跟踪状态，本项未检查',
      limitation: 'traced-state 只在 Linux 检查 /proc/self/status 的 TracerPid；其他平台需按人工检查清单确认',
    };
  }
  let text;
  try {
    text = readText('/proc/self/status');
  } catch {
    return {
      id: 'traced-state',
      hit: false,
      detail: '无法读取 /proc/self/status，本项未检查',
      limitation: '读取 /proc/self/status 失败，不等于没有跟踪；需按人工检查清单确认',
    };
  }
  const match = /^TracerPid:\s*(\d+)\s*$/m.exec(text);
  const tracerPid = match === null ? null : Number(match[1]);
  const hit = tracerPid !== null && tracerPid > 0;
  return {
    id: 'traced-state',
    hit,
    detail: hit ? `TracerPid 为 ${String(tracerPid)}，进程正被跟踪` : 'TracerPid 为 0 或缺失，未发现跟踪',
    limitation: 'TracerPid 只反映 ptrace 附加，不覆盖硬件调试器与内核级观察',
  };
}

/**
 * 检查检查器端口：启动参数或 NODE_OPTIONS 是否挂接了检查器。
 * @param {readonly string[]} [execArgv] Node 执行参数
 * @param {Record<string, string | undefined>} [env] 环境变量
 * @returns {Record<string, unknown>} 检查结果
 */
export function checkInspectorPort(execArgv = process.execArgv, env = process.env) {
  const flags = [...execArgv];
  if (typeof env.NODE_OPTIONS === 'string' && env.NODE_OPTIONS !== '') {
    flags.push(...env.NODE_OPTIONS.split(/\s+/));
  }
  const inspecting = flags.some((flag) => /^--inspect(-brk|-port)?(=|$)/.test(flag));
  return {
    id: 'inspector-port',
    hit: inspecting,
    detail: inspecting ? '启动参数或 NODE_OPTIONS 含检查器参数' : '未发现检查器启动参数',
    limitation: '本项只覆盖启动时挂接的检查器；运行期另开的调试端口需按人工检查清单确认',
  };
}

/**
 * 汇总全部检查项，并按例外清单抑制会在持续集成与远程执行场景误伤的项。
 * @param {Record<string, unknown>} [options] 依赖注入
 * @returns {{checks: Array<Record<string, unknown>>, activeExceptions: string[], suppressed: string[]}}
 */
export function collectSignals(options = {}) {
  const env = options.env ?? process.env;
  const argv = options.argv ?? process.argv;
  const execArgv = options.execArgv ?? process.execArgv;
  const stream = options.stream ?? process.stdout;
  const ppid = options.ppid ?? process.ppid;
  const readText = options.readText ?? defaultReadText;
  const platform = options.platform ?? process.platform;

  const checks = [
    checkEnvWriteMarker(env),
    checkPseudoTerminalSigns(env, stream, ppid, readText, platform),
    checkInjectedScriptPrefix(argv, env),
    checkTracedState(readText, platform),
    checkInspectorPort(execArgv, env),
  ];

  const activeExceptions = EXCEPTIONS.filter((name) => envHas(env, name, platform));
  const suppressed = new Set();
  for (const name of activeExceptions) {
    for (const checkId of EXCEPTION_SUPPRESSES[name] ?? []) {
      suppressed.add(checkId);
    }
  }
  for (const signal of checks) {
    signal.suppressed = signal.hit === true && suppressed.has(signal.id);
  }
  return { checks, activeExceptions, suppressed: [...suppressed] };
}

/**
 * 联合判定：未被抑制的命中项数达到阈值才判定为观察到运行期观察。
 * @param {{checks: Array<Record<string, unknown>>, activeExceptions: string[], suppressed: string[]}} signals 检查结果汇总
 * @param {number} [threshold] 阈值
 * @returns {Record<string, unknown>} 判定结果
 */
export function evaluate(signals, threshold = SIGNAL_THRESHOLD) {
  const hits = signals.checks
    .filter((signal) => signal.hit === true && signal.suppressed !== true)
    .map((signal) => signal.id);
  return {
    observed: hits.length >= threshold,
    hits,
    threshold,
    mode: RESPONSE_MODE,
    activeExceptions: signals.activeExceptions,
    suppressed: signals.suppressed,
    details: signals.checks,
  };
}

/**
 * 创建运行期探针。默认响应是记录并继续：判定结果记进内存，用 records() 读取。
 * @param {{
 *   env?: Record<string, string | undefined>,
 *   argv?: readonly string[],
 *   execArgv?: readonly string[],
 *   stream?: {isTTY?: boolean, columns?: number, rows?: number},
 *   ppid?: number,
 *   readText?: (path: string) => string,
 *   platform?: string,
 *   signalThreshold?: number,
 *   onObservation?: (outcome: Record<string, unknown>) => void,
 *   onRefuse?: (outcome: Record<string, unknown>) => void,
 * }} [options] 依赖注入与回调
 * @returns {Record<string, unknown>} 探针对象
 */
export function createRuntimeProbe(options = {}) {
  const threshold = Number.isInteger(options.signalThreshold) && options.signalThreshold >= 1
    ? options.signalThreshold
    : SIGNAL_THRESHOLD;
  const onObservation = typeof options.onObservation === 'function' ? options.onObservation : null;
  const onRefuse = typeof options.onRefuse === 'function' ? options.onRefuse : null;
  const records = [];

  function record(outcome) {
    if (onObservation !== null) {
      onObservation(outcome);
    } else {
      records.push(outcome);
      if (records.length > 64) {
        records.shift();
      }
    }
    return outcome;
  }

  function refuse(outcome) {
    if (onRefuse !== null) {
      return onRefuse(outcome);
    }
    throw new ProbeRefusalError(outcome);
  }

  return {
    threshold,
    collect() {
      return collectSignals(options);
    },
    check() {
      const signals = collectSignals(options);
      const outcome = evaluate(signals, threshold);
      if (outcome.observed === true && RESPONSE_MODE === 'report-and-refuse' && REFUSAL_ENABLED === true) {
        return refuse(outcome);
      }
      return record(outcome);
    },
    records() {
      return [...records];
    },
  };
}
// anti-rea-probe-template-end: runtime-probe
