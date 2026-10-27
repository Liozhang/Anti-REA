// 命令行参数解析。
// 零依赖手写解析：只支持长选项，避免引入参数解析库。
// 每个子命令有自己的选项表，出现未登记选项即报用法错误（退出码 2）。

/** 布尔选项。 */
const BOOLEAN = 'boolean';
/** 取值选项。 */
const STRING = 'string';

/**
 * 各子命令的参数规格。
 * positionals 声明必需的位置参数个数，0 表示不接受位置参数。
 */
export const SUBCOMMAND_SPECS = Object.freeze({
  audit: Object.freeze({
    positionals: 1,
    positionalLabel: '<目录或文件>',
    options: Object.freeze({
      json: BOOLEAN,
      redacted: BOOLEAN,
      format: STRING,
      policy: STRING,
      out: STRING,
    }),
    requiredOptions: Object.freeze([]),
  }),
  harden: Object.freeze({
    positionals: 1,
    positionalLabel: '<目录或文件>',
    options: Object.freeze({
      json: BOOLEAN,
      from: STRING,
      policy: STRING,
      out: STRING,
    }),
    requiredOptions: Object.freeze(['from']),
  }),
  verify: Object.freeze({
    positionals: 1,
    positionalLabel: '<目录或文件>',
    options: Object.freeze({
      json: BOOLEAN,
      from: STRING,
      policy: STRING,
      out: STRING,
    }),
    requiredOptions: Object.freeze([]),
  }),
  notice: Object.freeze({
    positionals: 0,
    positionalLabel: '',
    options: Object.freeze({
      json: BOOLEAN,
      format: STRING,
      template: STRING,
      policy: STRING,
      out: STRING,
    }),
    requiredOptions: Object.freeze(['template']),
  }),
  probe: Object.freeze({
    positionals: 1,
    positionalLabel: '<输出目录>',
    options: Object.freeze({
      json: BOOLEAN,
      format: STRING,
      policy: STRING,
      out: STRING,
    }),
    requiredOptions: Object.freeze([]),
  }),
});

/** 全局选项，任何子命令都接受。 */
export const GLOBAL_OPTIONS = Object.freeze({
  help: BOOLEAN,
  version: BOOLEAN,
});

/** 子命令封闭集合。 */
export const SUBCOMMANDS = Object.freeze(Object.keys(SUBCOMMAND_SPECS));

/**
 * 解析命令行参数。
 * @param {readonly string[]} argv 进程参数，不含 node 与脚本路径
 * @returns {{ok: true, subcommand: string, positionals: string[], options: Record<string, string | boolean>, help: boolean, version: boolean} | {ok: false, errors: string[]}}
 */
export function parseArgs(argv) {
  const errors = [];
  const options = {};
  let help = false;
  let version = false;

  const args = [...argv];
  if (args.length === 0) {
    return { ok: false, errors: ['缺少子命令'] };
  }

  // 允许把 --help 与 --version 放在子命令之前，例如 node bin/anti-rea.js --help。
  if (args[0] === '--help' || args[0] === '--version') {
    return {
      ok: true,
      subcommand: '',
      positionals: [],
      options: {},
      help: args[0] === '--help',
      version: args[0] === '--version',
    };
  }

  const subcommand = args.shift();
  if (!SUBCOMMANDS.includes(subcommand)) {
    return { ok: false, errors: [`未知子命令：${subcommand}，可用子命令为 ${SUBCOMMANDS.join('、')}`] };
  }
  const spec = SUBCOMMAND_SPECS[subcommand];

  const positionals = [];
  while (args.length > 0) {
    const arg = args.shift();
    if (arg === '--') {
      positionals.push(...args);
      break;
    }
    if (arg.startsWith('--')) {
      const equals = arg.indexOf('=');
      const name = equals === -1 ? arg.slice(2) : arg.slice(2, equals);
      const inlineValue = equals === -1 ? undefined : arg.slice(equals + 1);
      if (Object.hasOwn(GLOBAL_OPTIONS, name)) {
        if (name === 'help') {
          help = true;
        } else {
          version = true;
        }
        continue;
      }
      const kind = spec.options[name];
      if (kind === undefined) {
        errors.push(`子命令 ${subcommand} 不支持的选项：--${name}`);
        continue;
      }
      if (kind === BOOLEAN) {
        options[name] = true;
        continue;
      }
      let value = inlineValue;
      if (value === undefined) {
        value = args.shift();
        if (value === undefined) {
          errors.push(`选项 --${name} 缺少取值`);
          continue;
        }
      }
      options[name] = value;
      continue;
    }
    if (arg.startsWith('-') && arg.length > 1) {
      errors.push(`不支持的短选项：${arg}，本工具只接受长选项`);
      continue;
    }
    positionals.push(arg);
  }

  if (positionals.length > spec.positionals) {
    errors.push(`子命令 ${subcommand} 只接受 ${spec.positionals} 个位置参数，收到 ${positionals.length} 个`);
  }
  if (positionals.length < spec.positionals && !help) {
    errors.push(`子命令 ${subcommand} 缺少位置参数${spec.positionalLabel ? ` ${spec.positionalLabel}` : ''}`);
  }
  for (const name of spec.requiredOptions) {
    if (options[name] === undefined && !help) {
      errors.push(`子命令 ${subcommand} 缺少必需选项 --${name}`);
    }
  }
  if (options.format !== undefined && !['json', 'text'].includes(options.format)) {
    errors.push(`--format 只支持 json 或 text，收到 ${options.format}`);
  }

  if (errors.length > 0) {
    return { ok: false, errors };
  }
  return { ok: true, subcommand, positionals, options, help, version };
}
