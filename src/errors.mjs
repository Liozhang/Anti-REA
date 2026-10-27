// 统一错误类型与退出码约定。
// 退出码表（命令行与 MCP 服务共用）：
//   0 成功（审计正常完成，包括发现暴露；加固施加成功；复审通过；声明生成成功）
//   1 业务不通过（复审未通过且已回滚；工作流步骤未实现）
//   2 用法或输入错误（子命令未知、参数缺失、目标不存在、审计结果文件无法解析）
//   3 拒否（法律字段缺失等原因拒绝生成声明；此时代码未改动制品）
import { EXIT_CODES } from './cli/exit-codes.mjs';

/** 全部错误的基类。code 字段直接对应上面的退出码表。 */
export class AntireaError extends Error {
  /**
   * @param {string} message 面向用户的说明
   * @param {number} code 退出码
   * @param {{detail?: unknown}} [options]
   */
  constructor(message, code, options = {}) {
    super(message);
    this.name = new.target.name;
    this.code = code;
    this.detail = options.detail;
  }
}

/** 用法或输入错误，对应退出码 2。 */
export class UsageError extends AntireaError {
  constructor(message, detail) {
    super(message, EXIT_CODES.USAGE_ERROR, { detail });
  }
}

/** 业务不通过，对应退出码 1。 */
export class BusinessError extends AntireaError {
  constructor(message, detail) {
    super(message, EXIT_CODES.BUSINESS_FAILURE, { detail });
  }
}

/** 拒否，对应退出码 3。拒否时必须产出含 omitted_reason 的报告。 */
export class RefusalError extends AntireaError {
  /**
   * @param {string[]} omittedReason 逐条列出被拒原因
   */
  constructor(omittedReason, message = '请求被拒绝，原因见 omitted_reason') {
    super(message, EXIT_CODES.REFUSAL, { detail: { omittedReason } });
    this.omittedReason = omittedReason;
  }
}

/** 骨架占位：对应模块尚未实现业务逻辑。 */
export class NotImplementedError extends AntireaError {
  constructor(module, capability) {
    super(`模块 ${module} 尚未实现：${capability}`, EXIT_CODES.BUSINESS_FAILURE, {
      detail: { module, capability },
    });
    this.module = module;
    this.capability = capability;
  }
}

/**
 * 把未知异常折算成退出码与可报告结构，避免堆栈直接抛给用户。
 * @param {unknown} error
 * @returns {{exitCode: number, kind: string, message: string, detail?: unknown}}
 */
export function describeError(error) {
  if (error instanceof AntireaError) {
    return { exitCode: error.code, kind: error.name, message: error.message, detail: error.detail };
  }
  if (error instanceof Error) {
    return { exitCode: EXIT_CODES.BUSINESS_FAILURE, kind: 'InternalError', message: error.message };
  }
  return { exitCode: EXIT_CODES.BUSINESS_FAILURE, kind: 'UnknownError', message: String(error) };
}
