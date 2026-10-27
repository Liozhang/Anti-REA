// 退出码表。命令行与 MCP 服务共用同一套定义，测试直接导入本模块锁定契约。

export const EXIT_CODES = Object.freeze({
  /** 成功。审计正常完成（包括发现暴露）、加固施加成功、复审通过、声明生成成功。 */
  SUCCESS: 0,
  /** 业务不通过。例如复审未通过并已回滚。 */
  BUSINESS_FAILURE: 1,
  /** 用法或输入错误。例如子命令未知、参数缺失、目标路径不存在、审计结果文件无法解析。 */
  USAGE_ERROR: 2,
  /** 拒否。例如生成声明时法律字段缺失。此时代码未改动制品。 */
  REFUSAL: 3,
});

/** 退出码到人读说明的映射，用于标准错误输出。 */
export const EXIT_CODE_LABELS = Object.freeze({
  [EXIT_CODES.SUCCESS]: '成功',
  [EXIT_CODES.BUSINESS_FAILURE]: '业务不通过',
  [EXIT_CODES.USAGE_ERROR]: '用法或输入错误',
  [EXIT_CODES.REFUSAL]: '拒否',
});

export default EXIT_CODES;
