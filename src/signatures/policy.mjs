// 签名观察器的策略读取与门控决策辅助。
// 观察器只回答“制品是否带签名或校验和机制”，门控决策由观察结果叠加策略得出：
//   默认（allowRewriteSigned=false, allowChecksumRecompute=false）对签名制品跳过改写；
//   策略显式允许时才施加，并在结果里标记 requires_resign。

/**
 * 读取签名相关策略，缺失字段回落到默认值（一律不允许）。
 * @param {Record<string, unknown>} policy 策略对象
 * @returns {{allowRewriteSigned: boolean, allowChecksumRecompute: boolean}}
 */
export function readSignaturesPolicy(policy) {
  const section = (policy ?? {}).signatures ?? {};
  return {
    allowRewriteSigned: section.allowRewriteSigned === true,
    allowChecksumRecompute: section.allowChecksumRecompute === true,
  };
}

/**
 * 观察结果的公共信封：每个观察器的 analyze 都返回这一形状，外加格式专属字段。
 * @typedef {object} Observation
 * @property {string} observer 观察器标识
 * @property {string} container 容器标识
 * @property {boolean} parseable 结构是否解析成功
 * @property {string | null} limitation 无法完整解析时的限制说明
 * @property {{action: string, requiresResign: boolean, reason: string | null}} gate 门控决策
 * @property {boolean} signatureDetected 是否检测到代码签名机制
 * @property {boolean} checksumDetected 是否检测到校验和机制
 */
