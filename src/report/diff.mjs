// 加固前后差异比对：残留发现、新增发现、消失发现。
// 供审计与复审共用，也是运营留痕的组成部分。

/**
 * 发现的稳定标识：层、分类与读取器三项组合，不依赖路径与字节范围，
 * 这样同一事实在加固前后仍能对上，等长覆写后字节范围变化也不会误判为“消失又新增”。
 * @param {Record<string, unknown>} finding 发现
 * @returns {string}
 */
function findingKey(finding) {
  return [finding.layer, finding.category, finding.reader].join('|');
}

/**
 * 取报告里的发现列表。畸形输入一律按空列表处理：
 * 比对是运营留痕的一环，输入残缺时给出“什么都没有”的比对结果，
 * 比把异常甩给调用方更接近留痕的用途；调用方拿到的报告仍以原报告为准。
 * @param {unknown} report 审计报告
 * @returns {Record<string, unknown>[]}
 */
function findingsOf(report) {
  if (report === null || typeof report !== 'object') {
    return [];
  }
  const list = report.findings;
  if (!Array.isArray(list)) {
    return [];
  }
  return list.filter((finding) => finding !== null && typeof finding === 'object');
}

/**
 * 按稳定标识分组，保留出现顺序。同一标识可以对应多条发现
 * （同一读取器在同一层报了多处同类事实），分组而不是互相覆盖，
 * 否则多条变一条时比对会平白少算一项。
 * @param {Record<string, unknown>[]} findings 发现列表
 * @returns {Map<string, Record<string, unknown>[]>}
 */
function groupByKey(findings) {
  const groups = new Map();
  for (const finding of findings) {
    const key = findingKey(finding);
    const list = groups.get(key);
    if (list === undefined) {
      groups.set(key, [finding]);
    } else {
      list.push(finding);
    }
  }
  return groups;
}

/**
 * 比对两份审计报告。
 * 同一标识出现多次时按次数配对：次数相同全部残留，基线多出来的记消失，
 * 本次多出来的记新增。判定不看严重度与证据，只看标识。
 * @param {Record<string, unknown>} baseline 加固前报告
 * @param {Record<string, unknown>} current 加固后报告
 * @returns {{resolved: unknown[], introduced: unknown[], persisting: unknown[]}}
 */
export function diffAudits(baseline, current) {
  const baselineGroups = groupByKey(findingsOf(baseline));
  const currentGroups = groupByKey(findingsOf(current));

  const resolved = [];
  const introduced = [];
  const persisting = [];
  for (const [key, list] of baselineGroups) {
    const currentList = currentGroups.get(key) ?? [];
    const shared = Math.min(list.length, currentList.length);
    persisting.push(...list.slice(0, shared));
    resolved.push(...list.slice(shared));
  }
  for (const [key, list] of currentGroups) {
    // 同一标识本次多出来的次数记新增；标识只出现在本次时全部记新增。
    const baselineList = baselineGroups.get(key) ?? [];
    const shared = Math.min(list.length, baselineList.length);
    introduced.push(...list.slice(shared));
  }
  return { resolved, introduced, persisting };
}

/**
 * 按稳定标识比对两份审计报告，每个标识只出一个代表项。
 * 与 diffAudits 的分工：diffAudits 按出现次数配对，服务运营留痕的精确记账；
 * 本函数只判标识在不在，服务安全门——复审报告按“暴露”说话，一个标识就是一处暴露，
 * 同一标识出现多次只是同一暴露的多处落点（例如静态符号表与动态符号表同为
 * elf-symtab 一处暴露），逐次列出会让“残留几项”虚高，也会让只清了其中一处的
 * 暴露被当成整处消失，据此派生豁免与安全门“看不到问题才放行”的前提相悖。
 * 取值口径：残留与新增取本次审计的代表发现，证据反映加固后的当前状态；
 * 消失取基线侧的代表发现，该项本次已不存在。
 * @param {Record<string, unknown>} baseline 加固前报告
 * @param {Record<string, unknown>} current 加固后报告
 * @returns {{resolved: unknown[], introduced: unknown[], persisting: unknown[]}}
 */
export function diffAuditsByKey(baseline, current) {
  const baselineGroups = groupByKey(findingsOf(baseline));
  const currentGroups = groupByKey(findingsOf(current));

  const resolved = [];
  const introduced = [];
  const persisting = [];
  for (const [key, list] of baselineGroups) {
    const currentList = currentGroups.get(key);
    if (currentList === undefined) {
      resolved.push(list[0]);
    } else {
      persisting.push(currentList[0]);
    }
  }
  for (const [key, list] of currentGroups) {
    // 标识只出现在本次时记新增；标识两侧都在时已按残留计入，不重复列。
    if (!baselineGroups.has(key)) {
      introduced.push(list[0]);
    }
  }
  return { resolved, introduced, persisting };
}

/**
 * 比对两份制品摘要，判断本次产出与已存在输出是否逐字节相同。
 * 摘要相同即字节相同：sha256 相同而字节不同在计算上不可构造。
 * 任一侧缺失摘要或不是对象时返回 false，由调用方按“需要写出”处理。
 * @param {{sha256?: string} | null | undefined} left
 * @param {{sha256?: string} | null | undefined} right
 * @returns {boolean}
 */
export function sameDigest(left, right) {
  if (left === null || left === undefined || right === null || right === undefined) {
    return false;
  }
  if (typeof left !== 'object' || typeof right !== 'object') {
    return false;
  }
  return typeof left.sha256 === 'string' && left.sha256 === right.sha256;
}
