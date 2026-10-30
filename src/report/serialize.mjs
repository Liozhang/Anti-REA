// 报告序列化：机器可读 JSON 与人读文本两种形态，审计与复审共用。
// 序列化受策略的报表字节上限约束：超限时截断并附限制说明，而不是无限增长。
//
// 三条保证贯穿全文件：
//   1. 输出永不超限。硬截断按 UTF-8 字符边界回退，不会把多字节字符切成两半后
//      因替换字符胀出上限；上限为零时输出空串，不抛错。
//   2. 截断必须留痕。第二阶段把 truncated 与 truncation 放在键序最前，
//      硬截断后的任何前缀都还能看到“这份报表被截断过”，残缺不会冒充完整。
//   3. 分级降级而不是失败。先保汇总丢明细，明细丢了还超限才硬截断，
//      每一级都在输出里留下限制说明。

import { budgetsOf } from '../policy/schema.mjs';

/** 截断标记，出现在被截断的报表末尾。 */
export const TRUNCATION_MARK = '…[报表已达到策略字节上限，内容已截断]';

/**
 * 人读文本逐条列出的发现条数上限。
 * 序列化有字节预算兜底，人读文本没有：一份几千条发现的制品若逐条全印，
 * 文本会无上限增长，终端与日志都接不住。超出部分只报条数并指向 JSON 输出，
 * 残缺不冒充完整——这句话本身就是限制说明。
 */
export const TEXT_FINDING_LIMIT = 20;

/**
 * 序列化为 JSON 文本。
 * 超限时先去掉最占空间的 findings 与 limitations 明细，只保留汇总；
 * 仍然超限则在 UTF-8 字符边界处硬截断，末尾附截断标记。
 * @param {Record<string, unknown>} report 报告对象
 * @param {{policy?: Record<string, unknown>, indent?: number}} [options]
 * @returns {string}
 */
export function serializeReport(report, options = {}) {
  const indent = options.indent ?? 2;
  const limit = budgetsOf(options.policy ?? {}).maxReportBytes;
  const full = JSON.stringify(report, null, indent);
  if (typeof full !== 'string') {
    // undefined 之类的不可序列化输入：给出 null 文本，不把异常甩给调用方。
    return 'null';
  }
  if (Buffer.byteLength(full, 'utf8') <= limit) {
    return full;
  }

  // 畸形输入（数组、标量）没有 findings 可丢，包一层再走降级路径，不让解构把流程打断。
  const source = report !== null && typeof report === 'object' && !Array.isArray(report) ? report : { value: report };
  const { findings, limitations, ...rest } = source;
  const truncated = {
    truncated: true,
    truncation: {
      reason: `报表字节数超过策略上限 ${limit}`,
      limit,
    },
    ...rest,
  };
  const slim = JSON.stringify(truncated, null, indent);
  if (Buffer.byteLength(slim, 'utf8') <= limit) {
    return slim;
  }
  return hardCut(slim, limit);
}

/**
 * 硬截断：在字符边界处把文本压进上限，末尾尽量附上截断标记。
 * 标记放不下时只保留能放下的最长前缀；此时前缀开头就是第二阶段写在前面的
 * truncated 字段，截断痕迹仍然可见。
 * @param {string} text 已序列化的文本
 * @param {number} limit 字节上限
 * @returns {string}
 */
function hardCut(text, limit) {
  const markBytes = Buffer.byteLength(TRUNCATION_MARK, 'utf8');
  if (limit < markBytes) {
    return cutToLimit(decodePrefix(text, limit), limit);
  }
  const room = limit - markBytes;
  let head = cutToLimit(decodePrefix(text, room), room);
  const lastNewline = head.lastIndexOf('\n');
  if (lastNewline > 0) {
    head = head.slice(0, lastNewline + 1);
  }
  return `${head}${TRUNCATION_MARK}`;
}

/**
 * 取文本的前 limit 个字节并解码。可能以替换字符结尾，由 cutToLimit 收尾。
 * @param {string} text 文本
 * @param {number} limit 字节数
 * @returns {string}
 */
function decodePrefix(text, limit) {
  return Buffer.from(text, 'utf8').subarray(0, Math.max(limit, 0)).toString('utf8');
}

/**
 * 从尾部逐字符回退，直到文本字节数不超限。只会在边界处回退几个字符。
 * @param {string} text 文本
 * @param {number} limit 字节上限
 * @returns {string}
 */
function cutToLimit(text, limit) {
  let out = text;
  while (out.length > 0 && Buffer.byteLength(out, 'utf8') > limit) {
    out = out.slice(0, -1);
  }
  return out;
}

/**
 * 渲染为人读文本。
 * 报告缺字段时给“未知”占位，不抛错：人读文本是兜底输出形态，
 * 调用方拿到半份报告时也要能看，而不是再吃一个异常。
 * @param {Record<string, unknown>} report 报告对象
 * @returns {string}
 */
export function renderTextReport(report) {
  const lines = [];
  lines.push(`工具：${report?.tool ?? '未知'}`);
  lines.push(`状态：${report?.status ?? '未知'}`);
  const artifact = report?.artifact ?? {};
  lines.push(`制品摘要：${artifact.sha256 ?? '未知'}`);
  lines.push(`制品字节数：${artifact.bytes ?? 0}`);
  if (artifact.container !== undefined) {
    lines.push(`容器类型：${artifact.container}`);
  }
  const summary = report?.summary ?? {};
  if (summary.findings === undefined && summary.checks !== undefined) {
    // 复审报告按检查族统计，没有“发现数”可数：拿发现数 0 冒充会把一门通过的检查说成没有产出。
    // 通过、失败、待定、不适用各自计数，看不到问题与真的通过在文本里区分得开。
    lines.push(
      `检查数：${summary.checks ?? 0} 项（通过 ${summary.passed ?? 0}、失败 ${summary.failed ?? 0}、待定 ${summary.pending ?? 0}、不适用 ${summary.notApplicable ?? 0}）`,
    );
  } else {
    lines.push(`发现数：${summary.findings ?? 0}`);
    const byLayer = summary.byLayer ?? {};
    for (const [layer, count] of Object.entries(byLayer)) {
      if (count > 0) {
        lines.push(`  ${layer}：${count}`);
      }
    }
  }
  // 逐条发现：按层计数只回答“有多少”，不回答“是哪几条、读了会看到什么”。
  // 残留风险与源头解法跟发现一起出，用户在审计阶段就看到这项措施做不到什么、
  // 以及更彻底的做法是什么，而不是等加固结束后才发现记录清零了字符串还在。
  const findings = Array.isArray(report?.findings) ? report.findings : [];
  if (findings.length > 0) {
    lines.push(`逐条发现：${findings.length} 条`);
    const shown = findings.slice(0, TEXT_FINDING_LIMIT);
    for (const finding of shown) {
      lines.push(
        `  ${finding?.id ?? '（无编号）'} [${finding?.severity ?? '未知'}] ${finding?.title ?? '（无标题）'}（${finding?.category ?? '未知'}）`,
      );
      const evidence = finding?.evidence ?? {};
      const range = Array.isArray(evidence.byteRange) ? `：${evidence.byteRange[0]}-${evidence.byteRange[1]}` : '';
      lines.push(`    证据：${evidence.path ?? '未知'}${range}`);
      lines.push(`    读取器 ${finding?.reader ?? '未知'}：${finding?.readerLimitation ?? '未说明'}`);
      if (typeof finding?.residualRisk === 'string' && finding.residualRisk !== '') {
        lines.push(`    施加后仍会暴露：${finding.residualRisk}`);
      }
      const fix = finding?.sourceFix;
      if (fix !== null && typeof fix === 'object') {
        lines.push(`    更彻底的做法：${fix.action}`);
        lines.push(`    该做法的自身代价：${fix.risk}`);
      }
    }
    if (findings.length > shown.length) {
      lines.push(`  另有 ${findings.length - shown.length} 条发现未在此列出，完整清单请用 JSON 输出`);
    }
  }
  const boundaries = report?.capabilityBoundaries ?? [];
  if (boundaries.length > 0) {
    lines.push(`能力边界：${boundaries.length} 项`);
    for (const boundary of boundaries) {
      lines.push(`  ${boundary.id}：${boundary.reason}`);
    }
  }
  const limitations = report?.limitations ?? [];
  if (limitations.length > 0) {
    lines.push(`限制说明：${limitations.length} 项`);
    for (const limitation of limitations) {
      lines.push(`  ${limitation.code}：${limitation.message}`);
    }
  }
  if (report?.comparison !== undefined && report.comparison !== null) {
    const comparison = report.comparison;
    lines.push(`与基线比较：消失 ${comparison.resolved?.length ?? 0} 项，新增 ${comparison.introduced?.length ?? 0} 项，残留 ${comparison.persisting?.length ?? 0} 项`);
  }
  if (Array.isArray(report?.applied)) {
    lines.push(`已施加缓解：${report.applied.length} 项`);
    for (const item of report.applied) {
      lines.push(`  ${item.mitigation}（${item.kind}）`);
      if (typeof item.residualRisk === 'string' && item.residualRisk !== '') {
        lines.push(`    施加后仍会暴露：${item.residualRisk}`);
      }
      if (item.sourceFix !== null && typeof item.sourceFix === 'object') {
        lines.push(`    更彻底的做法：${item.sourceFix.action}（该做法的自身代价：${item.sourceFix.risk}）`);
      }
    }
  }
  if (Array.isArray(report?.skipped)) {
    lines.push(`已跳过缓解：${report.skipped.length} 项`);
    for (const item of report.skipped) {
      lines.push(`  ${item.mitigation ?? '（未标注编号）'}：${item.reason}`);
      if (typeof item.residualRisk === 'string' && item.residualRisk !== '') {
        lines.push(`    即使施加也仍会暴露：${item.residualRisk}`);
      }
      if (item.sourceFix !== null && typeof item.sourceFix === 'object') {
        lines.push(`    更彻底的做法：${item.sourceFix.action}（该做法的自身代价：${item.sourceFix.risk}）`);
      }
    }
  }
  if (report?.outputNote !== undefined) {
    lines.push(`输出说明：${report.outputNote}`);
  }
  if (report?.requiresResign === true) {
    lines.push('需要重新签名：本次改动影响了签名或校验和，请用自有签名身份重新签名后再放行');
  }
  // 拒否报告的字段名是蛇形 omitted_reason（src/cli/workflows.mjs 的 buildRefusalReport 产出）；
  // 人读输出仍以“拒否原因”段给出，与机器可读报告是同一份数据。
  if (report?.omitted_reason !== undefined) {
    lines.push('拒否原因：');
    for (const reason of report.omitted_reason ?? []) {
      lines.push(`  ${reason}`);
    }
  }
  if (Array.isArray(report?.warnings) && report.warnings.length > 0) {
    lines.push(`警告：${report.warnings.length} 条`);
    for (const warning of report.warnings) {
      lines.push(`  ${warning}`);
    }
  }
  return `${lines.join('\n')}\n`;
}
