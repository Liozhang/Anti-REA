// pyc 读取器：魔数、标志位与 source_hash 的事实提取。
// 只读：Python 3.7 起的 pyc 在魔数后带四字节标志位，hash_based 置位时源文件摘要跟在标志位之后。
// 清零 source_hash 必须同时清除 check_source，否则标志位与哈希状态不一致，本读取器把这一对事实一起报告。

import { createFinding } from '../audit/finding.mjs';
import { defineReader, limitation, readEntryBytes, readUIntLE, sanitizeExcerpt, truncationLimitation } from './common.mjs';
import { appendTokenScan } from './scan.mjs';

/** hash_based 标志位：源文件摘要替代时间戳与大小。 */
const FLAG_HASH_BASED = 0b01;

/** check_source 标志位：运行期核对源文件摘要。 */
const FLAG_CHECK_SOURCE = 0b10;

/**
 * pyc 读取器入口。
 * @param {{entry: Record<string, unknown>, policy: Record<string, unknown>, budgets: Record<string, number>}} context
 * @returns {Promise<{findings: Array<Record<string, unknown>>, limitations: Array<Record<string, unknown>>}>}
 */
async function readPyc(context) {
  const entry = context.entry;
  const budgets = context.budgets ?? {};
  const read = await readEntryBytes(entry, budgets);
  const bytes = read.bytes;
  const findings = [];
  const limitations = [];
  const path = entry.relativePath;

  if (!read.complete) {
    limitations.push(truncationLimitation(read));
  }

  if (bytes.length < 4) {
    limitations.push(limitation('pyc-too-short', '文件不足四字节，读不到魔数。该条目不等于没有暴露，只是本次没有提取到事实'));
    return { findings, limitations };
  }
  if (bytes[2] !== 0x0d || bytes[3] !== 0x0a) {
    limitations.push(limitation('pyc-magic-marker-missing', '字节 2 至 3 不是 0D 0A，不符合 pyc 魔数之后的固定标记，按非 pyc 处理'));
    return { findings, limitations };
  }

  // 字节码区的字符串常量（含凭据）与头部事实同样是要报告的暴露：格式已确认，扫全部已读字节。
  appendTokenScan(bytes, findings, limitations, { path, reader: 'pyc' });

  // pyc 头四字节是两字节魔数加固定的 0D 0A 标记；魔数按两字节读，标记单独核对。
  const magic = readUIntLE(bytes, 0, 2);
  if (magic === undefined) {
    limitations.push(limitation('pyc-magic-unreadable', '魔数读取越界'));
    return { findings, limitations };
  }

  const headerFinding = createFinding({
    layer: 'metadata-hygiene',
    severity: 'info',
    title: 'pyc 魔数与标志位',
    category: 'pyc-header',
    evidence: { path, byteRange: [0, 4], excerpt: `魔数 0x${magic.toString(16)}` },
    reader: 'pyc',
    readerLimitation: '魔数到 Python 版本的映射表未随读取器登记，只报告原始魔数值；字节码指令不在 v1 反汇编范围内',
    mitigation: null,
    detail: { magic },
  });
  findings.push(headerFinding);

  if (bytes.length < 8) {
    limitations.push(limitation('pyc-flags-unreadable', '文件不足八字节，读不到标志位字段，标志位事实本次没有覆盖'));
    return { findings, limitations };
  }
  const flags = readUIntLE(bytes, 4, 4);
  if (flags === undefined) {
    limitations.push(limitation('pyc-flags-unparsable', '标志位字段读取越界'));
    return { findings, limitations };
  }
  headerFinding.detail.flags = flags;

  const hashBased = (flags & FLAG_HASH_BASED) !== 0;
  const checkSource = (flags & FLAG_CHECK_SOURCE) !== 0;
  headerFinding.detail.hashBased = hashBased;
  headerFinding.detail.checkSource = checkSource;

  const unknownBits = flags & ~0b11;
  if (unknownBits !== 0) {
    limitations.push(
      limitation('pyc-unknown-flag-bits', `标志位 0x${flags.toString(16)} 含 v1 未登记的位 0x${unknownBits.toString(16)}，这些位的语义本次没有解读`),
    );
  }

  if (!hashBased) {
    // 时间戳加源大小的经典布局：暴露的是编译时刻与源文件大小。
    if (bytes.length >= 16) {
      const timestamp = readUIntLE(bytes, 8, 4);
      const sourceSize = readUIntLE(bytes, 12, 4);
      if (timestamp !== undefined && sourceSize !== undefined) {
        findings.push(
          createFinding({
            layer: 'metadata-hygiene',
            severity: 'low',
            title: 'pyc 时间戳与源文件大小',
            category: 'pyc-timestamp',
            evidence: { path, byteRange: [8, 16], excerpt: `时间戳 ${timestamp}，源大小 ${sourceSize}` },
            reader: 'pyc',
            readerLimitation: '只登记魔数之后的经典四字段，时间戳的时区与源文件路径不在 pyc 头内，本次没有覆盖',
            mitigation: null,
            detail: { timestamp, sourceSize },
          }),
        );
      }
    }
    return { findings, limitations };
  }

  if (bytes.length < 16) {
    limitations.push(limitation('pyc-source-hash-unreadable', '标志位声明 hash_based，但文件不足十六字节，读不到源文件摘要，哈希状态本次没有覆盖'));
    return { findings, limitations };
  }
  const sourceHash = bytes.subarray(8, 16);
  const sourceHashHex = sourceHash.toString('hex');
  findings.push(
    createFinding({
      layer: 'metadata-hygiene',
      severity: 'medium',
      title: 'pyc 源文件摘要（hash_based）',
      category: 'pyc-source-hash',
      evidence: { path, byteRange: [8, 16], excerpt: sourceHashHex },
      reader: 'pyc',
      readerLimitation:
        '清零 source_hash 必须同时清除 check_source 标志，否则标志位与哈希状态不一致；清零后按名核对源文件的机制失效，不等于字节码不可分析',
      mitigation: 'metadata.pyc-source-hash-clear',
      detail: {
        hashBased: true,
        checkSource,
        sourceHash: sourceHashHex,
        flagConsistency: checkSource ? 'check_source 置位，运行期会核对源文件摘要' : 'check_source 未置位，源文件摘要只作记录',
      },
    }),
  );

  return { findings, limitations };
}

export const pycReader = defineReader({
  id: 'pyc',
  formats: ['pyc'],
  layers: ['metadata-hygiene'],
  purpose: 'pyc 魔数、标志位与 source_hash 的事实提取',
  read: readPyc,
});
