// 令牌模式扫描：秘密不下客户端的只读事实来源。
// 只做前缀锚定的已知令牌格式匹配与保守的凭据赋值匹配，不做熵值启发式——
// 压缩与加密在熵上不可区分，熵扫描无法区分“高熵数据”和“凭据”，误报会淹没真实发现。
// 每条命中都给出偏移与摘录，改写与否由 harden 按策略决定，审计默认只报告。

import { createFinding } from '../audit/finding.mjs';
import { EXCERPT_MAX_CHARS, limitation, sanitizeExcerpt } from './common.mjs';

/**
 * 单次令牌扫描的最大字节数。
 * 与默认单文件预算（64 MiB）一致：读取本身已受策略预算约束，这里只兜底防止无预算调用时扫过大文件。
 * 超出窗口的部分不扫，并在限制说明里写明覆盖缺口。
 */
export const TOKEN_SCAN_WINDOW_BYTES = 64 * 1024 * 1024;

/**
 * 令牌模式表。每条模式：
 *   id        模式标识，进报告的 category
 *   label     人读名称
 *   pattern   正则；一律前缀锚定，并要求令牌两侧不是同类字符
 *   severity  命中后的严重度
 * 前缀锚定的取舍：只覆盖有公开格式的凭据家族，任意自创令牌不在覆盖内，
 * 覆盖缺口由每条发现的限制说明显式声明，不用宽松模式把误报塞进报告。
 * 两侧定界的理由：二进制里常出现“前缀加一串相邻字符”的偶然字节串
 * （实测某 Go 二进制的字符串表里 gho_ 后面恰好跟着 36 个字母数字字符），
 * 真实令牌两侧是引号、空白或空字符一类的非令牌字符，因此用前后断言把这类偶然串排除。
 */
export const TOKEN_PATTERNS = Object.freeze([
  { id: 'aws-access-key-id', label: 'AWS 访问键标识', pattern: /(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])/g, severity: 'high' },
  { id: 'aws-secret-access-key', label: 'AWS 秘密访问键', pattern: /(?<![A-Za-z0-9_-])aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/gi, severity: 'high' },
  { id: 'github-token', label: 'GitHub 个人访问令牌', pattern: /(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{36}(?![A-Za-z0-9])/g, severity: 'high' },
  { id: 'github-fine-grained-token', label: 'GitHub 细粒度令牌', pattern: /(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{82}(?![A-Za-z0-9_])/g, severity: 'high' },
  { id: 'slack-token', label: 'Slack 令牌', pattern: /(?<![A-Za-z0-9-])xox[baprse]-[A-Za-z0-9-]{10,}(?![A-Za-z0-9-])/g, severity: 'high' },
  { id: 'google-api-key', label: 'Google API 密钥', pattern: /(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])/g, severity: 'high' },
  { id: 'stripe-secret-key', label: 'Stripe 秘密密钥', pattern: /(?<![A-Za-z0-9_])sk_live_[0-9a-zA-Z]{24}(?![A-Za-z0-9])/g, severity: 'high' },
  { id: 'npm-token', label: 'npm 访问令牌', pattern: /(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])/g, severity: 'high' },
  { id: 'pypi-token', label: 'PyPI 访问令牌', pattern: /(?<![A-Za-z0-9_-])pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}(?![A-Za-z0-9_-])/g, severity: 'high' },
  { id: 'json-web-token', label: 'JSON Web 令牌', pattern: /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])/g, severity: 'medium' },
  { id: 'private-key-block', label: '私钥块', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, severity: 'high' },
  { id: 'slack-webhook', label: 'Slack Webhook 地址', pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]+(?![A-Za-z0-9_])/g, severity: 'medium' },
  {
    id: 'credential-assignment',
    label: '凭据赋值',
    pattern: /(?<![A-Za-z0-9_-])(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|client[_-]?secret)\s*[:=]\s*["']?[A-Za-z0-9/_+\-.]{12,}(?![A-Za-z0-9/_+\-.])/gi,
    severity: 'medium',
  },
]);

/**
 * 扫描字节区间内的疑似凭据。
 * @param {Buffer} bytes 待扫描字节
 * @param {{maxBytes?: number, label?: string}} [options] label 用于说明这段字节的来源，例如条目名
 * @returns {{hits: Array<{id: string, label: string, offset: number, excerpt: string, severity: string}>, scannedBytes: number, complete: boolean}}
 */
export function scanTokens(bytes, options = {}) {
  const window = Math.min(bytes.length, options.maxBytes ?? TOKEN_SCAN_WINDOW_BYTES);
  const text = bytes.toString('latin1', 0, window);
  const hits = [];
  const seen = new Set();
  for (const pattern of TOKEN_PATTERNS) {
    pattern.pattern.lastIndex = 0;
    let match = pattern.pattern.exec(text);
    while (match !== null) {
      const offset = match.index;
      const key = `${pattern.id}:${offset}`;
      if (!seen.has(key)) {
        seen.add(key);
        hits.push({
          id: pattern.id,
          label: pattern.label,
          offset,
          excerpt: sanitizeExcerpt(bytes.subarray(offset, offset + match[0].length), EXCERPT_MAX_CHARS),
          severity: pattern.severity,
        });
      }
      if (pattern.pattern.lastIndex === match.index) {
        pattern.pattern.lastIndex = match.index + 1;
      }
      match = pattern.pattern.exec(text);
    }
  }
  hits.sort((left, right) => left.offset - right.offset || left.id.localeCompare(right.id));
  return { hits, scannedBytes: window, complete: window >= bytes.length };
}

/**
 * 把令牌命中转成发现。字节来源可以是原始字节，也可以是解压后的条目内容。
 * @param {{hits: Array<{id: string, label: string, offset: number, excerpt: string, severity: string}>}} scan 扫描结果
 * @param {{path: string, reader: string, baseOffset?: number, source?: string}} context
 * @returns {Array<Record<string, unknown>>}
 */
export function tokenFindings(scan, context) {
  const baseOffset = context.baseOffset ?? 0;
  return scan.hits.map((hit) =>
    createFinding({
      layer: 'secret-minimization',
      severity: hit.severity,
      title: `疑似凭据：${hit.label}`,
      category: `token-${hit.id}`,
      evidence: {
        path: context.path,
        byteRange: [baseOffset + hit.offset, baseOffset + hit.offset + hit.excerpt.length],
        excerpt: hit.excerpt,
      },
      reader: context.reader,
      readerLimitation:
        '令牌模式只覆盖有公开格式的凭据家族，任意自创令牌不在覆盖内；检索为空不证明制品里没有秘密，改写与否需用户逐条确认',
      mitigation: 'secret.token-placeholder-overwrite',
      detail: {
        patternId: hit.id,
        byteSource: context.source ?? 'raw-bytes',
        fileOffset: baseOffset + hit.offset,
      },
    }),
  );
}

/**
 * 把令牌扫描结果并进读取器的输出。格式已确认之后调用一次：
 * 扫描全部已读字节，命中转成发现，扫描窗口未覆盖整文件时附限制说明。
 * 四个不解析原生二进制的读取器（pyc、gguf、safetensors、beam）与 elf、macho、pe、zip
 * 共用这一入口，保证同一批字节在哪个格式下都过同一张模式表。
 * @param {Buffer} bytes 已读字节
 * @param {Array<Record<string, unknown>>} findings 读取器的发现数组，就地追加
 * @param {Array<Record<string, unknown>>} limitations 读取器的限制说明数组，就地追加
 * @param {{path: string, reader: string}} context
 * @returns {void}
 */
export function appendTokenScan(bytes, findings, limitations, context) {
  const scan = scanTokens(bytes);
  findings.push(...tokenFindings(scan, { path: context.path, reader: context.reader, source: 'raw-bytes' }));
  const scanLimitation = tokenScanLimitation(scan, '制品字节');
  if (scanLimitation !== null) {
    limitations.push(scanLimitation);
  }
}

/**
 * 令牌扫描的覆盖缺口限制说明。
 * @param {{scannedBytes: number, complete: boolean}} scan 扫描结果
 * @param {string} source 字节来源说明
 * @returns {ReturnType<typeof limitation> | null}
 */
export function tokenScanLimitation(scan, source) {
  if (scan.complete) {
    return null;
  }
  return limitation(
    'token-scan-window-limited',
    `令牌扫描窗口为 ${TOKEN_SCAN_WINDOW_BYTES} 字节，${source} 超出窗口的部分只按窗口内结果报告，未覆盖部分没有提取事实`,
  );
}
