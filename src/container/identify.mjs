// 制品身份识别：把命令行给出的路径解析成可审计的条目清单。
// 目录目标按相对路径排序后枚举，单文件目标只有一个条目。
// 所有读取都受策略资源预算约束：超限时跳过并记录限制说明，不让进程失败或超时。
// 单个目录条目读取失败时跳过并登记到 skipped，用户显式给出的单文件目标不可读时按用法错误处理。

import { createHash } from 'node:crypto';
import { open, readdir, stat } from 'node:fs/promises';
import { relative, resolve, sep } from 'node:path';

import { UsageError } from '../errors.mjs';
import { budgetsOf } from '../policy/schema.mjs';
import { DETECTION_PREFIX_BYTES, detectContainer, detectionProbeLength } from './detect.mjs';

/** 流式摘要时的分块大小。 */
const HASH_CHUNK_BYTES = 1024 * 1024;

/**
 * 从文件开头读取若干字节，返回实际读到的内容。
 * @param {import('node:fs/promises').FileHandle} handle 已打开的文件句柄
 * @param {number} length 期望读取的字节数
 * @returns {Promise<Buffer>}
 */
async function readPrefix(handle, length) {
  if (length <= 0) {
    return Buffer.alloc(0);
  }
  const buffer = Buffer.alloc(length);
  const { bytesRead } = await handle.read(buffer, 0, length, 0);
  return buffer.subarray(0, bytesRead);
}

/**
 * 读取文件头若干字节并计算整文件摘要。
 * 文件头读取量受单文件预算约束；摘要流式读取，受累计扫描窗口约束。
 * 结构魔数（PE 签名位置、safetensors 头部长度）的关键字节可能落在标准窗口之外，
 * 此时在预算内补读，补读仍不完整时把 detectionLimited 置真。
 * @param {string} absolutePath 绝对路径
 * @param {{maxFileBytes: number, remainingScanBytes: number}} budget
 * @param {(path: string, flags: string) => Promise<import('node:fs/promises').FileHandle>} openFile 打开文件，可注入便于测试
 * @returns {Promise<{prefix: Buffer, sha256: string | null, bytes: number, detectionLimited: boolean, digestTruncated: boolean, consumedScanBytes: number}>}
 */
async function inspectFile(absolutePath, budget, openFile) {
  const handle = await openFile(absolutePath, 'r');
  try {
    const info = await handle.stat();
    const fileBudget = Math.max(budget.maxFileBytes, 0);
    const standardWindow = Math.min(DETECTION_PREFIX_BYTES, info.size);

    let prefix = await readPrefix(handle, Math.min(standardWindow, fileBudget));
    let detectionLimited = prefix.length < standardWindow;

    const probeLength = detectionProbeLength(prefix, info.size);
    if (probeLength > prefix.length) {
      const extended = Math.min(probeLength, fileBudget);
      if (extended > prefix.length) {
        prefix = await readPrefix(handle, extended);
      }
    }
    if (probeLength > prefix.length && probeLength <= info.size) {
      // 判定所需字节超出单文件预算，容器判定可能不完整。
      detectionLimited = true;
    }

    const hash = createHash('sha256');
    const chunk = Buffer.alloc(HASH_CHUNK_BYTES);
    let position = 0;
    let consumed = 0;
    let digestTruncated = false;
    while (position < info.size) {
      const remaining = budget.remainingScanBytes - consumed;
      if (remaining <= 0) {
        digestTruncated = true;
        break;
      }
      const wanted = Math.min(HASH_CHUNK_BYTES, info.size - position, remaining);
      const result = await handle.read(chunk, 0, wanted, position);
      if (result.bytesRead === 0) {
        break;
      }
      hash.update(chunk.subarray(0, result.bytesRead));
      position += result.bytesRead;
      consumed += result.bytesRead;
    }

    return {
      prefix,
      sha256: digestTruncated ? null : hash.digest('hex'),
      bytes: info.size,
      detectionLimited,
      digestTruncated,
      consumedScanBytes: consumed,
    };
  } finally {
    await handle.close();
  }
}

/**
 * 递归枚举目录下的普通文件，按绝对路径排序。
 * 符号链接不计入普通文件，既避免目录环，也不把链接目标当成制品内容。
 * @param {string} root 目录绝对路径
 * @param {number} maxFiles 文件数上限
 * @returns {Promise<{files: string[], truncated: boolean}>}
 */
async function listFiles(root, maxFiles) {
  const files = [];
  let truncated = false;
  const queue = [root];
  while (queue.length > 0 && !truncated) {
    const current = queue.shift();
    const dirents = await readdir(current, { withFileTypes: true });
    for (const dirent of dirents) {
      const absolute = resolve(current, dirent.name);
      if (dirent.isDirectory()) {
        queue.push(absolute);
        continue;
      }
      if (!dirent.isFile()) {
        continue;
      }
      if (files.length >= maxFiles) {
        truncated = true;
        break;
      }
      files.push(absolute);
    }
  }
  files.sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
  return { files, truncated };
}

/**
 * 把读取失败折算成可登记的原因，绝对路径换成相对路径，避免把完整路径带进记录。
 * @param {unknown} error 捕获到的异常
 * @param {string} absolutePath 条目绝对路径
 * @param {string} relativePath 条目相对路径
 * @returns {string}
 */
function describeReadFailure(error, absolutePath, relativePath) {
  const code = (error !== null && typeof error === 'object' && 'code' in error ? String(error.code) : null) ?? 'Error';
  const message = error instanceof Error ? error.message : String(error);
  return `${code}: ${message.split(absolutePath).join(relativePath)}`;
}

/**
 * 计算制品摘要。两种语义按目标类型分开，区别写在下面：
 *   单文件   直接返回文件自身字节的 sha256，与条目摘要同值。收件方对同一个文件重算
 *            sha256 就能核对报告里的制品摘要，不需要知道任何再摘要的拼接口径。
 *   目录     目录没有“自身字节”可摘要，只能按排序后的条目清单再摘要：每条拼
 *            相对路径\0条目摘要\0字节数\n，同一目录两次识别因此得到同一摘要。
 * 条目摘要为 null（累计扫描窗口耗尽导致摘要截断）时，两种语义都退化为拼空串的再摘要：
 * 都不冒充覆盖了完整字节，也都仍然给出确定的摘要串，让部分结果能被识别与比对。
 * @param {string} kind 目标类型
 * @param {Array<{relativePath: string, sha256: string | null, bytes: number}>} entries 条目
 * @returns {string}
 */
function digestOf(kind, entries) {
  if (kind === 'file') {
    const entry = entries[0];
    if (entry.sha256 !== null) {
      return entry.sha256;
    }
    // 摘要截断：给不出文件自身字节的摘要，按字节数派生一个确定值兜底。
    return createHash('sha256').update(`${entry.sha256 ?? ''}\0${entry.bytes}`, 'utf8').digest('hex');
  }
  const hash = createHash('sha256');
  for (const entry of [...entries].sort((left, right) => (left.relativePath < right.relativePath ? -1 : 1))) {
    hash.update(entry.relativePath, 'utf8');
    hash.update('\0', 'utf8');
    hash.update(entry.sha256 ?? '', 'utf8');
    hash.update('\0', 'utf8');
    hash.update(String(entry.bytes), 'utf8');
    hash.update('\n', 'utf8');
  }
  return hash.digest('hex');
}

/**
 * 识别制品：解析路径、枚举条目、逐条目判定容器。
 * @param {string} target 命令行给出的目录或文件路径
 * @param {Record<string, unknown>} policy 策略，用于取资源预算
 * @param {{open?: Function, stat?: Function}} [io] 文件系统注入，便于测试失败路径
 * @returns {Promise<{
 *   kind: 'file' | 'directory',
 *   path: string,
 *   absolutePath: string,
 *   entries: Array<{absolutePath: string, relativePath: string, bytes: number, sha256: string | null, container: ReturnType<typeof detectContainer>, detectionLimited: boolean, digestTruncated: boolean}>,
 *   skipped: Array<{relativePath: string, reason: string}>,
 *   truncated: boolean,
 *   sha256: string,
 *   bytes: number
 * }>}
 */
export async function identifyArtifact(target, policy, io = {}) {
  const openFile = io.open ?? open;
  const statPath = io.stat ?? stat;
  if (typeof target !== 'string' || target.trim() === '') {
    throw new UsageError('缺少目标路径：请给出要审计的目录或文件');
  }
  const budgets = budgetsOf(policy);
  const absolutePath = resolve(target);
  const info = await statPath(absolutePath).catch(() => null);
  if (info === null) {
    throw new UsageError(`目标不存在或不可访问：${target}`);
  }
  const kind = info.isDirectory() ? 'directory' : info.isFile() ? 'file' : 'other';
  if (kind === 'other') {
    throw new UsageError(`目标既不是普通文件也不是目录：${target}`);
  }

  const listed = kind === 'file' ? { files: [absolutePath], truncated: false } : await listFiles(absolutePath, budgets.maxFiles);
  const entries = [];
  const skipped = [];
  let remainingScanBytes = budgets.maxTotalScanBytes;
  for (const path of listed.files) {
    const relativePath = kind === 'file' ? path.split(sep).pop() : relative(absolutePath, path).split(sep).join('/');
    let inspected;
    try {
      inspected = await inspectFile(path, { maxFileBytes: budgets.maxFileBytes, remainingScanBytes }, openFile);
    } catch (error) {
      if (kind === 'file') {
        // 用户显式给出的单个目标不可读，属输入错误。
        throw new UsageError(`无法读取目标文件：${target}`, { cause: String(error) });
      }
      // 目录中的单个条目不可读：跳过并登记，其余条目照常审计。
      skipped.push({ relativePath, reason: describeReadFailure(error, path, relativePath) });
      continue;
    }
    remainingScanBytes -= inspected.consumedScanBytes;
    entries.push({
      absolutePath: path,
      relativePath,
      bytes: inspected.bytes,
      sha256: inspected.sha256,
      container: detectContainer(inspected.prefix, inspected.bytes),
      detectionLimited: inspected.detectionLimited,
      digestTruncated: inspected.digestTruncated,
    });
  }

  return {
    kind,
    path: target,
    absolutePath,
    entries,
    skipped,
    truncated: listed.truncated,
    sha256: digestOf(kind, entries),
    bytes: entries.reduce((total, entry) => total + entry.bytes, 0),
  };
}
