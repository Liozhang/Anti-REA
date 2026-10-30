// 九类格式读取器共用的只读基础设施。
// 这里只放与具体格式无关的部分：受预算约束的字节读取、限制说明构造、数字解析与文本净化。
// 全部函数只读取字节，不写目标文件、不执行制品内代码、不发起网络请求。
// 约定：任何解析失败都在读取器内部转成限制说明，不向审计引擎抛异常——
// 畸形输入的正确输出是“解析到哪里、缺什么”，而不是让审计失败，更不是返回空结果冒充没有暴露。

import { open } from 'node:fs/promises';

import { NotImplementedError } from '../errors.mjs';

/** 单次读取的分块大小。 */
const CHUNK_BYTES = 1024 * 1024;

/** 证据摘录的最大字符数。超长内容截断，避免报表被单条发现撑爆。 */
export const EXCERPT_MAX_CHARS = 96;

/**
 * 读取器定义：把九类格式各自的解析函数包装成审计引擎认识的形状。
 * 字段与骨架阶段保持一致：id、formats、layers、purpose、read。
 * read 的入参为 { entry, policy, budgets }，返回 { findings, limitations }。
 * 包在最外层的保护：读取器自身已保证畸形输入不抛错，这里兜底防止意外异常让整个审计失败。
 * @param {{id: string, formats: readonly string[], layers: readonly string[], purpose: string, read: Function}} spec
 * @returns {{id: string, formats: readonly string[], layers: readonly string[], purpose: string, read: Function}}
 */
export function defineReader({ id, formats, layers, purpose, read }) {
  return Object.freeze({
    id,
    formats: Object.freeze([...formats]),
    layers: Object.freeze([...layers]),
    purpose,
    async read(context) {
      try {
        const result = await read(context);
        return {
          findings: Array.isArray(result?.findings) ? result.findings : [],
          limitations: Array.isArray(result?.limitations) ? result.limitations : [],
        };
      } catch (error) {
        // NotImplementedError 继续上抛，让审计引擎登记“该读取器尚未实现”。
        if (error instanceof NotImplementedError) {
          throw error;
        }
        return {
          findings: [],
          limitations: [
            limitation(
              'reader-error',
              `读取器 ${id} 在解析 ${context?.entry?.relativePath ?? '未知条目'} 时遇到意外错误：${String(error?.message ?? error)}。该条目不等于没有暴露，只是本次没有提取到事实`,
              'entry',
              context?.entry?.relativePath,
            ),
          ],
        };
      }
    },
  });
}

/**
 * 构造一条限制说明。限制说明是报告的一等公民：部分结果必须附限制说明。
 * @param {string} code 限制标识
 * @param {string} message 面向用户的说明，说明缺什么、对结论的影响
 * @param {'entry' | 'artifact'} [scope] 作用范围
 * @param {string} [path] 消息里出现的条目路径。消息是自由文本，路径一旦只以文本形态
 *   存在，脱敏就只能按路径形态猜，猜不出无扩展名的产物内相对路径；这里结构化带上，
 *   让脱敏可以精确整条替换。与 scope 无关，任何携带路径的说明都该传。
 * @returns {{code: string, message: string, scope: string, path?: string}}
 */
export function limitation(code, message, scope = 'entry', path = null) {
  const note = { code, message, scope };
  if (typeof path === 'string' && path !== '') {
    note.path = path;
  }
  return note;
}

/**
 * 受预算约束地读取条目字节。
 * 单文件上限取自策略 budgets.maxFileBytes；缺失时按条目实际大小读取。
 * 返回值里的 complete 表示是否覆盖整个文件：false 时调用方必须附限制说明。
 * @param {{absolutePath: string, bytes: number, relativePath: string}} entry 制品条目
 * @param {Record<string, number>} budgets 策略资源预算
 * @returns {Promise<{bytes: Buffer, bytesRead: number, fileSize: number, complete: boolean}>}
 */
export async function readEntryBytes(entry, budgets = {}) {
  const fileSize = Number.isFinite(entry?.bytes) ? entry.bytes : 0;
  const cap = typeof budgets?.maxFileBytes === 'number' && Number.isFinite(budgets.maxFileBytes) ? Math.max(0, Math.floor(budgets.maxFileBytes)) : fileSize;
  const wanted = Math.min(fileSize, cap);
  const handle = await open(entry.absolutePath, 'r');
  try {
    const buffer = Buffer.allocUnsafe(wanted);
    let read = 0;
    while (read < wanted) {
      const result = await handle.read(buffer, read, wanted - read, read);
      if (result.bytesRead === 0) {
        break;
      }
      read += result.bytesRead;
    }
    return { bytes: buffer.subarray(0, read), bytesRead: read, fileSize, complete: read >= fileSize };
  } finally {
    await handle.close();
  }
}

/**
 * 读取未覆盖整个文件时的限制说明。
 * @param {{bytesRead: number, fileSize: number}} read 读取结果
 * @returns {{code: string, message: string, scope: string}}
 */
export function truncationLimitation(read) {
  return limitation(
    'entry-read-truncated',
    `条目只读取了前 ${read.bytesRead} 字节（文件共 ${read.fileSize} 字节），未覆盖部分没有提取事实；结论只对已读区间成立`,
  );
}

/** 大端无符号整数读取。越界返回 undefined，由调用方转成限制说明。 */
export function readUIntBE(buffer, offset, size) {
  if (offset < 0 || offset + size > buffer.length) {
    return undefined;
  }
  let value = 0;
  for (let index = 0; index < size; index += 1) {
    value = value * 256 + buffer[offset + index];
  }
  return value;
}

/** 小端无符号整数读取。越界返回 undefined。 */
export function readUIntLE(buffer, offset, size) {
  if (offset < 0 || offset + size > buffer.length) {
    return undefined;
  }
  let value = 0;
  for (let index = size - 1; index >= 0; index -= 1) {
    value = value * 256 + buffer[offset + index];
  }
  return value;
}

/**
 * 读取无前缀正数的 LEB128 变长整数（Go 构建信息与 GGUF 之外的自定义编码不使用它）。
 * @param {Buffer} buffer
 * @param {number} offset
 * @param {{maxBytes?: number}} [options]
 * @returns {{value: number, next: number} | undefined}
 */
export function readUvarint(buffer, offset, options = {}) {
  const maxBytes = options.maxBytes ?? 10;
  let value = 0;
  let shift = 0;
  let position = offset;
  for (let index = 0; index < maxBytes; index += 1) {
    if (position >= buffer.length) {
      return undefined;
    }
    const byte = buffer[position];
    position += 1;
    value += (byte & 0x7f) * 2 ** shift;
    if ((byte & 0x80) === 0) {
      return { value, next: position };
    }
    shift += 7;
    if (shift > 63) {
      return undefined;
    }
  }
  return undefined;
}

/**
 * 把任意字节净化为可入报告的摘录：非可打印字符替换为点，超长截断。
 * 二进制内容也会得到一句可读的描述，而不是把原始字节塞进报告。
 * @param {Buffer} bytes
 * @param {number} [maxChars]
 * @returns {string}
 */
export function sanitizeExcerpt(bytes, maxChars = EXCERPT_MAX_CHARS) {
  const limit = Math.max(0, maxChars);
  let text = '';
  for (let index = 0; index < bytes.length && text.length < limit; index += 1) {
    const byte = bytes[index];
    text += byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : '.';
  }
  if (bytes.length > text.length) {
    text = `${text.slice(0, limit)}…`;
  }
  return text;
}

/**
 * 读取以空字符结尾的字符串。找不到终止符时返回 undefined。
 * @param {Buffer} bytes
 * @param {number} offset
 * @param {number} [maxChars]
 * @returns {string | undefined}
 */
export function readCString(bytes, offset, maxChars = EXCERPT_MAX_CHARS) {
  if (offset < 0 || offset >= bytes.length) {
    return undefined;
  }
  let end = offset;
  while (end < bytes.length && bytes[end] !== 0) {
    end += 1;
  }
  if (end >= bytes.length) {
    return undefined;
  }
  return sanitizeExcerpt(bytes.subarray(offset, end), maxChars);
}

/**
 * 在字节区间内查找子序列，返回全部命中偏移。
 * @param {Buffer} bytes
 * @param {Buffer} needle
 * @param {{from?: number, to?: number}} [range]
 * @returns {number[]}
 */
export function findAll(bytes, needle, range = {}) {
  const from = Math.max(0, range.from ?? 0);
  const to = Math.min(bytes.length, range.to ?? bytes.length);
  const hits = [];
  if (needle.length === 0) {
    return hits;
  }
  let position = from;
  while (position + needle.length <= to) {
    const found = bytes.indexOf(needle, position);
    if (found < 0 || found + needle.length > to) {
      break;
    }
    hits.push(found);
    position = found + 1;
  }
  return hits;
}

/**
 * 判断字节是否全部落在可打印 ASCII 范围内。用于校验解析出来的字符串像不像文本。
 * @param {Buffer} bytes
 * @returns {boolean}
 */
export function isPrintableAscii(bytes) {
  if (bytes.length === 0) {
    return false;
  }
  for (const byte of bytes) {
    if (byte < 0x20 || byte > 0x7e) {
      return false;
    }
  }
  return true;
}
