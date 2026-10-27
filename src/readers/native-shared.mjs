// ELF 与 Mach-O 共用的原生制品事实识别：Go 构建信息魔数与 Rust 依赖节载荷。
// 两类格式都以内嵌压缩或指针形式携带这些事实，识别逻辑按字节特征共享，与容器格式无关。

import { inflateRawSync, inflateSync } from 'node:zlib';

import { isPrintableAscii, readUvarint } from './common.mjs';

/** Go 构建信息魔数：0xFF 后接 " Go buildinf:"。 */
export const GO_BUILDINFO_MAGIC = Buffer.from([0xff, 0x20, 0x47, 0x6f, 0x20, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e, 0x66, 0x3a], 'latin1');

/** Go 构建信息魔数字节数。 */
export const GO_BUILDINFO_MAGIC_LENGTH = GO_BUILDINFO_MAGIC.length;

/**
 * 识别 Go 构建信息编码并取出可见内容。
 * inline 编码在魔数后直接跟“变长长度加版本串、变长长度加模块信息”；
 * pointer 编码在魔数后跟指向这两个串的变长指针。无法确认编码时如实报告未解析。
 * @param {Buffer} bytes 制品字节
 * @param {number} magicOffset 魔数起始偏移
 * @returns {{encoding: 'inline' | 'pointer' | 'unresolved', version?: string, moduleInfo?: boolean, detail: Record<string, unknown>}}
 */
export function inspectGoBuildinfo(bytes, magicOffset) {
  const after = magicOffset + GO_BUILDINFO_MAGIC_LENGTH;
  const inline = readUvarint(bytes, after);
  if (inline !== undefined && inline.value >= 1 && inline.value <= 64) {
    const start = inline.next;
    const end = start + inline.value;
    if (end <= bytes.length && isPrintableAscii(bytes.subarray(start, end)) && /^go\d/.test(bytes.subarray(start, end).toString('latin1'))) {
      const moduleInfo = readUvarint(bytes, end);
      return {
        encoding: 'inline',
        version: bytes.subarray(start, end).toString('latin1'),
        moduleInfo: moduleInfo !== undefined && moduleInfo.value <= 8 * 1024 * 1024,
        detail: { magicOffset, versionOffset: start, versionLength: inline.value },
      };
    }
  }
  const pointer = readUvarint(bytes, after);
  if (pointer !== undefined && pointer.value > 0 && pointer.value < bytes.length) {
    const target = readUvarint(bytes, pointer.value);
    if (target !== undefined && target.value >= 1 && target.value <= 64) {
      const start = target.next;
      const end = start + target.value;
      if (end <= bytes.length && isPrintableAscii(bytes.subarray(start, end)) && /^go\d/.test(bytes.subarray(start, end).toString('latin1'))) {
        return {
          encoding: 'pointer',
          version: bytes.subarray(start, end).toString('latin1'),
          moduleInfo: false,
          detail: { magicOffset, versionPointer: pointer.value, versionLength: target.value },
        };
      }
    }
  }
  return { encoding: 'unresolved', detail: { magicOffset } };
}

/**
 * 把版本串与模块信息标记补进 detail，供报告直接引用。
 * @param {ReturnType<typeof inspectGoBuildinfo>} info 识别结果
 * @returns {Record<string, unknown>}
 */
export function goBuildinfoDetail(info) {
  return {
    ...info.detail,
    encoding: info.encoding,
    version: info.version ?? null,
    moduleInfoPresent: info.moduleInfo ?? false,
  };
}

/**
 * 尝试解压 Rust 依赖节 .dep-v0 的载荷。
 * 先用 zlib 封装格式，失败再用裸 deflate；两种都不成时如实报告未解出。
 * @param {Buffer} bytes 节内容
 * @returns {{entries: string[], method: string} | {method: 'none', error: string}}
 */
export function inspectDepV0(bytes) {
  for (const [method, inflate] of [
    ['zlib', inflateSync],
    ['deflate-raw', inflateRawSync],
  ]) {
    try {
      const inflated = inflate(bytes);
      const entries = inflated
        .toString('latin1')
        .split(/[^\x20-\x7e]+/)
        .map((entry) => entry.trim())
        .filter((entry) => entry.length > 0);
      if (entries.length > 0) {
        return { entries, method };
      }
    } catch {
      // 换下一种解压方式。
    }
  }
  return { method: 'none', error: 'node:zlib 既不能按 zlib 封装格式、也不能按裸 deflate 解压该节内容' };
}
