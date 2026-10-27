// readers 模块出口：按容器标识分派读取器。
// 读取器只读、零写入风险，是所有后续工具的事实来源。

import { basename } from 'node:path';

import { SUPPORTED_CONTAINERS } from '../container/detect.mjs';
import { CAPABILITY_BOUNDARIES, FORMAT_READERS } from './formats.mjs';

/** 读取器登记表，键为容器标识。 */
export const READER_REGISTRY = Object.freeze(
  Object.freeze(
    FORMAT_READERS.reduce((registry, reader) => {
      for (const format of reader.formats) {
        registry[format] = Object.freeze([...(registry[format] ?? []), reader]);
      }
      return registry;
    }, {}),
  ),
);

/**
 * 取某容器标识对应的读取器列表。
 * @param {string} containerType 容器标识
 * @returns {readonly typeof FORMAT_READERS[number][]}
 */
export function readersForContainer(containerType) {
  return READER_REGISTRY[containerType] ?? Object.freeze([]);
}

/**
 * 判断某容器是否有可用读取器。
 * @param {string} containerType 容器标识
 * @returns {boolean}
 */
export function hasReader(containerType) {
  return readersForContainer(containerType).length > 0;
}

/**
 * 按标识取能力边界说明。
 * @param {string} boundaryId 边界标识
 * @returns {{id: string, label: string, reason: string, hint: string} | null}
 */
export function boundaryById(boundaryId) {
  return CAPABILITY_BOUNDARIES.find((boundary) => boundary.id === boundaryId) ?? null;
}

/**
 * 取范围外格式的能力边界说明。
 * 先按文件名约定归类（IL2CPP 全局元数据的固定文件名、Android 包的固定扩展名），
 * 其余范围外容器走通用说明。文件名只是约定，内容级判定需后续版本的专用识别，
 * 因此每条边界都带 reason 与 hint，不冒充“已解析”。
 * @param {{container: {type: string}, relativePath: string}} entry 制品条目
 * @returns {{id: string, label: string, reason: string, hint: string}}
 */
export function capabilityBoundaryFor(entry) {
  if (SUPPORTED_CONTAINERS.includes(entry.container.type)) {
    return null;
  }
  const name = basename(entry.relativePath ?? '').toLowerCase();
  for (const boundary of CAPABILITY_BOUNDARIES) {
    for (const fileName of boundary.fileNames ?? []) {
      if (name === fileName) {
        return { id: boundary.id, label: boundary.label, reason: boundary.reason, hint: boundary.hint };
      }
    }
    for (const extension of boundary.fileExtensions ?? []) {
      if (name.endsWith(extension)) {
        return { id: boundary.id, label: boundary.label, reason: boundary.reason, hint: boundary.hint };
      }
    }
  }
  return {
    id: 'generic-script-package',
    label: '范围外容器',
    reason: `制品条目不落入 v1 格式集（${SUPPORTED_CONTAINERS.join('、')}）中的任何一类，识别结果为 ${entry.container.type}`,
    hint: '把制品打成受支持的容器格式后再审计；文本类与专用格式暴露面需后续版本的读取器',
  };
}

export { CAPABILITY_BOUNDARIES, FORMAT_READERS };
