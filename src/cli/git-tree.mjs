// git 工作树判定。
// 审计报告是制品暴露面地图，提交进版本库等于把地图递给每个读仓库的人。
// 因此任何把结果写出文件的命令，只要目标路径位于 git 工作树内，就向标准错误输出警告。

import { stat } from 'node:fs/promises';
import { dirname, parse, resolve } from 'node:path';

/**
 * 从给定路径向上逐级查找 .git，判断路径是否位于 git 工作树内。
 * .git 既可以是目录（普通仓库），也可以是文件（工作树或子模块）。
 * @param {string} target 任意路径，可以是文件或目录
 * @returns {Promise<boolean>}
 */
export async function isInsideGitWorkTree(target) {
  let current = resolve(target);
  while (true) {
    const marker = resolve(current, '.git');
    const info = await stat(marker).catch(() => null);
    if (info !== null && (info.isDirectory() || info.isFile())) {
      return true;
    }
    const parent = dirname(current);
    if (parent === current) {
      return false;
    }
    current = parent;
  }
}

/**
 * 生成写入 git 工作树的警告文本。
 * @param {string} outputPath 目标输出路径
 * @returns {string}
 */
export function gitTreeWarning(outputPath) {
  return `警告：输出路径 ${outputPath} 位于 git 工作树内。审计报告是制品暴露面地图，提交进版本库会把这份地图递给每一个读仓库的人；如需分享，请改用 --redacted 脱敏报告。`;
}

/**
 * 取路径的根，用于在遍历到文件系统根时停止。
 * @param {string} path
 * @returns {string}
 */
export function rootOf(path) {
  return parse(resolve(path)).root;
}
