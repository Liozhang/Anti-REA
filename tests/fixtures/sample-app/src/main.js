// 示例应用入口。只做命令行问候，不读取网络、不加载原生模块。

import { APP_VERSION } from './version.js';

/**
 * 生成问候语。
 * @param {string} name 用户名
 * @returns {string} 问候语
 */
export function greet(name) {
  const who = typeof name === 'string' && name.trim() !== '' ? name.trim() : 'world';
  return `hello, ${who}`;
}

/**
 * 返回应用版本。
 * @returns {string} 版本号
 */
export function version() {
  return APP_VERSION;
}

if (process.argv[1] !== undefined && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/'))) {
  process.stdout.write(`${greet(process.argv[2])}\n`);
}
