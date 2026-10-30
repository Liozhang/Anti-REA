// v1 九类格式的读取器登记。
// 读取器只读：只检查字节，不加载、不执行制品内代码。
// 每条发现都带证据、会消费它的读取器、读取器自身声明的限制，以及建议的缓解措施编号；
// 畸形输入与部分读取都转成限制说明，而不是让审计失败，更不是返回空结果冒充“没有暴露”。

import { beamReader } from './beam.mjs';
import { dexReader } from './dex.mjs';
import { elfReader } from './elf.mjs';
import { ggufReader } from './gguf.mjs';
import { machoReader } from './macho.mjs';
import { peReader } from './pe.mjs';
import { pycReader } from './pyc.mjs';
import { safetensorsReader } from './safetensors.mjs';
import { zipReader } from './zip.mjs';

/** v1 九类格式读取器。 */
export const FORMAT_READERS = Object.freeze([elfReader, peReader, machoReader, zipReader, ggufReader, safetensorsReader, pycReader, beamReader, dexReader]);

/**
 * 范围外格式的能力边界表。
 * 传入这些格式时，审计输出 unsupported 与边界说明，而不是空结果。
 * 字段：
 *   fileNames        按约定归类的文件名，小写比对，内容级判定留给后续版本
 *   fileExtensions   按约定归类的扩展名，小写比对
 *   reason           为什么超出 v1 范围
 *   hint             用户可行的下一步
 */
export const CAPABILITY_BOUNDARIES = Object.freeze([
  {
    id: 'il2cpp-metadata',
    label: 'IL2CPP 全局元数据',
    fileNames: Object.freeze(['global-metadata.dat']),
    reason: 'v1 读取器集不含 IL2CPP 元数据解析，运行期必需数据也不在可改写范围内',
    hint: '类型名与方法名的恢复需要专门的 IL2CPP 读取器，属后续版本范围',
  },
  {
    id: 'apk-signature-scheme',
    label: 'APK 签名方案',
    fileExtensions: Object.freeze(['.apk', '.aab']),
    reason: 'v1 的签名观察器覆盖 ZIP 条目 CRC32、PE 安全目录与 CheckSum、Mach-O LC_CODE_SIGNATURE 与 ELF note，不含 APK v2 及以上签名块',
    hint: 'APK 签名块验证需要独立的签名方案解析，属后续版本范围',
  },
  {
    id: 'gpu-container',
    label: 'GPU 容器',
    reason: 'PTX、CUDA 信息、AMD 目标与 clang offload 捆绑等 GPU 载荷容器不在 v1 范围内',
    hint: 'GPU 载荷需要对应厂商容器解析，属后续版本范围',
  },
  {
    id: 'generic-script-package',
    label: '通用脚本包',
    reason: 'v1 按容器魔数判定，纯文本、配置与通用脚本包不落入九类格式中的任何一类',
    hint: '把制品打成受支持的容器格式后再审计；文本类暴露面需专用读取器',
  },
  {
    id: 'managed-metadata',
    label: '.NET 托管元数据',
    reason: 'PE 读取器覆盖可选头、节表、调试目录、安全目录与导入导出表，.NET 元数据堆与中间语言指令解析不在 v1 范围内',
    hint: '程序集事实与成员清单需要托管元数据读取器，属后续版本范围',
  },
  {
    id: 'javascript-bundle',
    label: 'JavaScript 源码地图与模块图',
    reason: 'v1 不含 JavaScript 读取器，源码地图与模块图恢复不在范围内',
    hint: 'JavaScript 暴露面需要专用读取器，属后续版本范围',
  },
]);
