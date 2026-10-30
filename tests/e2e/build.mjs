// 端到端模拟小项目的确定性生成脚本。
// 用途：产出一个“看起来像要发布的小应用”的目录，供 tests/e2e/sample-project.test.mjs
// 在真实字节上跑通 audit、harden、verify、notice 四条工作流与 MCP 四个工具的调用。
//
// 三条约定贯穿本文件：
//   1. 确定性。全部字节由固定串或固定种子的线性同余序列生成，不含随机源、时间戳、
//      环境相关取值；同一份代码在任何机器、任何时刻运行都得到同一串字节。
//   2. 不提交字节。产物只写进调用方给出的目录（测试里是系统临时目录），
//      仓库里不留任何生成结果；需要核对时按 sha256 逐项比对。
//   3. 复用既有构造器。九类格式的字节一律取自 tests/transforms/fixture-bytes.mjs
//      的确定性构造器，与单元测试跑的是同一套实现；只有仓库里还没有的格式
//      （Java 类文件）才在本文件按同样风格新写，并说明它覆盖哪条路径。
//
// 目录整体作为目录目标；其中 bin/app-linux 等单个文件作为文件目标，
// 两类目标在测试里各跑一遍完整工作流。

import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { computePeChecksum } from '../../src/signatures/pe-checksum.mjs';
import {
  buildElfGoInline,
  buildGguf,
  buildMachOWithGoAndDep,
  buildPeWithDebugDirectory,
  buildPyc,
  buildSafetensors,
  buildZip,
} from '../transforms/fixture-bytes.mjs';

/** 伪随机字节的线性同余种子。固定值，保证可复现。 */
const LCG_SEED = 20261027;

/**
 * 生成确定性字节序列：固定图案开头，其余由线性同余序列填充。
 * 只用于“内容不重要、但必须是固定字节”的占位数据（例如 ZIP 里的二进制条目）。
 * @param {number} length 字节数
 * @returns {Buffer}
 */
function patternBytes(length) {
  const out = Buffer.alloc(length);
  out.set([0x5a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77], 0);
  let state = LCG_SEED;
  for (let index = 8; index < length; index += 1) {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    out[index] = state & 0xff;
  }
  return out;
}

/**
 * 修正 ELF 入口地址，使其落在唯一的 PT_LOAD 段内。
 * fixture-bytes 的 buildElf 把 e_entry 写成 0x401000，而唯一段从 0x400000 起、
 * 长度只有几百字节，入口落在段外；复审的 elf.segment-load 因此判“没有覆盖入口地址的
 * PT_LOAD 段”。模拟项目要的是结构健全的制品，这里把入口改到段内：段从文件偏移 0 开始，
 * 文件偏移 0x40 对应虚拟地址 0x400040，落在段内。
 * @param {Buffer} buffer buildElf 产出的缓冲区
 * @returns {Buffer} 同一缓冲区
 */
function fixElfEntryPoint(buffer) {
  buffer.writeBigUInt64LE(0x400040n, 24); // e_entry
  return buffer;
}

/**
 * 构造带调试目录且 CheckSum 非零的 PE。
 * 调试目录取自 fixture-bytes 的 buildPeWithDebugDirectory；CheckSum 按
 * src/signatures/pe-checksum.mjs 的同一套算法回填，字段位置从文件自身的
 * e_lfanew 推导，不写死偏移，保证与复审时的重算口径一致。
 * 入口 RVA 一并回填成 .text 节的虚拟地址：fixture-bytes 的 buildPe 不写
 * AddressOfEntryPoint，留零会让复审的 pe.entry-point 判“入口不落在任何已映射节内”。
 * @returns {Buffer}
 */
function buildPeWithDebugAndChecksum() {
  const built = buildPeWithDebugDirectory();
  const buffer = built.buffer;
  const peOffset = buffer.readUInt32LE(0x3c);
  const optionalOffset = peOffset + 4 + 20;
  buffer.writeUInt32LE(0x1000, optionalOffset + 16); // AddressOfEntryPoint 指向首个节
  const checksumFieldOffset = optionalOffset + 64;
  buffer.writeUInt32LE(computePeChecksum(buffer, checksumFieldOffset), checksumFieldOffset);
  return buffer;
}

/**
 * 构造最小但结构完整的 Java 类文件：CAFEBABE 魔数、常量池、访问标志、
 * this/super、接口表、字段表、方法表与类属性表齐全。
 * 仓库里没有 Java 类文件的构造器，这里按 fixture-bytes 的风格新写一份；
 * 它覆盖的路径是“CAFEBABE 与 Mach-O 胖二进制魔数歧义”：魔数后四字节是
 * Java 8 主版本号 52，不落在一到三十二的分片数区间，首个分片头也不符合
 * 胖二进制结构，容器识别据此判为范围外容器并附歧义说明，不送进 Mach-O 读取器。
 * @returns {Buffer}
 */
function buildJavaClass() {
  const constantPool = [];
  const utf8 = (text) => {
    constantPool.push(Buffer.concat([Buffer.from([0x01]), u16(Buffer.byteLength(text)), Buffer.from(text, 'latin1')]));
    return constantPool.length; // 常量池下标从 1 起，length 即本条的下标
  };
  const classRef = (nameIndex) => {
    constantPool.push(Buffer.concat([Buffer.from([0x07]), u16(nameIndex)]));
    return constantPool.length;
  };

  const appName = utf8('com/example/App');
  const thisClass = classRef(appName);
  const objectName = utf8('java/lang/Object');
  const superClass = classRef(objectName);
  const methodName = utf8('main');
  const methodDescriptor = utf8('([Ljava/lang/String;)V');

  const header = Buffer.concat([
    Buffer.from([0xca, 0xfe, 0xba, 0xbe]),
    u16(0), // minor_version
    u16(52), // major_version：Java 8
    u16(constantPool.length + 1), // constant_pool_count 含未使用的 0 号下标
  ]);
  const body = Buffer.concat([
    u16(0x0021), // access_flags：public super
    u16(thisClass),
    u16(superClass),
    u16(0), // interfaces_count
    u16(0), // fields_count
    u16(1), // methods_count
    u16(0x0009), // public static
    u16(methodName),
    u16(methodDescriptor),
    u16(0), // 方法属性数
    u16(0), // 类属性数
  ]);
  return Buffer.concat([header, ...constantPool, body]);
}

/**
 * 大端写入无符号十六位整数。
 * @param {number} value
 * @returns {Buffer}
 */
function u16(value) {
  const out = Buffer.alloc(2);
  out.writeUInt16BE(value, 0);
  return out;
}

/**
 * 构造带 __metadata__ 槽位的 safetensors。
 * fixture-bytes 的 buildSafetensors 只按张量表构造头部，这里在同一套布局上
 * 补一个 __metadata__ 槽位：重写长度前缀与头部 JSON，张量数据区原样接在后面，
 * data_offsets 是相对数据区起点的偏移，不随头部长度变化，因此制品仍然自洽。
 * @returns {Buffer}
 */
function buildSafetensorsWithMetadata() {
  const plain = buildSafetensors([{ name: 'weight', dtype: 'F32', shape: [4], data: patternBytes(16) }]);
  const headerLength = Number(plain.readBigUInt64LE(0));
  const header = JSON.parse(plain.toString('utf8', 8, 8 + headerLength));
  header.__metadata__ = { format: 'pt', producer: 'anti-rea-e2e' };
  const headerBytes = Buffer.from(JSON.stringify(header), 'utf8');
  const prefix = Buffer.alloc(8);
  prefix.writeBigUInt64LE(BigInt(headerBytes.length));
  return Buffer.concat([prefix, headerBytes, plain.subarray(8 + headerLength)]);
}

/** 许可文本：与 notice 生成的声明配套，内容是真实条款，普通文本条目。 */
const LICENSE_TEXT = `MIT License

Copyright (c) 2026 示例主体

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
`;

/** 说明文档：普通 Markdown 条目，同时是审计时最容易被忽略的一类文件。 */
const README_TEXT = `# 示例应用

一个用于端到端测试的模拟小应用：同一份目录里同时放桌面端可执行文件、
模型文件、字节码、Java 类文件、打包产物与普通文本文件。

## 目录

- \`bin/\` 三个平台的可执行文件
- \`models/\` 两个模型文件
- \`pycache/\` 编译后的字节码
- \`java/\` 一个 Java 类文件
- \`dist/\` 打包产物
- \`src/\`、\`config/\`、\`docs/\` 普通源码、配置与文档

## 许可

见 LICENSE，条款与 \`notice --template license\` 生成的声明一致。
`;

/** 清单文件：普通 JSON 条目。 */
const PACKAGE_JSON = `${JSON.stringify(
  {
    name: 'sample-app',
    version: '1.0.0',
    private: true,
    description: '端到端测试用的模拟小应用',
    main: 'src/bundle.js',
    license: 'MIT',
  },
  null,
  2,
)}\n`;

/** 配置文件：普通 JSON 条目，含默认配置。 */
const SETTINGS_JSON = `${JSON.stringify({ logLevel: 'info', retries: 3, endpoints: ['https://api.example.com'] }, null, 2)}\n`;

/** 变更记录：普通 Markdown 条目。 */
const CHANGELOG_TEXT = `# 变更记录

## 1.0.0

- 首次发布
`;

/** 备注文件：普通纯文本条目。 */
const NOTES_TEXT = '构建备注：本目录由 tests/e2e/build.mjs 确定性生成，只用于测试。\n';

/** 带源码地图引用的 JavaScript 文件：v1 没有 JavaScript 读取器，走能力边界。 */
const BUNDLE_JS = `(function () {
  'use strict';
  const version = '1.0.0';
  function greet(name) {
    return 'hello ' + name + ' ' + version;
  }
  globalThis.greet = greet;
})();
//# sourceMappingURL=bundle.js.map
`;

/**
 * 模拟项目的文件清单。每项字段：
 *   relativePath 条目相对路径，也是审计发现里 evidence.path 的取值
 *   covers       本条目覆盖哪条路径，供测试与报告引用
 *   build        确定性字节构造器
 */
export const SAMPLE_PROJECT_FILES = Object.freeze([
  {
    relativePath: 'README.md',
    covers: '普通 Markdown 条目：不落入九类格式，审计记能力边界',
    build: () => Buffer.from(README_TEXT, 'utf8'),
  },
  {
    relativePath: 'LICENSE',
    covers: '普通文本条目：许可条款原文，与 notice 声明内容对应',
    build: () => Buffer.from(LICENSE_TEXT, 'utf8'),
  },
  {
    relativePath: 'package.json',
    covers: '普通 JSON 条目：清单文件',
    build: () => Buffer.from(PACKAGE_JSON, 'utf8'),
  },
  {
    relativePath: 'config/settings.json',
    covers: '普通 JSON 条目：配置文件',
    build: () => Buffer.from(SETTINGS_JSON, 'utf8'),
  },
  {
    relativePath: 'docs/CHANGELOG.md',
    covers: '普通 Markdown 条目：变更记录',
    build: () => Buffer.from(CHANGELOG_TEXT, 'utf8'),
  },
  {
    relativePath: 'notes.txt',
    covers: '普通纯文本条目',
    build: () => Buffer.from(NOTES_TEXT, 'utf8'),
  },
  {
    relativePath: 'src/bundle.js',
    covers: '带源码地图引用的 JavaScript：v1 无 JavaScript 读取器，审计记能力边界',
    build: () => Buffer.from(BUNDLE_JS, 'utf8'),
  },
  {
    relativePath: 'bin/app-linux',
    covers: 'ELF 可执行文件：带 Go 构建信息 inline 编码，metadata.go-buildinfo-inline-overwrite 的施加目标',
    build: () => fixElfEntryPoint(buildElfGoInline().buffer),
  },
  {
    relativePath: 'bin/app-windows.exe',
    covers: 'PE 可执行文件：带调试目录与非零 CheckSum，签名门控与 CheckSum 重算路径',
    build: () => buildPeWithDebugAndChecksum(),
  },
  {
    relativePath: 'bin/app-macos',
    covers: 'Mach-O 可执行文件：带 Go 构建信息与 __DATA,.dep-v0',
    build: () => buildMachOWithGoAndDep().buffer,
  },
  {
    relativePath: 'models/model.gguf',
    covers: 'GGUF 模型文件：元数据键值与张量索引，model.gguf-metadata-relayout 的施加目标',
    build: () =>
      buildGguf({
        metadata: [
          { key: 'general.architecture', type: 8, value: 'demo' },
          { key: 'general.name', type: 8, value: 'sample-model' },
        ],
        tensors: [{ name: 'token_embd.weight', shape: [4], data: patternBytes(16) }],
      }),
  },
  {
    relativePath: 'models/weights.safetensors',
    covers: 'safetensors 模型文件：__metadata__ 槽位与张量索引，model.safetensors-metadata-relayout 的施加目标',
    build: () => buildSafetensorsWithMetadata(),
  },
  {
    relativePath: 'pycache/app.cpython-312.pyc',
    covers: 'pyc：hash_based 且 check_source 置位，metadata.pyc-source-hash-clear 的施加目标',
    build: () => buildPyc({ checkSource: true }),
  },
  {
    relativePath: 'java/com/example/App.class',
    covers: 'Java 类文件：CAFEBABE 与 Mach-O 胖二进制魔数歧义，按分片表判为范围外容器并附歧义说明',
    build: () => buildJavaClass(),
  },
  {
    relativePath: 'dist/bundle.zip',
    covers: 'ZIP：存储条目与 deflate 条目各一，条目 CRC32 一致性检查的目标',
    build: () =>
      buildZip([
        { name: 'assets/readme.txt', content: Buffer.from('zip stored entry\n', 'latin1') },
        { name: 'assets/data.bin', method: 8, content: patternBytes(64) },
      ]),
  },
]);

/**
 * 构造全部条目字节，不写盘。返回顺序与 SAMPLE_PROJECT_FILES 一致。
 * @returns {Array<{relativePath: string, covers: string, bytes: Buffer}>}
 */
export function buildSampleProjectFiles() {
  return SAMPLE_PROJECT_FILES.map((file) => ({
    relativePath: file.relativePath,
    covers: file.covers,
    bytes: file.build(),
  }));
}

/**
 * 计算条目摘要，供测试登记固定字节。
 * @param {Buffer} bytes
 * @returns {string} sha256 十六进制串
 */
export function digestOf(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * 把模拟项目写进目标目录，保持相对路径结构，返回每条目的绝对路径与摘要。
 * 目录已存在时复用，不清理调用方的其他文件。
 * @param {string} root 目标目录
 * @returns {Promise<Array<{relativePath: string, absolutePath: string, bytes: number, sha256: string}>>}
 */
export async function writeSampleProject(root) {
  const written = [];
  for (const file of buildSampleProjectFiles()) {
    const absolutePath = join(root, ...file.relativePath.split('/'));
    await mkdir(join(absolutePath, '..'), { recursive: true });
    await writeFile(absolutePath, file.bytes);
    written.push({
      relativePath: file.relativePath,
      absolutePath,
      bytes: file.bytes.length,
      sha256: digestOf(file.bytes),
    });
  }
  return written;
}

// 直接运行本脚本时把项目写进临时目录并打印清单，便于人工核对。
// 用法：node tests/e2e/build.mjs
if (process.argv[1] !== undefined && import.meta.url === new URL(`file://${process.argv[1].replace(/\\/g, '/')}`).href) {
  const { mkdtemp } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const root = await mkdtemp(join(tmpdir(), 'anti-rea-e2e-sample-'));
  const written = await writeSampleProject(root);
  process.stdout.write(`模拟项目已写入 ${root}\n`);
  for (const entry of written) {
    process.stdout.write(`${entry.relativePath}\t${entry.bytes}\t${entry.sha256}\n`);
  }
}
