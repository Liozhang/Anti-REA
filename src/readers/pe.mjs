// PE 读取器：可选头、节表、调试目录、安全目录与导入导出表的事实提取。
// 只读：按 e_lfanew 找 PE 签名，逐节解析节表，数据目录按索引取，RVA 经节表折算成文件偏移。
// 每条发现都附读取器自身限制；解析不到的部分转成限制说明，不让审计失败。

import { createFinding } from '../audit/finding.mjs';
import {
  defineReader,
  findAll,
  limitation,
  readCString,
  readEntryBytes,
  readUIntLE,
  sanitizeExcerpt,
  truncationLimitation,
} from './common.mjs';
import { scanTokens, tokenFindings, tokenScanLimitation } from './scan.mjs';

/** Go 构建信息魔数：0xFF 后接 " Go buildinf:"。 */
const GO_BUILDINFO_MAGIC = Buffer.from([0xff, 0x20, 0x47, 0x6f, 0x20, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e, 0x66, 0x3a], 'latin1');

/** PE 可选头魔数。 */
const OPTIONAL_MAGICS = Object.freeze({ 0x10b: 'PE32', 0x20b: 'PE32+' });

/** PE 机器类型。 */
const PE_MACHINES = Object.freeze({ 0x14c: 'i386', 0x8664: 'x86-64', 0xaa64: 'ARM64', 0x1c0: 'ARM', 0x1c4: 'ARMNT', 0x5032: 'RISC-V 32', 0x5064: 'RISC-V 64' });

/** PE 子系统。 */
const PE_SUBSYSTEMS = Object.freeze({ 1: '原生', 2: '图形界面', 3: '控制台', 5: 'OS/2 控制台', 7: 'POSIX 控制台', 10: 'EFI 应用' });

/** Go 二进制在 PE 里承载构建信息的节特征位：可读、可写、已初始化数据。 */
const GO_PE_CHARACTERISTICS = 0xc0000040;

/** 数据目录索引名，只登记 v1 会报告的四项。 */
const DATA_DIRECTORY_NAMES = Object.freeze({ 0: '导出表', 1: '导入表', 4: '安全目录', 6: '调试目录' });

/** 摘要里最多列出的导入表动态链接库数量。 */
const IMPORT_NAME_LIMIT = 12;

/**
 * 把相对虚拟地址折算成文件偏移。节表之外的回落到文件头区间。
 * @param {number} rva
 * @param {Array<Record<string, number>>} sections
 * @param {number} sizeOfHeaders
 * @returns {number | undefined}
 */
function rvaToOffset(rva, sections, sizeOfHeaders) {
  if (rva < sizeOfHeaders) {
    return rva;
  }
  for (const section of sections) {
    const span = Math.max(section.virtualSize, section.sizeOfRawData);
    if (rva >= section.virtualAddress && rva < section.virtualAddress + span) {
      return section.pointerToRawData + (rva - section.virtualAddress);
    }
  }
  return undefined;
}

/**
 * 解析 PE：DOS 头、PE 签名、COFF 头、可选头与节表。
 * @param {Buffer} bytes
 * @returns {{ok: true, data: Record<string, unknown>} | {ok: false, reason: string}}
 */
function parsePe(bytes) {
  if (bytes.length < 0x40) {
    return { ok: false, reason: '文件不足 64 字节，读不到 DOS 头' };
  }
  if (bytes[0] !== 0x4d || bytes[1] !== 0x5a) {
    return { ok: false, reason: '文件头不是 MZ 签名' };
  }
  const peOffset = readUIntLE(bytes, 0x3c, 4);
  if (peOffset === undefined || peOffset + 24 > bytes.length) {
    return { ok: false, reason: 'e_lfanew 指向的 PE 签名超出已读取字节范围' };
  }
  if (bytes[peOffset] !== 0x50 || bytes[peOffset + 1] !== 0x45 || bytes[peOffset + 2] !== 0 || bytes[peOffset + 3] !== 0) {
    return { ok: false, reason: 'e_lfanew 处不是 PE\\0\\0 签名' };
  }
  const coff = peOffset + 4;
  const machine = readUIntLE(bytes, coff, 2);
  const numberOfSections = readUIntLE(bytes, coff + 2, 2);
  const timeDateStamp = readUIntLE(bytes, coff + 4, 4);
  const sizeOfOptionalHeader = readUIntLE(bytes, coff + 16, 2);
  const characteristics = readUIntLE(bytes, coff + 18, 2);
  if (machine === undefined || numberOfSections === undefined || timeDateStamp === undefined || sizeOfOptionalHeader === undefined || characteristics === undefined) {
    return { ok: false, reason: 'COFF 头字段读取越界' };
  }
  const optionalOffset = coff + 20;
  const data = {
    peOffset,
    machine,
    numberOfSections,
    timeDateStamp,
    sizeOfOptionalHeader,
    characteristics,
    optionalOffset,
    optionalMagic: null,
    optionalMagicLabel: '无',
    checksum: null,
    subsystem: null,
    sizeOfHeaders: null,
    numberOfRvaAndSizes: 0,
    dataDirectoryOffset: null,
    sections: [],
  };
  if (sizeOfOptionalHeader === 0) {
    return { ok: true, data };
  }
  if (optionalOffset + 2 > bytes.length) {
    return { ok: false, reason: '可选头起始位置超出已读取字节范围' };
  }
  const optionalMagic = readUIntLE(bytes, optionalOffset, 2);
  if (optionalMagic === undefined || OPTIONAL_MAGICS[optionalMagic] === undefined) {
    return { ok: false, reason: `可选头魔数 ${optionalMagic} 不是 0x10b（PE32）或 0x20b（PE32+）` };
  }
  const checksum = readUIntLE(bytes, optionalOffset + 64, 4);
  const subsystem = readUIntLE(bytes, optionalOffset + 68, 2);
  const sizeOfHeaders = readUIntLE(bytes, optionalOffset + 60, 4);
  const numberOfRvaAndSizesOffset = optionalOffset + (optionalMagic === 0x20b ? 108 : 92);
  const numberOfRvaAndSizes = readUIntLE(bytes, numberOfRvaAndSizesOffset, 4);
  if (checksum === undefined || subsystem === undefined || sizeOfHeaders === undefined || numberOfRvaAndSizes === undefined) {
    return { ok: false, reason: '可选头字段读取越界' };
  }
  data.optionalMagic = optionalMagic;
  data.optionalMagicLabel = OPTIONAL_MAGICS[optionalMagic];
  data.checksum = checksum;
  data.subsystem = subsystem;
  data.sizeOfHeaders = sizeOfHeaders;
  data.numberOfRvaAndSizes = numberOfRvaAndSizes;
  data.dataDirectoryOffset = optionalOffset + (optionalMagic === 0x20b ? 112 : 96);

  // 节表紧跟可选头之后。
  const sectionTableOffset = optionalOffset + sizeOfOptionalHeader;
  for (let index = 0; index < numberOfSections; index += 1) {
    const base = sectionTableOffset + index * 40;
    if (base + 40 > bytes.length) {
      break;
    }
    const name = sanitizeExcerpt(bytes.subarray(base, base + 8), 8).replace(/\.+$/, '');
    data.sections.push({
      index,
      name,
      virtualSize: readUIntLE(bytes, base + 8, 4),
      virtualAddress: readUIntLE(bytes, base + 12, 4),
      sizeOfRawData: readUIntLE(bytes, base + 16, 4),
      pointerToRawData: readUIntLE(bytes, base + 20, 4),
      characteristics: readUIntLE(bytes, base + 36, 4),
    });
  }
  return { ok: true, data };
}

/**
 * 取数据目录项。
 * @param {Buffer} bytes
 * @param {Record<string, unknown>} data PE 解析结果
 * @param {number} index 目录索引
 * @returns {{virtualAddress: number, size: number} | null}
 */
function dataDirectory(bytes, data, index) {
  if (data.dataDirectoryOffset === null || index >= data.numberOfRvaAndSizes) {
    return null;
  }
  const base = data.dataDirectoryOffset + index * 8;
  const virtualAddress = readUIntLE(bytes, base, 4);
  const size = readUIntLE(bytes, base + 4, 4);
  if (virtualAddress === undefined || size === undefined) {
    return null;
  }
  if (virtualAddress === 0 && size === 0) {
    return null;
  }
  return { virtualAddress, size };
}

/**
 * 解析调试目录，取出 CODEVIEW 记录里的符号文件路径。
 * @param {Buffer} bytes
 * @param {Record<string, unknown>} data PE 解析结果
 * @returns {{paths: string[], limitations: Array<Record<string, unknown>>}}
 */
function parseDebugDirectory(bytes, data) {
  const paths = [];
  const limitations = [];
  const directory = dataDirectory(bytes, data, 6);
  if (directory === null) {
    return { paths, limitations };
  }
  // 安全目录的虚拟地址是文件偏移，调试目录的虚拟地址是 RVA，两者语义不同，分别处理。
  const offset = rvaToOffset(directory.virtualAddress, data.sections, data.sizeOfHeaders);
  if (offset === undefined) {
    limitations.push(limitation('pe-debug-rva-unresolved', '调试目录的相对虚拟地址无法经节表折算成文件偏移，符号文件路径未取出'));
    return { paths, limitations };
  }
  const entryCount = Math.max(1, Math.floor(directory.size / 28));
  for (let index = 0; index < entryCount; index += 1) {
    const base = offset + index * 28;
    if (base + 28 > bytes.length) {
      limitations.push(limitation('pe-debug-entry-out-of-range', `第 ${index} 号调试目录项超出已读取字节范围，该项及其后的项没有解析`));
      break;
    }
    const type = readUIntLE(bytes, base + 12, 4);
    const sizeOfData = readUIntLE(bytes, base + 16, 4);
    // PE 规范排法：+20 是 AddressOfRawData（相对虚拟地址），+24 是 PointerToRawData（文件偏移）。
    // 在文件内定位 CODEVIEW 记录要用文件偏移，因此取 +24。
    const pointerToRawData = readUIntLE(bytes, base + 24, 4);
    if (type === undefined || sizeOfData === undefined || pointerToRawData === undefined) {
      continue;
    }
    if (type !== 2 || pointerToRawData + sizeOfData > bytes.length) {
      continue;
    }
    // CODEVIEW 记录：四字节签名、十六字节全局标识、四字节年龄，之后是空字符结尾的符号文件路径。
    const path = readCString(bytes, pointerToRawData + 24);
    if (path !== undefined && path.length > 0) {
      paths.push(path);
    }
  }
  if (paths.length === 0) {
    limitations.push(limitation('pe-debug-no-codeview-path', '调试目录里没有取到 CODEVIEW 符号文件路径，只登记调试目录存在'));
  }
  return { paths, limitations };
}

/**
 * 解析导入表，列出动态链接库名。
 * @param {Buffer} bytes
 * @param {Record<string, unknown>} data PE 解析结果
 * @returns {{dlls: string[], limitations: Array<Record<string, unknown>>}}
 */
function parseImports(bytes, data) {
  const dlls = [];
  const limitations = [];
  const directory = dataDirectory(bytes, data, 1);
  if (directory === null) {
    return { dlls, limitations };
  }
  const offset = rvaToOffset(directory.virtualAddress, data.sections, data.sizeOfHeaders);
  if (offset === undefined) {
    limitations.push(limitation('pe-import-rva-unresolved', '导入表的相对虚拟地址无法经节表折算成文件偏移，导入的动态链接库清单未取出'));
    return { dlls, limitations };
  }
  for (let index = 0; index < 1024; index += 1) {
    const base = offset + index * 20;
    if (base + 20 > bytes.length) {
      limitations.push(limitation('pe-import-out-of-range', `第 ${index} 号导入描述符超出已读取字节范围，该项及其后的项没有解析`));
      break;
    }
    const nameRva = readUIntLE(bytes, base + 12, 4);
    const firstThunk = readUIntLE(bytes, base + 16, 4);
    if (nameRva === undefined || firstThunk === undefined) {
      break;
    }
    if (nameRva === 0 && firstThunk === 0) {
      break;
    }
    const nameOffset = rvaToOffset(nameRva, data.sections, data.sizeOfHeaders);
    const name = nameOffset === undefined ? undefined : readCString(bytes, nameOffset);
    if (name !== undefined && name.length > 0) {
      dlls.push(name);
    }
  }
  return { dlls, limitations };
}

/**
 * 解析导出表。
 * @param {Buffer} bytes
 * @param {Record<string, unknown>} data PE 解析结果
 * @returns {{moduleName: string | null, functionCount: number, limitations: Array<Record<string, unknown>>}}
 */
function parseExports(bytes, data) {
  const directory = dataDirectory(bytes, data, 0);
  if (directory === null) {
    return { moduleName: null, functionCount: 0, limitations: [] };
  }
  const offset = rvaToOffset(directory.virtualAddress, data.sections, data.sizeOfHeaders);
  if (offset === undefined || offset + 40 > bytes.length) {
    return {
      moduleName: null,
      functionCount: 0,
      limitations: [limitation('pe-export-unresolved', '导出表无法解析：相对虚拟地址折算失败或目录超出已读取字节范围，导出清单未取出')],
    };
  }
  const nameRva = readUIntLE(bytes, offset + 12, 4);
  const numberOfFunctions = readUIntLE(bytes, offset + 20, 4);
  const nameOffset = nameRva === undefined ? undefined : rvaToOffset(nameRva, data.sections, data.sizeOfHeaders);
  const moduleName = nameOffset === undefined ? null : (readCString(bytes, nameOffset) ?? null);
  return { moduleName, functionCount: numberOfFunctions ?? 0, limitations: [] };
}

/**
 * PE 读取器入口。
 * @param {{entry: Record<string, unknown>, policy: Record<string, unknown>, budgets: Record<string, number>}} context
 * @returns {Promise<{findings: Array<Record<string, unknown>>, limitations: Array<Record<string, unknown>>}>}
 */
async function readPe(context) {
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

  const parsed = parsePe(bytes);
  if (!parsed.ok) {
    limitations.push(limitation('pe-unparsable', `PE 解析失败：${parsed.reason}。该条目不等于没有暴露，只是本次没有提取到事实`));
    return { findings, limitations };
  }
  const data = parsed.data;

  const machineLabel = PE_MACHINES[data.machine] ?? String(data.machine);
  const subsystemLabel = data.subsystem === null ? '未声明' : (PE_SUBSYSTEMS[data.subsystem] ?? String(data.subsystem));
  findings.push(
    createFinding({
      layer: 'metadata-hygiene',
      severity: 'info',
      title: 'PE 头声明的格式事实',
      category: 'pe-header',
      evidence: {
        path,
        byteRange: [data.peOffset, data.peOffset + 24 + data.sizeOfOptionalHeader],
        excerpt: `${data.optionalMagicLabel} ${machineLabel} ${subsystemLabel} ${data.numberOfSections} 个节`,
      },
      reader: 'pe',
      readerLimitation: '只解析 PE 头、可选头与节表声明的字段，不反汇编、不恢复源码；头字段可被伪造，声明与真实行为未必一致',
      mitigation: null,
      detail: {
        machine: machineLabel,
        optionalHeader: data.optionalMagicLabel,
        subsystem: subsystemLabel,
        sectionCount: data.sections.length,
        characteristics: data.characteristics,
      },
    }),
  );

  // 安全目录：Authenticode 签名表。存在即登记，默认跳过改写由 harden 决定。
  const security = dataDirectory(bytes, data, 4);
  if (security !== null) {
    findings.push(
      createFinding({
        layer: 'metadata-hygiene',
        severity: 'medium',
        title: 'PE 带安全目录（代码签名表）',
        category: 'pe-security-directory',
        evidence: { path, byteRange: [security.virtualAddress, security.virtualAddress + security.size], excerpt: `安全目录 ${security.size} 字节` },
        reader: 'pe',
        readerLimitation: '只登记安全目录存在与大小，不验证密码学信任、不解码签名者身份；目录内容是否有效签名不在 v1 判定范围',
        mitigation: null,
        detail: { offset: security.virtualAddress, size: security.size },
      }),
    );
  }

  // 可选头校验和。
  if (typeof data.checksum === 'number' && data.checksum !== 0) {
    findings.push(
      createFinding({
        layer: 'metadata-hygiene',
        severity: 'info',
        title: 'PE 可选头 CheckSum 非零',
        category: 'pe-checksum',
        evidence: { path, byteRange: [data.optionalOffset + 64, data.optionalOffset + 68], excerpt: `CheckSum 0x${data.checksum.toString(16)}` },
        reader: 'pe',
        readerLimitation: '只登记校验和字段非零，不按 PE 校验和算法重算、不判断是否匹配；是否重算由策略显式许可',
        mitigation: null,
        detail: { checksum: data.checksum },
      }),
    );
  }

  // 调试目录里的符号文件路径。
  const debug = parseDebugDirectory(bytes, data);
  limitations.push(...debug.limitations);
  if (debug.paths.length > 0) {
    findings.push(
      createFinding({
        layer: 'metadata-hygiene',
        severity: 'high',
        title: 'PE 调试目录携带符号文件路径',
        category: 'pe-debug-directory',
        evidence: { path, byteRange: [data.dataDirectoryOffset + 6 * 8, data.dataDirectoryOffset + 7 * 8], excerpt: debug.paths.slice(0, 3).join('、') },
        reader: 'pe',
        readerLimitation: '只取 CODEVIEW 记录里的符号文件路径，路径指向的符号文件本身是否随制品分发不在 v1 判定范围',
        mitigation: 'metadata.pe-debug-directory-overwrite',
        detail: { paths: debug.paths },
      }),
    );
  }

  // 导入表。
  const imports = parseImports(bytes, data);
  limitations.push(...imports.limitations);
  if (imports.dlls.length > 0) {
    findings.push(
      createFinding({
        layer: 'metadata-hygiene',
        severity: 'medium',
        title: 'PE 导入表声明的动态链接库',
        category: 'pe-imports',
        evidence: { path, byteRange: [data.dataDirectoryOffset + 8, data.dataDirectoryOffset + 16], excerpt: imports.dlls.slice(0, IMPORT_NAME_LIMIT).join('、') },
        reader: 'pe',
        readerLimitation: '导入表按描述符逐条取出动态链接库名，导入函数的逐项清单不在 v1 范围内；运行期延迟导入不在此列',
        mitigation: null,
        detail: { dlls: imports.dlls },
      }),
    );
  }

  // 导出表。
  const exports = parseExports(bytes, data);
  limitations.push(...exports.limitations);
  if (exports.moduleName !== null || exports.functionCount > 0) {
    findings.push(
      createFinding({
        layer: 'metadata-hygiene',
        severity: 'medium',
        title: 'PE 导出表',
        category: 'pe-exports',
        evidence: { path, byteRange: [data.dataDirectoryOffset, data.dataDirectoryOffset + 8], excerpt: exports.moduleName ?? `${exports.functionCount} 个导出` },
        reader: 'pe',
        readerLimitation: '导出表只报模块名与导出函数数量，逐项导出名不在 v1 范围内',
        mitigation: null,
        detail: { moduleName: exports.moduleName, functionCount: exports.functionCount },
      }),
    );
  }

  // Go 构建信息：整文件搜魔数，并记录是否落在特征位为 0xc0000040 的节里。
  const magicHits = findAll(bytes, GO_BUILDINFO_MAGIC);
  for (const magicOffset of magicHits) {
    const section = data.sections.find(
      (candidate) => candidate.characteristics === GO_PE_CHARACTERISTICS && magicOffset >= candidate.pointerToRawData && magicOffset < candidate.pointerToRawData + candidate.sizeOfRawData,
    );
    findings.push(
      createFinding({
        layer: 'metadata-hygiene',
        severity: 'high',
        title: 'Go 构建信息',
        category: 'go-buildinfo',
        evidence: { path, byteRange: [magicOffset, magicOffset + 32], excerpt: `魔数位于文件偏移 ${magicOffset}` },
        reader: 'pe',
        readerLimitation:
          '只按魔数定位存在与所在节，不解析 inline 与 pointer 两种编码的载荷；覆写范围以实际命中节为准，其余字节仍可被裸检索',
        mitigation: 'metadata.go-buildinfo-pe-characteristics-overwrite',
        detail: { magicOffset, section: section?.name ?? null, sectionCharacteristics: section?.characteristics ?? null },
      }),
    );
  }

  // 令牌扫描。
  const scan = scanTokens(bytes);
  findings.push(...tokenFindings(scan, { path, reader: 'pe', source: 'raw-bytes' }));
  const scanLimitation = tokenScanLimitation(scan, '制品字节');
  if (scanLimitation !== null) {
    limitations.push(scanLimitation);
  }

  return { findings, limitations };
}

export const peReader = defineReader({
  id: 'pe',
  formats: ['pe'],
  layers: ['metadata-hygiene', 'secret-minimization'],
  purpose: 'PE 可选头、节表、调试目录、安全目录与导入导出表的事实提取',
  read: readPe,
});
