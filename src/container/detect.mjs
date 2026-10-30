// 容器识别：按文件头魔数把制品分派到对应格式读取器。
// 只读取文件头固定长度字节，不加载、不执行任何代码，也不解压容器内容。
//
// 判定分三类：
//   固定魔数    ELF、PE、Mach-O（含胖二进制）、ZIP、GGUF、BEAM，字节表逐项比对
//   结构魔数    safetensors（8 字节头部长度加 JSON 头）、pyc（魔数之后固定 0D 0A）
//   追加判定    PE 的 PE\0\0 签名、BEAM 的 BEAM 标记、Mach-O 胖二进制与 Java 类文件的分片表判别，
//               命中魔数后仍需确认
// 结构魔数的关键字节可能落在标准窗口之外，由 detectionProbeLength 指出需要补读多少字节，
// 读取动作在 identify.mjs 完成，本模块只给出格式知识。

/** 识别时读取的标准文件头长度。九类格式的魔数都在前 4096 字节内可判定。 */
export const DETECTION_PREFIX_BYTES = 4096;

/** safetensors 头部长度声明的补读上限。超过此值的声明不触发补读，也不按 safetensors 处理。 */
export const SAFETENSORS_HEADER_PROBE_MAX = 8 * 1024 * 1024;

/** safetensors 头部长度声明的合理性上限。超过此值即判定不是 safetensors。 */
const SAFETENSORS_HEADER_MAX = 1024 * 1024 * 1024;

/** PE 签名位置的补读上限。e_lfanew 超过此值不触发补读。 */
const PE_SIGNATURE_PROBE_MAX = 1024 * 1024;

/** 胖二进制分片数的合理区间：少于一个没有分片可解析，多于三十二个不是常见胖二进制。 */
const FAT_ARCH_COUNT_RANGE = Object.freeze({ min: 1, max: 32 });

/** 胖二进制头长度：四字节魔数加四字节大端 nfat_arch。 */
const FAT_HEADER_BYTES = 8;

/** 胖二进制单个分片项长度：cputype、cpusubtype、offset、size、align 各四字节，共二十字节。 */
const FAT_ARCH_BYTES = 20;

/** Mach-O 胖二进制魔数与 Java 类文件魔数相同，需要显式记录这一歧义。 */
const MACH_O_FAT_AMBIGUITY = '魔数 CAFEBABE 也用于 Java 类文件，已按分片表结构判别为胖二进制';

/** 命中 CAFEBABE 但分片表不符合胖二进制结构时的归类说明。 */
const JAVA_CLASS_NOTE = '魔数 CAFEBABE 也用于 Java 类文件，分片数或首个分片头不符合胖二进制结构，判为范围外容器';

/** 命中 CAFEBABE 但已读窗口不足以读取分片表时的未判定说明。 */
const FAT_UNDETERMINED_NOTE = 'CAFEBABE 魔数命中，但已读窗口不足以读取分片表，无法确认或排除';

/** 命中 MZ 但窗口不足以确认 PE 签名时的未判定说明。 */
const PE_UNDETERMINED_NOTE = 'MZ 魔数命中，但已读窗口不足以确认 PE 签名，无法确认或排除';

/** 命中 FOR1 但窗口不足以确认 BEAM 标记时的未判定说明。 */
const BEAM_UNDETERMINED_NOTE = 'FOR1 魔数命中，但已读窗口不足以确认 BEAM 标记，无法确认或排除';

/** 命中 dex\n 但窗口不足以确认版本号时的未判定说明。 */
const DEX_UNDETERMINED_NOTE = 'dex\\n 魔数命中，但已读窗口不足以确认版本号，无法确认或排除';

/** 命中 dex\n 但版本号不是三位数字加终止零时的归类说明。 */
const DEX_VERSION_NOTE = 'dex\\n 之后不是三位版本号加一个零字节，判为范围外容器';

/**
 * 九类 v1 格式的魔数表。顺序即判定优先级。
 * 每项字段：
 *   type      容器标识，供读取器注册表与报告使用
 *   label     人读格式名
 *   magic     魔数字节序列
 *   offset    魔数在文件中的偏移
 *   confirm   可选，命中 magic 后需要追加判定的函数名
 *   note      可选，命中后附带的歧义或判定说明
 */
const CONTAINER_TABLE = [
  { type: 'elf', label: 'ELF', magic: [0x7f, 0x45, 0x4c, 0x46], offset: 0 },
  { type: 'pe', label: 'PE', magic: [0x4d, 0x5a], offset: 0, confirm: 'confirmPe' },
  { type: 'mach-o', label: 'Mach-O', magic: [0xcf, 0xfa, 0xed, 0xfe], offset: 0 },
  { type: 'mach-o', label: 'Mach-O', magic: [0xce, 0xfa, 0xed, 0xfe], offset: 0 },
  { type: 'mach-o', label: 'Mach-O', magic: [0xfe, 0xed, 0xfa, 0xce], offset: 0 },
  { type: 'mach-o', label: 'Mach-O', magic: [0xfe, 0xed, 0xfa, 0xcf], offset: 0 },
  { type: 'mach-o-fat', label: 'Mach-O 胖二进制', magic: [0xca, 0xfe, 0xba, 0xbe], offset: 0, confirm: 'confirmFat', note: MACH_O_FAT_AMBIGUITY },
  { type: 'mach-o-fat', label: 'Mach-O 胖二进制', magic: [0xbe, 0xba, 0xfe, 0xca], offset: 0 },
  { type: 'zip', label: 'ZIP', magic: [0x50, 0x4b, 0x03, 0x04], offset: 0 },
  { type: 'zip', label: 'ZIP', magic: [0x50, 0x4b, 0x05, 0x06], offset: 0 },
  { type: 'zip', label: 'ZIP', magic: [0x50, 0x4b, 0x07, 0x08], offset: 0 },
  { type: 'gguf', label: 'GGUF', magic: [0x47, 0x47, 0x55, 0x46], offset: 0 },
  { type: 'beam', label: 'BEAM', magic: [0x46, 0x4f, 0x52, 0x31], offset: 0, confirm: 'confirmBeam' },
  // DEX 魔数共八字节：'dex' 加换行，随后三位版本号数字，最后一个是零字节。
  // 版本号从 035 到 039，未来版本继续递增，因此只校验形态而不校验具体值。
  { type: 'dex', label: 'DEX', magic: [0x64, 0x65, 0x78, 0x0a], offset: 0, confirm: 'confirmDex' },
];

/** v1 支持的九类格式容器标识，封闭集合。 */
export const SUPPORTED_CONTAINERS = Object.freeze([
  'elf',
  'pe',
  'mach-o',
  'mach-o-fat',
  'zip',
  'gguf',
  'safetensors',
  'pyc',
  'beam',
  'dex',
]);

/**
 * 读取 PE 的 e_lfanew 并确认存在 PE\0\0 签名。
 * 返回三态：confirmed 命中、refuted 明确不是、undetermined 已读窗口不足以判定。
 * @param {Buffer} prefix 文件头字节
 * @returns {'confirmed' | 'refuted' | 'undetermined'}
 */
function confirmPe(prefix) {
  if (prefix.length < 0x40) {
    // 读不到 e_lfanew：窗口被截断，既不能确认也不能排除。
    return 'undetermined';
  }
  const peOffset = prefix.readUInt32LE(0x3c);
  if (peOffset < 0x40 || peOffset > PE_SIGNATURE_PROBE_MAX) {
    // 偏移越界或超出补读上限，不按 PE 处理。
    return 'refuted';
  }
  if (peOffset + 4 > prefix.length) {
    return 'undetermined';
  }
  const isPe = prefix[peOffset] === 0x50 && prefix[peOffset + 1] === 0x45 && prefix[peOffset + 2] === 0x00 && prefix[peOffset + 3] === 0x00;
  return isPe ? 'confirmed' : 'refuted';
}

/**
 * 确认 BEAM：FOR1 之后是长度，再之后是 BEAM 标记。
 * 返回三态，含义同 confirmPe。
 * @param {Buffer} prefix 文件头字节
 * @returns {'confirmed' | 'refuted' | 'undetermined'}
 */
function confirmBeam(prefix) {
  if (prefix.length < 12) {
    return 'undetermined';
  }
  return prefix.toString('latin1', 8, 12) === 'BEAM' ? 'confirmed' : 'refuted';
}

/**
 * 确认 DEX：'dex' 加换行之后是三位 ASCII 数字版本号，最后一个字节是零。
 * 返回三态，含义同 confirmPe。
 * @param {Buffer} prefix 文件头字节
 * @returns {'confirmed' | 'refuted' | 'undetermined'}
 */
function confirmDex(prefix) {
  if (prefix.length < 8) {
    return 'undetermined';
  }
  const digit = (byte) => byte >= 0x30 && byte <= 0x39;
  if (digit(prefix[4]) && digit(prefix[5]) && digit(prefix[6]) && prefix[7] === 0x00) {
    return 'confirmed';
  }
  return 'refuted';
}

/**
 * 判别 CAFEBABE 是 Mach-O 胖二进制还是 Java 类文件。
 * 胖二进制在魔数之后是大端 nfat_arch，随后每个分片项依次给出 cputype、cpusubtype、offset、size、align；
 * Java 类文件在这几个位置放的是次版本号、主版本号与常量池计数，取值结构完全不同。
 * 判据有两条，同时满足才按胖二进制处理：
 *   1. nfat_arch 落在一到三十二之间，且首个分片项的 cputype 不是零；
 *   2. 首个分片项的 offset 加 size 不超出文件长度。
 * 任一条不满足都按 Java 类文件处理，归入范围外容器，不送进 Mach-O 读取器。
 * 返回三态，含义同 confirmPe。
 * @param {Buffer} prefix 文件头字节
 * @param {number} fileSize 文件字节数
 * @returns {'confirmed' | 'refuted' | 'undetermined'}
 */
function confirmFat(prefix, fileSize) {
  if (prefix.length < FAT_HEADER_BYTES) {
    // 读不到 nfat_arch：窗口被截断，既不能确认也不能排除。
    return 'undetermined';
  }
  const archCount = prefix.readUInt32BE(4);
  if (archCount < FAT_ARCH_COUNT_RANGE.min || archCount > FAT_ARCH_COUNT_RANGE.max) {
    // 分片数为零或超出常见范围。Java 类文件的主版本号落在这个位置，据此排除。
    return 'refuted';
  }
  if (prefix.length < FAT_HEADER_BYTES + FAT_ARCH_BYTES) {
    // 分片数合理，但读不到首个分片项：窗口被截断。
    return 'undetermined';
  }
  const cputype = prefix.readUInt32BE(FAT_HEADER_BYTES);
  const offset = prefix.readUInt32BE(FAT_HEADER_BYTES + 8);
  const size = prefix.readUInt32BE(FAT_HEADER_BYTES + 12);
  if (cputype === 0) {
    // 每个分片都必须声明处理器类型，零不是合法的 cputype。
    return 'refuted';
  }
  if (offset + size > fileSize) {
    // 首个分片越出文件尾：这不是一份分片表。
    return 'refuted';
  }
  return 'confirmed';
}

/**
 * 取 safetensors 头部长度声明：前 8 字节是小端无符号 64 位整数。
 * @param {Buffer} prefix 文件头字节
 * @returns {number | null} 声明值；字节不足或不是正整数时返回 null
 */
export function safetensorsHeaderLength(prefix) {
  if (!Buffer.isBuffer(prefix) || prefix.length < 8) {
    return null;
  }
  const length = Number(prefix.readBigUInt64LE(0));
  if (!Number.isSafeInteger(length) || length <= 0) {
    return null;
  }
  return length;
}

/**
 * 取确认 PE 需要读取到的字节位置：e_lfanew 指出 PE\0\0 签名的偏移，加 4 即签名结束处。
 * @param {Buffer} prefix 文件头字节
 * @returns {number | null} 需要读取到的字节数；字节不足或偏移不合理时返回 null
 */
export function peSignatureEnd(prefix) {
  if (!Buffer.isBuffer(prefix) || prefix.length < 0x40) {
    return null;
  }
  const peOffset = prefix.readUInt32LE(0x3c);
  if (peOffset < 0x40 || peOffset > PE_SIGNATURE_PROBE_MAX) {
    return null;
  }
  return peOffset + 4;
}

/**
 * 计算完成魔数判定还需要读取到第几字节。
 * 两类结构魔数的关键字节不在固定偏移：
 *   PE           PE\0\0 签名的偏移由 e_lfanew 指出，个别加壳制品会落在标准窗口之外；
 *   safetensors  头部长度由前 8 字节声明，大模型文件的头部经常超过 4096 字节。
 * 标准窗口内即可判定时返回 0；声明不合理或超出文件实际大小时同样返回 0。
 * @param {Buffer} prefix 已读取的文件头
 * @param {number} fileSize 文件字节数
 * @returns {number} 建议读取到的字节数，0 表示当前窗口已足够
 */
export function detectionProbeLength(prefix, fileSize) {
  let needed = 0;
  const peEnd = peSignatureEnd(prefix);
  if (peEnd !== null && peEnd <= fileSize) {
    needed = Math.max(needed, peEnd);
  }
  const headerLength = safetensorsHeaderLength(prefix);
  if (headerLength !== null && headerLength <= SAFETENSORS_HEADER_PROBE_MAX) {
    const headerEnd = 8 + headerLength;
    if (headerEnd <= fileSize) {
      needed = Math.max(needed, headerEnd);
    }
  }
  return needed;
}

/**
 * 识别 safetensors：8 字节小端头部长度前缀，加一个能解析成对象的 JSON 头。
 * @param {Buffer} prefix 文件头字节
 * @returns {{matched: boolean, note?: string}} note 在头部长度声明合理但超出已读窗口时给出
 */
function detectSafetensors(prefix) {
  if (prefix.length < 16) {
    return { matched: false };
  }
  const headerLength = safetensorsHeaderLength(prefix);
  if (headerLength === null || 8 + headerLength > SAFETENSORS_HEADER_MAX) {
    return { matched: false };
  }
  const available = prefix.length - 8;
  if (headerLength > available) {
    if (headerLength > SAFETENSORS_HEADER_PROBE_MAX) {
      // 声明值超过补读上限，不按 safetensors 处理，交给后续判定。
      return { matched: false };
    }
    if (prefix.length >= 9 && prefix[8] !== 0x7b) {
      // safetensors 的头部是 JSON 对象，第 9 字节必须是 '{'。
      // 只读了大半零字节的制品（例如未读完的 MZ 文件头）会碰巧给出小长度声明，据此排除。
      return { matched: false };
    }
    // 头部长度声明合理但超出已读窗口：既不能确认也不能排除，交由调用方补读后重判。
    return {
      matched: false,
      note: `safetensors 头部长度声明为 ${headerLength} 字节，超出已读取的 ${available} 字节窗口，无法在不读取更多字节的前提下确认或排除`,
    };
  }
  let header;
  try {
    header = JSON.parse(prefix.toString('utf8', 8, 8 + headerLength));
  } catch {
    return { matched: false };
  }
  if (header === null || typeof header !== 'object' || Array.isArray(header)) {
    return { matched: false };
  }
  const hasMetadata = Object.hasOwn(header, '__metadata__');
  const looksLikeTensorTable = Object.values(header).some(
    (value) => value !== null && typeof value === 'object' && 'dtype' in value && 'data_offsets' in value,
  );
  if (!hasMetadata && !looksLikeTensorTable) {
    return { matched: false };
  }
  return { matched: true };
}

/**
 * 判定前两个字节是否都落在可打印 ASCII 区间。
 * 已知 pyc 魔数至少有一个字节落在该区间之外：Python 3.x 的魔数在 0x0c3a 至 0x0df3 一带，
 * 高字节是 0x0c 或 0x0d；Python 2.x 在 0xc3xx 至 0xf3xx 一带，高字节不小于 0x80；
 * Python 1.x 在 0x4e99 一带，低字节是 0x99。两个字节都可打印的文本文件因此不会被误判成 pyc。
 * @param {Buffer} prefix 文件头字节
 * @returns {boolean}
 */
function bothBytesPrintable(prefix) {
  const printable = (byte) => byte >= 0x20 && byte <= 0x7e;
  return printable(prefix[0]) && printable(prefix[1]);
}

/**
 * 识别 pyc：四字节魔数之后固定是 0x0D 0x0A。
 * @param {Buffer} prefix 文件头字节
 * @returns {boolean}
 */
function detectPyc(prefix) {
  return prefix.length >= 4 && prefix[2] === 0x0d && prefix[3] === 0x0a && !bothBytesPrintable(prefix);
}

/**
 * 按魔数识别容器。
 * @param {Buffer} prefix 文件头字节，长度不限，判定只检查窗口内字节
 * @param {number} [fileSize] 文件字节数。省略时按已读窗口长度推断，窗口小于真实文件的调用方必须显式给出，
 *   否则分片偏移与大小会因拿不到真实文件长度而被误判
 * @returns {{type: string, label: string, note?: string, magicOffset?: number}}
 */
export function detectContainer(prefix, fileSize) {
  if (!Buffer.isBuffer(prefix) || prefix.length < 4) {
    return { type: 'unknown', label: '未知', note: '文件头不足四字节，无法按魔数判定' };
  }
  // 调用方不给文件大小时，把已读窗口当作全部已知字节：窗口内的字节都算数，窗口外的一律未知。
  const size = Number.isFinite(fileSize) && fileSize >= 0 ? fileSize : prefix.length;
  for (const entry of CONTAINER_TABLE) {
    const start = entry.offset;
    const end = start + entry.magic.length;
    if (end > prefix.length) {
      continue;
    }
    let hit = true;
    for (let index = 0; index < entry.magic.length; index += 1) {
      if (prefix[start + index] !== entry.magic[index]) {
        hit = false;
        break;
      }
    }
    if (!hit) {
      continue;
    }
    if (entry.confirm === 'confirmPe') {
      const verdict = confirmPe(prefix);
      if (verdict === 'refuted') {
        continue;
      }
      if (verdict === 'undetermined') {
        return { type: 'unknown', label: '未判定', note: PE_UNDETERMINED_NOTE };
      }
    }
    if (entry.confirm === 'confirmBeam') {
      const verdict = confirmBeam(prefix);
      if (verdict === 'refuted') {
        continue;
      }
      if (verdict === 'undetermined') {
        return { type: 'unknown', label: '未判定', note: BEAM_UNDETERMINED_NOTE };
      }
    }
    if (entry.confirm === 'confirmDex') {
      const verdict = confirmDex(prefix);
      if (verdict === 'refuted') {
        // dex\n 只是四个字节，文本文件与别的容器都可能以它开头。
        // 版本号形态不符时按范围外容器归类，不送进 DEX 读取器。
        return { type: 'unsupported', label: '范围外容器', note: DEX_VERSION_NOTE };
      }
      if (verdict === 'undetermined') {
        return { type: 'unknown', label: '未判定', note: DEX_UNDETERMINED_NOTE };
      }
    }
    if (entry.confirm === 'confirmFat') {
      const verdict = confirmFat(prefix, size);
      if (verdict === 'refuted') {
        // CAFEBABE 同时是 Java 类文件魔数：分片表不符时按范围外容器归类，
        // 不把 Java 类文件当成胖二进制送进 Mach-O 读取器。
        return { type: 'unsupported', label: '范围外容器', note: JAVA_CLASS_NOTE };
      }
      if (verdict === 'undetermined') {
        return { type: 'unknown', label: '未判定', note: FAT_UNDETERMINED_NOTE };
      }
    }
    return { type: entry.type, label: entry.label, note: entry.note, magicOffset: start };
  }
  const safetensors = detectSafetensors(prefix);
  if (safetensors.matched) {
    return { type: 'safetensors', label: 'safetensors', note: safetensors.note };
  }
  if (safetensors.note !== undefined) {
    // 头部长度声明合理但窗口不足：如实报告未判定，不冒充范围外容器。
    return { type: 'unknown', label: '未判定', note: safetensors.note };
  }
  if (detectPyc(prefix)) {
    return { type: 'pyc', label: 'pyc', note: '字节 2 至 3 为 0D 0A，符合 pyc 魔数之后的固定标记' };
  }
  return { type: 'unsupported', label: '范围外容器', note: '文件头不匹配 v1 九类格式中的任何一类' };
}

/**
 * 判断某容器是否在 v1 范围内。
 * @param {string} type 容器标识
 * @returns {boolean}
 */
export function isSupportedContainer(type) {
  return SUPPORTED_CONTAINERS.includes(type);
}
