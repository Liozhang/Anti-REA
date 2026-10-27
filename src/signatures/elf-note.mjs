// ELF note 存在性观察器。
// 只读：解析 ELF 头与程序头，找出 PT_NOTE 段并逐条解析 note（namesz、descsz、type、name、desc）。
// 只观察不据此拒改：note 多为构建标识（如 NT_GNU_BUILD_ID），属元数据而非代码签名门；
// 若改写 note 内容，须走必需集豁免。只观察不验证密码学信任。

/** 程序头类型 PT_NOTE。 */
const PT_NOTE = 4;

/** 常见 note 类型到名称，仅用于报告可读性。 */
const NOTE_TYPE_NAMES = Object.freeze({
  1: 'NT_GNU_ABI_TAG',
  2: 'NT_GNU_HWCAP',
  3: 'NT_GNU_BUILD_ID',
  4: 'NT_GNU_GOLD_VERSION',
  5: 'NT_GNU_PROPERTY_TYPE_0',
});

/**
 * 按 ELF 数据字节序读取 16 位无符号整数。
 * @param {Buffer} buffer
 * @param {number} offset
 * @param {boolean} little
 * @returns {number}
 */
function rd16(buffer, offset, little) {
  return little ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset);
}

/**
 * 按 ELF 数据字节序读取 32 位无符号整数。
 * @param {Buffer} buffer
 * @param {number} offset
 * @param {boolean} little
 * @returns {number}
 */
function rd32(buffer, offset, little) {
  return little ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
}

/**
 * 读取 64 位程序头偏移字段并折算成安全整数。
 * @param {Buffer} buffer
 * @param {number} offset
 * @param {boolean} little
 * @returns {number}
 */
function rd64(buffer, offset, little) {
  const value = little ? buffer.readBigUInt64LE(offset) : buffer.readBigUInt64BE(offset);
  return Number(value);
}

/**
 * 解析一段 PT_NOTE 区间内的全部 note。
 * @param {Buffer} buffer
 * @param {number} start 段文件偏移
 * @param {number} size 段文件长度
 * @param {number} segmentIndex 段序号，供报告定位
 * @param {boolean} little 字节序
 * @param {Array<Record<string, unknown>>} out 输出数组
 * @returns {string | null} 解析中的限制说明
 */
function parseNotes(buffer, start, size, segmentIndex, little, out) {
  const end = start + size;
  let position = start;
  let limitation = null;
  while (position + 12 <= end) {
    const namesz = rd32(buffer, position, little);
    const descsz = rd32(buffer, position + 4, little);
    const type = rd32(buffer, position + 8, little);
    const nameStart = position + 12;
    const namePadded = Math.ceil(namesz / 4) * 4;
    const descStart = nameStart + namePadded;
    const descPadded = Math.ceil(descsz / 4) * 4;
    if (nameStart + namesz > end || descStart + descsz > end) {
      limitation = `第 ${segmentIndex} 段内 note 尺寸越界，停止解析`;
      break;
    }
    const name = buffer.toString('utf8', nameStart, nameStart + namesz).replace(/\0+$/, '');
    out.push({
      segment: segmentIndex,
      name,
      type,
      typeName: NOTE_TYPE_NAMES[type] ?? `type-${type}`,
      descSize: descsz,
    });
    position = descStart + descPadded;
    if (descPadded === 0 && namesz === 0 && descsz === 0) {
      // 防御性跳出，避免零长 note 造成死循环。
      break;
    }
  }
  return limitation;
}

/**
 * 观察 ELF：是否存在 note 段及其内容。
 * @param {Buffer} buffer 制品字节
 * @returns {Record<string, unknown>} 观察结果
 */
export function analyzeElf(buffer) {
  const base = {
    observer: 'elf-note',
    container: 'elf',
    signatureDetected: false,
    checksumDetected: false,
  };

  if (!Buffer.isBuffer(buffer) || buffer.length < 20 || buffer[0] !== 0x7f || buffer[1] !== 0x45 || buffer[2] !== 0x4c || buffer[3] !== 0x46) {
    return {
      ...base,
      parseable: false,
      limitation: '不是有效的 ELF 文件（缺少 ELF 魔数）',
      notes: [],
      hasNotes: false,
      gate: { action: 'observe-only', requiresResign: false, reason: '无法解析 ELF 结构' },
    };
  }

  const is64 = buffer[4] === 2;
  const is32 = buffer[4] === 1;
  const little = buffer[5] === 1;
  if (!is64 && !is32) {
    return {
      ...base,
      parseable: false,
      limitation: `ELF 类别无法识别：${buffer[4]}`,
      notes: [],
      hasNotes: false,
      gate: { action: 'observe-only', requiresResign: false, reason: 'ELF 类别无法识别' },
    };
  }

  let phoff;
  let phentsize;
  let phnum;
  if (is64) {
    phoff = rd64(buffer, 32, little);
    phentsize = rd16(buffer, 54, little);
    phnum = rd16(buffer, 56, little);
  } else {
    phoff = rd32(buffer, 28, little);
    phentsize = rd16(buffer, 42, little);
    phnum = rd16(buffer, 44, little);
  }

  const notes = [];
  const limitations = [];
  const phdrSize = is64 ? 56 : 28;

  for (let index = 0; index < phnum; index += 1) {
    const ph = phoff + index * phentsize;
    if (ph + phdrSize > buffer.length) {
      limitations.push(`第 ${index + 1} 个程序头越界，停止枚举`);
      break;
    }
    const pType = rd32(buffer, ph, little);
    if (pType !== PT_NOTE) {
      continue;
    }
    let pOffset;
    let pFilesz;
    if (is64) {
      pOffset = rd64(buffer, ph + 8, little);
      pFilesz = rd64(buffer, ph + 32, little);
    } else {
      pOffset = rd32(buffer, ph + 4, little);
      pFilesz = rd32(buffer, ph + 16, little);
    }
    if (pOffset + pFilesz > buffer.length) {
      limitations.push(`第 ${index + 1} 个 PT_NOTE 段内容越界，跳过`);
      continue;
    }
    const noteLimitation = parseNotes(buffer, pOffset, pFilesz, index, little, notes);
    if (noteLimitation !== null) {
      limitations.push(noteLimitation);
    }
  }

  const hasNotes = notes.length > 0;
  return {
    ...base,
    parseable: true,
    limitation: limitations.length > 0 ? limitations.join('；') : null,
    notes,
    hasNotes,
    programHeaderCount: phnum,
    gate: {
      action: 'observe-only',
      requiresResign: false,
      reason: hasNotes
        ? 'ELF note 为构建标识等元数据，只观察不据此拒改；改写 note 内容需走必需集豁免'
        : '未检测到 note 段',
    },
  };
}

/** ELF note 观察器登记项。 */
export const ELF_NOTE_OBSERVER = Object.freeze({
  id: 'elf-note',
  containers: Object.freeze(['elf']),
  observes: 'ELF note 段是否存在构建标识等签名性元数据',
  defaultBehavior: '只观察，不据此拒改，但改写 note 内容需走必需集豁免',
  analyze: analyzeElf,
});
