// DEX 读取器：头部声明事实、类型描述符、方法与字段名、字符串表的事实提取。
// 只读：只按头部给出的偏移与计数定位各张表，不加载、不执行任何字节码。
//
// DEX 是 Android 应用的可执行格式，也是 APK 里 classes.dex 的格式。
// 独立 .dex 文件此前落入通用脚本包边界，一条事实都提不出来——
// 而类型描述符与方法名恰恰是这类制品暴露面最大的部分：
// 反编译产物里的类名、方法名、字符串常量全部来自这几张表。
//
// 本读取器做四件事：
//   1. 头部声明事实   魔数版本、各张表的大小与偏移、文件长度
//   2. 类型描述符     type_ids 经 string_ids 取出的 Lcom/example/Foo; 形式类名
//   3. 方法与字段名   method_ids 与 field_ids 经 string_ids 取出名字
//   4. 字符串与令牌   按 string_ids 偏移逐一取出字符串，并对全部已读字节跑令牌扫描
//
// 畸形输入一律转成限制说明：偏移越界、计数不合理、字符串读不出来，
// 都写成“解析到哪里、缺什么”，不让审计失败，也不返回空结果冒充没有暴露。

import { createFinding } from '../audit/finding.mjs';
import {
  defineReader,
  limitation,
  readEntryBytes,
  readUIntLE,
  readUvarint,
  sanitizeExcerpt,
  truncationLimitation,
} from './common.mjs';
import { appendTokenScan } from './scan.mjs';

/** DEX 头部长度，固定 112 字节。 */
const DEX_HEADER_BYTES = 112;

/** 字节序标记，合法值固定为 0x12345678 小端。 */
const DEX_ENDIAN_TAG = 0x12345678;

/** 单张表最多登记的条目数，超出部分在限制说明里声明。 */
const TABLE_ITEM_LIMIT = 4096;

/** 单个字符串最多登记的字符数，与证据摘录上限一致。 */
const STRING_CHAR_LIMIT = 4096;

/** 类型描述符样例最多登记的条数。 */
const SAMPLE_LIMIT = 32;

/** 头部各字段的偏移。字段名与 DEX 规范一致。 */
const HEADER_FIELDS = Object.freeze({
  magic: 0,
  checksum: 8,
  signature: 12,
  fileSize: 32,
  headerSize: 36,
  endianTag: 40,
  linkSize: 44,
  linkOff: 48,
  mapOff: 52,
  stringIdsSize: 56,
  stringIdsOff: 60,
  typeIdsSize: 64,
  typeIdsOff: 68,
  protoIdsSize: 72,
  protoIdsOff: 76,
  fieldIdsSize: 80,
  fieldIdsOff: 84,
  methodIdsSize: 88,
  methodIdsOff: 92,
  classDefsSize: 96,
  classDefsOff: 100,
  dataSize: 104,
  dataOff: 108,
});

/** 表描述：编号后缀、标签、条目字节数、偏移字段、计数字段。 */
const TABLES = Object.freeze([
  { key: 'string', label: '字符串索引', itemBytes: 4, sizeField: 'stringIdsSize', offField: 'stringIdsOff' },
  { key: 'type', label: '类型索引', itemBytes: 4, sizeField: 'typeIdsSize', offField: 'typeIdsOff' },
  { key: 'proto', label: '原型索引', itemBytes: 12, sizeField: 'protoIdsSize', offField: 'protoIdsOff' },
  { key: 'field', label: '字段索引', itemBytes: 8, sizeField: 'fieldIdsSize', offField: 'fieldIdsOff' },
  { key: 'method', label: '方法索引', itemBytes: 8, sizeField: 'methodIdsSize', offField: 'methodIdsOff' },
  { key: 'class', label: '类定义', itemBytes: 32, sizeField: 'classDefsSize', offField: 'classDefsOff' },
]);

/**
 * 读取 DEX 头部全部字段。
 * @param {Buffer} bytes 制品字节
 * @returns {{fields: Record<string, number>, problems: string[]}}
 */
function readHeader(bytes) {
  const fields = {};
  const problems = [];
  for (const [name, offset] of Object.entries(HEADER_FIELDS)) {
    if (name === 'magic' || name === 'signature') {
      continue;
    }
    const value = readUIntLE(bytes, offset, 4);
    if (value === undefined) {
      problems.push(`头部字段 ${name} 位于偏移 ${offset}，超出已读取的 ${bytes.length} 字节`);
      continue;
    }
    fields[name] = value;
  }
  return { fields, problems };
}

/**
 * 按 string_ids 偏移取出一条字符串。
 * string_data_item 的结构是：uleb128 长度（按 UTF-16 码元计），随后是 MUTF-8 字节，最后是零字节。
 * @param {Buffer} bytes 制品字节
 * @param {number} offset string_data_item 的偏移
 * @returns {{text: string, consumed: number} | null}
 */
function readStringData(bytes, offset) {
  if (offset < 0 || offset >= bytes.length) {
    return null;
  }
  const length = readUvarint(bytes, offset);
  if (length === undefined || length.value > STRING_CHAR_LIMIT) {
    return null;
  }
  let position = length.next;
  let text = '';
  let consumed = 0;
  while (position < bytes.length && text.length < length.value) {
    const byte = bytes[position];
    position += 1;
    consumed += 1;
    if (byte === 0) {
      break;
    }
    // MUTF-8 与 UTF-8 在字符串表里的实际内容上一致；非 ASCII 字节原样透出，
    // 由 sanitizeExcerpt 在入报告前净化，这里不做编码猜测。
    text += String.fromCharCode(byte);
  }
  if (text.length === 0) {
    return null;
  }
  return { text, consumed };
}

/**
 * 按 string_ids 偏移取出字符串，最多取到 SAMPLE_LIMIT 条作为样例，同时报告可读条数。
 * @param {Buffer} bytes 制品字节
 * @param {{stringIdsSize: number, stringIdsOff: number}} header 头部字段
 * @returns {{strings: string[], readableCount: number, problems: string[]}}
 */
function readStringTable(bytes, header) {
  const strings = [];
  const problems = [];
  const total = Math.min(header.stringIdsSize, TABLE_ITEM_LIMIT);
  let readableCount = 0;
  for (let index = 0; index < total; index += 1) {
    const entryOffset = header.stringIdsOff + index * 4;
    const dataOffset = readUIntLE(bytes, entryOffset, 4);
    if (dataOffset === undefined) {
      problems.push(`字符串索引第 ${index} 项的偏移字段位于 ${entryOffset}，超出已读取范围`);
      break;
    }
    const decoded = readStringData(bytes, dataOffset);
    if (decoded === null) {
      continue;
    }
    readableCount += 1;
    if (strings.length < SAMPLE_LIMIT) {
      strings.push(decoded.text);
    }
  }
  if (header.stringIdsSize > TABLE_ITEM_LIMIT) {
    problems.push(`字符串索引声明 ${header.stringIdsSize} 条，本次只解析前 ${TABLE_ITEM_LIMIT} 条`);
  }
  return { strings, readableCount, problems };
}

/**
 * 按 string_ids 下标取字符串。需要字符串索引表本身可读，因此单独传入其偏移与计数。
 * @param {Buffer} bytes 制品字节
 * @param {number} index string_ids 下标
 * @param {{stringIdsSize: number, stringIdsOff: number}} stringTable 字符串索引表位置
 * @returns {string | null}
 */
function readStringByIndex(bytes, index, stringTable) {
  if (index >= stringTable.stringIdsSize) {
    return null;
  }
  const entryOffset = stringTable.stringIdsOff + index * 4;
  const dataOffset = readUIntLE(bytes, entryOffset, 4);
  if (dataOffset === undefined) {
    return null;
  }
  const decoded = readStringData(bytes, dataOffset);
  return decoded === null ? null : decoded.text;
}

/**
 * 按字节解析 DEX，返回发现与限制说明。
 * 与读取器入口分开的原因：ZIP 读取器要从 APK 条目里取出 classes.dex 的字节后
 * 复用同一套解析，此时字节已在内存中，不能再走读文件那条路。
 * @param {Buffer} bytes DEX 字节
 * @param {string} path 证据路径，调用方可传入条目内路径（如 app.apk!classes.dex）
 * @returns {{findings: Array<Record<string, unknown>>, limitations: Array<Record<string, unknown>>}}
 */
export function parseDex(bytes, path) {
  const findings = [];
  const limitations = [];

  if (bytes.length < 8 || bytes.toString('latin1', 0, 4) !== 'dex\n') {
    limitations.push(
      limitation('dex-container-missing', '文件不是以 dex 加换行开头的 DEX 容器。该条目不等于没有暴露，只是本次没有提取到事实'),
    );
    return { findings, limitations };
  }
  // 字符串表与常量池里可能带凭据：容器结构已确认，扫全部已读字节。
  appendTokenScan(bytes, findings, limitations, { path, reader: 'dex' });

  const version = sanitizeExcerpt(bytes.subarray(4, 8));
  if (bytes.length < DEX_HEADER_BYTES) {
    limitations.push(
      limitation('dex-header-truncated', `文件仅 ${bytes.length} 字节，不足 DEX 头部固定的 ${DEX_HEADER_BYTES} 字节，各张表的偏移与计数不可读，本次没有提取结构事实`),
    );
    findings.push(
      createFinding({
        layer: 'metadata-hygiene',
        severity: 'info',
        title: 'DEX 魔数与版本',
        category: 'dex-magic',
        evidence: { path, byteRange: [0, 8], excerpt: `dex ${version}` },
        reader: 'dex',
        readerLimitation: '只读魔数与版本号，头部其余字段因文件过短不可读',
        mitigation: null,
        detail: { version },
      }),
    );
    return { findings, limitations };
  }

  const { fields, problems } = readHeader(bytes);
  for (const problem of problems) {
    limitations.push(limitation('dex-header-field-unreadable', `${problem}。该条目不等于没有暴露，只是本次没有提取到事实`));
  }

  const endianOk = fields.endianTag === DEX_ENDIAN_TAG;
  if (!endianOk) {
    limitations.push(
      limitation(
        'dex-endian-tag-mismatch',
        `字节序标记为 0x${(fields.endianTag ?? 0).toString(16)}，不是 DEX 规定的 0x${DEX_ENDIAN_TAG.toString(16)}；后续各表的字段按小端解释，结论可能不成立`,
      ),
    );
  }

  // 表格区间合理性：任一张表的区间越界，就说明头部的偏移或计数不可信，
  // 此时不按这些偏移去读内容，只登记头部声明本身。
  const tableProblems = [];
  const usableTables = [];
  for (const table of TABLES) {
    const size = fields[table.sizeField];
    const off = fields[table.offField];
    if (!Number.isFinite(size) || !Number.isFinite(off)) {
      continue;
    }
    if (size === 0) {
      continue;
    }
    const end = off + size * table.itemBytes;
    if (end > bytes.length) {
      tableProblems.push(`${table.label}声明 ${size} 项、位于偏移 ${off}，区间终点 ${end} 超出已读取的 ${bytes.length} 字节，该表没有解析`);
      continue;
    }
    usableTables.push({ ...table, size, off });
  }
  for (const problem of tableProblems) {
    limitations.push(limitation('dex-table-out-of-range', `${problem}。该条目不等于没有暴露，只是本次没有提取到事实`));
  }

  findings.push(
    createFinding({
      layer: 'metadata-hygiene',
      severity: 'info',
      title: 'DEX 头部声明的格式事实',
      category: 'dex-header',
      evidence: { path, byteRange: [0, DEX_HEADER_BYTES], excerpt: `dex ${version}` },
      reader: 'dex',
      readerLimitation:
        '只读头部声明的各表大小与偏移，不解析指令流、不恢复源码；头部字段可被伪造，声明与真实内容未必一致',
      mitigation: null,
      detail: {
        version,
        fileSize: fields.fileSize ?? null,
        headerSize: fields.headerSize ?? null,
        endianTag: fields.endianTag ?? null,
        endianTagOk: endianOk,
        checksum: fields.checksum ?? null,
        linkSize: fields.linkSize ?? null,
        linkOff: fields.linkOff ?? null,
        mapOff: fields.mapOff ?? null,
        dataSize: fields.dataSize ?? null,
        dataOff: fields.dataOff ?? null,
        tables: usableTables.map((table) => ({ key: table.key, label: table.label, size: table.size, offset: table.off })),
      },
    }),
  );

  if (fields.fileSize !== undefined && fields.fileSize > bytes.length) {
    limitations.push(
      limitation('dex-declared-size-mismatch', `头部声明文件长度 ${fields.fileSize}，实际只读取 ${bytes.length} 字节，制品可能被截断，未读取部分没有提取事实`),
    );
  }

  const stringTable = usableTables.find((table) => table.key === 'string');
  let strings = [];
  let readableStrings = 0;
  if (stringTable === undefined) {
    limitations.push(
      limitation('dex-string-table-unavailable', '字符串索引表不可用或区间越界，类型描述符与方法名均无法取出，本次只登记头部声明'),
    );
  } else {
    const table = readStringTable(bytes, { stringIdsSize: stringTable.size, stringIdsOff: stringTable.off });
    strings = table.strings;
    readableStrings = table.readableCount;
    for (const problem of table.problems) {
      limitations.push(limitation('dex-string-entry-unreadable', `${problem}。该条目不等于没有暴露，只是本次没有提取到事实`));
    }
  }

  // 类型描述符：type_ids 的每一项是 string_ids 下标，取出的字符串形如 Lcom/example/Foo;。
  const typeTable = usableTables.find((table) => table.key === 'type');
  let typeNames = [];
  if (typeTable !== undefined && stringTable !== undefined) {
    const stringTableInfo = { stringIdsSize: stringTable.size, stringIdsOff: stringTable.off };
    const names = [];
    const problems = [];
    const total = Math.min(typeTable.size, TABLE_ITEM_LIMIT);
    for (let index = 0; index < total; index += 1) {
      const itemOffset = typeTable.off + index * 4;
      const descriptorIndex = readUIntLE(bytes, itemOffset, 4);
      if (descriptorIndex === undefined) {
        problems.push(`类型索引第 ${index} 项位于 ${itemOffset}，超出已读取的 ${bytes.length} 字节，该项及其后的条目没有解析`);
        break;
      }
      const text = readStringByIndex(bytes, descriptorIndex, stringTableInfo);
      if (text === null) {
        continue;
      }
      if (names.length < SAMPLE_LIMIT) {
        names.push(text);
      }
    }
    typeNames = names;
    for (const problem of problems) {
      limitations.push(limitation('dex-type-entry-unreadable', `${problem}。该条目不等于没有暴露，只是本次没有提取到事实`));
    }
  }

  // 方法名与字段名：两项的最后一个字段都是 string_ids 下标。
  const nameTables = usableTables.filter((table) => table.key === 'method' || table.key === 'field');
  const methodNames = [];
  const fieldNames = [];
  const methodTable = nameTables.find((table) => table.key === 'method');
  const fieldTable = nameTables.find((table) => table.key === 'field');
  if (stringTable === undefined) {
    limitations.push(
      limitation('dex-name-tables-unavailable', '字符串索引表不可用，方法名与字段名无法经 string_ids 取出，本次只登记头部声明'),
    );
  }
  for (const table of nameTables) {
    if (stringTable === undefined) {
      break;
    }
    const stringTableInfo = { stringIdsSize: stringTable.size, stringIdsOff: stringTable.off };
    const total = Math.min(table.size, TABLE_ITEM_LIMIT);
    const collected = [];
    for (let index = 0; index < total; index += 1) {
      const itemOffset = table.off + index * table.itemBytes;
      if (itemOffset + table.itemBytes > bytes.length) {
        limitations.push(
          limitation('dex-name-entry-unreadable', `${table.label}第 ${index} 项位于 ${itemOffset}，超出已读取的 ${bytes.length} 字节，该项及其后的条目没有解析`),
        );
        break;
      }
      const nameIndex = readUIntLE(bytes, itemOffset + table.itemBytes - 4, 4);
      if (nameIndex === undefined) {
        continue;
      }
      const text = readStringByIndex(bytes, nameIndex, stringTableInfo);
      if (text === null) {
        continue;
      }
      if (collected.length < SAMPLE_LIMIT) {
        collected.push(text);
      }
    }
    if (table.key === 'method') {
      methodNames.push(...collected);
    } else {
      fieldNames.push(...collected);
    }
  }

  if (typeTable !== undefined && typeNames.length > 0) {
    findings.push(
      createFinding({
        layer: 'metadata-hygiene',
        severity: 'medium',
        title: 'DEX 类型描述符',
        category: 'dex-type-descriptors',
        evidence: { path, byteRange: [typeTable.off, typeTable.off + typeTable.size * 4], excerpt: typeNames.slice(0, 8).join('、') },
        reader: 'dex',
        readerLimitation:
          '类型描述符按 type_ids 经 string_ids 取出，形如“Lcom/example/Foo;”这样的类名；不解析类成员、注解与指令流，混淆后的短名同样如实登记',
        mitigation: null,
        detail: { declaredCount: typeTable.size, sampleCount: typeNames.length, sampleTypes: typeNames },
      }),
    );
  }

  if (methodTable !== undefined && methodNames.length > 0) {
    findings.push(
      createFinding({
        layer: 'metadata-hygiene',
        severity: 'medium',
        title: 'DEX 方法名',
        category: 'dex-method-names',
        evidence: { path, byteRange: [methodTable.off, methodTable.off + methodTable.size * 8], excerpt: methodNames.slice(0, 8).join('、') },
        reader: 'dex',
        readerLimitation: '方法名按 method_ids 的名字列经 string_ids 取出，不含签名与所属类；不解析方法体',
        mitigation: null,
        detail: { declaredCount: methodTable.size, sampleCount: methodNames.length, sampleMethods: methodNames },
      }),
    );
  }

  if (fieldTable !== undefined && fieldNames.length > 0) {
    findings.push(
      createFinding({
        layer: 'metadata-hygiene',
        severity: 'low',
        title: 'DEX 字段名',
        category: 'dex-field-names',
        evidence: { path, byteRange: [fieldTable.off, fieldTable.off + fieldTable.size * 8], excerpt: fieldNames.slice(0, 8).join('、') },
        reader: 'dex',
        readerLimitation: '字段名按 field_ids 的名字列经 string_ids 取出，不含类型与所属类',
        mitigation: null,
        detail: { declaredCount: fieldTable.size, sampleCount: fieldNames.length, sampleFields: fieldNames },
      }),
    );
  }

  if (stringTable !== undefined && readableStrings > 0) {
    findings.push(
      createFinding({
        layer: 'metadata-hygiene',
        severity: 'low',
        title: 'DEX 字符串常量',
        category: 'dex-string-constants',
        evidence: { path, byteRange: [stringTable.off, stringTable.off + stringTable.size * 4], excerpt: strings.slice(0, 8).join('、') },
        reader: 'dex',
        readerLimitation:
          '字符串按 string_ids 偏移逐一取出，只登记前若干条；字符串是常量池的主体，日志文案、接口地址、错误提示都在其中',
        mitigation: null,
        detail: { declaredCount: stringTable.size, readableCount: readableStrings, sampleCount: strings.length, sampleStrings: strings },
      }),
    );
  }

  return { findings, limitations };
}

/**
 * DEX 读取器入口。
 * @param {{entry: Record<string, unknown>, policy: Record<string, unknown>, budgets: Record<string, number>}} context
 * @returns {Promise<{findings: Array<Record<string, unknown>>, limitations: Array<Record<string, unknown>>}>}
 */
async function readDex(context) {
  const entry = context.entry;
  const budgets = context.budgets ?? {};
  const read = await readEntryBytes(entry, budgets);
  if (!read.complete) {
    const truncated = parseDex(read.bytes, entry.relativePath);
    truncated.limitations.unshift(truncationLimitation(read));
    return truncated;
  }
  return parseDex(read.bytes, entry.relativePath);
}

export const dexReader = defineReader({
  id: 'dex',
  formats: ['dex'],
  layers: ['metadata-hygiene', 'secret-minimization'],
  purpose: 'DEX 头部声明、类型描述符、方法名与字段名、字符串常量的事实提取',
  read: readDex,
});
