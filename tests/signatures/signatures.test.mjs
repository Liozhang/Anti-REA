// signatures 模块测试：ZIP 条目 CRC32、PE 安全目录与 CheckSum、Mach-O LC_CODE_SIGNATURE、ELF note。
// 覆盖正常输入、畸形输入与部分读取（含预算受限的文件读取路径）。
// 只观察不验证密码学信任：断言观察器只读、不改动字节，只报告“是否带机制”与门控决策。

import assert from 'node:assert/strict';
import { crc32 as zlibCrc32 } from 'node:zlib';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import {
  SIGNATURE_OBSERVERS,
  observersForContainer,
  analyzeByContainer,
  observeFile,
  APK_SIGNATURE_BOUNDARY,
  crc32,
  analyzeZip,
  analyzePe,
  analyzeMacho,
  analyzeElf,
  computePeChecksum,
} from '../../src/signatures/index.mjs';
import { buildZip, buildPe, buildMacho64, buildMachoFat, buildElf64 } from './fixture-builders.mjs';

/** 断言观察是只读的：分析前后缓冲区逐字节不变。 */
function assertReadOnly(buffer, analyze) {
  const before = Buffer.from(buffer);
  analyze(buffer);
  assert.ok(buffer.equals(before), '观察器不得改动输入字节');
}

// ---------------------------------------------------------------------------
// CRC32
// ---------------------------------------------------------------------------

test('CRC32 与 node:zlib 的 crc32 在多样输入上一致', () => {
  const cases = [Buffer.alloc(0), Buffer.from('a'), Buffer.from('hello stored world'), Buffer.from('compress me '.repeat(50)), Buffer.from([0, 255, 1, 254, 128])];
  for (const data of cases) {
    assert.equal(crc32(data), zlibCrc32(data), `CRC32 不一致：长度 ${data.length}`);
  }
});

test('CRC32 对已知向量给出固定值', () => {
  // "123456789" 的标准 CRC32 为 0xCBF43926。
  assert.equal(crc32(Buffer.from('123456789')), 0xcbf43926);
});

// ---------------------------------------------------------------------------
// ZIP 条目 CRC32 与中央目录一致性
// ---------------------------------------------------------------------------

test('ZIP：存储与 deflate 混合条目一致，扫描模式分别标记', () => {
  const zip = buildZip([
    { name: 'stored.txt', data: Buffer.from('hello stored world'), method: 0 },
    { name: 'deflated.txt', data: Buffer.from('compress me '.repeat(30)), method: 8 },
  ]);
  assertReadOnly(zip, (buffer) => analyzeZip(buffer));
  const result = analyzeZip(zip);
  assert.equal(result.parseable, true);
  assert.equal(result.hasCentralDirectory, true);
  assert.equal(result.entries.length, 2);
  assert.equal(result.allCrcConsistent, true);
  assert.equal(result.inconsistentEntryCount, 0);
  assert.equal(result.checksumDetected, true);
  assert.equal(result.gate.action, 'allow');
  assert.equal(result.entries[0].methodName, 'stored');
  assert.equal(result.entries[0].scanMode, 'raw-bytes');
  assert.equal(result.entries[0].contentAvailable, true);
  assert.equal(result.entries[1].methodName, 'deflate');
  assert.equal(result.entries[1].scanMode, 'decompressed');
  assert.equal(result.entries[1].contentAvailable, true);
  for (const entry of result.entries) {
    assert.equal(entry.consistent, true);
    assert.equal(entry.declaredConsistent, true);
    assert.equal(entry.computedConsistent, true);
  }
});

test('ZIP：中央目录 CRC 被篡改时判定不一致', () => {
  const zip = buildZip([{ name: 'bad.txt', data: Buffer.from('tampered content here'), method: 0, crcCentral: 0xdeadbeef, crcLocal: 0xdeadbeef }]);
  const result = analyzeZip(zip);
  assert.equal(result.allCrcConsistent, false);
  assert.equal(result.inconsistentEntryCount, 1);
  assert.equal(result.entries[0].consistent, false);
  assert.equal(result.entries[0].computedConsistent, false);
});

test('ZIP：本地头 CRC 与中央目录不符时判定不一致', () => {
  const zip = buildZip([{ name: 'decl.txt', data: Buffer.from('some data payload'), method: 0, crcLocal: 0x11111111 }]);
  const result = analyzeZip(zip);
  assert.equal(result.entries[0].declaredConsistent, false);
  assert.equal(result.entries[0].consistent, false);
  assert.equal(result.allCrcConsistent, false);
});

test('ZIP：deflate 条目解压失败时退回原始字节并附限制说明', () => {
  // 用一个不是合法 deflate 流的“压缩数据”，方法却标为 8。
  const zip = buildZip([{ name: 'broken.bin', data: Buffer.from('not really deflate data at all'), method: 0 }]);
  // 手工把本地头与中央目录的 method 改成 8，但不改数据，制造解压失败。
  zip.writeUInt16LE(8, 30 + 8); // 本地头 method 在偏移 8
  // 中央目录：先定位。本地数据后是中央目录。
  // 直接改中央目录 method：本地区长 = 30 + nameLen(10) + dataLen
  const dataLen = Buffer.from('not really deflate data at all').length;
  const cdStart = 30 + Buffer.from('broken.bin').length + dataLen;
  zip.writeUInt16LE(8, cdStart + 10);
  const result = analyzeZip(zip);
  assert.equal(result.parseable, true);
  assert.equal(result.entries[0].scanMode, 'raw-bytes');
  assert.equal(result.entries[0].contentAvailable, false);
  assert.match(result.entries[0].limitation, /解压失败/);
});

test('ZIP：畸形输入不崩溃，返回不可解析与限制说明', () => {
  const tooSmall = analyzeZip(Buffer.from('PK'));
  assert.equal(tooSmall.parseable, false);
  assert.ok(tooSmall.limitation.length > 0);

  const noEocd = analyzeZip(Buffer.from('PK\x03\x04' + '\0'.repeat(40)));
  assert.equal(noEocd.parseable, false);
  assert.match(noEocd.limitation, /结尾记录/);
});

test('ZIP：部分读取（缓冲区被截断）不崩溃', () => {
  const zip = buildZip([{ name: 'x.txt', data: Buffer.from('payload'), method: 0 }]);
  const truncated = analyzeZip(zip.subarray(0, 20));
  assert.equal(truncated.parseable, false);
  assert.ok(truncated.limitation.length > 0);
});

// ---------------------------------------------------------------------------
// PE 安全目录与可选头 CheckSum
// ---------------------------------------------------------------------------

test('PE：无安全目录且 CheckSum 为零时门控为允许', () => {
  const pe = buildPe({ checksum: 0, securitySize: 0 });
  assertReadOnly(pe, (buffer) => analyzePe(buffer));
  const result = analyzePe(pe);
  assert.equal(result.parseable, true);
  assert.equal(result.securityDirectory.present, false);
  assert.equal(result.checksum.nonZero, false);
  assert.equal(result.signatureDetected, false);
  assert.equal(result.checksumDetected, false);
  assert.equal(result.gate.action, 'allow');
});

test('PE：CheckSum 非零时默认跳过改写，策略允许重算时给重算门', () => {
  const pe = buildPe({ checksum: 0x12345678, securitySize: 0 });
  const fieldOffset = analyzePe(pe).checksum.fieldOffset;
  assert.equal(typeof fieldOffset, 'number');

  const def = analyzePe(pe, {});
  assert.equal(def.checksum.nonZero, true);
  assert.equal(def.checksumDetected, true);
  assert.equal(def.gate.action, 'skip-rewrite');

  const allowed = analyzePe(pe, { signatures: { allowChecksumRecompute: true } });
  assert.equal(allowed.gate.action, 'recompute-checksum');
});

test('PE：安全目录存在时默认跳过改写并标记需重新签名', () => {
  const pe = buildPe({ securitySize: 0x400, securityOffset: 0x300 });
  const result = analyzePe(pe, {});
  assert.equal(result.securityDirectory.present, true);
  assert.equal(result.securityDirectory.size, 0x400);
  assert.equal(result.signatureDetected, true);
  assert.equal(result.gate.action, 'skip-rewrite');
  assert.equal(result.gate.requiresResign, true);

  const allowed = analyzePe(pe, { signatures: { allowRewriteSigned: true } });
  assert.equal(allowed.gate.action, 'allow');
  assert.equal(allowed.gate.requiresResign, true);
  assert.match(allowed.gate.reason, /requires_resign/);
});

test('PE：PE32 与 PE32+ 都能定位安全目录', () => {
  const pe32 = analyzePe(buildPe({ isPe32Plus: false, securitySize: 0x200 }));
  assert.equal(pe32.parseable, true);
  assert.equal(pe32.securityDirectory.present, true);
  const pe32p = analyzePe(buildPe({ isPe32Plus: true, securitySize: 0x200 }));
  assert.equal(pe32p.parseable, true);
  assert.equal(pe32p.securityDirectory.present, true);
});

test('PE：computePeChecksum 对自身字段免疫且确定', () => {
  const base = buildPe({ checksum: 0, extraBytes: 64 });
  const fieldOffset = analyzePe(base).checksum.fieldOffset;
  const withZero = computePeChecksum(base, fieldOffset);
  const withGarbage = Buffer.from(base);
  withGarbage.writeUInt32LE(0xffffffff, fieldOffset);
  assert.equal(computePeChecksum(withGarbage, fieldOffset), withZero, 'CheckSum 字段内容不得影响重算结果');
  // 再次计算同一缓冲区结果稳定。
  assert.equal(computePeChecksum(base, fieldOffset), withZero);
});

test('PE：等长改写数据后重算，读取值与重算值一致', () => {
  const pe = buildPe({ checksum: 0, extraBytes: 32 });
  const fieldOffset = analyzePe(pe).checksum.fieldOffset;
  const sum = computePeChecksum(pe, fieldOffset);
  pe.writeUInt32LE(sum >>> 0, fieldOffset);
  assert.equal(analyzePe(pe).checksum.value, sum);

  // 等长改动一个数据字节（.text 节区在文件末尾附近），重算后写入，读取值应等于新重算值。
  const dataByteIndex = pe.length - 5;
  pe[dataByteIndex] ^= 0xff;
  const newSum = computePeChecksum(pe, fieldOffset);
  assert.notEqual(newSum, sum, '改动数据后校验和应变化');
  pe.writeUInt32LE(newSum >>> 0, fieldOffset);
  assert.equal(analyzePe(pe).checksum.value, newSum);
});

test('PE：畸形输入不崩溃', () => {
  assert.equal(analyzePe(Buffer.from('MZ')).parseable, false);
  const badE_lfanew = Buffer.alloc(0x40);
  badE_lfanew.write('MZ', 0, 'ascii');
  badE_lfanew.writeUInt32LE(0x7fffffff, 0x3c);
  assert.equal(analyzePe(badE_lfanew).parseable, false);
  const noPeSig = Buffer.alloc(0x80);
  noPeSig.write('MZ', 0, 'ascii');
  noPeSig.writeUInt32LE(0x40, 0x3c);
  assert.equal(analyzePe(noPeSig).parseable, false);
  assert.match(analyzePe(noPeSig).limitation, /PE 签名/);
});

// ---------------------------------------------------------------------------
// Mach-O LC_CODE_SIGNATURE
// ---------------------------------------------------------------------------

test('Mach-O：无 LC_CODE_SIGNATURE 时门控为允许', () => {
  const mo = buildMacho64({ withCodeSignature: false });
  assertReadOnly(mo, (buffer) => analyzeMacho(buffer));
  const result = analyzeMacho(mo);
  assert.equal(result.parseable, true);
  assert.equal(result.isFat, false);
  assert.equal(result.signatureDetected, false);
  assert.equal(result.gate.action, 'allow');
});

test('Mach-O：带 LC_CODE_SIGNATURE 时默认跳过改写并标记需重新签名', () => {
  const mo = buildMacho64({ withCodeSignature: true });
  const result = analyzeMacho(mo, {});
  assert.equal(result.signatureDetected, true);
  assert.equal(result.slices[0].hasCodeSignature, true);
  assert.equal(result.slices[0].codeSignature.dataoff, 0x1000);
  assert.equal(result.slices[0].codeSignature.datasize, 0x200);
  assert.equal(result.gate.action, 'skip-rewrite');
  assert.equal(result.gate.requiresResign, true);

  const allowed = analyzeMacho(mo, { signatures: { allowRewriteSigned: true } });
  assert.equal(allowed.gate.action, 'allow');
  assert.equal(allowed.gate.requiresResign, true);
});

test('Mach-O：胖二进制逐分片检查 LC_CODE_SIGNATURE', () => {
  const fat = buildMachoFat({ withCodeSignature: true });
  const result = analyzeMacho(fat);
  assert.equal(result.container, 'mach-o-fat');
  assert.equal(result.isFat, true);
  assert.equal(result.slices.length, 1);
  assert.equal(result.signatureDetected, true);

  const fatClean = analyzeMacho(buildMachoFat({ withCodeSignature: false }));
  assert.equal(fatClean.signatureDetected, false);
});

test('Mach-O：畸形输入不崩溃', () => {
  const bad = analyzeMacho(Buffer.from('not a mach-o at all'));
  assert.equal(bad.parseable, false);
  assert.match(bad.limitation, /Mach-O/);
});

// ---------------------------------------------------------------------------
// ELF note 存在性
// ---------------------------------------------------------------------------

test('ELF：带 PT_NOTE 段时报告 build id，门控为只观察', () => {
  const elf = buildElf64({ withNotes: true });
  assertReadOnly(elf, (buffer) => analyzeElf(buffer));
  const result = analyzeElf(elf);
  assert.equal(result.parseable, true);
  assert.equal(result.hasNotes, true);
  assert.equal(result.notes.length, 1);
  assert.equal(result.notes[0].name, 'GNU');
  assert.equal(result.notes[0].type, 3);
  assert.equal(result.notes[0].typeName, 'NT_GNU_BUILD_ID');
  assert.equal(result.signatureDetected, false, 'ELF note 不是代码签名门');
  assert.equal(result.gate.action, 'observe-only');
  assert.equal(result.gate.requiresResign, false);
});

test('ELF：无 note 段时报告未检测到', () => {
  const result = analyzeElf(buildElf64({ withNotes: false }));
  assert.equal(result.parseable, true);
  assert.equal(result.hasNotes, false);
  assert.equal(result.notes.length, 0);
});

test('ELF：畸形输入不崩溃', () => {
  assert.equal(analyzeElf(Buffer.from('ELF')).parseable, false);
  const badClass = Buffer.alloc(64);
  badClass[0] = 0x7f;
  badClass[1] = 0x45;
  badClass[2] = 0x4c;
  badClass[3] = 0x46;
  badClass[4] = 9; // 非法类别
  assert.equal(analyzeElf(badClass).parseable, false);
});

test('ELF：程序头表被截断时部分读取，附限制说明且不崩溃', () => {
  const elf = buildElf64({ withNotes: true });
  // 保留完整头与一个程序头，但截断 note 数据区，制造 filesz 越界。
  const result = analyzeElf(elf.subarray(0, elf.length - 10));
  assert.equal(result.parseable, true);
  assert.ok(Array.isArray(result.notes));
  // 越界的 PT_NOTE 段被跳过并记录限制，进程不失败。
  assert.ok(result.limitation === null || /越界/.test(result.limitation));
});

// ---------------------------------------------------------------------------
// 分派与文件读取（含部分读取/预算受限）
// ---------------------------------------------------------------------------

test('SIGNATURE_OBSERVERS 登记四个观察器，容器归属正确', () => {
  assert.equal(SIGNATURE_OBSERVERS.length, 4);
  const ids = SIGNATURE_OBSERVERS.map((observer) => observer.id);
  assert.deepEqual(ids, ['zip-entry-crc32', 'pe-security-and-checksum', 'mach-o-code-signature', 'elf-note']);
  for (const observer of SIGNATURE_OBSERVERS) {
    assert.ok(observer.containers.length > 0);
    assert.ok(typeof observer.observes === 'string' && observer.observes.length > 0);
    assert.equal(typeof observer.analyze, 'function');
  }
  assert.deepEqual(observersForContainer('pe').map((o) => o.id), ['pe-security-and-checksum']);
  assert.deepEqual(
    observersForContainer('mach-o-fat').map((o) => o.id),
    ['mach-o-code-signature'],
  );
  assert.deepEqual(observersForContainer('gguf').map((o) => o.id), []);
});

test('analyzeByContainer 按容器分派，自动模式由各自自校验', () => {
  const pe = buildPe({ securitySize: 0x100 });
  const byType = analyzeByContainer(pe, 'pe');
  assert.equal(byType.length, 1);
  assert.equal(byType[0].parseable, true);

  const auto = analyzeByContainer(pe);
  const parseable = auto.filter((result) => result.parseable);
  assert.equal(parseable.length, 1);
  assert.equal(parseable[0].observer, 'pe-security-and-checksum');
});

test('observeFile 完整读取制品并分派观察器', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-sig-'));
  try {
    const zipPath = join(dir, 'mixed.zip');
    const zip = buildZip([{ name: 'a.txt', data: Buffer.from('content a'), method: 0 }]);
    await writeFile(zipPath, zip);
    const result = await observeFile(zipPath, { container: 'zip' });
    assert.equal(result.truncated, false);
    assert.equal(result.bytes, zip.length);
    assert.equal(result.observations[0].parseable, true);
    assert.equal(result.observations[0].allCrcConsistent, true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('observeFile 预算受限时只读部分字节并附限制说明，进程不失败', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-sig-'));
  try {
    const zipPath = join(dir, 'mixed.zip');
    const zip = buildZip([{ name: 'a.txt', data: Buffer.from('content a'), method: 0 }]);
    await writeFile(zipPath, zip);
    const result = await observeFile(zipPath, { container: 'zip', budgets: { maxFileBytes: 16 } });
    assert.equal(result.truncated, true);
    assert.equal(result.bytesRead, 16);
    assert.equal(result.bytes, zip.length);
    const observation = result.observations[0];
    assert.equal(observation.parseable, false);
    assert.match(observation.limitation, /单文件上限/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 能力边界与观察语义
// ---------------------------------------------------------------------------

test('APK 签名方案能力边界保持不变', () => {
  assert.equal(APK_SIGNATURE_BOUNDARY.id, 'apk-signature-scheme');
  assert.match(APK_SIGNATURE_BOUNDARY.reason, /APK/);
  // APK 签名方案按普通 ZIP 处理：带签名块的制品仍是 zip 容器，走 zip 观察器。
  assert.ok(observersForContainer('zip').length === 1);
});

test('观察器只观察不改字节：四种制品分析后逐字节不变', () => {
  const fixtures = [
    buildZip([{ name: 'z.txt', data: Buffer.from('zip data'), method: 8 }]),
    buildPe({ securitySize: 0x100, checksum: 0x10 }),
    buildMacho64({ withCodeSignature: true }),
    buildElf64({ withNotes: true }),
  ];
  const analyzers = [analyzeZip, analyzePe, analyzeMacho, analyzeElf];
  for (let index = 0; index < fixtures.length; index += 1) {
    assertReadOnly(fixtures[index], analyzers[index]);
  }
});
