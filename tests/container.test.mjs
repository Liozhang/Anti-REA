// container 模块测试：只读容器识别与镜像解析。
// 覆盖三类输入：
//   正常输入   九类格式各至少一个真实字节夹具，经内存判定与磁盘读取两条路径
//   畸形输入   空文件、不足四字节、随机字节、确认失败、坏 JSON、范围外格式
//   部分读取   单文件上限、累计扫描窗口、条目数上限、结构魔数补读与被截断
// 夹具由 tests/helpers/container-fixtures.mjs 确定性生成，本文件把 sha256 与登记值比对，
// 保证测试跑的是固定真实字节。

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { inflateRawSync, crc32 } from 'node:zlib';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

import {
  DETECTION_PREFIX_BYTES,
  SAFETENSORS_HEADER_PROBE_MAX,
  SUPPORTED_CONTAINERS,
  detectContainer,
  detectionProbeLength,
  identifyArtifact,
  isSupportedContainer,
  peSignatureEnd,
  safetensorsHeaderLength,
} from '../src/container/index.mjs';
import { UsageError } from '../src/errors.mjs';
import { CONTAINER_FIXTURES, writeContainerFixtures } from './helpers/container-fixtures.mjs';
import { runCli } from './helpers/cli.mjs';

/** 夹具登记表里每个夹具的 sha256，与字节级构造绑定。 */
const PINNED_DIGESTS = Object.freeze({
  'elf/basic.elf': '755d7ce2ed1befb561b7c7511e443a8362fe43f1bb8b740ff92ee20d4621f063',
  'elf/header-only.elf': 'e94466faac02d08efbb3109dbe52d0c13c5a53859e328d50dbeb2e6f0ee89871',
  'pe/basic.pe': '6df48a6ee62acbea8277d45742de91a9811d7d2b0a02025ff90eea3794d086bc',
  'pe/far-signature.pe': 'e8a8fb0b98702753b341db6f89dd670b1d4d18e1506f614a36975e06c21a4953',
  'mach-o/basic.macho': '2aeec62fd909040e737b70d03db0043ebec58ff2355a8b03faf895eafa7f1587',
  'mach-o/big-endian.macho': 'e77746e83f74b8cff0f8eb0d49a127bfcc5c2cc0cc108233b537c83075c44fe0',
  'mach-o/fat.macho': 'c0860157c92cff20521fb0c0b597beea1618c64e60e182d6792785b9f3570616',
  'zip/mixed-entries.zip': '8a1daeddb8eb790ccc5802565196a1850c97f97cb38d68a2db849f0c3a371bef',
  'zip/empty.zip': '8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85',
  'gguf/basic.gguf': 'f2071bcab7dbe37049fa9707b64d882e19abb756281ae6ff459bb16143c8d2d5',
  'safetensors/basic.safetensors': '7672290adf3f8d088b16b1e093eb694fdf352d6a9ddd4ee987d92f613dd82c7b',
  'safetensors/large-header.safetensors': 'fe25e6842944ccbf6333d170cc1dfbfcd51e9770c48223d11365e3aab8423deb',
  'pyc/hash-based.pyc': '217abb3906189eb8837d784e79e409d15ec9e69679f374f9366a312693648f36',
  'pyc/timestamp-based.pyc': 'faa7f2b2500e182558b4e53df8bd214a02a534bb13d93d32d700ff482ee7b174',
  'beam/basic.beam': 'dc7f52d4f3ff2b2e76884dbe2083ab3d367fca9f2af9b7aa8b12e4db8bbcfbe9',
  'dex/basic.dex': 'bfa85d917f9d502c09c24b311206f015f106f343ffe33c1110a1e05ae6b5e1d3',
  'malformed/empty.bin': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  'malformed/tiny.bin': '039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81',
  'malformed/random.bin': '4e42bf2050186cbe1171225cc122203eff53f8d8d5c5badca05dd1d7b16863f3',
  'malformed/text-crlf.txt': 'eb99093ad052fd172002466b20c2e94767183105f1a9a85a02e2f71f4fd835ab',
  'malformed/mz-no-signature.bin': '1ed7a28a753abd67da5551c799e6001672c994a1721e5ddd1f783744720b8cda',
  'malformed/mz-truncated.bin': '26fde04a7416f96f536e69ba5da867ca17b1051c01c05998babb6782715fafbb',
  'malformed/form-aiff.bin': '899192e05cbfeb4642b7dad6b35993f4a94636deac48d4e6575777d64ab72c61',
  'malformed/safetensors-bad-json.bin': 'a9a4f28de30d3afaa24be4f850462cac4d8b26cc7c1c2fa060034a9f7db8cbf3',
  'malformed/safetensors-short.bin': '7d5f971b7961947198f30f5b5bf51c10c3b90a67d6e17b1140b110638bb367fb',
  'unsupported/il2cpp-metadata.bin': '13ba6b9915d3a38797b00e5f3975b3f01190d58320eb71c5ecab20f45f8f9ef0',
  'unsupported/apk-signature-scheme.bin': 'd6358f0b0927bc511b04bbda337836553116cacba6994cbe752c1f90917e2031',
  'unsupported/java-class.class': 'e38a171505dfe57169c6afdc13976595e6d6ea115591b808b6e0339319a8c1f6',
});

/** v1 九类格式，每类至少一个夹具。 */
const EIGHT_FORMATS = Object.freeze(['elf', 'pe', 'mach-o', 'zip', 'gguf', 'safetensors', 'pyc', 'beam']);

const fixturesRoot = await mkdtemp(join(tmpdir(), 'anti-rea-container-'));
const writtenFixtures = await writeContainerFixtures(fixturesRoot);
after(async () => {
  await rm(fixturesRoot, { recursive: true, force: true });
});

/**
 * 取夹具字节。
 * @param {string} relativePath 夹具相对路径
 * @returns {Buffer}
 */
function fixtureBytes(relativePath) {
  return writtenFixtures.find((fixture) => fixture.relativePath === relativePath).bytes;
}

/**
 * 取夹具在磁盘上的绝对路径。
 * @param {string} relativePath 夹具相对路径
 * @returns {string}
 */
function fixturePath(relativePath) {
  return join(fixturesRoot, ...relativePath.split('/'));
}

test('夹具登记表覆盖 v1 九类格式与范围外格式', () => {
  for (const container of [...EIGHT_FORMATS, 'mach-o-fat']) {
    assert.ok(
      CONTAINER_FIXTURES.some((fixture) => fixture.expected.type === container),
      `夹具登记表缺少 ${container}`,
    );
  }
  for (const unsupported of ['il2cpp-metadata', 'apk-signature-scheme']) {
    assert.ok(
      CONTAINER_FIXTURES.some((fixture) => fixture.relativePath.includes(unsupported)),
      `夹具登记表缺少范围外格式 ${unsupported}`,
    );
  }
});

test('每个夹具的 sha256 与登记值一致，保证测试跑的是固定真实字节', () => {
  assert.equal(Object.keys(PINNED_DIGESTS).length, CONTAINER_FIXTURES.length, '登记值必须逐个对应');
  for (const fixture of CONTAINER_FIXTURES) {
    const digest = createHash('sha256').update(fixture.bytes).digest('hex');
    assert.equal(digest, PINNED_DIGESTS[fixture.relativePath], `夹具摘要与登记值不一致：${fixture.relativePath}`);
  }
});

test('受支持容器集合是九类格式的封闭集合，胖二进制单列', () => {
  assert.equal(DETECTION_PREFIX_BYTES, 4096);
  assert.equal(SAFETENSORS_HEADER_PROBE_MAX, 8 * 1024 * 1024);
  for (const container of EIGHT_FORMATS) {
    assert.ok(SUPPORTED_CONTAINERS.includes(container), `受支持集合缺少 ${container}`);
  }
  assert.ok(SUPPORTED_CONTAINERS.includes('mach-o-fat'), 'Mach-O 胖二进制应在受支持集合内');
  for (const type of ['unknown', 'unsupported', 'il2cpp', '']) {
    assert.equal(isSupportedContainer(type), false, `${type} 不应视为受支持容器`);
  }
  assert.equal(isSupportedContainer('elf'), true);
});

test('九类格式夹具在内存中按魔数判定为登记的类型', () => {
  for (const fixture of CONTAINER_FIXTURES) {
    const result = detectContainer(fixture.bytes, fixture.bytes.length);
    assert.equal(result.type, fixture.expected.type, `判定结果与登记不符：${fixture.relativePath}`);
    assert.ok(result.label.length > 0, '判定必须带人读标签');
  }
});

test('固定魔数判定给出魔数偏移，结构魔数判定不带偏移', () => {
  assert.equal(detectContainer(fixtureBytes('elf/basic.elf')).magicOffset, 0);
  assert.equal(detectContainer(fixtureBytes('zip/mixed-entries.zip')).magicOffset, 0);
  assert.equal(detectContainer(fixtureBytes('gguf/basic.gguf')).magicOffset, 0);
  assert.equal(detectContainer(fixtureBytes('beam/basic.beam')).magicOffset, 0);
  assert.equal(detectContainer(fixtureBytes('safetensors/basic.safetensors')).magicOffset, undefined);
  assert.equal(detectContainer(fixtureBytes('pyc/hash-based.pyc')).magicOffset, undefined);
});

test('Mach-O 胖二进制与 Java 类文件按分片表判别，不再共用同一判定', () => {
  // 歧义说明挂在魔数上：凡判为胖二进制都带这条说明，点名 CAFEBABE 同时是 Java 类文件魔数。
  const fat = detectContainer(fixtureBytes('mach-o/fat.macho'));
  assert.equal(fat.type, 'mach-o-fat');
  assert.match(fat.note ?? '', /CAFEBABE/);

  // Java 类文件：分片数是主版本号，不是合理分片数，判为范围外容器。
  const javaClass = detectContainer(fixtureBytes('unsupported/java-class.class'));
  assert.equal(javaClass.type, 'unsupported');
  assert.equal(javaClass.label, '范围外容器');
  assert.match(javaClass.note ?? '', /CAFEBABE/);
  assert.match(javaClass.note ?? '', /Java/);
  assert.equal(isSupportedContainer(javaClass.type), false);

  // 判别依据：胖二进制在魔数之后是大端 nfat_arch 与首个分片头，Java 类文件放的是版本号与常量池计数。
  const fatBytes = fixtureBytes('mach-o/fat.macho');
  assert.equal(fatBytes.readUInt32BE(4), 1, '胖二进制夹具应声明一个分片');
  assert.equal(fatBytes.readUInt32BE(8), 0x01000007, '首个分片头的 cputype 应为 x86-64');
  assert.equal(fatBytes.readUInt32BE(16), 4096, '首个分片头声明的偏移应为 4096');
  assert.equal(4096 + fatBytes.readUInt32BE(20), fatBytes.length, '首个分片应正好覆盖到文件尾');
  const javaBytes = fixtureBytes('unsupported/java-class.class');
  assert.equal(javaBytes.readUInt32BE(4), 0x34, 'Java 类文件该位置是主版本号，不是合理分片数');
});

test('CAFEBABE 判据边界：分片数、cputype 与分片范围各自能否定胖二进制', () => {
  // 以真胖二进制夹具为底样只改分片表头字段，逐条验证判据。
  const fatBytes = fixtureBytes('mach-o/fat.macho');
  const sliceSize = fatBytes.readUInt32BE(20);
  const withArch = (archCount, cputype, offset, size) => {
    const copy = Buffer.from(fatBytes);
    copy.writeUInt32BE(archCount, 4);
    copy.writeUInt32BE(cputype, 8);
    copy.writeUInt32BE(offset, 16);
    copy.writeUInt32BE(size, 20);
    return copy;
  };

  assert.equal(detectContainer(withArch(1, 0x01000007, 4096, sliceSize), fatBytes.length).type, 'mach-o-fat');
  assert.equal(detectContainer(withArch(32, 0x01000007, 4096, sliceSize), fatBytes.length).type, 'mach-o-fat', '分片数到三十二仍算胖二进制');
  assert.equal(detectContainer(withArch(0, 0x01000007, 4096, sliceSize), fatBytes.length).type, 'unsupported', '零个分片不是胖二进制');
  assert.equal(detectContainer(withArch(33, 0x01000007, 4096, sliceSize), fatBytes.length).type, 'unsupported', '分片数超过三十二不算胖二进制');
  assert.equal(detectContainer(withArch(1, 0, 4096, sliceSize), fatBytes.length).type, 'unsupported', 'cputype 为零不是胖二进制');
  assert.equal(detectContainer(withArch(1, 0x01000007, 4096, sliceSize + 1), fatBytes.length).type, 'unsupported', '首个分片越出文件尾不算胖二进制');

  // 分片数合理但读不到首个分片项：窗口被截断，判为未判定，不冒充范围外容器。
  const shortWindow = Buffer.from(fatBytes.subarray(0, 12));
  shortWindow.writeUInt32BE(1, 4);
  const truncated = detectContainer(shortWindow, fatBytes.length);
  assert.equal(truncated.type, 'unknown');
  assert.equal(truncated.label, '未判定');
  assert.match(truncated.note ?? '', /CAFEBABE/);
});

test('首个分片落在识别窗口之外时，按真实文件长度仍判胖二进制', () => {
  // 夹具的首个分片偏移 4096，正好顶到标准窗口末尾：只按已读窗口长度推断会把它误判成 Java 类文件，
  // 因此识别阶段必须把真实文件长度交给判别。
  const fatBytes = fixtureBytes('mach-o/fat.macho');
  const window = fatBytes.subarray(0, DETECTION_PREFIX_BYTES);
  assert.equal(detectContainer(window, fatBytes.length).type, 'mach-o-fat');
  assert.equal(detectContainer(window).type, 'unsupported', '不给文件长度时只能按窗口推断，会误判');
});

test('复审对 Java 类文件不再失败：范围外条目不进入结构复审', async () => {
  const path = fixturePath('unsupported/java-class.class');
  const result = await runCli(['verify', path, '--json']);
  assert.equal(result.code, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, 'passed');
  assert.deepEqual(report.checks, [], '范围外容器没有可复审的结构，不出检查记录');
  assert.equal(report.summary.outOfScopeEntries, 1, '范围外条目要计入范围外计数');
  assert.ok(
    report.limitations.some((limitation) => limitation.code === 'verify-out-of-scope'),
    `应留范围外限制说明：${JSON.stringify(report.limitations)}`,
  );
});

test('BEAM 的 FOR1 魔数需要 BEAM 标记确认，AIFF 因此判为范围外', () => {
  assert.equal(detectContainer(fixtureBytes('beam/basic.beam')).type, 'beam');
  const aiff = detectContainer(fixtureBytes('malformed/form-aiff.bin'));
  assert.equal(aiff.type, 'unsupported');
});

test('PE 的 MZ 魔数需要 PE\\0\\0 签名确认', () => {
  assert.equal(detectContainer(fixtureBytes('pe/basic.pe')).type, 'pe');
  assert.equal(detectContainer(fixtureBytes('malformed/mz-no-signature.bin')).type, 'unsupported');
});

test('畸形输入得到 unknown 或 unsupported，不抛异常', () => {
  assert.equal(detectContainer(Buffer.alloc(0)).type, 'unknown');
  assert.equal(detectContainer(Buffer.from([0x01, 0x02, 0x03])).type, 'unknown');
  assert.equal(detectContainer(fixtureBytes('malformed/random.bin')).type, 'unsupported');
  assert.equal(detectContainer(fixtureBytes('malformed/tiny.bin')).type, 'unknown');
  assert.equal(detectContainer(fixtureBytes('malformed/empty.bin')).type, 'unknown');
  for (const input of [null, undefined, 'not-a-buffer', 42, []]) {
    const result = detectContainer(input);
    assert.equal(result.type, 'unknown', `非 Buffer 输入应判为 unknown：${String(input)}`);
    assert.match(result.note ?? '', /四字节/);
  }
});

test('范围外格式判为 unsupported 且不落入任何读取器', () => {
  for (const relativePath of [
    'unsupported/il2cpp-metadata.bin',
    'unsupported/apk-signature-scheme.bin',
    'malformed/random.bin',
    'malformed/safetensors-bad-json.bin',
  ]) {
    const result = detectContainer(fixtureBytes(relativePath));
    assert.equal(result.type, 'unsupported', relativePath);
    assert.equal(isSupportedContainer(result.type), false);
  }
});

test('pyc 判定要求魔数之后是 0D 0A，且两个魔数字不能都可打印', () => {
  assert.equal(detectContainer(fixtureBytes('pyc/hash-based.pyc')).type, 'pyc');
  // 0x0d61 的低字节是可打印字符 'a'，高字节 0x0d 不是，真实魔数因此仍然命中。
  assert.equal(detectContainer(fixtureBytes('pyc/timestamp-based.pyc')).type, 'pyc');
  // 两个字节都可打印的文本文件带 CRLF 时不是 pyc。
  assert.equal(detectContainer(fixtureBytes('malformed/text-crlf.txt')).type, 'unsupported');
  assert.equal(detectContainer(Buffer.from('XY\r\n0123456789abcdef', 'latin1')).type, 'unsupported');
});

test('safetensors 头部长度声明的读取与 plausibility 判定', () => {
  const basic = fixtureBytes('safetensors/basic.safetensors');
  assert.equal(safetensorsHeaderLength(basic), basic.length - 16);
  assert.equal(safetensorsHeaderLength(Buffer.alloc(4)), null, '字节不足时无法读取声明');
  assert.equal(safetensorsHeaderLength(Buffer.from([0, 0, 0, 0, 0, 0, 0, 0])), null, '声明为 0 不是 safetensors');
  const overCap = Buffer.alloc(16);
  overCap.writeBigUInt64LE(BigInt(SAFETENSORS_HEADER_PROBE_MAX + 1), 0);
  assert.equal(safetensorsHeaderLength(overCap), SAFETENSORS_HEADER_PROBE_MAX + 1);
  // 声明合理但第 9 字节不是 '{'：不是 safetensors，也不产生未判定说明。
  const zeros = Buffer.alloc(4096);
  zeros.writeBigUInt64LE(1000n, 0);
  assert.equal(detectContainer(zeros).type, 'unsupported');
});

test('结构魔数补读长度：PE 远偏移与大头部 safetensors 需要补读，普通格式不需要', () => {
  assert.equal(detectionProbeLength(fixtureBytes('elf/basic.elf'), 337), 0);
  assert.equal(detectionProbeLength(fixtureBytes('zip/mixed-entries.zip'), 271), 0);
  assert.equal(detectionProbeLength(Buffer.alloc(0), 0), 0);

  const farPe = fixtureBytes('pe/far-signature.pe');
  assert.equal(peSignatureEnd(farPe.subarray(0, 4096)), 5004);
  assert.equal(detectionProbeLength(farPe.subarray(0, 4096), farPe.length), 5004);
  assert.equal(peSignatureEnd(Buffer.alloc(32)), null, '读不到 e_lfanew 时返回 null');
  const badOffset = Buffer.alloc(0x100);
  badOffset.writeUInt32LE(0xfffffff0, 0x3c);
  assert.equal(peSignatureEnd(badOffset), null, '偏移越界时返回 null');

  const large = fixtureBytes('safetensors/large-header.safetensors');
  const headerLength = safetensorsHeaderLength(large);
  assert.ok(headerLength > DETECTION_PREFIX_BYTES, '夹具头部应超出标准窗口');
  assert.equal(detectionProbeLength(large.subarray(0, DETECTION_PREFIX_BYTES), large.length), 8 + headerLength);

  // 声明超过补读上限或超出文件实际大小时不补读。
  const overCap = Buffer.alloc(4096);
  overCap.writeBigUInt64LE(BigInt(SAFETENSORS_HEADER_PROBE_MAX + 1), 0);
  assert.equal(detectionProbeLength(overCap, 1 << 20), 0);
  assert.equal(detectionProbeLength(farPe.subarray(0, 4096), 1024), 0, '签名偏移超出文件大小时不补读');
});

test('identifyArtifact 单文件：类型、字节数、摘要与容器判定', async () => {
  const path = fixturePath('elf/basic.elf');
  const identity = await identifyArtifact(path, {});
  assert.equal(identity.kind, 'file');
  assert.equal(identity.path, path);
  assert.equal(identity.absolutePath, path);
  assert.equal(identity.entries.length, 1);
  assert.equal(identity.truncated, false);
  assert.deepEqual(identity.skipped, []);
  const entry = identity.entries[0];
  assert.equal(entry.relativePath, 'basic.elf');
  assert.equal(entry.container.type, 'elf');
  assert.equal(entry.detectionLimited, false);
  assert.equal(entry.digestTruncated, false);
  assert.equal(entry.bytes, 337);
  assert.equal(entry.sha256, createHash('sha256').update(await readFile(path)).digest('hex'));
  assert.equal(identity.bytes, 337);
  // 单文件制品的摘要就是文件自身字节的 sha256，与条目摘要同值，不再做再摘要。
  assert.equal(identity.sha256, entry.sha256);
  assert.equal(identity.sha256, createHash('sha256').update(await readFile(path)).digest('hex'));
});

test('identifyArtifact 单文件：摘要截断时仍给出确定摘要，不冒充完整字节摘要', async () => {
  const path = fixturePath('elf/basic.elf');
  const truncated = await identifyArtifact(path, { budgets: { maxTotalScanBytes: 1 } });
  assert.equal(truncated.entries[0].digestTruncated, true);
  assert.equal(truncated.entries[0].sha256, null);
  // 条目摘要为 null 时按字节数派生兜底值：仍是 64 位十六进制，但不等于文件自身字节的摘要。
  assert.match(truncated.sha256, /^[0-9a-f]{64}$/);
  assert.notEqual(truncated.sha256, createHash('sha256').update(await readFile(path)).digest('hex'));
  const again = await identifyArtifact(path, { budgets: { maxTotalScanBytes: 1 } });
  assert.equal(again.sha256, truncated.sha256, '同一制品两次识别得到同一摘要');
});

test('identifyArtifact 目录：条目排序、正斜杠相对路径、字节汇总', async () => {
  const identity = await identifyArtifact(fixturesRoot, {});
  assert.equal(identity.kind, 'directory');
  assert.equal(identity.entries.length, CONTAINER_FIXTURES.length);
  assert.equal(identity.truncated, false);
  assert.deepEqual(identity.skipped, []);
  const relativePaths = identity.entries.map((entry) => entry.relativePath);
  assert.deepEqual(relativePaths, [...relativePaths].sort());
  for (const relativePath of relativePaths) {
    assert.ok(!relativePath.includes('\\'), `相对路径应使用正斜杠：${relativePath}`);
  }
  const expectedBytes = CONTAINER_FIXTURES.reduce((total, fixture) => total + fixture.bytes.length, 0);
  assert.equal(identity.bytes, expectedBytes);
});

test('identifyArtifact 目录：同一目录两次识别得到同一摘要', async () => {
  const first = await identifyArtifact(fixturesRoot, {});
  const second = await identifyArtifact(fixturesRoot, {});
  assert.equal(first.sha256, second.sha256);
  assert.match(first.sha256, /^[0-9a-f]{64}$/);
  const third = await identifyArtifact(`${fixturesRoot}${'\\'}`, {});
  assert.equal(third.sha256, first.sha256, '带末尾分隔符的路径应识别同一目录');
});

test('目录制品摘要是条目清单的再摘要，与单文件摘要语义不同', async () => {
  const identity = await identifyArtifact(fixturesRoot, {});
  const manifest = [...identity.entries]
    .sort((left, right) => (left.relativePath < right.relativePath ? -1 : 1))
    .map((entry) => `${entry.relativePath}\0${entry.sha256 ?? ''}\0${entry.bytes}\n`)
    .join('');
  assert.equal(identity.sha256, createHash('sha256').update(manifest, 'utf8').digest('hex'));

  // 同一批字节按单文件目标识别时，摘要是文件自身字节的 sha256，两种语义必须能区分。
  const single = await identifyArtifact(fixturePath('elf/basic.elf'), {});
  assert.equal(single.sha256, single.entries[0].sha256);
  assert.notEqual(identity.sha256, single.sha256);
});

test('目录摘要随内容变化，空目录摘要是空输入的 sha256', async () => {
  const root = await mkdtemp(join(tmpdir(), 'anti-rea-container-digest-'));
  try {
    const empty = await identifyArtifact(root, {});
    assert.equal(empty.entries.length, 0);
    assert.equal(empty.bytes, 0);
    assert.equal(empty.sha256, createHash('sha256').update(Buffer.alloc(0)).digest('hex'));

    await mkdir(join(root, 'a'), { recursive: true });
    await writeFile(join(root, 'a', 'first.txt'), 'first', 'utf8');
    await writeFile(join(root, 'second.txt'), 'second', 'utf8');
    const before = await identifyArtifact(root, {});
    assert.deepEqual(
      before.entries.map((entry) => entry.relativePath),
      ['a/first.txt', 'second.txt'],
    );
    await writeFile(join(root, 'a', 'first.txt'), 'first!', 'utf8');
    const afterChange = await identifyArtifact(root, {});
    assert.notEqual(afterChange.sha256, before.sha256, '内容变化必须反映到制品摘要');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('磁盘上的夹具经 identifyArtifact 判定为登记的类型', async () => {
  for (const fixture of CONTAINER_FIXTURES) {
    const identity = await identifyArtifact(fixturePath(fixture.relativePath), {});
    assert.equal(identity.entries[0].container.type, fixture.expected.type, fixture.relativePath);
    assert.equal(identity.entries[0].detectionLimited, false, fixture.relativePath);
    assert.equal(identity.entries[0].digestTruncated, false, fixture.relativePath);
  }
});

test('结构魔数补读：大头部 safetensors 与远偏移 PE 在默认预算下判定成功', async () => {
  const large = await identifyArtifact(fixturePath('safetensors/large-header.safetensors'), {});
  assert.equal(large.entries[0].container.type, 'safetensors');
  assert.equal(large.entries[0].detectionLimited, false);

  const farPe = await identifyArtifact(fixturePath('pe/far-signature.pe'), {});
  assert.equal(farPe.entries[0].container.type, 'pe');
  assert.equal(farPe.entries[0].detectionLimited, false);
});

test('部分读取：单文件上限截断识别窗口时判定不完整并附说明', async () => {
  const elf = await identifyArtifact(fixturePath('elf/basic.elf'), { budgets: { maxFileBytes: 4 } });
  assert.equal(elf.entries[0].container.type, 'elf', '魔数在已读字节内时仍可判定');
  assert.equal(elf.entries[0].detectionLimited, true, '窗口小于标准长度必须标记判定不完整');

  const zero = await identifyArtifact(fixturePath('elf/basic.elf'), { budgets: { maxFileBytes: 0 } });
  assert.equal(zero.entries[0].container.type, 'unknown');
  assert.equal(zero.entries[0].detectionLimited, true);
  assert.equal(zero.entries[0].sha256, createHash('sha256').update(await readFile(fixturePath('elf/basic.elf'))).digest('hex'), '摘要不受识别窗口影响');
});

test('部分读取：预算截断结构魔数补读时报告未判定与原因', async () => {
  const cappedSt = await identifyArtifact(fixturePath('safetensors/large-header.safetensors'), { budgets: { maxFileBytes: 1024 } });
  assert.equal(cappedSt.entries[0].container.type, 'unknown');
  assert.equal(cappedSt.entries[0].detectionLimited, true);
  assert.match(cappedSt.entries[0].container.note ?? '', /safetensors 头部长度声明为/);

  const cappedPe = await identifyArtifact(fixturePath('pe/far-signature.pe'), { budgets: { maxFileBytes: 1024 } });
  assert.equal(cappedPe.entries[0].container.type, 'unknown');
  assert.equal(cappedPe.entries[0].detectionLimited, true);
  assert.match(cappedPe.entries[0].container.note ?? '', /PE 签名/);
});

test('部分读取：累计扫描窗口耗尽时摘要截断且置空', async () => {
  const one = await identifyArtifact(fixturePath('elf/basic.elf'), { budgets: { maxTotalScanBytes: 1 } });
  assert.equal(one.entries[0].digestTruncated, true);
  assert.equal(one.entries[0].sha256, null);
  assert.equal(one.entries[0].detectionLimited, false);

  const root = await mkdtemp(join(tmpdir(), 'anti-rea-container-window-'));
  try {
    for (const name of ['a.bin', 'b.bin', 'c.bin']) {
      await writeFile(join(root, name), Buffer.alloc(100, 0x41));
    }
    const identity = await identifyArtifact(root, { budgets: { maxTotalScanBytes: 250 } });
    assert.equal(identity.entries[0].digestTruncated, false);
    assert.equal(identity.entries[1].digestTruncated, false);
    assert.equal(identity.entries[2].digestTruncated, true, '窗口耗尽后后续条目摘要截断');
    assert.equal(identity.entries[2].sha256, null);
    assert.notEqual(identity.entries[0].sha256, null);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('部分读取：目录条目数达到上限时截断并保留已枚举条目', async () => {
  const identity = await identifyArtifact(fixturesRoot, { budgets: { maxFiles: 3 } });
  assert.equal(identity.entries.length, 3);
  assert.equal(identity.truncated, true);
  assert.deepEqual(
    identity.entries.map((entry) => entry.relativePath),
    ['beam/basic.beam', 'dex/basic.dex', 'elf/basic.elf'],
  );
});

test('标准窗口边界：恰好 4096 字节与恰好填满窗口的 safetensors 头部都判定完整', async () => {
  const root = await mkdtemp(join(tmpdir(), 'anti-rea-container-window-fit-'));
  try {
    const elf = Buffer.alloc(DETECTION_PREFIX_BYTES);
    elf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
    await writeFile(join(root, 'exact.elf'), elf);
    const elfIdentity = await identifyArtifact(join(root, 'exact.elf'), {});
    assert.equal(elfIdentity.entries[0].container.type, 'elf');
    assert.equal(elfIdentity.entries[0].detectionLimited, false);

    // 头部长度取可用窗口内最大值，仍不需要补读。
    const available = DETECTION_PREFIX_BYTES - 8;
    let header = Buffer.from(JSON.stringify({ __metadata__: { pad: 'y'.repeat(available - 32) } }), 'utf8');
    header = Buffer.from(JSON.stringify({ __metadata__: { pad: 'y'.repeat(available - 32 + (available - header.length)) } }), 'utf8');
    assert.equal(header.length, available);
    const safetensors = Buffer.alloc(8 + header.length + 4);
    safetensors.writeBigUInt64LE(BigInt(header.length), 0);
    header.copy(safetensors, 8);
    await writeFile(join(root, 'exact.safetensors'), safetensors);
    const stIdentity = await identifyArtifact(join(root, 'exact.safetensors'), {});
    assert.equal(stIdentity.entries[0].container.type, 'safetensors');
    assert.equal(stIdentity.entries[0].detectionLimited, false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('目录中的符号链接不计入条目，避免目录环与链接目标混入', async () => {
  const root = await mkdtemp(join(tmpdir(), 'anti-rea-container-symlink-'));
  try {
    await writeFile(join(root, 'real.elf'), fixtureBytes('elf/basic.elf'));
    try {
      await symlink(join(root, 'real.elf'), join(root, 'link.elf'));
    } catch {
      // 本机不支持创建符号链接时跳过，不把用例判为失败。
      return;
    }
    const identity = await identifyArtifact(root, {});
    assert.deepEqual(
      identity.entries.map((entry) => entry.relativePath),
      ['real.elf'],
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('用法错误：目标缺失、不存在或类型不符时抛 UsageError 且退出码为 2', async () => {
  for (const target of ['', '   ', null, 42]) {
    const error = await identifyArtifact(target, {}).catch((caught) => caught);
    assert.ok(error instanceof UsageError, `应抛 UsageError：${String(target)}`);
    assert.equal(error.code, 2);
    assert.match(error.message, /缺少目标路径/);
  }
  const missing = await identifyArtifact(join(fixturesRoot, 'no-such-file'), {}).catch((caught) => caught);
  assert.ok(missing instanceof UsageError);
  assert.equal(missing.code, 2);
  assert.match(missing.message, /目标不存在或不可访问/);

  const other = await identifyArtifact(join(fixturesRoot, 'elf', 'basic.elf'), {}, {
    stat: async () => ({ isDirectory: () => false, isFile: () => false }),
  }).catch((caught) => caught);
  assert.ok(other instanceof UsageError);
  assert.equal(other.code, 2);
  assert.match(other.message, /既不是普通文件也不是目录/);
});

test('单文件目标不可读时按用法错误处理，退出码为 2', async () => {
  const failing = async () => {
    const error = new Error("permission denied, open 'x'");
    error.code = 'EACCES';
    throw error;
  };
  const error = await identifyArtifact(fixturePath('elf/basic.elf'), {}, { open: failing }).catch((caught) => caught);
  assert.ok(error instanceof UsageError);
  assert.equal(error.code, 2);
  assert.match(error.message, /无法读取目标文件/);
});

test('目录中的单个条目不可读时跳过并登记，其余条目照常识别', async () => {
  const realOpen = (await import('node:fs/promises')).open;
  const failing = async (path, flags) => {
    if (String(path).endsWith('random.bin')) {
      const error = new Error(`permission denied, open '${path}'`);
      error.code = 'EACCES';
      throw error;
    }
    return realOpen(path, flags);
  };
  const identity = await identifyArtifact(fixturesRoot, {}, { open: failing });
  assert.equal(identity.entries.length, CONTAINER_FIXTURES.length - 1);
  assert.equal(identity.skipped.length, 1);
  assert.equal(identity.skipped[0].relativePath, 'malformed/random.bin');
  assert.match(identity.skipped[0].reason, /EACCES/);
  assert.ok(!identity.skipped[0].reason.includes(fixturesRoot), '跳过原因不得带出绝对路径');
  assert.ok(!identity.entries.some((entry) => entry.relativePath === 'malformed/random.bin'));
});

test('夹具字节自洽：ELF 节表、Mach-O 加载命令、BEAM 块、GGUF 元数据、pyc 头、ZIP 条目', async () => {
  const elf = fixtureBytes('elf/basic.elf');
  assert.deepEqual([...elf.subarray(0, 4)], [0x7f, 0x45, 0x4c, 0x46]);
  assert.equal(elf.readUInt16LE(18), 62, 'e_machine 应为 x86-64');
  assert.equal(elf.readUInt16LE(60), 3, 'e_shnum 应为 3');
  const shoff = Number(elf.readBigUInt64LE(40));
  const shentsize = elf.readUInt16LE(58);
  const shstrndx = elf.readUInt16LE(62);
  const strtabOffset = Number(elf.readBigUInt64LE(shoff + shstrndx * shentsize + 24));
  const nameOffset = elf.readUInt32LE(shoff + 1 * shentsize);
  assert.equal(elf.toString('latin1', strtabOffset + nameOffset, strtabOffset + nameOffset + 5), '.text');

  const machO = fixtureBytes('mach-o/basic.macho');
  assert.equal(machO.readUInt32LE(0), 0xfeedfacf);
  assert.equal(machO.readInt32LE(4), 0x01000007);
  assert.equal(machO.toString('latin1', 40, 46), '__TEXT');
  const fat = fixtureBytes('mach-o/fat.macho');
  assert.equal(fat.readUInt32BE(0), 0xcafebabe);
  assert.equal(fat.readUInt32BE(4), 1, 'nfat_arch 应为 1');
  assert.equal(fat.readUInt32BE(16), 4096, '切片偏移应为 4096');
  assert.equal(fat.readUInt32LE(4096), 0xfeedfacf, '偏移 4096 处应是一片 Mach-O');

  const beam = fixtureBytes('beam/basic.beam');
  assert.equal(beam.toString('latin1', 0, 4), 'FOR1');
  assert.equal(beam.readUInt32BE(4), beam.length - 8, '外框长度应覆盖其余字节');
  assert.equal(beam.toString('latin1', 8, 12), 'BEAM');
  assert.equal(beam.toString('latin1', 16, 20), 'AtU8');

  const gguf = fixtureBytes('gguf/basic.gguf');
  assert.equal(gguf.toString('latin1', 0, 4), 'GGUF');
  assert.equal(gguf.readUInt32LE(4), 3, '版本应为 3');
  assert.equal(Number(gguf.readBigUInt64LE(16)), 1, '元数据条目数应为 1');
  assert.equal(Number(gguf.readBigUInt64LE(24)), 20, '键名长度应为 20');
  assert.equal(gguf.toString('latin1', 32, 52), 'general.architecture');
  assert.equal(gguf.readUInt32LE(52), 8, '值类型应为字符串');
  assert.equal(Number(gguf.readBigUInt64LE(56)), 4, '值长度应为 4');
  assert.equal(gguf.toString('latin1', 64, 68), 'demo');
  assert.equal(gguf.length, 68);

  const pyc = fixtureBytes('pyc/hash-based.pyc');
  assert.equal(pyc.readUInt16LE(0), 0x0da7);
  assert.equal(pyc[2], 0x0d);
  assert.equal(pyc[3], 0x0a);
  assert.equal(pyc.readUInt32LE(4), 0x03, 'flags 应为 hash_based 加 check_source');

  const zip = fixtureBytes('zip/mixed-entries.zip');
  let position = -1;
  const seen = [];
  while ((position = zip.indexOf(Buffer.from([0x50, 0x4b, 0x03, 0x04]), position + 1)) !== -1) {
    const nameLength = zip.readUInt16LE(position + 26);
    const name = zip.toString('latin1', position + 30, position + 30 + nameLength);
    const method = zip.readUInt16LE(position + 8);
    const checksum = zip.readUInt32LE(position + 14);
    const compressedSize = zip.readUInt32LE(position + 18);
    const uncompressedSize = zip.readUInt32LE(position + 22);
    const data = zip.subarray(position + 30 + nameLength, position + 30 + nameLength + compressedSize);
    const plain = method === 8 ? inflateRawSync(data) : data;
    assert.equal(plain.length, uncompressedSize, `${name} 解压后长度与记录不符`);
    assert.equal(crc32(plain), checksum, `${name} 解压后 CRC32 与记录不符`);
    seen.push(name);
  }
  assert.deepEqual(seen, ['stored.txt', 'deflated.txt'], 'ZIP 夹具应含存储条目与 deflate 条目');
});

test('命令行集成：audit 对夹具单文件与夹具目录正常完成且退出码为 0', async () => {
  const single = await runCli(['audit', fixturePath('elf/basic.elf'), '--json']);
  assert.equal(single.code, 0, single.stderr);
  const singleReport = JSON.parse(single.stdout);
  assert.equal(singleReport.tool, 'audit-artifact');
  assert.equal(singleReport.artifact.kind, 'file');
  assert.equal(singleReport.artifact.container, 'elf');
  assert.equal(singleReport.artifact.bytes, 337);
  assert.equal(singleReport.status, 'complete');

  const directory = await runCli(['audit', fixturesRoot, '--json']);
  assert.equal(directory.code, 0, directory.stderr);
  const directoryReport = JSON.parse(directory.stdout);
  assert.equal(directoryReport.artifact.kind, 'directory');
  assert.equal(directoryReport.artifact.entryCount, CONTAINER_FIXTURES.length);
  const containerTypes = Object.keys(directoryReport.summary.byContainer);
  for (const container of EIGHT_FORMATS) {
    assert.ok(containerTypes.includes(container), `审计报告应统计容器 ${container}`);
  }
});
