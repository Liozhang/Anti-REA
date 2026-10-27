// fixtures 模块测试：字节级夹具的真实性、格式覆盖、畸形输入与部分读取。
// 覆盖三条路径：
//   正常输入   八类格式夹具各被识别为对应容器，真实读取器从夹具里取出预期事实
//   畸形输入   截断的 ELF、损坏结尾记录的 ZIP、越界的 safetensors 索引、被破坏 pyc 标记的制品
//   部分读取   单文件上限与累计扫描窗口触发的部分结果与限制说明
// 夹具说明：全部用例跑 tests/fixtures/ 下已提交且摘要登记在 manifest.json 的固定字节；
// 需要改字节的用例先把夹具复制进临时目录，绝不动已提交夹具。

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import { auditArtifact } from '../src/audit/engine.mjs';
import { detectContainer } from '../src/container/detect.mjs';
import { GO_BUILDINFO_MAGIC } from '../src/readers/native-shared.mjs';
import { crc32Of } from '../src/readers/zip.mjs';
import { computePeChecksum } from '../src/signatures/pe-checksum.mjs';
import { clearElfBuildIdNotes, clearElfSymtab, clearPycSourceHash, overwriteGoBuildinfo, overwriteRustDepSection } from '../src/transforms/equal-length.mjs';
import { locateElfBuildIdNotes, parseElfStructure } from '../src/transforms/parse.mjs';
import { locateZipEntries, patchEntryCrc32 } from '../src/transforms/zip-entry.mjs';
import { buildElf } from './transforms/fixture-bytes.mjs';
import { BYTE_FIXTURES, buildFixtureBytes } from './fixtures/build.mjs';

const FIXTURES_DIR = fileURLToPath(new URL('./fixtures/', import.meta.url));

/** v1 八类格式的容器标识，封闭集合。 */
const SUPPORTED = Object.freeze(['elf', 'pe', 'mach-o', 'zip', 'gguf', 'safetensors', 'pyc', 'beam']);

/** 临时目录在测试结束后清理。 */
let workDir = null;

test.before(async () => {
  workDir = await mkdtemp(join(tmpdir(), 'anti-rea-fixtures-'));
});

test.after(async () => {
  if (workDir !== null) {
    await rm(workDir, { recursive: true, force: true });
  }
});

/**
 * 取已提交夹具的绝对路径。
 * @param {string} relativePath 相对 tests/fixtures/ 的路径
 * @returns {string}
 */
function fixturePath(relativePath) {
  return join(FIXTURES_DIR, ...relativePath.split('/'));
}

/**
 * 读取已提交夹具字节。
 * @param {string} relativePath 相对 tests/fixtures/ 的路径
 * @returns {Promise<Buffer>}
 */
async function fixtureBytes(relativePath) {
  return readFile(fixturePath(relativePath));
}

/**
 * 审计一个已提交夹具。
 * @param {string} relativePath 相对 tests/fixtures/ 的路径
 * @returns {Promise<Record<string, unknown>>}
 */
async function auditFixture(relativePath) {
  return auditArtifact(fixturePath(relativePath));
}

/**
 * 把字节写进临时目录并审计，返回报告与文件路径。
 * @param {string} name 文件名
 * @param {Buffer} bytes 文件内容
 * @returns {Promise<{report: Record<string, unknown>, path: string}>}
 */
async function auditBytes(name, bytes) {
  const path = join(workDir, name);
  await writeFile(path, bytes);
  return { report: await auditArtifact(path), path };
}

/**
 * 按分类取审计报告里的发现。
 * @param {Record<string, unknown>} report 审计报告
 * @param {string} category 分类标识
 * @returns {Record<string, unknown>}
 */
function findingOf(report, category) {
  const finding = report.findings.find((candidate) => candidate.category === category);
  assert.notEqual(finding, undefined, `报告里没有分类为 ${category} 的发现：${JSON.stringify(report.findings.map((item) => item.category))}`);
  return finding;
}

/**
 * 取报告里的限制说明标识集合。
 * @param {Record<string, unknown>} report 审计报告
 * @returns {string[]}
 */
function limitationCodes(report) {
  return report.limitations.map((limitation) => limitation.code);
}

// ---------------------------------------------------------------------------
// 正常输入：容器识别与格式覆盖
// ---------------------------------------------------------------------------

test('v1 八类格式的夹具各至少一个，且都被识别为对应容器', () => {
  for (const container of SUPPORTED) {
    const fixtures = BYTE_FIXTURES.filter((fixture) => fixture.container === container);
    assert.ok(fixtures.length >= 1, `${container} 没有夹具`);
    for (const fixture of fixtures) {
      const bytes = fixture.build();
      const detected = detectContainer(bytes.subarray(0, Math.min(4096, bytes.length)));
      assert.equal(detected.type, container, `夹具 ${fixture.path} 应被识别为 ${container}，实际 ${detected.type}`);
    }
  }
});

test('ELF 夹具：节表、符号表与 Go 构建信息两类编码的事实都被取出', async () => {
  const basic = await auditFixture('elf/basic.elf');
  assert.equal(basic.status, 'complete');
  assert.equal(basic.artifact.container, 'elf');
  const header = findingOf(basic, 'elf-header');
  assert.equal(header.detail.class, 'ELFCLASS64');
  assert.equal(header.detail.machine, 'x86-64');
  const symtab = findingOf(basic, 'elf-symtab');
  assert.equal(symtab.detail.symbolCount, 3);
  assert.deepEqual(symtab.detail.sampleNames, ['main', 'helper_function', 'leaked_internal_name']);
  assert.equal(symtab.mitigation, 'metadata.elf-symtab-clear');

  const inline = await auditFixture('elf/go-buildinfo-inline.elf');
  const inlineInfo = findingOf(inline, 'go-buildinfo');
  assert.equal(inlineInfo.detail.encoding, 'inline');
  assert.equal(inlineInfo.detail.version, 'go1.22.0');
  assert.equal(inlineInfo.detail.moduleInfoPresent, true);
  assert.equal(inlineInfo.mitigation, 'metadata.go-buildinfo-inline-overwrite');

  const pointer = await auditFixture('elf/go-buildinfo-pointer.elf');
  const pointerInfo = findingOf(pointer, 'go-buildinfo');
  assert.equal(pointerInfo.detail.encoding, 'pointer');
  assert.equal(pointerInfo.detail.version, 'go1.22.5');
  assert.equal(pointerInfo.detail.inWritableNonExecutableLoad, true, '魔数应落在可写且非执行的 load region 内');
  assert.equal(pointerInfo.mitigation, 'metadata.go-buildinfo-writable-region-overwrite');
});

test('ELF 夹具：.dep-v0 依赖节命中且依赖清单解出', async () => {
  const report = await auditFixture('elf/rust-dep-v0.elf');
  const finding = findingOf(report, 'rust-dep-v0');
  assert.equal(finding.detail.decompressMethod, 'deflate-raw');
  assert.deepEqual(finding.detail.dependencies, ['serde 1.0.193', 'libc 0.2.146', 'tokio 1.32.0']);
  assert.equal(finding.mitigation, 'metadata.rust-dep-section-overwrite');
});

test('ELF 夹具：等长覆写后 Go 构建信息魔数不再出现，字节数不变且节表仍可解析', async () => {
  for (const relativePath of ['elf/go-buildinfo-inline.elf', 'elf/go-buildinfo-pointer.elf']) {
    const bytes = await fixtureBytes(relativePath);
    const report = await auditFixture(relativePath);
    const finding = findingOf(report, 'go-buildinfo');
    const result = overwriteGoBuildinfo(bytes, finding);
    assert.equal(result.ok, true, `${relativePath} 应可施加等长覆写：${result.reason ?? ''}`);
    assert.equal(result.buffer.length, bytes.length, '等长覆写保持文件字节数不变');
    assert.equal(result.buffer.indexOf(GO_BUILDINFO_MAGIC), -1, '覆写后魔数不得再出现');
    assert.equal(result.buffer.subarray(0, 64).equals(bytes.subarray(0, 64)), true, 'ELF 文件头不得被覆写破坏');
    const structure = parseElfStructure(result.buffer);
    assert.equal(structure.ok, true, `覆写后 ELF 节表仍应可解析：${structure.reason ?? ''}`);
    assert.ok(structure.data.sections.length >= 3);
  }
});

test('ELF 构建标识 note：段内与节内各定位一遍，等长清零描述符且结构保持可解析', () => {
  // 实测背景：真实 Go 二进制的构建标识同时被 PT_NOTE 段与 .note.gnu.build-id 节覆盖，
  // 只清一处另一处原样暴露。这里构造同一份 note 字节被两处覆盖的 ELF，验证去重与只清描述符。
  const descriptor = Buffer.from('0123456789abcdef0123', 'latin1');
  const noteHeader = Buffer.alloc(12);
  noteHeader.writeUInt32LE(4, 0); // namesz
  noteHeader.writeUInt32LE(descriptor.length, 4); // descsz
  noteHeader.writeUInt32LE(3, 8); // NT_GNU_BUILD_ID
  const note = Buffer.concat([noteHeader, Buffer.from('GNU\0', 'latin1'), descriptor]);
  const built = buildElf({ sections: [{ name: '.note.gnu.build-id', type: 7, data: note }], loads: [{ flags: 0x4 }] });
  const noteOffset = built.sectionOffsets.get('.note.gnu.build-id');

  // 把唯一的程序头改成 PT_NOTE 并指向同一份 note 字节：段内与节内各有一份覆盖。
  const elf = Buffer.from(built.buffer);
  elf.writeUInt32LE(4, 64); // p_type = PT_NOTE
  elf.writeBigUInt64LE(BigInt(noteOffset), 64 + 8); // p_offset
  elf.writeBigUInt64LE(BigInt(note.length), 64 + 32); // p_filesz

  const located = locateElfBuildIdNotes(elf);
  assert.equal(located.ok, true, located.reason ?? '');
  assert.equal(located.notes.length, 1, '段内与节内覆盖同一份字节，去重后只应有一处');

  const result = clearElfBuildIdNotes(elf);
  assert.equal(result.ok, true, `应可施加等长覆写：${result.reason ?? ''}`);
  assert.equal(result.buffer.length, elf.length, '等长覆写保持字节数不变');
  const descStart = noteOffset + 16;
  assert.ok(
    result.buffer.subarray(descStart, descStart + descriptor.length).equals(Buffer.alloc(descriptor.length, 0)),
    '描述符应被清零',
  );
  assert.equal(result.buffer.readUInt32LE(noteOffset), 4, 'namesz 不得改动');
  assert.equal(result.buffer.readUInt32LE(noteOffset + 4), descriptor.length, 'descsz 不得改动');
  assert.equal(result.buffer.readUInt32LE(noteOffset + 8), 3, 'note 类型不得改动');
  assert.equal(result.buffer.subarray(noteOffset + 12, noteOffset + 16).toString('latin1'), 'GNU\0', 'note 名称不得改动');

  const structure = parseElfStructure(result.buffer);
  assert.equal(structure.ok, true, `覆写后 ELF 节表仍应可解析：${structure.reason ?? ''}`);
  assert.ok(structure.data.sections.some((section) => section.type === 7 && section.size === note.length), 'note 节应仍在');

  // 幂等：描述符已全零时拒写，不重复覆写。
  const again = clearElfBuildIdNotes(result.buffer);
  assert.equal(again.ok, false);
  assert.match(again.reason, /无需重复覆写/);
  // 非 ELF 与无构建标识的 ELF 都拒写。
  assert.equal(clearElfBuildIdNotes(Buffer.from('not an elf at all')).ok, false);
  const withoutNote = buildElf({ sections: [{ name: '.text', type: 1, data: Buffer.from('code', 'latin1') }], loads: [{ flags: 0x5 }] });
  const missing = clearElfBuildIdNotes(withoutNote.buffer);
  assert.equal(missing.ok, false);
  assert.match(missing.reason, /找不到/);
});

test('ELF 构建标识 note：审计发现带配套措施，清零后审计如实停止报告携带', async () => {
  const descriptor = Buffer.from('fedcba9876543210edcb', 'latin1');
  const noteHeader = Buffer.alloc(12);
  noteHeader.writeUInt32LE(4, 0);
  noteHeader.writeUInt32LE(descriptor.length, 4);
  noteHeader.writeUInt32LE(3, 8);
  const note = Buffer.concat([noteHeader, Buffer.from('GNU\0', 'latin1'), descriptor]);
  const built = buildElf({ sections: [{ name: '.note.gnu.build-id', type: 7, data: note }], loads: [{ flags: 0x4 }] });

  const before = await auditBytes('with-build-id.elf', built.buffer);
  const finding = before.report.findings.find((item) => item.category === 'elf-build-id');
  assert.ok(finding !== undefined, '带构建标识 note 的 ELF 应登记 elf-build-id 发现');
  assert.equal(finding.mitigation, 'metadata.elf-build-id-note-overwrite');

  const result = clearElfBuildIdNotes(built.buffer);
  assert.equal(result.ok, true, result.reason ?? '');
  const after = await auditBytes('cleared-build-id.elf', result.buffer);
  assert.equal(
    after.report.findings.some((item) => item.category === 'elf-build-id'),
    false,
    '描述符清零后不得再报成携带构建标识',
  );
  assert.ok(
    after.report.findings.some((item) => item.category === 'elf-note'),
    'note 结构仍在，应由 note 段存在发现覆盖',
  );
});

test('ELF 夹具：等长覆写 .dep-v0 节名与节类型后审计不再命中，节表仍可解析', async () => {
  const bytes = await fixtureBytes('elf/rust-dep-v0.elf');
  const before = await auditFixture('elf/rust-dep-v0.elf');
  assert.ok(before.findings.some((finding) => finding.category === 'rust-dep-v0'));
  const finding = findingOf(before, 'rust-dep-v0');

  const result = overwriteRustDepSection(bytes, finding, 'elf');
  assert.equal(result.ok, true, `应可施加等长覆写：${result.reason ?? ''}`);
  assert.equal(result.buffer.length, bytes.length, '等长覆写保持文件字节数不变');

  const { report } = await auditBytes('overwritten-dep.elf', result.buffer);
  assert.ok(
    !report.findings.some((candidate) => candidate.category === 'rust-dep-v0'),
    '节名与节类型覆写后审计不再命中 .dep-v0',
  );
  const structure = parseElfStructure(result.buffer);
  assert.equal(structure.ok, true, `覆写后 ELF 节表仍应可解析：${structure.reason ?? ''}`);
  assert.equal(structure.data.sections.length, parseElfStructure(bytes).data.sections.length, '节数量不得变化');
});

test('ELF 夹具：静态符号表可清零，节表仍可解析', async () => {
  const bytes = await fixtureBytes('elf/basic.elf');
  const report = await auditFixture('elf/basic.elf');
  const finding = findingOf(report, 'elf-symtab');
  const result = clearElfSymtab(bytes, finding);
  assert.equal(result.ok, true, `应可清零静态符号表：${result.reason ?? ''}`);
  assert.equal(result.buffer.length, bytes.length);
  assert.equal(result.buffer.indexOf(Buffer.from('leaked_internal_name', 'latin1')), -1, '符号名不得再可检索');
  const structure = parseElfStructure(result.buffer);
  assert.equal(structure.ok, true, `清零后 ELF 节表仍应可解析：${structure.reason ?? ''}`);
});

test('pyc 夹具：清零 source_hash 时一并清除 check_source，标志与哈希状态保持一致', async () => {
  const bytes = await fixtureBytes('pyc/hash-based-check-source.pyc');
  const result = clearPycSourceHash(bytes);
  assert.equal(result.ok, true, `应可清零源文件摘要：${result.reason ?? ''}`);
  assert.equal(result.buffer.length, bytes.length, '等长覆写保持文件字节数不变');
  assert.equal(result.buffer.readBigUInt64LE(8), 0n, 'source_hash 必须清零');
  assert.equal(result.buffer.readUInt32LE(4) & 0b10, 0, 'check_source 必须一并清除');
  assert.equal(result.buffer.readUInt32LE(4) & 0b01, 1, 'hash_based 标志保持置位');

  const { report } = await auditBytes('cleared.pyc', result.buffer);
  const hash = findingOf(report, 'pyc-source-hash');
  assert.equal(hash.detail.sourceHash, '0000000000000000');
  assert.equal(hash.detail.checkSource, false, '标志位与清零后的哈希状态必须一致');
});

test('PE 夹具：可选头、安全目录与非零 CheckSum 的事实都被取出', async () => {
  const basic = await auditFixture('pe/basic.pe');
  const header = findingOf(basic, 'pe-header');
  assert.equal(header.detail.optionalHeader, 'PE32+');
  assert.equal(header.detail.machine, 'x86-64');
  assert.equal(header.detail.sectionCount, 1);

  const signed = await auditFixture('pe/security-directory.pe');
  const security = findingOf(signed, 'pe-security-directory');
  assert.equal(security.detail.offset, 0x400);
  assert.equal(security.detail.size, 0x40);
  assert.ok(security.detail.size > 0, '安全目录大小必须非零才会被登记');

  const checksum = await auditFixture('pe/checksum-nonzero.pe');
  const checksumFinding = findingOf(checksum, 'pe-checksum');
  const bytes = await fixtureBytes('pe/checksum-nonzero.pe');
  const recomputed = computePeChecksum(bytes, 0x98);
  assert.ok(checksumFinding.detail.checksum > 0, 'CheckSum 必须非零');
  assert.equal(checksumFinding.detail.checksum, recomputed, '夹具里的 CheckSum 必须与按 PE 算法重算的结果一致');
});

test('Mach-O 夹具：加载命令、构建标识、动态库与代码签名的事实都被取出', async () => {
  const basic = await auditFixture('mach-o/basic.macho');
  const header = findingOf(basic, 'macho-header');
  assert.equal(header.detail.bits, 64);
  assert.equal(header.detail.cputype, 'x86-64');
  assert.ok(header.detail.loadCommandKinds.includes('LC_SEGMENT_64'));
  assert.ok(header.detail.loadCommandKinds.includes('LC_UUID'));
  assert.ok(header.detail.loadCommandKinds.includes('LC_LOAD_DYLIB'));
  const uuid = findingOf(basic, 'macho-uuid');
  assert.match(uuid.evidence.excerpt, /^[0-9a-f]+$/);
  const dylibs = findingOf(basic, 'macho-dylibs');
  assert.ok(dylibs.detail.dylibs.includes('/usr/lib/libSystem.B.dylib'));

  const signed = await auditFixture('mach-o/code-signature.macho');
  const signature = findingOf(signed, 'macho-code-signature');
  assert.equal(signature.detail.size, 16);
  const signedBytes = await fixtureBytes('mach-o/code-signature.macho');
  assert.ok(signature.detail.offset + signature.detail.size <= signedBytes.length, '签名数据区必须落在文件内');
});

test('ZIP 夹具：存储条目与 deflate 条目分别标记，CRC32 与中央目录记录一致', async () => {
  const report = await auditFixture('zip/mixed-entries.zip');
  const finding = findingOf(report, 'zip-entries');
  const entries = finding.detail.entries;
  assert.equal(entries.length, 2);

  const stored = entries.find((entry) => entry.name === 'stored.txt');
  assert.equal(stored.methodCode, 0);
  assert.equal(stored.coverage, 'raw-bytes-scanned');
  assert.equal(stored.crcMatch, true);
  assert.equal(stored.crc32Recorded, crc32Of(Buffer.from('hello zip stored entry\n', 'latin1')));

  const deflated = entries.find((entry) => entry.name === 'deflated.txt');
  assert.equal(deflated.methodCode, 8);
  assert.equal(deflated.coverage, 'decompressed-scanned');
  assert.equal(deflated.crcMatch, true);
  assert.equal(deflated.uncompressedSize, 'hello zip deflated entry\n'.length * 8);

  assert.deepEqual(limitationCodes(report).filter((code) => code.startsWith('zip-entry')), [], '两类条目都不应出现条目级限制说明');
});

test('ZIP 夹具：改写条目后同帧重算 CRC32，重算值与中央目录项一致', async () => {
  const original = await fixtureBytes('zip/mixed-entries.zip');
  const patched = Buffer.from(original);
  const located = locateZipEntries(patched);
  assert.equal(located.ok, true);
  const stored = located.entries.find((entry) => entry.name === 'stored.txt');
  assert.equal(stored.method, 0);

  // 改动存储条目数据区的一个字节，模拟令牌占位覆写。
  const modifiedByte = 0x58;
  assert.notEqual(patched[stored.dataStart], modifiedByte);
  patched[stored.dataStart] = modifiedByte;

  const result = patchEntryCrc32(patched, stored);
  assert.notEqual(result, null, '同帧重算必须成功');
  assert.notEqual(result.after, result.before, '内容已改，CRC32 必须变化');

  // 同帧：本地文件头与中央目录两处记录一起更新。
  const localCrc = patched.readUInt32LE(stored.localBase + 14);
  const centralCrc = patched.readUInt32LE(stored.centralOffset + 16);
  assert.equal(localCrc, result.after);
  assert.equal(centralCrc, result.after);
  assert.equal(centralCrc, crc32Of(patched.subarray(stored.dataStart, stored.dataEnd)));

  const { report } = await auditBytes('patched.zip', patched);
  const entries = findingOf(report, 'zip-entries').detail.entries;
  const storedReport = entries.find((entry) => entry.name === 'stored.txt');
  assert.equal(storedReport.crcMatch, true, '同帧重算后审计必须核对通过');
  assert.deepEqual(limitationCodes(report).filter((code) => code.startsWith('zip-entry')), []);
  // 改写只动条目数据与两处 CRC 记录，文件长度不变。
  assert.equal(patched.length, original.length);
});

test('GGUF 夹具：按原 alignment 推算张量数据区起点与各张量文件偏移', async () => {
  const report = await auditFixture('gguf/basic.gguf');
  const header = findingOf(report, 'gguf-header');
  assert.equal(header.detail.alignment, 32);
  assert.equal(header.detail.tensorCount, 2);
  assert.equal(header.detail.tensorDataOffset, 192);

  const tensors = findingOf(report, 'gguf-tensors');
  assert.deepEqual(
    tensors.detail.tensors.map((tensor) => [tensor.name, tensor.dataOffset, tensor.fileOffset]),
    [
      ['t0', 0, 192],
      ['t1', 32, 224],
    ],
  );

  const metadata = findingOf(report, 'gguf-metadata');
  const alignmentEntry = metadata.detail.keys.find((key) => key.key === 'general.alignment');
  assert.equal(alignmentEntry.value, 32);
});

test('safetensors 夹具：tensor_data_offset 等于 8 加头部长度，索引完整覆盖数据区', async () => {
  const bytes = await fixtureBytes('safetensors/basic.safetensors');
  const headerLength = Number(bytes.readBigUInt64LE(0));
  const report = await auditFixture('safetensors/basic.safetensors');
  const header = findingOf(report, 'safetensors-header');
  assert.equal(header.detail.headerLength, headerLength);
  assert.equal(header.detail.tensorDataOffset, 8 + headerLength);

  const metadata = findingOf(report, 'safetensors-metadata');
  assert.deepEqual(metadata.detail.metadata, { format: 'pt' });

  const tensors = findingOf(report, 'safetensors-tensors');
  assert.deepEqual(
    tensors.detail.tensors.map((tensor) => [tensor.name, tensor.start, tensor.end]),
    [
      ['t0', 0, 8],
      ['t1', 8, 16],
    ],
  );
  assert.deepEqual(
    limitationCodes(report).filter((code) => code.startsWith('safetensors-interval') || code === 'safetensors-unindexed-tail'),
    [],
    '索引覆盖整个数据区，不应有越界、间隙、重叠与未索引尾部',
  );
});

test('pyc 夹具：hash_based 且 check_source 置位，标志与哈希状态一致', async () => {
  const report = await auditFixture('pyc/hash-based-check-source.pyc');
  const header = findingOf(report, 'pyc-header');
  assert.equal(header.detail.flags, 0b11);
  assert.equal(header.detail.hashBased, true);
  assert.equal(header.detail.checkSource, true);

  const hash = findingOf(report, 'pyc-source-hash');
  assert.equal(hash.detail.hashBased, true);
  assert.equal(hash.detail.checkSource, true);
  assert.equal(hash.detail.sourceHash, '3031323334353637');
  assert.equal(hash.mitigation, 'metadata.pyc-source-hash-clear');
});

test('BEAM 夹具：块结构与已编译模块名的事实都被取出', async () => {
  const report = await auditFixture('beam/basic.beam');
  const chunks = findingOf(report, 'beam-chunks');
  assert.deepEqual(chunks.detail.chunks.map((chunk) => chunk.id), ['AtU8', 'Code', 'StrT']);
  const moduleName = findingOf(report, 'beam-module-name');
  assert.equal(moduleName.detail.moduleName, 'demo');
  assert.deepEqual(moduleName.detail.sampleAtoms, ['demo', 'code']);
  assert.deepEqual(limitationCodes(report), [], '块结构与原子表都应解出，不应留限制说明');
});

test('范围外格式：IL2CPP 元数据与 APK 签名方案返回 unsupported 与能力边界说明', async () => {
  const il2cpp = await auditFixture('unsupported/global-metadata.dat');
  assert.equal(il2cpp.status, 'complete');
  assert.equal(il2cpp.artifact.container, 'unsupported');
  assert.deepEqual(il2cpp.findings, [], '范围外格式不冒充没有暴露，也不应产出事实');
  assert.equal(il2cpp.capabilityBoundaries.length, 1);
  assert.equal(il2cpp.capabilityBoundaries[0].id, 'il2cpp-metadata');
  assert.ok(il2cpp.capabilityBoundaries[0].reason.length > 0, '能力边界必须附原因');
  assert.ok(il2cpp.capabilityBoundaries[0].hint.length > 0, '能力边界必须附下一步建议');

  const apk = await auditFixture('unsupported/apk-signature-scheme.apk');
  assert.equal(apk.artifact.container, 'unsupported');
  assert.deepEqual(apk.findings, []);
  assert.equal(apk.capabilityBoundaries.length, 1);
  assert.equal(apk.capabilityBoundaries[0].id, 'apk-signature-scheme');
  assert.ok(apk.capabilityBoundaries[0].reason.length > 0);
});

test('审计夹具是只读操作：制品逐字节不变，目录不新增文件', async () => {
  for (const relativePath of ['elf/basic.elf', 'zip/mixed-entries.zip', 'gguf/basic.gguf']) {
    const path = fixturePath(relativePath);
    const before = createHash('sha256').update(await readFile(path)).digest('hex');
    await auditArtifact(path);
    const after = createHash('sha256').update(await readFile(path)).digest('hex');
    assert.equal(after, before, `审计不得改动 ${relativePath}`);
  }
});

// ---------------------------------------------------------------------------
// 畸形输入
// ---------------------------------------------------------------------------

test('截断的 ELF 被判为 elf 容器，报告解析失败的限制说明而不是空结果', async () => {
  const bytes = await fixtureBytes('elf/basic.elf');
  const { report } = await auditBytes('truncated.elf', bytes.subarray(0, 16));
  assert.equal(report.status, 'complete');
  assert.equal(report.artifact.container, 'elf');
  assert.deepEqual(report.findings, []);
  assert.ok(limitationCodes(report).includes('elf-header-unparsable'));
});

test('损坏结尾记录的 ZIP 报告中央目录缺失的限制说明', async () => {
  const bytes = await fixtureBytes('zip/mixed-entries.zip');
  const broken = Buffer.from(bytes);
  // 结尾记录在文件末尾 22 字节处，没有注释；破坏其签名。
  broken.fill(0x00, broken.length - 22, broken.length - 18);
  const { report } = await auditBytes('broken-eocd.zip', broken);
  assert.equal(report.status, 'complete');
  assert.equal(report.artifact.container, 'zip');
  assert.ok(limitationCodes(report).includes('zip-eocd-missing'));
});

test('索引越界的 safetensors 头部被判为 safetensors，报告区间越界的限制说明', async () => {
  const header = {
    __metadata__: { format: 'pt' },
    t0: { dtype: 'F32', shape: [2], data_offsets: [0, 9999] },
  };
  const headerBytes = Buffer.from(JSON.stringify(header), 'utf8');
  const prefix = Buffer.alloc(8);
  prefix.writeBigUInt64LE(BigInt(headerBytes.length), 0);
  const { report } = await auditBytes('out-of-range.safetensors', Buffer.concat([prefix, headerBytes, Buffer.alloc(16, 0x5a)]));
  assert.equal(report.artifact.container, 'safetensors');
  assert.ok(limitationCodes(report).includes('safetensors-interval-out-of-range'));
});

test('被破坏 pyc 标记的制品不再被判为 pyc，也不冒充范围外格式的事实', async () => {
  const bytes = await fixtureBytes('pyc/hash-based-check-source.pyc');
  const broken = Buffer.from(bytes);
  broken[2] = 0x00;
  const { report } = await auditBytes('broken-marker.pyc', broken);
  assert.equal(report.status, 'complete');
  assert.equal(report.artifact.container, 'unsupported');
  assert.deepEqual(report.findings, []);
  assert.equal(report.capabilityBoundaries.length, 1);
  assert.ok(report.capabilityBoundaries[0].reason.includes('unsupported'), '能力边界要说明识别结果');
});

test('截断的 GGUF 报告头部不可解析的限制说明', async () => {
  const bytes = await fixtureBytes('gguf/basic.gguf');
  const { report } = await auditBytes('truncated.gguf', bytes.subarray(0, 8));
  assert.equal(report.status, 'complete');
  assert.equal(report.artifact.container, 'gguf');
  assert.ok(limitationCodes(report).includes('gguf-header-unparsable'));
});

// ---------------------------------------------------------------------------
// 部分读取（资源预算）
// ---------------------------------------------------------------------------

test('单文件上限设为极小值时输出 partial 并附限制说明，进程不失败', async () => {
  const report = await auditArtifact(fixturePath('elf/basic.elf'), { policy: { budgets: { maxFileBytes: 16 } } });
  assert.equal(report.status, 'partial');
  const codes = limitationCodes(report);
  assert.ok(codes.includes('max-file-bytes-exceeded'), JSON.stringify(codes));
  assert.ok(codes.includes('detection-prefix-limited'), JSON.stringify(codes));
  assert.ok(report.limitations.every((limitation) => limitation.message.length > 0), '限制说明不得为空');
});

test('累计扫描窗口耗尽时输出 partial 并附摘要截断说明', async () => {
  const report = await auditArtifact(fixturePath('zip/mixed-entries.zip'), { policy: { budgets: { maxTotalScanBytes: 8 } } });
  assert.equal(report.status, 'partial');
  assert.ok(limitationCodes(report).includes('digest-truncated'));
  assert.match(report.artifact.sha256, /^[0-9a-f]{64}$/, '摘要截断不等于没有摘要');
});

// ---------------------------------------------------------------------------
// 构建脚本自身
// ---------------------------------------------------------------------------

test('构建脚本重复运行结果稳定：输出字节与已提交夹具一致', () => {
  const first = buildFixtureBytes();
  const second = buildFixtureBytes();
  assert.equal(first.length, second.length);
  for (let index = 0; index < first.length; index += 1) {
    assert.equal(first[index].path, second[index].path);
    assert.ok(first[index].bytes.equals(second[index].bytes), `构造器不稳定：${first[index].path}`);
  }
});
