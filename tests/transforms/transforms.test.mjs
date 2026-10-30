// transforms 模块测试：等长覆写、重布局写入、签名门控、资源预算与畸形输入。
// 全部用例跑在字节级真实夹具上：夹具先经项目自己的读取器审计确认能产出预期发现，
// 再施加缓解、复审（重新审计）确认发现消失且制品结构仍可解析。
// 覆盖三类输入：正常输入（各类格式夹具）、畸形输入（截断、损坏、词表外编号）、
// 部分读取与资源上限（单文件上限极小值时全部跳过并附限制说明）。

import assert from 'node:assert/strict';
import { mkdtemp, readdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { auditArtifact } from '../../src/audit/engine.mjs';
import { MITIGATION_IDS } from '../../src/audit/finding.mjs';
import { NotImplementedError } from '../../src/errors.mjs';
import { computePeChecksum } from '../../src/signatures/index.mjs';
import { exemptionsFor } from '../../src/required-sets/index.mjs';
import {
  DEFAULT_OUTPUT_SUFFIX,
  TRANSFORM_REGISTRY,
  applyMitigation,
  applyMitigations,
  listTransforms,
  transformById,
  transformsOfKind,
} from '../../src/transforms/index.mjs';
import { parseElfStructure, parsePeStructure } from '../../src/transforms/parse.mjs';
import { parseGguf, validateGguf, validateSafetensors } from '../../src/transforms/relayout.mjs';
import { inspectContainer } from '../../src/verify/facts.mjs';
import {
  GO_BUILDINFO_MAGIC,
  buildElf,
  buildElfGoInline,
  buildElfGoPointer,
  buildElfWithRustDep,
  buildElfWithSymbols,
  buildElfWithToken,
  buildGguf,
  buildMachOWithCodeSignature,
  buildMachOWithGoAndDep,
  buildPe,
  buildPeWithDebugDirectory,
  buildPyc,
  buildPycWithTokenAt,
  buildSafetensors,
  buildZip,
} from './fixture-bytes.mjs';

/** 测试用临时目录。 */
let workDir = '';

test.before(async () => {
  workDir = await mkdtemp(join(tmpdir(), 'antirea-transforms-'));
});

/**
 * 把夹具字节写到临时目录并审计，返回路径、审计报告与发现列表。
 * @param {string} name 文件名
 * @param {Buffer} bytes 夹具字节
 * @returns {Promise<{path: string, report: Record<string, unknown>, findings: Array<Record<string, unknown>>}>}
 */
async function fixture(name, bytes) {
  const path = join(workDir, name);
  await writeFile(path, bytes);
  const report = await auditArtifact(path, {});
  return { path, report, findings: report.findings };
}

/**
 * 取第一条匹配缓解编号的发现。
 * @param {Array<Record<string, unknown>>} findings 发现列表
 * @param {string} mitigation 缓解编号
 * @returns {Record<string, unknown>}
 */
function findingOf(findings, mitigation) {
  const found = findings.find((finding) => finding.mitigation === mitigation);
  assert.ok(found !== undefined, `夹具应当产出编号为 ${mitigation} 的发现`);
  return found;
}

/** 法律字段齐全的策略，供模型层元数据派生使用。 */
const LEGAL_POLICY = {
  legal: {
    subject: '示例主体',
    contact: 'security@example.com',
    jurisdiction: '中华人民共和国',
    licenseId: '专有许可',
    licenseTextSource: '随制品分发的 LICENSE 文件',
    prohibitedActs: ['反向编译', '破除授权校验'],
    consequences: [{ statement: '将依法追究责任', statuteExcerpt: '《中华人民共和国著作权法》第五十三条' }],
  },
};

// ---- 登记表 ----

test('缓解措施登记表覆盖全部已登记编号，且每项都声明功能风险与签名影响', () => {
  assert.deepEqual(
    TRANSFORM_REGISTRY.map((transform) => transform.id).sort(),
    [...MITIGATION_IDS].sort(),
  );
  for (const transform of TRANSFORM_REGISTRY) {
    assert.equal(typeof transform.functionalRisk, 'string');
    assert.ok(transform.functionalRisk.length > 0, `${transform.id} 缺少功能风险说明`);
    assert.equal(typeof transform.signatureImpact, 'string');
    assert.ok(transform.signatureImpact.length > 0, `${transform.id} 缺少签名影响说明`);
    assert.ok(['equal-length-overwrite', 'relayout-write', 'generated-integration-package'].includes(transform.kind));
  }
  // 等长覆写与重布局写入两类都必须有实质条目。
  assert.ok(transformsOfKind('equal-length-overwrite').length >= 8);
  assert.equal(transformsOfKind('relayout-write').length, 2);
  assert.equal(transformsOfKind('generated-integration-package').length, 1);
});

test('列出缓解措施时不暴露施加函数', () => {
  for (const transform of listTransforms()) {
    assert.equal(transform.apply, undefined);
    assert.equal(transform.applyToBuffer, undefined);
  }
  assert.equal(transformById('not-a-mitigation'), null);
  assert.equal(transformById('model.gguf-metadata-relayout').kind, 'relayout-write');
});

test('反运行时观察集成包不写字节，施加时明确拒绝并给出原因', async () => {
  const transform = transformById('runtime.probe-integration-package');
  const { path } = await fixture('probe.elf', buildElfGoInline().buffer);
  await assert.rejects(
    () => transform.apply({ target: path, finding: { mitigation: 'runtime.probe-integration-package' }, policy: {} }),
    NotImplementedError,
  );
  const result = await applyMitigations({
    target: path,
    findings: [{ id: 'F-x', mitigation: 'runtime.probe-integration-package' }],
    policy: {},
  });
  assert.equal(result.status, 'no-op');
  assert.match(result.skipped[0].reason, /probe-kit/);
});

// ---- Go 构建信息：inline 编码（ELF） ----

test('ELF Go 构建信息 inline 覆写后魔数消失、字节数不变、节表仍可解析', async () => {
  const { path, findings } = await fixture('go-inline.elf', buildElfGoInline().buffer);
  const finding = findingOf(findings, 'metadata.go-buildinfo-inline-overwrite');
  assert.equal(finding.detail.encoding, 'inline');

  const result = await applyMitigations({ target: path, findings, policy: {} });
  assert.equal(result.changed, true);
  assert.equal(result.wrote, true);
  assert.equal(result.applied.length, 1);
  assert.equal(result.applied[0].mitigation, 'metadata.go-buildinfo-inline-overwrite');

  const hardened = await readFile(result.artifact.outputPath);
  const original = await readFile(path);
  assert.equal(hardened.length, original.length, '等长覆写必须保持字节数不变');
  assert.equal(hardened.includes(GO_BUILDINFO_MAGIC), false, '魔数必须不再出现');
  // 版本串所在区间一并清零。
  assert.equal(hardened.readUInt8(finding.detail.versionOffset), 0);

  // 复审：重新审计加固后制品，Go 构建信息发现消失，ELF 头与节表发现仍在。
  const after = await auditArtifact(result.artifact.outputPath, {});
  assert.equal(after.findings.some((item) => item.category === 'go-buildinfo'), false);
  assert.equal(after.findings.some((item) => item.category === 'elf-header'), true);
  assert.ok(parseElfStructure(hardened).ok, '节表必须仍可解析');
});

test('ELF Go 构建信息覆写幂等：第二次运行产出与已存在输出逐字节相同', async () => {
  const { path, findings } = await fixture('go-inline-idem.elf', buildElfGoInline().buffer);
  const first = await applyMitigations({ target: path, findings, policy: {} });
  assert.equal(first.changed, true);
  const second = await applyMitigations({ target: path, findings, policy: {} });
  assert.equal(second.changed, false, '第二次运行的产出必须与已存在输出逐字节相同');
  assert.equal(second.wrote, false);
  assert.equal(second.idempotent, true);
  const output = await readFile(first.artifact.outputPath);
  const again = await readFile(`${path}${DEFAULT_OUTPUT_SUFFIX}`);
  assert.ok(output.equals(again));
});

// ---- Go 构建信息：pointer 编码（ELF 可写且非执行 load region） ----

test('ELF Go 构建信息 pointer 覆写后魔数与指针目标串都不再可读', async () => {
  const { path, findings } = await fixture('go-pointer.elf', buildElfGoPointer().buffer);
  const finding = findingOf(findings, 'metadata.go-buildinfo-writable-region-overwrite');
  assert.equal(finding.detail.encoding, 'pointer');
  assert.equal(finding.detail.inWritableNonExecutableLoad, true);

  const result = await applyMitigations({ target: path, findings, policy: {} });
  assert.equal(result.applied.length, 1);
  const hardened = await readFile(result.artifact.outputPath);
  const original = await readFile(path);
  assert.equal(hardened.length, original.length);
  assert.equal(hardened.includes(GO_BUILDINFO_MAGIC), false);
  // 指针指向的版本串必须被清零：只清零魔数不足以移除可提取事实。
  const versionStart = finding.detail.versionPointer + 1;
  assert.equal(hardened.toString('latin1', versionStart, versionStart + finding.detail.versionLength), '\0'.repeat(finding.detail.versionLength));

  const after = await auditArtifact(result.artifact.outputPath, {});
  assert.equal(after.findings.some((item) => item.category === 'go-buildinfo'), false);
});

test('pointer 编码也可按 pointer-overwrite 编号施加', async () => {
  const { path, findings } = await fixture('go-pointer-2.elf', buildElfGoPointer().buffer);
  const crafted = findings.map((finding) =>
    finding.mitigation === 'metadata.go-buildinfo-writable-region-overwrite'
      ? { ...finding, mitigation: 'metadata.go-buildinfo-pointer-overwrite' }
      : finding,
  );
  const result = await applyMitigations({ target: path, findings: crafted, policy: {} });
  assert.equal(result.applied[0].mitigation, 'metadata.go-buildinfo-pointer-overwrite');
  const hardened = await readFile(result.artifact.outputPath);
  assert.equal(hardened.includes(GO_BUILDINFO_MAGIC), false);
});

// ---- PE：调试目录与 Go 构建信息 ----

test('PE 调试目录路径与 Go 构建信息同批次施加，两项覆写都落在同一输出文件里', async () => {
  const peFixture = buildPeWithDebugDirectory();
  const { path, report, findings } = await fixture('debug.pe', peFixture.buffer);
  assert.equal(report.artifact.container, 'pe');
  const debugFinding = findingOf(findings, 'metadata.pe-debug-directory-overwrite');
  const goFinding = findingOf(findings, 'metadata.go-buildinfo-pe-characteristics-overwrite');

  const result = await applyMitigations({ target: path, findings, policy: {} });
  assert.equal(result.applied.length, 2);
  const hardened = await readFile(result.artifact.outputPath);
  const original = await readFile(path);
  assert.equal(hardened.length, original.length, '等长覆写必须保持字节数不变');
  assert.equal(hardened.includes(GO_BUILDINFO_MAGIC), false);
  // 符号文件路径整体清零（含结尾空字符）。
  const pathLength = 'D:\\build\\agent\\app.pdb'.length;
  assert.equal(
    hardened.toString('latin1', peFixture.codeviewPathOffset, peFixture.codeviewPathOffset + pathLength + 1),
    '\0'.repeat(pathLength + 1),
  );
  assert.equal(debugFinding.detail.paths[0], 'D:\\build\\agent\\app.pdb');
  assert.equal(goFinding.detail.section, '.didat');

  // 复审：两类发现都消失，PE 头发现仍在，可选头仍可解析。
  const after = await auditArtifact(result.artifact.outputPath, {});
  assert.equal(after.findings.some((item) => item.category === 'pe-debug-directory'), false);
  assert.equal(after.findings.some((item) => item.category === 'go-buildinfo'), false);
  assert.equal(after.findings.some((item) => item.category === 'pe-header'), true);
  assert.ok(parsePeStructure(hardened).ok);
});

// ---- PE：CheckSum 与安全目录 ----

test('PE 非零 CheckSum：策略允许重算时等长重算，校验和与改写后字节一致', async () => {
  const bytes = buildPe({
    sections: [
      { name: '.text', characteristics: 0x60000020, data: Buffer.from('code-bytes', 'latin1') },
      { name: '.didat', characteristics: 0xc0000040, data: Buffer.concat([GO_BUILDINFO_MAGIC, Buffer.from('go1.22.0\0', 'latin1')]) },
    ],
    checksum: 0x00001234,
  });
  const { path, findings } = await fixture('checksum.pe', bytes.buffer);
  const finding = findingOf(findings, 'metadata.go-buildinfo-pe-characteristics-overwrite');

  const result = await applyMitigations({
    target: path,
    findings,
    policy: { signatures: { allowChecksumRecompute: true } },
  });
  assert.equal(result.applied.length, 1);
  assert.equal(result.checksumRecomputed, true);
  assert.notEqual(result.checksum.before, result.checksum.after);

  const hardened = await readFile(result.artifact.outputPath);
  assert.equal(hardened.length, bytes.buffer.length);
  assert.equal(hardened.includes(GO_BUILDINFO_MAGIC), false);
  // 复审口径：可选头 CheckSum 必须与改写后字节的重算结果一致。
  const stored = hardened.readUInt32LE(result.checksum.fieldOffset);
  assert.equal(stored, computePeChecksum(hardened, result.checksum.fieldOffset));
  assert.equal(finding.detail.section, '.didat', '魔数落在特征位为 0xc0000040 的节里');
});

test('PE 非零 CheckSum：策略未允许重算时默认跳过改写并给出原因', async () => {
  const bytes = buildPe({
    sections: [
      { name: '.text', characteristics: 0x60000020, data: Buffer.from('code-bytes', 'latin1') },
      { name: '.didat', characteristics: 0xc0000040, data: Buffer.concat([GO_BUILDINFO_MAGIC, Buffer.from('go1.22.0\0', 'latin1')]) },
    ],
    checksum: 0x00001234,
  });
  const { path, findings } = await fixture('checksum-skip.pe', bytes.buffer);
  const result = await applyMitigations({ target: path, findings, policy: {} });
  assert.equal(result.changed, false);
  assert.equal(result.applied.length, 0);
  assert.equal(result.gate.allowed, false);
  const blocked = result.skipped.find((item) => item.mitigation === 'metadata.go-buildinfo-pe-characteristics-overwrite');
  assert.match(blocked.reason, /CheckSum/);
  await assert.rejects(() => readFile(`${path}${DEFAULT_OUTPUT_SUFFIX}`), /ENOENT/);
});

test('PE 安全目录：默认跳过改写，制品摘要不变；策略显式允许时施加并标记 requires_resign', async () => {
  const bytes = buildPe({
    sections: [
      { name: '.text', characteristics: 0x60000020, data: Buffer.from('code-bytes', 'latin1') },
      { name: '.didat', characteristics: 0xc0000040, data: Buffer.concat([GO_BUILDINFO_MAGIC, Buffer.from('go1.22.0\0', 'latin1')]) },
    ],
    securityDirectory: { offset: 0x300, size: 32 },
  });
  const { path, findings } = await fixture('security.pe', bytes.buffer);

  const skipped = await applyMitigations({ target: path, findings, policy: {} });
  assert.equal(skipped.changed, false);
  assert.equal(skipped.applied.length, 0);
  assert.match(skipped.gate.reason, /安全目录/);
  assert.equal(skipped.artifact.sha256Before, skipped.artifact.sha256After);
  await assert.rejects(() => readFile(`${path}${DEFAULT_OUTPUT_SUFFIX}`), /ENOENT/);

  const allowed = await applyMitigations({
    target: path,
    findings,
    policy: { signatures: { allowRewriteSigned: true } },
  });
  assert.equal(allowed.applied.length, 1);
  assert.equal(allowed.requiresResign, true);
  assert.equal(allowed.gate.requiresResign, true);
  const hardened = await readFile(allowed.artifact.outputPath);
  assert.equal(hardened.includes(GO_BUILDINFO_MAGIC), false);
});

// ---- Mach-O ----

test('Mach-O Go 构建信息与 __DATA,.dep-v0 同批次覆写，节表仍可解析', async () => {
  const machoFixture = buildMachOWithGoAndDep();
  const { path, findings } = await fixture('go-dep.macho', machoFixture.buffer);
  const goFinding = findingOf(findings, 'metadata.go-buildinfo-macho-rw-overwrite');
  const depFinding = findingOf(findings, 'metadata.rust-dep-section-overwrite');
  assert.equal(depFinding.detail.segment, '__DATA');

  const result = await applyMitigations({ target: path, findings, policy: {} });
  assert.equal(result.applied.length, 2);
  const hardened = await readFile(result.artifact.outputPath);
  const original = await readFile(path);
  assert.equal(hardened.length, original.length);
  assert.equal(hardened.includes(GO_BUILDINFO_MAGIC), false);
  // 节头里的定长节名字段整段清零：节名为空，节表仍可解析。
  const nameOffset = machoFixture.sectionHeaderOffsets.get('.dep-v0');
  assert.ok(
    hardened.subarray(nameOffset, nameOffset + 16).every((byte) => byte === 0),
    '定长节名字段必须整段清零',
  );

  const after = await auditArtifact(result.artifact.outputPath, {});
  assert.equal(after.findings.some((item) => item.category === 'go-buildinfo'), false);
  assert.equal(after.findings.some((item) => item.category === 'rust-dep-v0'), false);
  assert.equal(after.findings.some((item) => item.category === 'macho-header'), true);
  assert.equal(goFinding.detail.inWritableSegment, true);
});

test('Mach-O LC_CODE_SIGNATURE：默认跳过改写，策略允许时施加并标记 requires_resign', async () => {
  const { path, findings } = await fixture('signed.macho', buildMachOWithCodeSignature().buffer);
  const finding = findingOf(findings, 'metadata.go-buildinfo-macho-rw-overwrite');

  const skipped = await applyMitigations({ target: path, findings, policy: {} });
  assert.equal(skipped.changed, false);
  assert.match(skipped.gate.reason, /LC_CODE_SIGNATURE/);
  assert.equal(skipped.requiresResign, false);

  const allowed = await applyMitigations({
    target: path,
    findings,
    policy: { signatures: { allowRewriteSigned: true } },
  });
  assert.equal(allowed.applied.length, 1);
  assert.equal(allowed.requiresResign, true);
  const hardened = await readFile(allowed.artifact.outputPath);
  const original = await readFile(path);
  assert.equal(hardened.length, original.length);
  assert.equal(hardened.includes(GO_BUILDINFO_MAGIC), false);
});

// ---- Rust 依赖节（ELF） ----

test('ELF .dep-v0 覆写节名与节类型后审计不再命中，节表仍可解析', async () => {
  const { path, findings } = await fixture('rust-dep.elf', buildElfWithRustDep().buffer);
  const finding = findingOf(findings, 'metadata.rust-dep-section-overwrite');
  assert.equal(finding.detail.decompressMethod, 'deflate-raw');

  const result = await applyMitigations({ target: path, findings, policy: {} });
  assert.equal(result.applied.length, 1);
  const hardened = await readFile(result.artifact.outputPath);
  const original = await readFile(path);
  assert.equal(hardened.length, original.length);

  const structure = parseElfStructure(hardened);
  assert.ok(structure.ok, '节表必须仍可解析');
  assert.equal(
    structure.data.sections.some((item) => item.name === '.dep-v0'),
    false,
    '.dep-v0 节名必须已不存在',
  );

  const after = await auditArtifact(result.artifact.outputPath, {});
  assert.equal(after.findings.some((item) => item.category === 'rust-dep-v0'), false);
  assert.equal(after.findings.some((item) => item.category === 'elf-header'), true);
});

// ---- ELF 符号表 ----

test('ELF 静态符号表清零，动态符号表拒改，复审只剩动态符号发现', async () => {
  const { path, findings } = await fixture('symbols.elf', buildElfWithSymbols().buffer);
  const dynsymFinding = findings.find((item) => item.detail?.section === '.dynsym');
  const symtabFinding = findings.find((item) => item.detail?.section === '.symtab');
  assert.ok(dynsymFinding !== undefined && symtabFinding !== undefined);

  const result = await applyMitigations({ target: path, findings, policy: {} });
  assert.equal(result.applied.length, 1);
  assert.equal(result.applied[0].mitigation, 'metadata.elf-symtab-clear');
  const refusal = result.skipped.find((item) => item.mitigation === 'metadata.elf-symtab-clear');
  assert.match(refusal.reason, /动态符号表/);

  const hardened = await readFile(result.artifact.outputPath);
  const original = await readFile(path);
  assert.equal(hardened.length, original.length, '等长覆写必须保持字节数不变');
  // 符号名载荷已清零：按名检索不到 main 与 helper。
  assert.equal(hardened.includes(Buffer.from('main\0', 'latin1')), false);
  assert.equal(hardened.includes(Buffer.from('helper\0', 'latin1')), false);

  const after = await auditArtifact(result.artifact.outputPath, {});
  assert.equal(after.findings.some((item) => item.detail?.section === '.symtab'), false);
  assert.equal(after.findings.some((item) => item.detail?.section === '.dynsym'), true, '动态符号表必须保持可解析');
  assert.equal(after.findings.some((item) => item.category === 'elf-header'), true);
});

// ---- pyc ----

test('pyc 清零 source_hash 并一并清除 check_source，复审标志位与哈希状态一致', async () => {
  const { path, findings } = await fixture('hash.pyc', buildPyc({ checkSource: true }));
  const finding = findingOf(findings, 'metadata.pyc-source-hash-clear');
  assert.equal(finding.detail.checkSource, true);

  const result = await applyMitigations({ target: path, findings, policy: {} });
  assert.equal(result.applied.length, 1);
  const hardened = await readFile(result.artifact.outputPath);
  const original = await readFile(path);
  assert.equal(hardened.length, original.length);
  // 哈希清零、check_source 清除、hash_based 保留。
  assert.equal(hardened.toString('latin1', 8, 16), '\0'.repeat(8));
  assert.equal(hardened.readUInt32LE(4) & 0b11, 0b01);

  const after = await auditArtifact(result.artifact.outputPath, {});
  // 复审：标志位与哈希状态一致——hash_based 仍声明哈希字段存在，check_source 已清除。
  const sourceHash = after.findings.find((item) => item.category === 'pyc-source-hash');
  assert.ok(sourceHash !== undefined, 'hash_based 制品的源文件摘要字段仍会被登记');
  assert.equal(sourceHash.detail.checkSource, false);
  assert.equal(sourceHash.detail.sourceHash, '00'.repeat(8), '清零后的摘要不可读出原值');
  const header = after.findings.find((item) => item.category === 'pyc-header');
  assert.equal(header.detail.hashBased, true);
  assert.equal(header.detail.checkSource, false, '标志位与清零后的哈希状态必须一致');
});

test('pyc 未声明 hash_based 时跳过并给出原因', async () => {
  const bytes = buildPyc({ checkSource: false });
  bytes.writeUInt32LE(0b00, 4);
  const { path } = await fixture('timestamp.pyc', bytes);
  // 时间戳制式的 pyc 不产出源文件摘要发现，这里按措施编号手工构造一项，验证拒改路径。
  const result = await applyMitigations({
    target: path,
    findings: [{ id: 'F-1', mitigation: 'metadata.pyc-source-hash-clear', detail: { hashBased: false } }],
    policy: {},
  });
  assert.equal(result.applied.length, 0);
  assert.match(result.skipped[0].reason, /hash_based/);
});

// ---- 秘密令牌 ----

test('ELF 原始字节里的疑似凭据等长占位覆写，复审不再命中', async () => {
  const { path, findings } = await fixture('token.elf', buildElfWithToken().buffer);
  const finding = findingOf(findings, 'secret.token-placeholder-overwrite');
  assert.equal(finding.detail.byteSource, 'raw-bytes');

  const result = await applyMitigations({ target: path, findings, policy: {} });
  assert.equal(result.applied.length, 1);
  const hardened = await readFile(result.artifact.outputPath);
  const original = await readFile(path);
  assert.equal(hardened.length, original.length);
  assert.equal(hardened.includes(Buffer.from('AKIA1234567890ABCDEF', 'latin1')), false);
  // 未纳入改写范围的字节保持原样。
  assert.ok(hardened.includes(Buffer.from('endpoint=https://api.example.com key=', 'latin1')));

  const after = await auditArtifact(result.artifact.outputPath, {});
  assert.equal(after.findings.some((item) => item.layer === 'secret-minimization'), false);
});

test('许可证样例文本不被判成疑似凭据，施加列表为空', async () => {
  const license = 'MIT License\n\nCopyright (c) 2026 Example\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files.\n';
  const built = buildElf({
    sections: [
      { name: '.text', type: 1, data: Buffer.from('code-bytes', 'latin1'), addr: 0x401000 },
      { name: '.rodata', type: 1, data: Buffer.from(license, 'latin1'), addr: 0x402000 },
    ],
    loads: [{ flags: 0x5 }],
  });
  const licensePath = join(workDir, 'license-only.elf');
  await writeFile(licensePath, built.buffer);
  const report = await auditArtifact(licensePath, {});
  assert.equal(report.findings.some((item) => item.layer === 'secret-minimization'), false);
  const result = await applyMitigations({ target: licensePath, findings: report.findings, policy: {} });
  assert.equal(result.applied.length, 0);
  assert.equal(result.changed, false);
});

// ---- ZIP：同帧 CRC32 重算 ----

test('ZIP 存储条目令牌覆写后同帧重算 CRC32，压缩条目跳过并说明覆盖缺口', async () => {
  const zipBytes = buildZip([
    { name: 'config/settings.json', method: 0, content: Buffer.from('{"key":"AKIA1234567890ABCDEF"}\n', 'latin1') },
    { name: 'data/blob.bin', method: 8, content: Buffer.from('token=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n', 'latin1') },
  ]);
  const { path, report, findings } = await fixture('mixed.zip', zipBytes);
  assert.equal(report.artifact.container, 'zip');
  const storedFinding = findingOf(findings, 'secret.token-placeholder-overwrite');
  assert.equal(storedFinding.detail.byteSource, 'stored-entry-raw-bytes');
  const deflateFinding = findings.find((item) => item.detail?.byteSource === 'deflate-entry-decompressed-bytes');
  assert.ok(deflateFinding !== undefined, '夹具必须含 deflate 条目里的令牌发现');

  const result = await applyMitigations({ target: path, findings, policy: {} });
  assert.equal(result.applied.length, 1);
  assert.equal(result.applied[0].zip.crc32Before !== result.applied[0].zip.crc32After, true);
  const hardened = await readFile(result.artifact.outputPath);
  const original = await readFile(path);
  assert.equal(hardened.length, original.length, '等长覆写必须保持字节数不变');
  assert.equal(hardened.includes(Buffer.from('AKIA1234567890ABCDEF', 'latin1')), false);

  // 复审：重新审计加固后 ZIP，不得出现条目 CRC32 不一致，存储条目的令牌发现消失。
  const after = await auditArtifact(result.artifact.outputPath, {});
  assert.equal(after.limitations.some((item) => item.code === 'zip-entry-crc-mismatch'), false);
  assert.equal(after.findings.some((item) => item.detail?.byteSource === 'stored-entry-raw-bytes'), false);

  // 压缩条目的令牌无法等长覆写，跳过原因必须写明覆盖缺口。
  const compressionSkip = result.skipped.find((item) => item.mitigation === 'secret.token-placeholder-overwrite');
  assert.match(compressionSkip.reason, /压缩或不可解压条目/);
});

// ---- 模型层重布局：safetensors ----

test('safetensors 写入 __metadata__ 后偏移语义保持，全部格式校验通过', async () => {
  const tensors = [
    { name: 't1', data: Buffer.from('aaaabbbb', 'latin1') },
    { name: 't2', data: Buffer.from('ccccdddd', 'latin1') },
  ];
  const original = buildSafetensors(tensors);
  const { path, findings } = await fixture('basic.safetensors', original);
  const before = await auditArtifact(path, {});
  const beforeTensors = before.findings.find((item) => item.category === 'safetensors-tensors');
  assert.equal(beforeTensors.detail.tensorDataOffset, 118);

  const result = await applyMitigations({
    target: path,
    findings,
    policy: LEGAL_POLICY,
  });
  assert.equal(result.applied.length, 1);
  assert.equal(result.applied[0].kind, 'relayout-write');
  const relayout = result.applied[0].relayout;
  const hardened = await readFile(result.artifact.outputPath);

  // 头部长度前缀与 tensor_data_offset 的关系：tensor_data_offset 等于 8 加新头部长度。
  assert.equal(hardened.readBigUInt64LE(0), BigInt(relayout.headerLengthAfter));
  assert.equal(relayout.tensorDataOffsetAfter, 8 + relayout.headerLengthAfter);

  // 各张量 data_offsets 与加固前逐一相等，张量数据逐字节不变。
  const after = await auditArtifact(result.artifact.outputPath, {});
  const afterTensors = after.findings.find((item) => item.category === 'safetensors-tensors');
  assert.equal(afterTensors.detail.tensorDataOffset, relayout.tensorDataOffsetAfter);
  assert.deepEqual(
    afterTensors.detail.tensors.map((tensor) => [tensor.start, tensor.end]),
    beforeTensors.detail.tensors.map((tensor) => [tensor.start, tensor.end]),
  );
  const originalData = original.subarray(beforeTensors.detail.tensorDataOffset);
  const newData = hardened.subarray(afterTensors.detail.tensorDataOffset);
  assert.ok(originalData.equals(newData), '张量数据必须整体后移且内容不改写');

  // 元数据槽位写入，且复审没有越界、间隙、重叠、未索引尾部。
  const metadata = after.findings.find((item) => item.category === 'safetensors-metadata');
  assert.ok(metadata !== undefined, '复审必须看得到 __metadata__ 槽位');
  assert.equal(metadata.detail.metadata['license.subject'], '示例主体');
  assert.equal(after.limitations.some((item) => item.code.startsWith('safetensors-interval') || item.code === 'safetensors-unindexed-tail'), false);
  assert.deepEqual(validateSafetensors(hardened), { ok: true, problems: [] });
});

test('safetensors 重布局写入幂等：对已加固制品再次施加不改变字节', async () => {
  const original = buildSafetensors([{ name: 't1', data: Buffer.from('aaaabbbb', 'latin1') }]);
  const { path, findings } = await fixture('st-idem.safetensors', original);
  const first = await applyMitigations({ target: path, findings, policy: LEGAL_POLICY });
  assert.equal(first.changed, true);
  const hardenedPath = first.artifact.outputPath;
  const after = await auditArtifact(hardenedPath, {});
  const second = await applyMitigations({
    target: hardenedPath,
    findings: after.findings,
    policy: LEGAL_POLICY,
    outputPath: join(workDir, 'st-idem-again.safetensors'),
  });
  assert.equal(second.changed, false, '对已加固制品再次施加必须不改变字节');
  assert.equal(second.wrote, false);
  // 产出的摘要与第一次加固后的制品一致：内容相同，没有写出第二个副本。
  assert.equal(second.artifact.sha256After, first.artifact.sha256After);
  await assert.rejects(() => readFile(join(workDir, 'st-idem-again.safetensors')), /ENOENT/);
});

test('模型层元数据缺法律字段时拒写，并以 omitted_reason 说明缺什么', async () => {
  const original = buildSafetensors([{ name: 't1', data: Buffer.from('aaaabbbb', 'latin1') }]);
  const { path, findings } = await fixture('st-refuse.safetensors', original);
  const result = await applyMitigations({ target: path, findings, policy: {} });
  assert.equal(result.changed, false);
  assert.equal(result.applied.length, 0);
  const skipped = result.skipped.find((item) => item.mitigation === 'model.safetensors-metadata-relayout');
  assert.ok(Array.isArray(skipped.omittedReason) && skipped.omittedReason.length > 0);
  assert.match(skipped.omittedReason[0], /主体名称/);
  await assert.rejects(() => readFile(`${path}${DEFAULT_OUTPUT_SUFFIX}`), /ENOENT/);
});

// ---- 模型层重布局：GGUF ----

test('GGUF 写入元数据后按原 alignment 重算 tensor_data_offset，张量数据不动', async () => {
  const tensorData = Buffer.from('aaaabbbb', 'latin1');
  const original = buildGguf({
    metadata: [
      { key: 'general.architecture', type: 8, value: 'llama' },
      { key: 'general.alignment', type: 4, value: 32 },
    ],
    tensors: [{ name: 't1', shape: [2], data: tensorData }],
    alignment: 32,
  });
  const { path, findings } = await fixture('basic.gguf', original);
  const before = await auditArtifact(path, {});
  const beforeHeader = before.findings.find((item) => item.category === 'gguf-header');
  const beforeTensors = before.findings.find((item) => item.category === 'gguf-tensors');
  assert.equal(beforeHeader.detail.alignment, 32);
  assert.equal(beforeTensors.detail.tensorDataOffset, beforeHeader.detail.tensorDataOffset);

  const result = await applyMitigations({ target: path, findings, policy: LEGAL_POLICY });
  assert.equal(result.applied.length, 1);
  const relayout = result.applied[0].relayout;
  assert.equal(relayout.alignment, 32);
  assert.equal(relayout.tensorDataOffsetAfter % 32, 0, '必须按原 alignment 重新对齐');

  const hardened = await readFile(result.artifact.outputPath);
  const after = await auditArtifact(result.artifact.outputPath, {});
  const afterHeader = after.findings.find((item) => item.category === 'gguf-header');
  const afterTensors = after.findings.find((item) => item.category === 'gguf-tensors');
  assert.equal(afterHeader.detail.tensorDataOffset, relayout.tensorDataOffsetAfter);
  // 各张量 file_offset 等于新 tensor_data_offset 加原 data_offset。
  for (const [index, tensor] of afterTensors.detail.tensors.entries()) {
    assert.equal(tensor.fileOffset, relayout.tensorDataOffsetAfter + tensor.dataOffset);
    assert.equal(tensor.dataOffset, beforeTensors.detail.tensors[index].dataOffset, '张量声明的 data_offset 必须保持原值');
  }
  // 张量数据整体后移且内容不改写。
  const originalData = original.subarray(beforeHeader.detail.tensorDataOffset);
  const newData = hardened.subarray(afterHeader.detail.tensorDataOffset);
  assert.ok(originalData.equals(newData));
  // 元数据键值已写入，复审看得到。
  const metadata = after.findings.find((item) => item.category === 'gguf-metadata');
  const keys = metadata.detail.keys.map((item) => item.key);
  assert.ok(keys.includes('license.subject'));
  assert.ok(keys.includes('general.alignment'), '原有 alignment 声明必须保留');
  assert.deepEqual(validateGguf(hardened), { ok: true, problems: [] });
});

test('GGUF 按原文件 general.alignment 对齐：声明 64 时数据区按 64 取整，复审同口径', async () => {
  const tensorData = Buffer.from('aaaabbbb', 'latin1');
  const original = buildGguf({
    metadata: [
      { key: 'general.architecture', type: 8, value: 'llama' },
      { key: 'general.alignment', type: 4, value: 64 },
    ],
    tensors: [{ name: 't1', shape: [2], data: tensorData }],
    alignment: 64,
  });
  const { path, findings } = await fixture('align64.gguf', original);
  const result = await applyMitigations({ target: path, findings, policy: LEGAL_POLICY });
  assert.equal(result.applied.length, 1);
  const relayout = result.applied[0].relayout;
  assert.equal(relayout.alignment, 64, '对齐值必须取文件自身的 general.alignment 声明');
  assert.equal(relayout.tensorDataOffsetAfter % 64, 0, '必须按原 alignment 重新对齐');
  const hardened = await readFile(result.artifact.outputPath);
  // 复审判定与重布局写入同一口径：结构事实也按 64 字节判定对齐，不再拿缺省三十二字节误算。
  const inspection = inspectContainer('gguf', hardened);
  assert.equal(inspection.parse.parseable, true);
  assert.equal(inspection.facts['gguf.alignment'].parsed, true);
  assert.match(inspection.facts['gguf.alignment'].reason, /按 64 字节对齐/);
  assert.equal(inspection.facts['gguf.tensor-data'].parsed, true);
  assert.deepEqual(validateGguf(hardened), { ok: true, problems: [] });
});

test('GGUF 重布局键覆盖：同一键内容不同时更新为本次值，策略不变时重复加固逐字节相同', async () => {
  const tensorData = Buffer.from('aaaabbbb', 'latin1');
  // 夹具预置一条内容不同的 license.subject：本次写入必须更新它，而不是堆一条重复键。
  const seeded = buildGguf({
    metadata: [
      { key: 'general.architecture', type: 8, value: 'llama' },
      { key: 'general.alignment', type: 4, value: 32 },
      { key: 'license.subject', type: 8, value: '旧主体' },
    ],
    tensors: [{ name: 't1', shape: [2], data: tensorData }],
    alignment: 32,
  });
  const { path, findings } = await fixture('override.gguf', seeded);
  const result = await applyMitigations({ target: path, findings, policy: LEGAL_POLICY });
  assert.equal(result.applied.length, 1);
  assert.deepEqual(result.applied[0].relayout.updatedKeys, ['license.subject'], '同键不同内容必须记为本键更新');
  const hardened = await readFile(result.artifact.outputPath);
  const parsed = parseGguf(hardened);
  const subjects = parsed.metadata.filter((item) => item.key === 'license.subject');
  assert.equal(subjects.length, 1, '更新后同一键只出现一次，不得留下重复键');
  assert.equal(subjects[0].valueBytes.toString('utf8', 8), '示例主体', '键值必须更新为本次声明');
  // 键数等于原有键数加全新键数：被替换的 license.subject 不增减计数，其余六个许可字段是全新键。
  assert.equal(parsed.metadataCount, 3 + 6, '替换不增减元数据键数，只有全新键才递增');
  // 复审看得到新值，且全部格式校验通过。
  const after = await auditArtifact(result.artifact.outputPath, {});
  const metadata = after.findings.find((item) => item.category === 'gguf-metadata');
  const subject = metadata.detail.keys.find((item) => item.key === 'license.subject');
  // 读取器对非可打印 ASCII 的元数据值按字节替换为点：这里断言它看到的是新值的净化形态，不是旧值。
  assert.equal(subject.value, '.'.repeat(Buffer.byteLength('示例主体', 'utf8')));
  assert.notEqual(subject.value, '.'.repeat(Buffer.byteLength('旧主体', 'utf8')));
  assert.deepEqual(validateGguf(hardened), { ok: true, problems: [] });

  // 幂等：策略不变时对已加固制品再次施加，产出与第一次逐字节相同。
  const again = await applyMitigations({
    target: result.artifact.outputPath,
    findings: after.findings,
    policy: LEGAL_POLICY,
    outputPath: join(workDir, 'override-again.gguf'),
  });
  assert.equal(again.changed, false, '策略不变时重复加固必须逐字节相同');
  assert.equal(again.wrote, false);
  assert.equal(again.artifact.sha256After, result.artifact.sha256After);
  await assert.rejects(() => readFile(join(workDir, 'override-again.gguf')), /ENOENT/);
});

// ---- 必需集豁免互通 ----

test('施加记录能被必需集豁免规则消费，Go 构建信息项被移除、其余项保留', async () => {
  const { path, findings } = await fixture('exempt.elf', buildElfGoInline().buffer);
  const result = await applyMitigations({ target: path, findings, policy: {} });
  const exemptions = exemptionsFor(result.applied, 'elf');
  assert.ok(exemptions.exempted.includes('elf.section.go-buildinfo'));
  assert.ok(exemptions.required.includes('elf.section-table'));
  assert.ok(exemptions.required.includes('elf.program-headers'));
});

// ---- 资源上限与部分读取 ----

test('单文件上限设为极小值时全部跳过并附限制说明，不写出任何字节', async () => {
  const { path, findings } = await fixture('budget.elf', buildElfGoInline().buffer);
  const result = await applyMitigations({
    target: path,
    findings,
    policy: { budgets: { maxFileBytes: 16 } },
  });
  assert.equal(result.status, 'no-op');
  assert.equal(result.applied.length, 0);
  assert.equal(result.skipped.length, findings.length);
  assert.equal(result.limitations[0].code, 'max-file-bytes-exceeded');
  assert.equal(result.artifact.outputPath, null);
  await assert.rejects(() => readFile(`${path}${DEFAULT_OUTPUT_SUFFIX}`), /ENOENT/);
});

// ---- 畸形输入 ----

test('畸形输入：截断的 ELF、空文件、词表外编号都不写出字节', async () => {
  const full = buildElfGoInline().buffer;
  const truncated = full.subarray(0, 40);
  const truncatedPath = join(workDir, 'truncated.elf');
  await writeFile(truncatedPath, truncated);
  const emptyPath = join(workDir, 'empty.bin');
  await writeFile(emptyPath, Buffer.alloc(0));

  const goFinding = { id: 'F-1', mitigation: 'metadata.go-buildinfo-inline-overwrite', detail: { magicOffset: 136 } };
  for (const [label, target] of [['截断的 ELF', truncatedPath], ['空文件', emptyPath]]) {
    const result = await applyMitigations({ target, findings: [goFinding], policy: {} });
    assert.equal(result.applied.length, 0, `${label} 不得施加任何措施`);
    assert.equal(result.changed, false);
    assert.ok(result.skipped[0].reason.length > 0, `${label} 必须附跳过原因`);
    await assert.rejects(() => readFile(`${target}${DEFAULT_OUTPUT_SUFFIX}`), /ENOENT/);
  }

  // 词表外编号与空编号都记跳过，不抛错。
  const unknown = await applyMitigations({ target: emptyPath, findings: [{ id: 'F-2', mitigation: 'not-a-mitigation' }], policy: {} });
  assert.match(unknown.skipped[0].reason, /不在已登记的缓解措施表内/);
  const missing = await applyMitigations({ target: emptyPath, findings: [{ id: 'F-3', mitigation: null }], policy: {} });
  assert.match(missing.skipped[0].reason, /未标注缓解措施编号/);
});

test('畸形输入：中央目录损坏的 ZIP 里覆写令牌会跳过而不是破坏归档', async () => {
  const content = Buffer.from('key=AKIA1234567890ABCDEF\n', 'latin1');
  const zipBytes = buildZip([{ name: 'a.txt', method: 0, content }]);
  const broken = Buffer.from(zipBytes);
  // 令牌在本地文件头（30 字节加五字节条目名）之后的条目数据里。
  const tokenOffset = 30 + 'a.txt'.length + 'key='.length;
  // 破坏中央目录文件头签名：结构定位必须失败，而不是照着坏结构改写条目。
  const centralOffset = broken.indexOf(Buffer.from('PK\x01\x02', 'latin1'));
  assert.ok(centralOffset > 0);
  broken.writeUInt32LE(0x504b0103, centralOffset);
  const brokenPath = join(workDir, 'broken.zip');
  await writeFile(brokenPath, broken);
  const result = await applyMitigations({
    target: brokenPath,
    findings: [
      {
        id: 'F-1',
        mitigation: 'secret.token-placeholder-overwrite',
        detail: { patternId: 'aws-access-key-id', byteSource: 'stored-entry-raw-bytes', fileOffset: tokenOffset },
      },
    ],
    policy: {},
  });
  assert.equal(result.applied.length, 0);
  assert.match(result.skipped[0].reason, /ZIP 结构定位失败/);
  await assert.rejects(() => readFile(`${brokenPath}${DEFAULT_OUTPUT_SUFFIX}`), /ENOENT/);
});

test('畸形输入：张量索引损坏的 safetensors 拒绝对其重布局', async () => {
  // 头部仍是合法 JSON 且带张量条目，容器判定成立，但 data_offsets 不是两个安全整数。
  const header = Buffer.from(JSON.stringify({ t1: { dtype: 'F32', shape: [2], data_offsets: 'bad' } }), 'utf8');
  const prefix = Buffer.alloc(8);
  prefix.writeBigUInt64LE(BigInt(header.length));
  const broken = Buffer.concat([prefix, header, Buffer.from('aaaabbbb', 'latin1')]);
  const brokenPath = join(workDir, 'broken-index.safetensors');
  await writeFile(brokenPath, broken);
  const result = await applyMitigations({
    target: brokenPath,
    findings: [{ id: 'F-1', mitigation: 'model.safetensors-metadata-relayout' }],
    policy: LEGAL_POLICY,
  });
  assert.equal(result.applied.length, 0);
  assert.match(result.skipped[0].reason, /data_offsets/);
  await assert.rejects(() => readFile(`${brokenPath}${DEFAULT_OUTPUT_SUFFIX}`), /ENOENT/);
});

test('畸形输入：内容保护层的发现没有字节区间时跳过而不是猜范围', async () => {
  const { path } = await fixture('segment.elf', buildElfWithToken().buffer);
  const result = await applyMitigations({
    target: path,
    findings: [{ id: 'F-1', mitigation: 'content.data-segment-overwrite', evidence: { path: 'segment.elf', byteRange: null } }],
    policy: {},
  });
  assert.equal(result.applied.length, 0);
  assert.match(result.skipped[0].reason, /证据字节区间/);
});

// ---- 单项施加接口 ----

test('单项施加接口写出到目标同目录的固定后缀路径', async () => {
  const { path, findings } = await fixture('single.elf', buildElfWithToken().buffer);
  const finding = findingOf(findings, 'secret.token-placeholder-overwrite');
  const result = await applyMitigation({ target: path, finding, policy: {} });
  assert.equal(result.applied.length, 1);
  assert.equal(result.artifact.outputPath, `${path}${DEFAULT_OUTPUT_SUFFIX}`);
  const hardened = await readFile(result.artifact.outputPath);
  assert.equal(hardened.includes(Buffer.from('AKIA1234567890ABCDEF', 'latin1')), false);
});

test('逐发现循环调用 apply 时多项措施叠加，不会互相覆盖', async () => {
  // 加固引擎按发现循环调用登记表上的 apply：同一进程内后一次必须叠在前一次的结果上。
  const peFixture = buildPeWithDebugDirectory();
  const { path, findings } = await fixture('compose.pe', peFixture.buffer);
  const results = [];
  for (const finding of findings) {
    if (typeof finding.mitigation !== 'string' || finding.mitigation === '') {
      continue;
    }
    const transform = transformById(finding.mitigation);
    results.push(await transform.apply({ target: path, finding, policy: {} }));
  }
  assert.equal(results.length, 2);
  assert.ok(results.every((result) => result.applied.length === 1));

  const hardened = await readFile(`${path}${DEFAULT_OUTPUT_SUFFIX}`);
  const original = await readFile(path);
  assert.equal(hardened.length, original.length, '等长覆写必须保持字节数不变');
  // 两项覆写都必须落在最终输出里：Go 构建信息魔数与符号文件路径都不再出现。
  assert.equal(hardened.includes(GO_BUILDINFO_MAGIC), false);
  const pathLength = 'D:\build\agent\app.pdb'.length;
  assert.equal(
    hardened.toString('latin1', peFixture.codeviewPathOffset, peFixture.codeviewPathOffset + pathLength + 1),
    '\u0000'.repeat(pathLength + 1),
  );
  const after = await auditArtifact(`${path}${DEFAULT_OUTPUT_SUFFIX}`, {});
  assert.equal(after.findings.some((item) => item.category === 'go-buildinfo'), false);
  assert.equal(after.findings.some((item) => item.category === 'pe-debug-directory'), false);
});

test('批量入口每次从制品原件读起，不把磁盘上已存在的输出当成输入', async () => {
  const { path, findings } = await fixture('fresh.elf', buildElfWithToken().buffer);
  const first = await applyMitigations({ target: path, findings, policy: {} });
  assert.equal(first.changed, true);
  // 再跑一次批量施加：产出与已存在输出逐字节相同，因此不算改动，也不重复写出。
  const second = await applyMitigations({ target: path, findings, policy: {} });
  assert.equal(second.changed, false);
  assert.equal(second.wrote, false);
  assert.equal(second.idempotent, true);
  const output = await readFile(first.artifact.outputPath);
  const original = await readFile(path);
  assert.equal(output.includes(Buffer.from('AKIA1234567890ABCDEF', 'latin1')), false);
  assert.equal(output.length, original.length);
});

test('目标不可读时抛用法错误，不写出任何字节', async () => {
  const { path } = await fixture('unreadable.elf', buildElfWithToken().buffer);
  await assert.rejects(
    () => applyMitigations({ target: workDir, findings: [{ id: 'F-1', mitigation: 'secret.token-placeholder-overwrite' }], policy: {} }),
    /无法读取目标文件/,
  );
  // 原文件未被触碰。
  const original = await readFile(path);
  assert.equal(original.includes(Buffer.from('AKIA1234567890ABCDEF', 'latin1')), true);
});

test('没有发现可施加时不写出任何字节', async () => {
  const { path } = await fixture('noop.elf', buildElfWithToken().buffer);
  const result = await applyMitigations({ target: path, findings: [], policy: {} });
  assert.equal(result.status, 'no-op');
  assert.equal(result.changed, false);
  assert.equal(result.wrote, false);
  assert.equal(result.artifact.outputPath, null);
  await assert.rejects(() => readFile(`${path}${DEFAULT_OUTPUT_SUFFIX}`), /ENOENT/);
});

test('容器不匹配的措施跳过并说明适用范围', async () => {
  const { path, findings } = await fixture('mismatch.pyc', buildPyc());
  const result = await applyMitigations({
    target: path,
    findings: [{ id: 'F-1', mitigation: 'metadata.rust-dep-section-overwrite', detail: { section: '.dep-v0' } }],
    policy: {},
  });
  assert.equal(result.applied.length, 0);
  assert.match(result.skipped[0].reason, /该措施适用于/);
  assert.equal(findings.length > 0, true);
});

// ---- 令牌覆写：扫描窗口与匹配长度 ----

/**
 * PyPI 长令牌：模式匹配长 119 字节，超过摘录上限 96 字符。
 * 修复前，超出覆写侧扫描窗口的命中找不到完整匹配，会按摘录长度只覆写约 97 字节，
 * 把二十余字节秘密原文留在文件里，而报告显示已施加、退出码为 0。
 */
const LONG_PYPI_TOKEN = `pypi-AgEIcHlwaS5vcmc${'Z'.repeat(100)}`;
/** 覆写侧扫描窗口之内的偏移：1 MiB。 */
const TOKEN_OFFSET_INSIDE = 1 * 1024 * 1024;
/** 覆写侧扫描窗口之外、读取器窗口之内的偏移：9 MiB。 */
const TOKEN_OFFSET_BEYOND = 9 * 1024 * 1024;

/**
 * 断言加固产物中令牌占用的每一个字节都已清零。
 * @param {Buffer} hardened 加固后字节
 * @param {number} offset 令牌起始偏移
 * @param {number} length 令牌长度
 * @returns {void}
 */
function assertTokenFullyCleared(hardened, offset, length) {
  const residue = [];
  for (let index = 0; index < length; index += 1) {
    if (hardened[offset + index] !== 0) {
      residue.push(offset + index);
    }
  }
  assert.deepEqual(residue, [], `令牌仍有 ${residue.length} 个字节未清零`);
}

test('扫描窗口内的长令牌完整覆写，不留残余字节', async () => {
  const { path, findings } = await fixture('token-inside.pyc', buildPycWithTokenAt({ offset: TOKEN_OFFSET_INSIDE, token: LONG_PYPI_TOKEN }));
  const finding = findingOf(findings, 'secret.token-placeholder-overwrite');

  const result = await applyMitigations({ target: path, findings: [finding], policy: {} });
  assert.equal(result.applied.length, 1);
  assert.equal(result.applied[0].mitigation, 'secret.token-placeholder-overwrite');

  const hardened = await readFile(result.artifact.outputPath);
  const original = await readFile(path);
  assert.equal(hardened.length, original.length, '等长覆写必须保持字节数不变');
  assertTokenFullyCleared(hardened, finding.detail.fileOffset, LONG_PYPI_TOKEN.length);

  // 复审视角：重新审计后该令牌不再被任何模式命中。
  const after = await auditArtifact(result.artifact.outputPath, {});
  assert.equal(after.findings.some((item) => item.detail?.patternId === 'pypi-token'), false);
});

test('超出覆写侧扫描窗口的长令牌同样完整覆写，不留残余字节', async () => {
  const { path, findings } = await fixture('token-beyond.pyc', buildPycWithTokenAt({ offset: TOKEN_OFFSET_BEYOND, token: LONG_PYPI_TOKEN }));
  const finding = findingOf(findings, 'secret.token-placeholder-overwrite');
  assert.equal(finding.detail.fileOffset, TOKEN_OFFSET_BEYOND);

  const result = await applyMitigations({ target: path, findings: [finding], policy: {} });
  assert.equal(result.applied.length, 1, '窗口外的令牌不得被跳过，也不得部分覆写');
  assert.equal(result.applied[0].mitigation, 'secret.token-placeholder-overwrite');

  const hardened = await readFile(result.artifact.outputPath);
  const original = await readFile(path);
  assert.equal(hardened.length, original.length, '等长覆写必须保持字节数不变');
  assertTokenFullyCleared(hardened, finding.detail.fileOffset, LONG_PYPI_TOKEN.length);

  const after = await auditArtifact(result.artifact.outputPath, {});
  assert.equal(after.findings.some((item) => item.detail?.patternId === 'pypi-token'), false);
});

// ---- 写出原子性 ----

test('写出中途失败不留下损坏副本，也不留下临时文件', async () => {
  const { path, findings } = await fixture('atomic-fail.elf', buildElfGoInline().buffer);
  const finding = findingOf(findings, 'metadata.go-buildinfo-inline-overwrite');
  const outputPath = `${path}${DEFAULT_OUTPUT_SUFFIX}`;

  await assert.rejects(
    () =>
      applyMitigations({
        target: path,
        findings: [finding],
        policy: {},
        io: {
          writeFile: async () => {
            throw new Error('磁盘空间不足');
          },
        },
      }),
    /无法写出加固产物/,
  );

  // 最终路径上什么都没有：不存在长度不足的损坏副本。
  await assert.rejects(() => readFile(outputPath), /ENOENT/);
  // 输出目录里没有临时文件残留。
  const leftovers = (await readdir(workDir)).filter((name) => name.endsWith('.tmp'));
  assert.deepEqual(leftovers, [], `写出失败后不得留下临时文件：${leftovers.join('、')}`);
});

test('成功写出后输出目录不留临时文件', async () => {
  const { path, findings } = await fixture('atomic-ok.elf', buildElfGoInline().buffer);
  const finding = findingOf(findings, 'metadata.go-buildinfo-inline-overwrite');

  const result = await applyMitigations({ target: path, findings: [finding], policy: {} });
  assert.equal(result.wrote, true);

  const leftovers = (await readdir(workDir)).filter((name) => name.endsWith('.tmp'));
  assert.deepEqual(leftovers, [], `成功写出后不得留下临时文件：${leftovers.join('、')}`);
  // 产物本身完整可读。
  const hardened = await readFile(result.artifact.outputPath);
  const original = await readFile(path);
  assert.equal(hardened.length, original.length);
});
