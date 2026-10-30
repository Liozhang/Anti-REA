// 缓解措施边界测试：残留风险与源头解法必须进入报告。
// 覆盖四类输入：登记表数据自身的完整性、真实字节夹具上的审计发现、
// 加固批量结果里的已施加与已跳过条目、人读文本与脱敏后的形状。
//
// 这一轮要守住的是一条既有原则：部分结果不得冒充完整结论。
// 审计侧早就这么做——识别阶段跳过的条目逐条转成限制说明；
// 缓解侧原先只说“已施加”，不说“还剩下什么”，等于让一份不完整的处置冒充完成。
// 本文件的断言全部围绕这句话是否真的传到了用户那里。

import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { auditArtifact } from '../src/audit/engine.mjs';
import { MITIGATION_IDS } from '../src/audit/finding.mjs';
import { NotImplementedError } from '../src/errors.mjs';
import { renderTextReport, TEXT_FINDING_LIMIT } from '../src/report/serialize.mjs';
import { redactReport } from '../src/report/redact.mjs';
import { TRANSFORM_REGISTRY, applyMitigations, residualRiskFor, sourceFixFor } from '../src/transforms/index.mjs';
import { overwriteTokenPlaceholder } from '../src/transforms/equal-length.mjs';
import { verifyArtifact } from '../src/verify/index.mjs';
import { writeContainerFixtures } from './helpers/container-fixtures.mjs';

/** Go 构建信息类的五个编号，残留风险与源头解法对它们是同一件事。 */
const GO_BUILDINFO_IDS = Object.freeze([
  'metadata.go-buildinfo-inline-overwrite',
  'metadata.go-buildinfo-pointer-overwrite',
  'metadata.go-buildinfo-writable-region-overwrite',
  'metadata.go-buildinfo-macho-rw-overwrite',
  'metadata.go-buildinfo-pe-characteristics-overwrite',
]);

/**
 * 建一个装了全部夹具的临时工作区。
 * @returns {Promise<{dir: string, root: string, cleanup: () => Promise<void>}>}
 */
async function fixtureWorkspace() {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-limits-'));
  const root = join(dir, 'fixtures');
  await writeContainerFixtures(root);
  return { dir, root, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

// ---------------------------------------------------------------------------
// 登记表数据自身的完整性
// ---------------------------------------------------------------------------

test('每项缓解措施都登记了残留风险，且是非空字符串', () => {
  assert.equal(TRANSFORM_REGISTRY.length, MITIGATION_IDS.length);
  for (const transform of TRANSFORM_REGISTRY) {
    assert.equal(typeof transform.residualRisk, 'string', `缓解 ${transform.id} 缺少残留风险说明`);
    assert.ok(transform.residualRisk.length > 0, `缓解 ${transform.id} 的残留风险说明不得为空`);
  }
});

test('源头解法要么没有，要么动作与自身代价都写全', () => {
  let withFix = 0;
  for (const transform of TRANSFORM_REGISTRY) {
    const fix = transform.sourceFix;
    if (fix === null) {
      continue;
    }
    withFix += 1;
    assert.equal(typeof fix, 'object', `缓解 ${transform.id} 的源头解法必须是对象或 null`);
    assert.equal(typeof fix.action, 'string', `缓解 ${transform.id} 的源头解法缺少 action`);
    assert.ok(fix.action.length > 0, `缓解 ${transform.id} 的源头解法动作不得为空`);
    assert.equal(typeof fix.risk, 'string', `缓解 ${transform.id} 的源头解法缺少 risk`);
    assert.ok(fix.risk.length > 0, `缓解 ${transform.id} 的源头解法自身代价不得为空`);
  }
  // 多数措施有源头解法，但不得全部都有：数据段区间由调用方指定，
  // 反运行时观察集成包本身就是给源码用的集成代码，这两项没有构建期动作可给。
  assert.ok(withFix > 0, '没有任何措施给出源头解法，登记表等于没补');
  assert.ok(withFix < TRANSFORM_REGISTRY.length, '全部措施都给了源头解法，说明该给 null 的两项漏了');
});

test('Go 构建信息类：残留风险点明字符串检索仍能命中，源头解法给出构建参数', () => {
  for (const id of GO_BUILDINFO_IDS) {
    const risk = residualRiskFor(id);
    assert.match(risk, /字符串检索/, `缓解 ${id} 的残留风险必须点明 strings 仍能命中`);
    const fix = sourceFixFor(id);
    assert.match(fix.action, /-trimpath/, `缓解 ${id} 的源头解法应给出 -trimpath`);
    assert.match(fix.action, /-ldflags="-s -w"/, `缓解 ${id} 的源头解法应给出 -s -w`);
    // 源头解法自身代价必须写：去掉符号表会影响 panic 堆栈，-trimpath 会改运行期路径。
    assert.match(fix.risk, /panic/, `缓解 ${id} 的源头解法必须说明对 panic 堆栈的影响`);
  }
});

test('没有源头解法的两项：调用方指定的数据段区间与反运行时观察集成包', () => {
  assert.equal(sourceFixFor('content.data-segment-overwrite'), null, '数据段区间是调用方自己指定的，没有构建期动作可给');
  assert.equal(sourceFixFor('runtime.probe-integration-package'), null, '集成包本身就是给源码用的集成代码，不存在更彻底的构建期做法');
  // 没有源头解法不等于没有残留风险：这两项仍要说明自己做不到什么。
  assert.ok(residualRiskFor('content.data-segment-overwrite').length > 0);
  assert.ok(residualRiskFor('runtime.probe-integration-package').length > 0);
});

test('令牌覆写的源头解法指向服务端下发，并说明这是唯一绝对有效的一层', () => {
  const fix = sourceFixFor('secret.token-placeholder-overwrite');
  assert.match(fix.action, /服务端/, '令牌的源头解法应指向服务端下发');
  assert.match(fix.risk, /唯一绝对有效/, '必须说明这是唯一绝对有效的一层，其余只提高成本');
});

test('编号不在表内或不是字符串时返回 null，不抛错', () => {
  for (const bad of ['metadata.not-a-real-mitigation', '', undefined, null, 42, {}]) {
    assert.equal(residualRiskFor(bad), null, `残留风险查询对 ${String(bad)} 应返回 null`);
    assert.equal(sourceFixFor(bad), null, `源头解法查询对 ${String(bad)} 应返回 null`);
  }
});

// ---------------------------------------------------------------------------
// 残留风险的内容必须可核验：每条都点明具体留下什么，而不是免责套话
// ---------------------------------------------------------------------------

test('每条残留风险都点明具体留下什么，可按关键词核验', () => {
  // 关键词不是文采要求，是“这句话有没有说清一件事”的判据。
  // 一条只写“可能存在风险”的声明无法被核验，也就无法被用户用来做决定。
  const expected = {
    'metadata.go-buildinfo-inline-overwrite': /字符串检索/,
    'metadata.go-buildinfo-pointer-overwrite': /字符串检索/,
    'metadata.go-buildinfo-writable-region-overwrite': /字符串检索/,
    'metadata.go-buildinfo-macho-rw-overwrite': /字符串检索/,
    'metadata.go-buildinfo-pe-characteristics-overwrite': /字符串检索/,
    'metadata.rust-dep-section-overwrite': /压缩载荷/,
    'metadata.elf-symtab-clear': /按名检索/,
    'metadata.elf-build-id-note-overwrite': /指纹/,
    'metadata.pe-debug-directory-overwrite': /调试目录结构/,
    'metadata.pyc-source-hash-clear': /反汇编/,
    'content.data-segment-overwrite': /区间外/,
    'runtime.probe-integration-package': /可分析面/,
    'model.safetensors-metadata-relayout': /再次剥离/,
    'model.gguf-metadata-relayout': /再次剥离/,
    'secret.token-placeholder-overwrite': /自创令牌/,
  };
  for (const transform of TRANSFORM_REGISTRY) {
    const pattern = expected[transform.id];
    assert.ok(pattern !== undefined, `缓解 ${transform.id} 没有登记残留风险核验关键词，测试覆盖有缺口`);
    assert.match(transform.residualRisk, pattern, `缓解 ${transform.id} 的残留风险未点明应当写清的事实`);
  }
});

test('每个源头解法都给出可核验的构建动作', () => {
  const expected = {
    'metadata.go-buildinfo-inline-overwrite': /-trimpath/,
    'metadata.go-buildinfo-pointer-overwrite': /-trimpath/,
    'metadata.go-buildinfo-writable-region-overwrite': /-trimpath/,
    'metadata.go-buildinfo-macho-rw-overwrite': /-trimpath/,
    'metadata.go-buildinfo-pe-characteristics-overwrite': /-trimpath/,
    'metadata.rust-dep-section-overwrite': /--remove-section=/,
    'metadata.elf-symtab-clear': /strip/,
    'metadata.elf-build-id-note-overwrite': /--build-id=none/,
    'metadata.pe-debug-directory-overwrite': /DEBUG:NONE/,
    'metadata.pyc-source-hash-clear': /--invalidation-mode timestamp/,
    'model.safetensors-metadata-relayout': /导出/,
    'model.gguf-metadata-relayout': /导出/,
    'secret.token-placeholder-overwrite': /服务端/,
  };
  for (const [id, pattern] of Object.entries(expected)) {
    const fix = sourceFixFor(id);
    assert.ok(fix !== null, `缓解 ${id} 应给出源头解法`);
    assert.match(fix.action, pattern, `缓解 ${id} 的源头解法动作不是可核验的构建命令`);
    // 没有代价说明的建议等于替用户做了决定，这条与功能风险同一标准。
    assert.ok(fix.risk.length > 0, `缓解 ${id} 的源头解法必须说明自身代价`);
  }
});

// ---------------------------------------------------------------------------
// 残留风险经实测成立，而不是只写在表里
// ---------------------------------------------------------------------------

test('令牌覆写的残留风险经实测成立：已知格式清零，自创格式原样留下', () => {
  // 登记表写着“任意自创令牌不在覆盖内；检索为空不证明制品里没有秘密”。
  // 这句话必须能用字节证明，否则它和套话没有区别。
  const known = 'AKIAIOSFODNN7EXAMPLE';
  const privateToken = 'svc-9f3a7b2e1d4c';
  const buffer = Buffer.from(`pre ${known} mid ${privateToken} post`, 'latin1');
  const finding = {
    layer: 'secret-minimization',
    severity: 'high',
    title: 'AWS 访问键标识',
    category: 'token-aws-access-key-id',
    evidence: { path: 'app.bin', byteRange: [buffer.indexOf(known), buffer.indexOf(known) + known.length], excerpt: null },
    reader: 'elf',
    readerLimitation: '只匹配有公开格式的已知凭据家族',
    mitigation: 'secret.token-placeholder-overwrite',
    detail: { patternId: 'aws-access-key-id', fileOffset: buffer.indexOf(known) },
  };
  const applied = overwriteTokenPlaceholder(buffer, finding, 'elf');
  assert.equal(applied.ok, true, `应可覆写：${applied.reason ?? ''}`);
  assert.equal(applied.buffer.includes(known), false, '已知格式的令牌应被清零');
  assert.equal(applied.buffer.includes(privateToken), true, '自创格式的令牌必须原样留下，这正是登记表声明的残留风险');
  // “区间外仍可被直接检索”同样要能证明：覆写区间之外的字节逐字节不变。
  const [from, to] = applied.ranges[0];
  assert.equal(applied.buffer.subarray(0, from).equals(buffer.subarray(0, from)), true, '覆写区间之前不得改动');
  assert.equal(applied.buffer.subarray(to).equals(buffer.subarray(to)), true, '覆写区间之后不得改动');
});

test('pyc 源哈希清零后：按名核对机制失效，字节码仍可解析', async () => {
  // 登记表写着“清零源哈希后按名核对源文件的机制失效，但字节码本身仍可被完整反汇编”。
  // 两侧都要证明：哈希变零、核对标志消失是一侧，复审仍判通过是另一侧。
  //
  // 夹具在这里自建而不用 tests/helpers/container-fixtures.mjs 的 hash-based.pyc：
  // 那份夹具的载荷是 0x42 填充，不是合法的 marshal 类型码，未修改时就通不过复审，
  // 用它做本测试会把夹具缺陷当成措施缺陷。摘要已登记，不能改共用夹具。
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-pyc-residual-'));
  try {
    const target = join(dir, 'hash-based.pyc');
    const bytecode = Buffer.concat([Buffer.from('c', 'latin1'), Buffer.alloc(48, 0x5a)]);
    const pyc = Buffer.concat([
      Buffer.from([0xa7, 0x0d, 0x0d, 0x0a]), // Python 3.11 魔数，字节 2 至 3 固定 0D 0A
      (() => { const b = Buffer.alloc(4); b.writeUInt32LE(0x03, 0); return b; })(), // hash_based 且 check_source
      Buffer.from('01234567', 'latin1'), // 源文件摘要
      bytecode,
    ]);
    await writeFile(target, pyc);

    const before = await auditArtifact(target);
    assert.ok(before.findings.some((finding) => finding.category === 'pyc-source-hash'), '应报源哈希');
    // 先证明夹具本身是健全的：没动过的制品就必须通过复审，否则后面的断言没有意义。
    const clean = await verifyArtifact(target, { applied: [] });
    assert.equal(clean.report.status, 'passed', `夹具本身应通过复审：${JSON.stringify(clean.report.summary)}`);

    const batch = await applyMitigations({ target, findings: before.findings, outputPath: join(dir, 'out.pyc') });
    assert.equal(batch.status, 'applied');
    const hardened = batch.artifact.outputPath;

    const after = await auditArtifact(hardened);
    const hashFinding = after.findings.find((finding) => finding.category === 'pyc-source-hash');
    assert.ok(hashFinding !== undefined, '清零后字段仍在，审计照样报告它当前的状态');
    assert.equal(hashFinding.detail.sourceHash, '0'.repeat(16), '清零后源哈希应全为零');
    assert.equal(hashFinding.detail.checkSource, false, '清零后按名核对源文件的机制应失效');

    // 另一侧：字节码本身仍可解析，复审不得因为清零而判不通过。
    // 豁免从施加记录派生，因此把 batch.applied 交给复审；施加过什么，
    // 复审才能判断哪些结构本该被破坏、哪些必须仍然完好。
    const review = await verifyArtifact(hardened, { applied: batch.applied });
    assert.equal(review.report.status, 'passed', `清零后复审应通过：${JSON.stringify(review.report.summary)}`);
    const sections = review.report.checks.find((check) => check.family === 'required-sections');
    assert.equal(sections.status, 'passed', `必需集应通过：${sections.reason ?? ''}`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});


// ---------------------------------------------------------------------------
// 审计发现：用户在审计阶段就看到这项措施做不到什么
// ---------------------------------------------------------------------------

test('审计发现按有无缓解编号分别挂载残留风险与源头解法', async () => {
  const workspace = await fixtureWorkspace();
  try {
    const report = await auditArtifact(workspace.root);
    assert.ok(report.findings.length > 0, '夹具目录应产生真实发现');

    let withMitigation = 0;
    let withoutMitigation = 0;
    for (const finding of report.findings) {
      // 两个字段必须在每条发现上都存在，取值只能是 null 或有内容：
      // 时有时无的字段会让消费方分不清“没有”与“没给”。
      assert.ok('residualRisk' in finding, `发现 ${finding.id} 缺少 residualRisk 字段`);
      assert.ok('sourceFix' in finding, `发现 ${finding.id} 缺少 sourceFix 字段`);
      if (finding.mitigation === null) {
        withoutMitigation += 1;
        assert.equal(finding.residualRisk, null, `发现 ${finding.id} 没有缓解编号，残留风险应为 null`);
        assert.equal(finding.sourceFix, null, `发现 ${finding.id} 没有缓解编号，源头解法应为 null`);
        continue;
      }
      withMitigation += 1;
      assert.ok(MITIGATION_IDS.includes(finding.mitigation), `发现 ${finding.id} 的缓解编号不在词表内`);
      assert.equal(typeof finding.residualRisk, 'string', `发现 ${finding.id} 有缓解编号却没有残留风险`);
      assert.ok(finding.residualRisk.length > 0, `发现 ${finding.id} 的残留风险不得为空`);
    }
    assert.ok(withMitigation > 0, '夹具目录里没有一条带缓解编号的发现，本条断言是空转');
    assert.ok(withoutMitigation > 0, '夹具目录里没有一条无缓解编号的发现，另一条断言是空转');
  } finally {
    await workspace.cleanup();
  }
});

test('pyc 源哈希发现的源头解法指向重新编译，且说明时间戳核对的代价', async () => {
  const workspace = await fixtureWorkspace();
  try {
    const report = await auditArtifact(join(workspace.root, 'pyc', 'hash-based.pyc'));
    const finding = report.findings.find((item) => item.category === 'pyc-source-hash');
    assert.ok(finding !== undefined, 'hash-based 夹具应报源哈希事实');
    assert.equal(finding.mitigation, 'metadata.pyc-source-hash-clear');
    assert.match(finding.sourceFix.action, /--invalidation-mode timestamp/);
    assert.match(finding.sourceFix.risk, /修改时间与大小/, '必须说明时间戳模式下解释器按什么核对');
  } finally {
    await workspace.cleanup();
  }
});

// ---------------------------------------------------------------------------
// 加固批量结果：已施加与已跳过都要说清还剩下什么
// ---------------------------------------------------------------------------

test('已施加的缓解项带残留风险与源头解法', async () => {
  const workspace = await fixtureWorkspace();
  try {
    const target = join(workspace.root, 'pyc', 'hash-based.pyc');
    const report = await auditArtifact(target);
    const batch = await applyMitigations({
      target,
      findings: report.findings,
      outputPath: join(workspace.dir, 'out.pyc'),
    });
    assert.equal(batch.status, 'applied', 'hash-based 夹具应真的施加一项措施');
    assert.equal(batch.applied.length, 1);
    const applied = batch.applied[0];
    assert.equal(applied.mitigation, 'metadata.pyc-source-hash-clear');
    assert.equal(typeof applied.residualRisk, 'string');
    assert.ok(applied.residualRisk.length > 0, '已施加项必须说明施加后仍会暴露什么');
    assert.equal(applied.sourceFix.action, sourceFixFor('metadata.pyc-source-hash-clear').action);
  } finally {
    await workspace.cleanup();
  }
});

test('跳过不施加的条目也带残留风险：没做这件事不等于这件事没有边界', async () => {
  const workspace = await fixtureWorkspace();
  try {
    // GGUF 重布局缺法律字段时拒写，该措施落在已跳过一栏。
    // 用户仍需要知道“就算施加了，元数据也能被再次剥离”。
    const target = join(workspace.root, 'gguf', 'basic.gguf');
    const report = await auditArtifact(target);
    const batch = await applyMitigations({
      target,
      findings: report.findings,
      outputPath: join(workspace.dir, 'out.gguf'),
    });
    const skipped = batch.skipped.find((item) => item.mitigation === 'model.gguf-metadata-relayout');
    assert.ok(skipped !== undefined, 'GGUF 夹具应产生一条被跳过的重布局措施');
    assert.equal(typeof skipped.residualRisk, 'string');
    assert.match(skipped.residualRisk, /再次剥离/);
    // 没有缓解编号可派的条目，两个字段保持 null，不编造内容。
    const anonymous = batch.skipped.find((item) => item.mitigation === null);
    assert.ok(anonymous !== undefined);
    assert.equal(anonymous.residualRisk, null);
    assert.equal(anonymous.sourceFix, null);
  } finally {
    await workspace.cleanup();
  }
});

test('单文件超预算全部跳过时，残留风险照写', async () => {
  const workspace = await fixtureWorkspace();
  try {
    const target = join(workspace.root, 'pyc', 'hash-based.pyc');
    const report = await auditArtifact(target);
    const batch = await applyMitigations({
      target,
      findings: report.findings,
      outputPath: join(workspace.dir, 'out.pyc'),
      policy: { budgets: { maxFileBytes: 1 } },
    });
    assert.equal(batch.status, 'no-op');
    assert.equal(batch.applied.length, 0);
    assert.ok(batch.skipped.length > 0);
    for (const item of batch.skipped) {
      if (item.mitigation === null) {
        assert.equal(item.residualRisk, null);
        continue;
      }
      assert.equal(typeof item.residualRisk, 'string', `超预算跳过的 ${item.mitigation} 仍应带残留风险`);
      assert.ok(item.residualRisk.length > 0);
    }
  } finally {
    await workspace.cleanup();
  }
});

// ---------------------------------------------------------------------------
// 错误归因：给错误的原因比没有原因更糟
// ---------------------------------------------------------------------------

test('读取器返回形状非法的结果时，限制说明点明是哪一项与哪一处不对', async () => {
  // 参照 REA 的 #7652 与 #7688：把畸形输入报成“提供方执行失败”、把普通文件父目录
  // 归类成“宿主写入失败”。共同点是给出了错误的原因，用户照着错误的原因排查，
  // 永远找不到真正的问题。本项目的要求：限制说明必须点明是哪一项、哪一处不对。
  const workspace = await fixtureWorkspace();
  try {
    const readers = {
      elf: [
        {
          id: 'elf-malformed',
          formats: ['elf'],
          layers: ['metadata-hygiene'],
          purpose: '返回形状非法结果的读取器替身',
          read: async () => ({ findings: 'not-an-array', limitations: [] }),
        },
      ],
    };
    const report = await auditArtifact(join(workspace.root, 'elf', 'basic.elf'), { readers });
    const note = report.limitations.find((limitation) => limitation.code === 'reader-error');
    assert.ok(note !== undefined, '形状非法的结果必须留下 reader-error 限制说明');
    assert.ok(note.message.includes('elf-malformed'), '必须点明是哪一个读取器');
    assert.ok(note.message.includes('findings'), '必须点明是哪一处形状不对');
    assert.equal(report.findings.length, 0, '形状非法的 findings 不得进报告');
  } finally {
    await workspace.cleanup();
  }
});

test('读取器提交词表外发现时，限制说明带真实校验原因', async () => {
  const workspace = await fixtureWorkspace();
  try {
    const readers = {
      elf: [
        {
          id: 'elf-bad-vocabulary',
          formats: ['elf'],
          layers: ['metadata-hygiene'],
          purpose: '提交非法层名的读取器替身',
          read: async () => ({
            findings: [
              {
                layer: 'not-a-layer',
                severity: 'info',
                title: '越界发现',
                category: 'elf-header',
                evidence: { path: 'elf/basic.elf' },
                reader: 'elf',
                readerLimitation: '无',
              },
            ],
            limitations: [],
          }),
        },
      ],
    };
    const report = await auditArtifact(join(workspace.root, 'elf', 'basic.elf'), { readers });
    const rejected = report.limitations.find((limitation) => limitation.code === 'finding-rejected');
    assert.ok(rejected !== undefined, '词表外发现必须留下 finding-rejected 限制说明');
    assert.match(rejected.message, /层标识不在封闭词表内/, '限制说明必须带上真实校验原因');
    assert.ok(!report.findings.some((finding) => finding.layer === 'not-a-layer'), '词表外发现不得混进报告');
  } finally {
    await workspace.cleanup();
  }
});

test('读取器声明未实现时，限制说明点明是哪一项与它的用途', async () => {
  const workspace = await fixtureWorkspace();
  try {
    const readers = {
      elf: [
        {
          id: 'elf-unimplemented',
          formats: ['elf'],
          layers: ['metadata-hygiene'],
          purpose: '解析节表并登记每节的类型与对齐',
          read: async () => {
            throw new NotImplementedError('readers/elf-unimplemented', '解析逻辑尚未实现');
          },
        },
      ],
    };
    const report = await auditArtifact(join(workspace.root, 'elf', 'basic.elf'), { readers });
    const note = report.limitations.find((limitation) => limitation.code === 'reader-not-implemented');
    assert.ok(note !== undefined, '未实现的读取器必须留下限制说明');
    assert.ok(note.message.includes('elf-unimplemented'), '必须点明是哪一项未实现');
    assert.ok(note.message.includes('解析节表'), '必须说明这项读取器本来要做什么');
  } finally {
    await workspace.cleanup();
  }
});

test('人读文本逐条列出发现，并带上残留风险与源头解法', async () => {
  const workspace = await fixtureWorkspace();
  try {
    const report = await auditArtifact(join(workspace.root, 'gguf', 'basic.gguf'));
    const text = renderTextReport(report);
    assert.ok(text.includes('逐条发现：'), '人读文本应逐条列出发现');
    const withFix = report.findings.find((finding) => finding.sourceFix !== null);
    assert.ok(withFix !== undefined, 'GGUF 夹具应有带源头解法的发现');
    assert.ok(text.includes(`施加后仍会暴露：${withFix.residualRisk}`), '人读文本应给出残留风险原文');
    assert.ok(text.includes(`更彻底的做法：${withFix.sourceFix.action}`), '人读文本应给出源头解法动作');
    assert.ok(text.includes(`该做法的自身代价：${withFix.sourceFix.risk}`), '人读文本应给出源头解法的自身代价');
    assert.ok(text.endsWith('\n'), '人读文本以换行收尾');
  } finally {
    await workspace.cleanup();
  }
});

test('人读文本逐条列出有上限，超出部分只报条数并指向 JSON 输出', () => {
  const findings = [];
  for (let index = 0; index < TEXT_FINDING_LIMIT + 7; index += 1) {
    findings.push({
      id: `F-metadata-hygiene-${String(index + 1).padStart(4, '0')}`,
      layer: 'metadata-hygiene',
      severity: 'info',
      title: `标题 ${index}`,
      category: 'elf-header',
      evidence: { path: `app-${index}.elf`, byteRange: [0, 64], excerpt: null },
      reader: 'elf',
      readerLimitation: '只读头部',
      mitigation: null,
      residualRisk: null,
      sourceFix: null,
    });
  }
  const report = {
    schema: 'anti-rea.audit-report/1',
    tool: 'audit-artifact',
    status: 'complete',
    artifact: { kind: 'directory', path: '/build/out', sha256: 'a'.repeat(64), bytes: 4096, entryCount: 27 },
    findings,
    limitations: [],
    summary: { findings: findings.length, byLayer: { 'metadata-hygiene': findings.length }, bySeverity: { info: findings.length } },
  };
  const text = renderTextReport(report);
  const printed = text.split('\n').filter((line) => line.includes('[info] 标题'));
  assert.equal(printed.length, TEXT_FINDING_LIMIT, '逐条列出不得超出上限');
  assert.ok(text.includes(`另有 7 条发现未在此列出，完整清单请用 JSON 输出`), '超出部分必须报条数并说明去哪里取');
});

test('复审报告的人读文本不列逐条发现，也不拿发现数 0 冒充', async () => {
  const workspace = await fixtureWorkspace();
  try {
    const { report } = await verifyArtifact(join(workspace.root, 'elf', 'basic.elf'));
    const text = renderTextReport(report);
    assert.ok(!text.includes('发现数'), '复审报告不得显示发现数 0');
    assert.ok(!text.includes('逐条发现'), '复审报告按检查族汇总，不得逐条列发现');
    assert.ok(text.includes(`检查数：${report.summary.checks} 项`));
  } finally {
    await workspace.cleanup();
  }
});

test('脱敏报告不保留残留风险与源头解法', async () => {
  const workspace = await fixtureWorkspace();
  try {
    const report = await auditArtifact(join(workspace.root, 'pyc', 'hash-based.pyc'));
    const redacted = redactReport(report);
    const text = JSON.stringify(redacted);
    assert.equal(redacted.redacted, true);
    assert.ok(!text.includes('residualRisk'), '脱敏报告不得保留残留风险字段');
    assert.ok(!text.includes('sourceFix'), '脱敏报告不得保留源头解法字段');
    assert.ok(!text.includes('--invalidation-mode'), '脱敏报告不得保留源头解法里的命令');
    // 脱敏保留的字段一条不少：分类信息仍是收件方能看懂的。
    assert.deepEqual(
      redacted.findings.map((finding) => [finding.layer, finding.severity, finding.category, finding.reader]),
      report.findings.map((finding) => [finding.layer, finding.severity, finding.category, finding.reader]),
    );
  } finally {
    await workspace.cleanup();
  }
});
