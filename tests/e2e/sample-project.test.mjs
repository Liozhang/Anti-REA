// 端到端测试：在 tests/e2e/build.mjs 生成的模拟小项目上跑通四条工作流与 MCP 服务层。
// 覆盖三类输入：
//   正常输入   目录目标与文件目标的 audit、harden（逐条目施加）、verify 通过与不通过、
//              notice 三种输出形态、MCP 四个工具、git 工作树警告、--redacted 脱敏、重复加固幂等
//   畸形输入   notice 法律字段缺失走拒否；probe 子命令与 generate_probe_kit 工具按目标契约断言
//   资源与边界 Java 类文件命中 CAFEBABE 魔数，识别阶段按分片表判为范围外容器并附歧义说明
//
// 每个用例都从 tests/e2e/build.mjs 重新生成一份项目写进临时目录，跑完即删：
// 夹具不提交字节，也不让上一个用例的加固产物污染下一个用例的审计基线。
// 进程内跑命令行（src/cli/index.mjs 的 runCli）为主，目录审计与两条 git 工作树用例
// 另走真实子进程（tests/helpers/cli.mjs），确认入口脚本本身也走得通。

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { runCli as runCliSubprocess } from '../helpers/cli.mjs';
import { EXIT_CODES } from '../../src/cli/exit-codes.mjs';
import { runCli } from '../../src/cli/index.mjs';
import { detectContainer } from '../../src/container/detect.mjs';
import { createMcpServer } from '../../src/mcp/server.mjs';
import { DEFAULT_OUTPUT_SUFFIX } from '../../src/transforms/index.mjs';
import { SAMPLE_PROJECT_FILES, buildSampleProjectFiles, writeSampleProject } from './build.mjs';

/** 生成项目所在的临时目录前缀。 */
const PROJECT_PREFIX = 'anti-rea-e2e-project-';

/** 法律字段齐全的策略：模型层重布局要写许可元数据，字段不齐时加固会拒否。 */
const COMPLETE_LEGAL = Object.freeze({
  subject: '示例主体',
  contact: 'security@example.com',
  jurisdiction: '示例辖区',
  licenseId: 'MIT',
  licenseTextSource: 'https://example.com/LICENSE',
  prohibitedActs: Object.freeze(['逆向工程']),
  consequences: Object.freeze([Object.freeze({ statement: '示例后果陈述', statuteExcerpt: '示例法条摘录' })]),
});

/** 字节级条目到期望容器的映射，按魔数判定，与 build.mjs 的 covers 一一对应。 */
const EXPECTED_CONTAINERS = Object.freeze({
  'bin/app-linux': 'elf',
  'bin/app-windows.exe': 'pe',
  'bin/app-macos': 'mach-o',
  'models/model.gguf': 'gguf',
  'models/weights.safetensors': 'safetensors',
  'pycache/app.cpython-312.pyc': 'pyc',
  'dist/bundle.zip': 'zip',
  'java/com/example/App.class': 'unsupported',
});

/**
 * 造一个带 .git 标记的临时目录，模拟 git 工作树。
 * 写法与 tests/cli-contract.test.mjs 的 makeGitTree 一致：.git 写成文件，
 * 指向仓库外的 gitdir，不依赖机器上是否装了 git。
 * @returns {Promise<string>} 临时目录路径
 */
async function makeGitTree() {
  const root = await mkdtemp(join(tmpdir(), 'anti-rea-e2e-git-'));
  await writeFile(join(root, '.git'), 'gitdir: /elsewhere\n', 'utf8');
  return root;
}

/**
 * 生成一份新的模拟项目，返回目录路径，调用方负责删除。
 * @returns {Promise<string>} 项目根目录
 */
async function makeProject() {
  const root = await mkdtemp(join(tmpdir(), PROJECT_PREFIX));
  await writeSampleProject(root);
  return root;
}

/**
 * 进程内运行命令行，收集退出码与输出。
 * @param {readonly string[]} args 命令行参数
 * @returns {Promise<{code: number, stdout: string, stderr: string}>}
 */
async function runInProcess(args) {
  let stdout = '';
  let stderr = '';
  const code = await runCli(args, {
    write: (text) => {
      stdout += text;
    },
    writeError: (text) => {
      stderr += text;
    },
  });
  return { code, stdout, stderr };
}

/**
 * 把策略写进临时文件，返回路径。
 * @param {Record<string, unknown>} legal legal 节
 * @returns {Promise<{path: string, dir: string}>} 策略文件路径与所在目录
 */
async function writePolicy(legal) {
  const dir = await mkdtemp(join(tmpdir(), 'anti-rea-e2e-policy-'));
  const path = join(dir, 'policy.json');
  await writeFile(path, JSON.stringify({ legal }), 'utf8');
  return { path, dir };
}

/**
 * 审计目标并把报告写到临时文件，返回报告对象、文件路径与所在目录。
 * @param {string} target 目录或文件路径
 * @param {string} dir 存放审计结果的目录
 * @returns {Promise<{report: Record<string, unknown>, path: string, dir: string}>}
 */
async function auditToFile(target, dir) {
  const result = await runInProcess(['audit', target, '--json']);
  assert.equal(result.code, EXIT_CODES.SUCCESS, `审计应正常完成：${result.stderr}`);
  const path = join(dir, 'audit.json');
  await writeFile(path, result.stdout, 'utf8');
  return { report: JSON.parse(result.stdout), path, dir };
}

/**
 * 计算文件 sha256。
 * @param {string} path 文件路径
 * @returns {Promise<string>}
 */
async function digestOf(path) {
  return createHash('sha256').update(await readFile(path)).digest('hex');
}

/**
 * 判断路径是否存在。
 * @param {string} path
 * @returns {Promise<boolean>}
 */
async function exists(path) {
  const info = await stat(path).catch(() => null);
  return info !== null;
}

// —— 生成脚本：确定性与覆盖面 ——

test('模拟项目按清单确定性生成，两次生成逐字节相同，且覆盖要求的各类制品', async () => {
  const first = await mkdtemp(join(tmpdir(), 'anti-rea-e2e-gen-'));
  const second = await mkdtemp(join(tmpdir(), 'anti-rea-e2e-gen-'));
  try {
    const left = await writeSampleProject(first);
    const right = await writeSampleProject(second);
    assert.equal(left.length, SAMPLE_PROJECT_FILES.length, '条目数应与清单一致');
    assert.deepEqual(
      left.map((entry) => [entry.relativePath, entry.bytes, entry.sha256]),
      right.map((entry) => [entry.relativePath, entry.bytes, entry.sha256]),
      '同一份构造器在任何时候都应产出同一串字节',
    );

    // 覆盖面：任务要求的八类字节级制品加源码地图引用、说明文档、许可与普通文件都要在。
    const paths = new Set(left.map((entry) => entry.relativePath));
    for (const required of [
      'bin/app-linux',
      'bin/app-windows.exe',
      'bin/app-macos',
      'models/model.gguf',
      'models/weights.safetensors',
      'pycache/app.cpython-312.pyc',
      'java/com/example/App.class',
      'dist/bundle.zip',
      'src/bundle.js',
      'README.md',
      'LICENSE',
      'package.json',
      'config/settings.json',
      'docs/CHANGELOG.md',
      'notes.txt',
    ]) {
      assert.ok(paths.has(required), `模拟项目缺少条目：${required}`);
    }

    // 每个字节级条目按魔数判定确实是目标容器，夹具没有名不对实。
    for (const [relativePath, containerType] of Object.entries(EXPECTED_CONTAINERS)) {
      const entry = buildSampleProjectFiles().find((item) => item.relativePath === relativePath);
      assert.notEqual(entry, undefined, `清单里找不到条目 ${relativePath}`);
      assert.equal(detectContainer(entry.bytes).type, containerType, `${relativePath} 应判为 ${containerType}`);
    }
  } finally {
    await rm(first, { recursive: true, force: true });
    await rm(second, { recursive: true, force: true });
  }
});

test('Java 类文件命中 CAFEBABE：识别阶段按分片表判为范围外容器并附带 Java 歧义说明', () => {
  const entry = buildSampleProjectFiles().find((item) => item.relativePath === 'java/com/example/App.class');
  const detected = detectContainer(entry.bytes);
  // CAFEBABE 同时是 Mach-O 胖二进制魔数：该文件魔数后四字节是 Java 8 主版本号 52，
  // 不落在一到三十二的分片数区间，常量池计数与类字段也不是合法分片头，
  // 识别阶段即按 Java 类文件归入范围外容器，不送进 Mach-O 读取器。
  // 判别口径与 tests/container.test.mjs 的“按分片表判别”一致。
  assert.equal(detected.type, 'unsupported');
  assert.equal(detected.label, '范围外容器');
  // 歧义说明必须挂在魔数上：读到的制品是 Java 类文件，工具不能默默按胖二进制解析。
  assert.match(detected.note ?? '', /CAFEBABE/);
  assert.match(detected.note ?? '', /Java/);
  assert.equal(entry.bytes.readUInt32BE(4), 52, 'Java 8 类文件该位置是主版本号，不是合理分片数');
});

// —— 正常输入：audit 的目录目标与文件目标 ——

test('audit 目录目标：退出码 0，报告覆盖全部条目、容器分类与能力边界', async () => {
  const root = await makeProject();
  try {
    const result = await runCliSubprocess(['audit', root, '--json']);
    assert.equal(result.code, EXIT_CODES.SUCCESS);
    const report = JSON.parse(result.stdout);
    assert.equal(report.tool, 'audit-artifact');
    assert.equal(report.artifact.kind, 'directory');
    assert.equal(report.artifact.entryCount, SAMPLE_PROJECT_FILES.length);
    assert.equal(report.status, 'complete', '预算取默认值时不应对完整项目产部分结果');

    const containerCounts = Object.fromEntries(report.containers.map((item) => [item.type, item.count]));
    for (const type of ['elf', 'pe', 'mach-o', 'zip', 'gguf', 'safetensors', 'pyc']) {
      assert.ok((containerCounts[type] ?? 0) >= 1, `报告里应出现容器 ${type}`);
    }
    // Java 类文件命中 CAFEBABE 但按分片表判为范围外容器，与七个普通文本条目一起计入 unsupported。
    assert.equal(containerCounts.unsupported, 8, 'Java 类文件加七个普通文本条目都不落入八类格式');

    assert.ok(report.findings.length > 0, '带 Go 构建信息、调试目录与模型元数据的项目应有发现');
    const evidencePaths = new Set(report.findings.map((finding) => finding.evidence.path));
    for (const relativePath of ['bin/app-linux', 'bin/app-macos', 'bin/app-windows.exe', 'models/model.gguf', 'pycache/app.cpython-312.pyc']) {
      assert.ok(evidencePaths.has(relativePath), `发现里应能定位到 ${relativePath}`);
    }
    // 普通文本条目没有读取器，按能力边界说明，不冒充“没有暴露”。
    assert.ok(report.capabilityBoundaries.length > 0, '范围外条目必须留下能力边界说明');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('audit 文件目标：退出码 0，容器判定与目录条目一致，证据路径取文件名', async () => {
  const root = await makeProject();
  try {
    const target = join(root, 'bin/app-linux');
    const result = await runInProcess(['audit', target, '--json']);
    assert.equal(result.code, EXIT_CODES.SUCCESS);
    const report = JSON.parse(result.stdout);
    assert.equal(report.artifact.kind, 'file');
    assert.equal(report.artifact.container, 'elf');
    assert.equal(report.summary.findings, 2, 'ELF 头与 Go 构建信息各一条');
    const categories = report.findings.map((finding) => finding.category);
    assert.deepEqual([...categories].sort(), ['elf-header', 'go-buildinfo']);
    assert.equal(report.findings[0].evidence.path, 'app-linux', '文件目标的证据路径取文件名');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// —— 正常输入：harden 的文件目标与目录目标 ——

test('harden 文件目标：施加 Go 构建信息覆写，产物写在 .hardened，原件逐字节不变', async () => {
  const root = await makeProject();
  try {
    const target = join(root, 'bin/app-linux');
    const before = await digestOf(target);
    const { path: auditPath, dir } = await auditToFile(target, await mkdtemp(join(tmpdir(), 'anti-rea-e2e-harden-')));
    try {
      const result = await runInProcess(['harden', target, '--from', auditPath, '--json']);
      assert.equal(result.code, EXIT_CODES.SUCCESS, result.stderr);
      const report = JSON.parse(result.stdout);
      assert.equal(report.status, 'applied');
      assert.equal(report.artifact.kind, 'file');
      assert.deepEqual(report.applied.map((item) => item.mitigation), ['metadata.go-buildinfo-inline-overwrite']);
      assert.ok(report.applied.every((item) => item.changed === true), '施加项都应真的改动了字节');
      assert.equal(report.output, `${target}${DEFAULT_OUTPUT_SUFFIX}`);
      assert.equal(report.changed, true);
      assert.equal(report.wrote, true);
      assert.equal(report.review.status, 'passed', '写入后自动复审应通过');
      assert.ok(await exists(`${target}${DEFAULT_OUTPUT_SUFFIX}`), '加固产物应落盘');
      assert.equal(await digestOf(target), before, '原件永不改动');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('harden 目录目标：逐条目施加，五个条目各自写出 .hardened，复审逐条通过', async () => {
  const root = await makeProject();
  try {
    const before = new Map();
    for (const file of SAMPLE_PROJECT_FILES) {
      before.set(file.relativePath, await digestOf(join(root, ...file.relativePath.split('/'))));
    }
    const { path: auditPath, dir } = await auditToFile(root, await mkdtemp(join(tmpdir(), 'anti-rea-e2e-harden-')));
    try {
      const { path: policyPath } = await writePolicy(COMPLETE_LEGAL);
      try {
        const result = await runInProcess(['harden', root, '--from', auditPath, '--json', '--policy', policyPath]);
        assert.equal(result.code, EXIT_CODES.SUCCESS, result.stderr);
        const report = JSON.parse(result.stdout);
        assert.equal(report.artifact.kind, 'directory');
        assert.equal(report.status, 'applied');

        // 逐条目施加：ELF、Mach-O、GGUF、safetensors、pyc 五个条目写出产物。
        // 写出的产物清单在报告的 rollback.output 字段：回滚即删除这些文件。
        const applied = new Set(report.applied.map((item) => item.mitigation));
        for (const mitigation of [
          'metadata.go-buildinfo-inline-overwrite',
          'metadata.go-buildinfo-macho-rw-overwrite',
          'metadata.rust-dep-section-overwrite',
          'model.gguf-metadata-relayout',
          'model.safetensors-metadata-relayout',
          'metadata.pyc-source-hash-clear',
        ]) {
          assert.ok(applied.has(mitigation), `应施加 ${mitigation}`);
        }
        assert.ok(Array.isArray(report.rollback.output), '报告应给出写出的产物清单');
        assert.equal(report.rollback.output.length, 5, '五个条目各写出一个加固产物');
        for (const output of report.rollback.output) {
          assert.ok(output.endsWith(DEFAULT_OUTPUT_SUFFIX), `产物路径应带固定后缀：${output}`);
          assert.ok(await exists(output), `产物应落盘：${output}`);
        }
        assert.equal(report.output, report.rollback.output[0], 'output 取首个写出的产物');
        assert.match(report.outputNote, /已写入加固后制品/);
        assert.equal(report.review.status, 'passed');
        assert.equal(report.review.entries.length, 5, '逐条目复审应给出五条结论');
        assert.ok(report.review.entries.every((entry) => entry.passed === true), '五条复审结论都应通过');

        // 目录目标逐条目施加，没有被发现的条目不读不写。
        for (const [relativePath, digest] of before) {
          assert.equal(await digestOf(join(root, ...relativePath.split('/'))), digest, `原件被改动：${relativePath}`);
        }
        assert.ok(!(await exists(join(root, 'README.md.hardened'))), '没有发现的条目不产出加固文件');
      } finally {
        await rm(join(policyPath, '..'), { recursive: true, force: true });
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('harden 目录目标：PE 条目因非零 CheckSum 且策略未允许重算而跳过改写', async () => {
  const root = await makeProject();
  try {
    const { path: auditPath, dir } = await auditToFile(root, await mkdtemp(join(tmpdir(), 'anti-rea-e2e-harden-')));
    try {
      const { path: policyPath } = await writePolicy(COMPLETE_LEGAL);
      try {
        const result = await runInProcess(['harden', root, '--from', auditPath, '--json', '--policy', policyPath]);
        assert.equal(result.code, EXIT_CODES.SUCCESS, result.stderr);
        const report = JSON.parse(result.stdout);
        const skipped = report.skipped.filter((item) => item.mitigation === 'metadata.pe-debug-directory-overwrite');
        assert.equal(skipped.length, 1, 'PE 调试目录覆写应被跳过');
        assert.match(skipped[0].reason, /CheckSum 非零/, '跳过原因应点名校验和门控');
        assert.ok(!(await exists(join(root, 'bin/app-windows.exe.hardened'))), '被门控跳过的条目不写产物');
        assert.equal(report.checksumRecomputed, false, '策略未允许重算时不得重算校验和');
      } finally {
        await rm(join(policyPath, '..'), { recursive: true, force: true });
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('重复加固幂等：第二次产出与已存在产物逐字节相同，不重复写入', async () => {
  const root = await makeProject();
  try {
    const { path: auditPath, dir } = await auditToFile(root, await mkdtemp(join(tmpdir(), 'anti-rea-e2e-idem-')));
    try {
      const { path: policyPath } = await writePolicy(COMPLETE_LEGAL);
      try {
        const first = JSON.parse((await runInProcess(['harden', root, '--from', auditPath, '--json', '--policy', policyPath])).stdout);
        assert.equal(first.wrote, true);
        const digests = new Map();
        for (const output of first.rollback.output) {
          digests.set(output, await digestOf(output));
        }

        const second = JSON.parse((await runInProcess(['harden', root, '--from', auditPath, '--json', '--policy', policyPath])).stdout);
        assert.equal(second.changed, false, '第二次加固不算改动');
        assert.equal(second.wrote, false, '第二次加固不重写字节');
        assert.equal(second.idempotent, true, '应标记幂等');
        assert.equal(second.output, null, '没有新写出时 output 为空');
        assert.match(second.outputNote, /逐字节相同/);
        for (const [output, digest] of digests) {
          assert.equal(await digestOf(output), digest, `加固产物被二次加固改写：${output}`);
        }
      } finally {
        await rm(join(policyPath, '..'), { recursive: true, force: true });
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// —— 正常输入：verify 的通过与不通过两条路径 ——

test('verify 文件目标通过：退出码 0，适用的检查族全部有结论', async () => {
  const root = await makeProject();
  try {
    const target = join(root, 'bin/app-macos');
    const result = await runInProcess(['verify', target, '--json']);
    assert.equal(result.code, EXIT_CODES.SUCCESS, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.status, 'passed');
    assert.equal(report.summary.failed, 0);
    assert.equal(report.summary.pending, 0, '看不到问题不等于通过：不许有未决项');
    const families = new Set(report.checks.map((check) => check.family));
    for (const family of ['container-parse', 'signature-consistency', 'required-sections']) {
      assert.ok(families.has(family), `Mach-O 制品应跑检查族 ${family}`);
    }
    assert.equal(report.comparison, null, '不给基线时不输出前后差异');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('verify 目录目标通过：Java 类文件条目按范围外容器跳过结构复审，退出码 0', async () => {
  const root = await makeProject();
  try {
    const result = await runInProcess(['verify', root, '--json']);
    assert.equal(result.code, EXIT_CODES.SUCCESS, `复审应通过，实际 ${result.code}`);
    const report = JSON.parse(result.stdout);
    assert.equal(report.status, 'passed');
    assert.equal(report.summary.failed, 0);
    // Java 类文件命中 CAFEBABE，但识别阶段已按分片表判为范围外容器：
    // 范围外条目没有可复审的结构，不出检查记录，也不冒充通过（tests/verify.test.mjs 另覆盖复审不通过路径）。
    for (const check of report.checks) {
      assert.notEqual(check.entry, 'java/com/example/App.class', `范围外条目不应进入结构复审：${check.entry}`);
    }
    const entries = new Set(report.checks.map((check) => check.entry));
    assert.ok(entries.has('bin/app-linux'), '字节级条目应照常出检查记录');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('verify 带基线比对：加固后 Go 构建信息发现消失，退出码仍为 0', async () => {
  const root = await makeProject();
  try {
    const target = join(root, 'bin/app-linux');
    const { path: auditPath, report: baseline, dir } = await auditToFile(target, await mkdtemp(join(tmpdir(), 'anti-rea-e2e-verify-')));
    try {
      assert.equal((await runInProcess(['harden', target, '--from', auditPath, '--json'])).code, EXIT_CODES.SUCCESS);
      const result = await runInProcess(['verify', `${target}${DEFAULT_OUTPUT_SUFFIX}`, '--json', '--from', auditPath]);
      assert.equal(result.code, EXIT_CODES.SUCCESS, result.stderr);
      const report = JSON.parse(result.stdout);
      assert.equal(report.status, 'passed');
      assert.notEqual(report.comparison, null, '给出基线时必须输出前后差异');
      const resolved = report.comparison.resolved.map((finding) => finding.mitigation);
      assert.ok(resolved.includes('metadata.go-buildinfo-inline-overwrite'), '加固掉的那条发现应记入消失');
      assert.deepEqual(report.comparison.introduced, [], '等长覆写不应引入新发现');
      assert.equal(report.applied.source, 'baseline-diff', '只有基线时按消失发现反推已施加措施');
      assert.ok(report.applied.mitigations.includes('metadata.go-buildinfo-inline-overwrite'));
      assert.ok(baseline.findings.some((finding) => finding.mitigation === 'metadata.go-buildinfo-inline-overwrite'));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// —— 正常输入：notice 的三种输出形态与拒否路径 ——

test('notice 三种输出形态：人读声明、JSON 报告、--out 落盘，三者内容一致', async () => {
  const root = await makeProject();
  try {
    const { path: policyPath, dir } = await writePolicy(COMPLETE_LEGAL);
    try {
      // 形态一：人读文本，直接给出声明文档全文。
      const human = await runInProcess(['notice', '--template', 'license', '--policy', policyPath]);
      assert.equal(human.code, EXIT_CODES.SUCCESS, human.stderr);
      assert.match(human.stdout, /# 许可与禁止逆向声明/);
      assert.match(human.stdout, /示例主体/);
      assert.match(human.stdout, /示例法条摘录/);
      // 声明不得引用工具自身，也不得透露加固或审计状态。
      for (const token of ['anti-rea', 'antirea', '加固', 'harden', 'mitigation', '缓解', 'audit', '审计', 'verify', '复审']) {
        assert.ok(!human.stdout.toLowerCase().includes(token), `声明里不应出现 ${token}`);
      }

      // 形态二：JSON 报告，带声明全文与模板名。
      const json = await runInProcess(['notice', '--template', 'license', '--policy', policyPath, '--json']);
      assert.equal(json.code, EXIT_CODES.SUCCESS);
      const report = JSON.parse(json.stdout);
      assert.equal(report.schema, 'anti-rea.notice/1');
      assert.equal(report.status, 'generated');
      assert.equal(report.template, 'license');
      assert.equal(report.notice, human.stdout, 'JSON 报告里的声明应与形态一逐字节相同');

      // 形态三：--out 落盘，写出的就是声明文档本身，标准输出仍是同一份文本。
      const outPath = join(dir, 'NOTICE.md');
      const written = await runInProcess(['notice', '--template', 'license', '--policy', policyPath, '--out', outPath]);
      assert.equal(written.code, EXIT_CODES.SUCCESS);
      assert.match(written.stderr, /声明已写入/);
      assert.equal(await readFile(outPath, 'utf8'), human.stdout, '落盘内容应与标准输出一致');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('notice 拒否路径：退出码 3，报告以蛇形 omitted_reason 点名缺失的法律字段', async () => {
  const root = await makeProject();
  try {
    // 默认策略的法律字段全空，七项字段一项都不齐。
    const result = await runInProcess(['notice', '--template', 'license', '--json']);
    assert.equal(result.code, EXIT_CODES.REFUSAL, `法律字段缺失应拒否，实际退出码 ${result.code}`);
    const report = JSON.parse(result.stdout);
    assert.equal(report.status, 'refused');
    // 契约字段名是蛇形 omitted_reason：src/notice/index.mjs 第 3 至 4 行、
    // src/errors.mjs 第 38 行、src/mcp/tools.mjs 第 112 行与 README 都这么写。
    assert.ok(
      Array.isArray(report.omitted_reason) && report.omitted_reason.length > 0,
      `拒否报告必须带蛇形 omitted_reason 字段；实际字段为 ${JSON.stringify(Object.keys(report))}`,
    );
    assert.equal(report.omitted_reason.length, 7, '七项法律字段一项都不齐时应全部点名');
    assert.ok(report.omitted_reason.some((reason) => reason.includes('主体名称')), '原因应点名缺失字段');
    assert.ok(report.omitted_reason.some((reason) => reason.includes('法条摘录')), '后果陈述缺摘录也要点名');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('notice 拒否路径：人读输出同样带拒否原因，且不产出声明文档', async () => {
  const root = await makeProject();
  try {
    const { dir } = await writePolicy({ subject: '示例主体' });
    try {
      const policyPath = join(dir, 'policy.json');
      const outPath = join(dir, 'NOTICE.md');
      const result = await runInProcess(['notice', '--template', 'license', '--policy', policyPath, '--out', outPath]);
      assert.equal(result.code, EXIT_CODES.REFUSAL);
      assert.match(result.stdout, /拒否原因/);
      assert.match(result.stdout, /联系渠道/);
      // 拒否时不产出声明文档：src/notice/index.mjs 的 generateNotice 在字段不齐时
      // 既不渲染正文也不落盘。命令行侧走的是四个子命令共用的 emitReport，
      // 会把拒否报告本身写到 --out；那也不是声明文档，两者不许混淆。
      const written = await readFile(outPath, 'utf8').catch(() => null);
      if (written !== null) {
        assert.ok(!written.includes('# 许可与禁止逆向声明'), '拒绝时不得把声明文档写到 --out');
        assert.match(written, /拒否原因/);
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('notice --format json 按通用选项生效，输出可被 JSON.parse', async () => {
  const root = await makeProject();
  try {
    const { path: policyPath, dir } = await writePolicy(COMPLETE_LEGAL);
    try {
      // src/cli/usage.mjs 第 21 行把 --format <json|text> 列在“通用选项”下，四个子命令都该认。
      const result = await runInProcess(['notice', '--template', 'license', '--policy', policyPath, '--format', 'json']);
      assert.equal(result.code, EXIT_CODES.SUCCESS, `notice 应接受通用选项 --format；标准错误：${result.stderr}`);
      const report = JSON.parse(result.stdout);
      assert.equal(report.schema, 'anti-rea.notice/1');
      assert.equal(report.status, 'generated');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// —— 正常输入：MCP 服务层四个工具进程内调用 ——

test('MCP 四个工具经 createMcpServer 进程内调用，与命令行共用同一套工作流', async () => {
  // 两条入口各用一份新建的相同项目：目录摘要含加固产物，同一份目录上先后跑两次
  // 会让第二条看到第一条写出的 .hardened，批次的 changed 与 wrote 因此不同，
  // 不能直接整份比对。
  const mcpRoot = await makeProject();
  const cliRoot = await makeProject();
  try {
    const server = createMcpServer();
    const call = async (name, args) => {
      const response = await server.handle({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name, arguments: args },
      });
      assert.equal(response.error, undefined, `${name} 不应返回协议错误`);
      return response.result;
    };
    const { path: policyPath, dir } = await writePolicy(COMPLETE_LEGAL);
    const cliAuditDir = await mkdtemp(join(tmpdir(), 'anti-rea-e2e-cli-'));
    try {
      const { path: mcpAudit } = await auditToFile(mcpRoot, dir);
      const { path: cliAudit } = await auditToFile(cliRoot, cliAuditDir);

      const audit = await call('audit_artifact', { path: mcpRoot, policy: policyPath });
      assert.equal(audit.isError, false);
      const auditReport = JSON.parse(audit.content[0].text);
      assert.equal(auditReport.tool, 'audit_artifact');
      assert.equal(auditReport.artifact.kind, 'directory');
      assert.equal(audit.structuredContent.artifact.sha256, auditReport.artifact.sha256);
      // Java 类文件判为范围外容器、不产生 Mach-O 发现，发现数由其余字节级条目锁定。
      assert.equal(auditReport.summary.findings, 18, '模拟项目的发现数应由清单锁定');

      const harden = await call('harden_artifact', { path: mcpRoot, from: mcpAudit, policy: policyPath });
      assert.equal(harden.isError, false);
      const hardenReport = JSON.parse(harden.content[0].text);
      assert.equal(hardenReport.tool, 'harden_artifact');
      assert.equal(hardenReport.status, 'applied');
      assert.equal(hardenReport.review.status, 'passed');

      const verify = await call('verify_artifact', { path: join(mcpRoot, 'bin/app-macos') });
      assert.equal(verify.isError, false);
      assert.equal(JSON.parse(verify.content[0].text).status, 'passed');

      const notice = await call('generate_notice', { template: 'license', policy: policyPath });
      assert.equal(notice.isError, false);
      const noticeReport = JSON.parse(notice.content[0].text);
      assert.equal(noticeReport.status, 'generated');
      assert.match(noticeReport.notice, /# 许可与禁止逆向声明/);

      // 两条入口必须产出同一份报告：把各自的临时目录路径换成占位串后逐字段比对，
      // 只剩工具名不同（harden_artifact 与 harden-artifact）。
      // Windows 上 JSON 文本里的反斜杠是转义形式，两种写法都要替换。
      const cli = JSON.parse(
        (await runInProcess(['harden', cliRoot, '--from', cliAudit, '--json', '--policy', policyPath])).stdout,
      );
      const normalize = (report, root) => {
        const text = JSON.stringify(report);
        const escaped = root.replace(/\\/g, '\\\\');
        return JSON.parse(text.split(root).join('<项目路径>').split(escaped).join('<项目路径>'));
      };
      assert.equal(cli.tool, 'harden-artifact');
      assert.deepEqual(
        { ...normalize(hardenReport, mcpRoot), tool: '' },
        { ...normalize(cli, cliRoot), tool: '' },
        'MCP 与命令行必须共用同一套工作流代码',
      );
    } finally {
      await rm(dir, { recursive: true, force: true });
      await rm(cliAuditDir, { recursive: true, force: true });
    }
  } finally {
    await rm(mcpRoot, { recursive: true, force: true });
    await rm(cliRoot, { recursive: true, force: true });
  }
});

// —— 畸形输入与目标契约：probe 子命令与 generate_probe_kit 工具尚未接线 ——

test('probe 子命令生成反运行时观察集成包（目标契约，当前尚未接线）', async () => {
  const root = await makeProject();
  const kitDir = await mkdtemp(join(tmpdir(), 'anti-rea-e2e-kit-'));
  try {
    const before = new Map();
    for (const file of SAMPLE_PROJECT_FILES) {
      before.set(file.relativePath, await digestOf(join(root, ...file.relativePath.split('/'))));
    }
    const result = await runInProcess(['probe', root, '--out', kitDir]);
    assert.equal(result.code, EXIT_CODES.SUCCESS, `probe 子命令应生成集成包；实际退出码 ${result.code}，标准错误：${result.stderr}`);
    // 集成包三份产物：检测代码片段、人工检查清单、集成方式说明。
    for (const name of ['runtime-probe.mjs', 'manual-checklist.md', 'INTEGRATION.md']) {
      const info = await stat(join(kitDir, name)).catch(() => null);
      assert.notEqual(info, null, `集成包缺少产物 ${name}`);
      assert.ok(info.isFile() && info.size > 0, `产物 ${name} 应为非空文件`);
    }
    // 生成是确定且幂等的：再跑一次产物逐字节相同。
    const probeDigest = await digestOf(join(kitDir, 'runtime-probe.mjs'));
    const again = await runInProcess(['probe', root, '--out', kitDir]);
    assert.equal(again.code, EXIT_CODES.SUCCESS, again.stderr);
    assert.equal(await digestOf(join(kitDir, 'runtime-probe.mjs')), probeDigest, '重复生成应幂等');
    // 集成包只生成代码与清单，不改动制品本身。
    for (const [relativePath, digest] of before) {
      assert.equal(await digestOf(join(root, ...relativePath.split('/'))), digest, `制品被改动：${relativePath}`);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(kitDir, { recursive: true, force: true });
  }
});

test('MCP generate_probe_kit 工具生成集成包（目标契约，当前尚未接线）', async () => {
  const root = await makeProject();
  const kitDir = await mkdtemp(join(tmpdir(), 'anti-rea-e2e-kit-'));
  try {
    const server = createMcpServer();
    const response = await server.handle({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'generate_probe_kit', arguments: { path: root, out: kitDir } },
    });
    const result = response.result;
    assert.equal(result.isError, false, `generate_probe_kit 应正常返回；实际内容：${result.content[0].text}`);
    const report = JSON.parse(result.content[0].text);
    assert.equal(report.status, 'generated');
    const names = report.files.map((file) => file.name);
    for (const name of ['runtime-probe.mjs', 'manual-checklist.md', 'INTEGRATION.md']) {
      assert.ok(names.includes(name), `集成包报告应登记产物 ${name}`);
      assert.ok(await exists(join(kitDir, name)), `产物应落盘：${name}`);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(kitDir, { recursive: true, force: true });
  }
});

// —— 正常输入：git 工作树警告与脱敏 ——

test('audit --out 写出路径位于 git 工作树内时向标准错误输出警告，同一路径只警告一次', async () => {
  const root = await makeProject();
  const gitTree = await makeGitTree();
  try {
    const outPath = join(gitTree, 'audit.json');
    const result = await runCliSubprocess(['audit', root, '--json', '--out', outPath]);
    assert.equal(result.code, EXIT_CODES.SUCCESS);
    const occurrences = result.stderr.split('git 工作树').length - 1;
    assert.equal(occurrences, 1, `同一路径只应警告一次，实际 ${occurrences} 次`);
    assert.match(result.stderr, /--redacted/);
    assert.ok(await exists(outPath), '警告不影响报告写出');
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(gitTree, { recursive: true, force: true });
  }
});

test('harden 的加固产物与报告写出路径都在 git 工作树内时，两条路径各警告一次', async () => {
  const gitTree = await makeGitTree();
  try {
    const target = join(gitTree, 'app.txt');
    await writeFile(target, '普通应用文件\n', 'utf8');
    const { path: auditPath } = await auditToFile(target, await mkdtemp(join(tmpdir(), 'anti-rea-e2e-git-')));
    try {
      const result = await runInProcess(['harden', target, '--from', auditPath, '--out', join(gitTree, 'report.json')]);
      assert.equal(result.code, EXIT_CODES.SUCCESS, result.stderr);
      const occurrences = result.stderr.split('git 工作树').length - 1;
      assert.equal(occurrences, 2, `加固输出路径与报告写出路径各一次，实际 ${occurrences} 次`);
      assert.match(result.stderr, /app\.txt\.hardened/);
      assert.match(result.stderr, /report\.json/);
    } finally {
      await rm(join(auditPath, '..'), { recursive: true, force: true });
    }
  } finally {
    await rm(gitTree, { recursive: true, force: true });
  }
});

test('harden 目录目标的每条加固产物写出路径都各自警告一次', async () => {
  const gitTree = await makeGitTree();
  try {
    // 项目整个放进 git 工作树：七个有条目的条目各警告一次，加报告写出路径一次。
    // Java 类文件判为范围外容器、没有发现，不写加固产物，也就不警告它的输出路径。
    await writeSampleProject(gitTree);
    const { path: auditPath, dir } = await auditToFile(gitTree, await mkdtemp(join(tmpdir(), 'anti-rea-e2e-git-')));
    try {
      const { path: policyPath } = await writePolicy(COMPLETE_LEGAL);
      try {
        const result = await runInProcess(['harden', gitTree, '--from', auditPath, '--json', '--policy', policyPath, '--out', join(gitTree, 'report.json')]);
        assert.equal(result.code, EXIT_CODES.SUCCESS, result.stderr);
        const occurrences = result.stderr.split('git 工作树').length - 1;
        assert.equal(occurrences, 8, `七个条目加报告写出路径共八次，实际 ${occurrences} 次`);
        assert.match(result.stderr, /app-linux\.hardened/);
        assert.match(result.stderr, /report\.json/);
      } finally {
        await rm(join(policyPath, '..'), { recursive: true, force: true });
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  } finally {
    await rm(gitTree, { recursive: true, force: true });
  }
});

test('--redacted 脱敏：保留分类与计数，隐去精确路径、字节范围与缓解措施对应关系', async () => {
  const root = await makeProject();
  try {
    const plain = JSON.parse((await runInProcess(['audit', root, '--json'])).stdout);
    const result = await runInProcess(['audit', root, '--json', '--redacted']);
    assert.equal(result.code, EXIT_CODES.SUCCESS);
    const redacted = JSON.parse(result.stdout);
    assert.equal(redacted.redacted, true);
    assert.equal(redacted.artifact.kind, 'directory');
    assert.equal(redacted.artifact.path, undefined, '脱敏报告不得带制品精确路径');
    assert.equal(redacted.artifact.sha256, plain.artifact.sha256, '制品摘要要保留，否则无法对照');
    assert.deepEqual(redacted.summary.byLayer, plain.summary.byLayer, '逐层计数要保留');
    assert.deepEqual(redacted.summary.bySeverity, plain.summary.bySeverity, '逐严重度计数要保留');
    assert.equal(redacted.summary.findings, plain.summary.findings);

    // 每条发现只留层、严重度、分类与读取器：证据路径、字节范围与缓解编号全部隐去。
    for (const finding of redacted.findings) {
      assert.deepEqual(Object.keys(finding).sort(), ['category', 'layer', 'reader', 'severity']);
    }
    // 脱敏是单向的：整份报告里不许再出现项目路径或条目相对路径。
    const serialized = JSON.stringify(redacted);
    assert.ok(!serialized.includes(root), '脱敏报告不得包含项目绝对路径');
    for (const relativePath of ['app-linux', 'app-windows.exe', 'bundle.js', 'App.class', 'model.gguf']) {
      assert.ok(!serialized.includes(relativePath), `脱敏报告不得包含条目路径片段 ${relativePath}`);
    }
    // 能力边界与限制说明的分类要保留，分享时才知道哪些面没覆盖。
    assert.equal(redacted.capabilityBoundaries.length, plain.capabilityBoundaries.length);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
