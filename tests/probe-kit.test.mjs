// probe-kit 集成包生成与生成代码的功能测试。
// 覆盖正常输入、畸形输入与部分读取；生成的检测代码真实导入并运行，不只做文本断言。

import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { test } from 'node:test';

import { UsageError } from '../src/errors.mjs';
import {
  DEFAULT_PROBE_EXCEPTIONS,
  PROBE_CHECKS,
  PROBE_KIT_PARTS,
  PROBE_TEMPLATE_FILES,
  buildProbeKit,
  effectiveProbeExceptions,
  probeKitContext,
  renderProbeKitText,
  renderTemplate,
} from '../src/probe-kit/index.mjs';
import { REPO_ROOT } from './helpers/cli.mjs';

/** 仓库内真实模板目录。 */
const TEMPLATES_DIR = join(REPO_ROOT, 'templates', 'probe-kit');

/** 占位符模式，与实现保持一致。 */
const TOKEN_PATTERN = /\{\{\s*([A-Z0-9_]+)\s*\}\}/g;

/**
 * 建一个本次测试独有的临时根目录，返回根与尚未存在的输出目录。
 * @param {string} prefix 目录前缀
 * @returns {Promise<{root: string, outDir: string}>}
 */
async function freshOutDir(prefix) {
  const root = await mkdtemp(join(tmpdir(), prefix));
  return { root, outDir: join(root, 'kit') };
}

/**
 * 把仓库内真实模板复制到临时目录，供畸形与部分读取用例改写。
 * @param {string} dir 目标目录
 */
async function copyTemplatesTo(dir) {
  await mkdir(dir, { recursive: true });
  for (const spec of PROBE_TEMPLATE_FILES) {
    const text = await readFile(join(TEMPLATES_DIR, spec.template), 'utf8');
    await writeFile(join(dir, spec.template), text, 'utf8');
  }
}

/**
 * 导入刚生成的检测代码片段。
 * @param {string} outDir 集成包目录
 * @returns {Promise<Record<string, unknown>>} 生成模块的导出
 */
async function importGenerated(outDir) {
  return await import(pathToFileURL(join(outDir, 'runtime-probe.mjs')).href);
}

test('正常生成：默认策略落盘三份产物，报告字段齐全', async () => {
  const { root, outDir } = await freshOutDir('anti-rea-probe-ok-');
  try {
    const report = await buildProbeKit({ policy: {}, outDir });
    assert.equal(report.status, 'generated');
    assert.equal(report.schema, 'anti-rea.probe-kit/1');
    assert.equal(report.tool, 'probe-kit');
    assert.equal(report.layer, 'runtime-observation-resistance');
    assert.equal(report.layerLabel, '反运行时观察');
    assert.equal(report.changed, true);
    assert.deepEqual(
      report.files.map((file) => file.name),
      PROBE_TEMPLATE_FILES.map((spec) => spec.output),
    );
    for (const file of report.files) {
      const info = await stat(file.path);
      assert.equal(info.isFile(), true);
      assert.equal(info.size, file.bytes);
    }
    // 默认响应是记录并继续，例外清单是基线四项。
    assert.equal(report.response.mode, 'report-only');
    assert.equal(report.response.refusalEnabled, false);
    assert.deepEqual(report.response.exceptions, [...DEFAULT_PROBE_EXCEPTIONS]);
    assert.deepEqual(report.checks, PROBE_CHECKS.map((check) => check.id));
    assert.ok(report.parts.includes(PROBE_KIT_PARTS[0]));

    const probe = await readFile(join(outDir, 'runtime-probe.mjs'), 'utf8');
    assert.equal(probe.match(TOKEN_PATTERN), null, '产出里不允许留下未替换占位符');
    assert.ok(probe.includes("export const RESPONSE_MODE = 'report-only';"));
    assert.ok(probe.includes('export const REFUSAL_ENABLED = false;'));
    const checklist = await readFile(join(outDir, 'manual-checklist.md'), 'utf8');
    for (const check of PROBE_CHECKS) {
      assert.ok(checklist.includes(check.id), `人工检查清单应覆盖 ${check.id}`);
    }
    const notes = await readFile(join(outDir, 'INTEGRATION.md'), 'utf8');
    assert.match(notes, /report-only/);
    assert.match(notes, /不自动改动制品/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('幂等：第二次生成与已存在输出逐字节相同，changed 为 false', async () => {
  const { root, outDir } = await freshOutDir('anti-rea-probe-idem-');
  try {
    await buildProbeKit({ policy: {}, outDir });
    const before = await Promise.all(
      PROBE_TEMPLATE_FILES.map(async (spec) => await readFile(join(outDir, spec.output), 'utf8')),
    );
    const second = await buildProbeKit({ policy: {}, outDir });
    assert.equal(second.changed, false);
    const after = await Promise.all(
      PROBE_TEMPLATE_FILES.map(async (spec) => await readFile(join(outDir, spec.output), 'utf8')),
    );
    assert.deepEqual(after, before);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('生成的检测代码不引用子进程与网络模块，也不含工具名', async () => {
  const { root, outDir } = await freshOutDir('anti-rea-probe-pure-');
  try {
    await buildProbeKit({ policy: {}, outDir });
    const probe = await readFile(join(outDir, 'runtime-probe.mjs'), 'utf8');
    for (const forbidden of ['node:child_process', 'node:net', 'node:http', 'child_process', 'execSync', 'fetch(']) {
      assert.ok(!probe.includes(forbidden), `生成代码不得引用 ${forbidden}`);
    }
    // 生成内容随用户软件分发，不写工具名，不透露加固状态。
    for (const file of ['runtime-probe.mjs', 'manual-checklist.md', 'INTEGRATION.md']) {
      const text = await readFile(join(outDir, file), 'utf8');
      assert.ok(!text.includes('Anti-REA'), `${file} 不应出现工具名`);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('层开关关闭：不生成集成包，也不创建输出目录', async () => {
  const { root, outDir } = await freshOutDir('anti-rea-probe-off-');
  try {
    const report = await buildProbeKit({
      policy: { layers: { 'runtime-observation-resistance': false } },
      outDir,
    });
    assert.equal(report.status, 'skipped');
    assert.equal(report.changed, false);
    assert.deepEqual(report.files, []);
    assert.match(report.skipReason, /runtime-observation-resistance/);
    await assert.rejects(() => stat(outDir), /ENOENT/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('畸形输入：输出目录缺失、是文件或策略不是对象', async () => {
  const { root, outDir } = await freshOutDir('anti-rea-probe-bad-');
  try {
    await assert.rejects(() => buildProbeKit({ policy: {} }), (error) => error instanceof UsageError && /outDir/.test(error.message));
    await assert.rejects(() => buildProbeKit({ policy: {}, outDir: '' }), UsageError);
    await assert.rejects(() => buildProbeKit({ policy: {}, outDir: 42 }), UsageError);
    await assert.rejects(() => buildProbeKit('not-an-object'), UsageError);
    await assert.rejects(() => buildProbeKit({ policy: [], outDir }), UsageError);
    // 输出路径是已存在文件时无法当目录用。
    const asFile = join(root, 'not-a-dir');
    await writeFile(asFile, 'x', 'utf8');
    await assert.rejects(() => buildProbeKit({ policy: {}, outDir: asFile }), UsageError);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('畸形策略：观察模式与拒绝开关矛盾', async () => {
  const { root, outDir } = await freshOutDir('anti-rea-probe-contra-');
  try {
    await assert.rejects(
      () => buildProbeKit({ policy: { observation: { mode: 'report-and-refuse' } }, outDir }),
      (error) => error instanceof UsageError && /refusalEnabled/.test(error.message),
    );
    await assert.rejects(
      () => buildProbeKit({ policy: { observation: { refusalEnabled: true } }, outDir }),
      (error) => error instanceof UsageError && /refusalEnabled/.test(error.message),
    );
    await assert.rejects(
      () => buildProbeKit({ policy: { observation: { mode: 'log-and-die' } }, outDir }),
      (error) => error instanceof UsageError && /observation\.mode/.test(error.message),
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('部分策略：只填例外清单时取默认模式，并合并基线例外', async () => {
  const { root, outDir } = await freshOutDir('anti-rea-probe-partial-');
  try {
    const report = await buildProbeKit({
      policy: { observation: { exceptions: ['MY_APP_SESSION'] } },
      outDir,
    });
    assert.equal(report.status, 'generated');
    assert.equal(report.response.mode, 'report-only');
    assert.deepEqual(report.response.exceptions, [...DEFAULT_PROBE_EXCEPTIONS, 'MY_APP_SESSION']);
    const probe = await readFile(join(outDir, 'runtime-probe.mjs'), 'utf8');
    assert.ok(probe.includes('"MY_APP_SESSION"'), '用户例外应写进生成代码');
    assert.ok(probe.includes('"MY_APP_SESSION":["env-write-marker","pseudo-terminal-signs"]'), '用户例外应有抑制映射');
    // 用户例外不进默认策略对象本身：策略文件仍是用户填的那一份。
    assert.deepEqual(effectiveProbeExceptions({ observation: { exceptions: ['MY_APP_SESSION'] } }), [
      ...DEFAULT_PROBE_EXCEPTIONS,
      'MY_APP_SESSION',
    ]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('部分读取：模板被截断时不落盘', async () => {
  const { root, outDir } = await freshOutDir('anti-rea-probe-trunc-');
  const brokenTemplates = join(root, 'broken-templates');
  try {
    await copyTemplatesTo(brokenTemplates);
    const target = join(brokenTemplates, 'runtime-probe.template.mjs');
    const full = await readFile(target, 'utf8');
    // 去掉最后一个非空行（结束标记），模拟写入被中断。
    const lines = full.split('\n');
    while (lines.length > 0 && lines[lines.length - 1].trim() === '') {
      lines.pop();
    }
    lines.pop();
    await writeFile(target, lines.join('\n'), 'utf8');

    await assert.rejects(
      () => buildProbeKit({ policy: {}, outDir, templatesDir: brokenTemplates }),
      (error) => error instanceof UsageError && /不完整|中断/.test(error.message),
    );
    await assert.rejects(() => stat(outDir), /ENOENT/, '渲染失败不得创建输出目录');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('部分读取：零字节模板按不完整处理', async () => {
  const { root, outDir } = await freshOutDir('anti-rea-probe-empty-');
  const brokenTemplates = join(root, 'broken-templates');
  try {
    await copyTemplatesTo(brokenTemplates);
    await writeFile(join(brokenTemplates, 'manual-checklist.template.md'), '', 'utf8');
    await assert.rejects(
      () => buildProbeKit({ policy: {}, outDir, templatesDir: brokenTemplates }),
      (error) => error instanceof UsageError && /为空|不完整/.test(error.message),
    );
    await assert.rejects(() => stat(outDir), /ENOENT/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('畸形模板：缺模板文件与未登记占位符', async () => {
  const { root, outDir } = await freshOutDir('anti-rea-probe-malformed-');
  const brokenTemplates = join(root, 'broken-templates');
  try {
    await copyTemplatesTo(brokenTemplates);
    await rm(join(brokenTemplates, 'integration-notes.template.md'));
    await assert.rejects(
      () => buildProbeKit({ policy: {}, outDir, templatesDir: brokenTemplates }),
      (error) => error instanceof UsageError && /无法读取集成包模板/.test(error.message),
    );

    await copyTemplatesTo(brokenTemplates);
    const target = join(brokenTemplates, 'runtime-probe.template.mjs');
    const full = await readFile(target, 'utf8');
    await writeFile(target, full.replace('{{RESPONSE_MODE}}', '{{NOT_A_REAL_TOKEN}}'), 'utf8');
    await assert.rejects(
      () => buildProbeKit({ policy: {}, outDir, templatesDir: brokenTemplates }),
      (error) => error instanceof UsageError && /未登记的占位符/.test(error.message),
    );
    await assert.rejects(() => stat(outDir), /ENOENT/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('上下文覆盖全部模板的占位符，渲染后无残留', () => {
  const context = probeKitContext({});
  for (const spec of PROBE_TEMPLATE_FILES) {
    const text = readFileSync(join(TEMPLATES_DIR, spec.template), 'utf8');
    for (const match of text.matchAll(TOKEN_PATTERN)) {
      assert.ok(Object.hasOwn(context, match[1]), `模板 ${spec.id} 的占位符 ${match[1]} 未登记进上下文`);
    }
    const rendered = renderTemplate(spec.id, text, context, spec.template);
    assert.equal(rendered.match(TOKEN_PATTERN), null);
    assert.ok(!rendered.includes('anti-rea-probe-template'), '标记行不应进入产出');
  }
  assert.throws(() => renderTemplate('runtime-probe', '{{UNKNOWN}}', context, 'x'), UsageError);
});

test('warnTree 在写出前以输出目录调用一次', async () => {
  const { root, outDir } = await freshOutDir('anti-rea-probe-warn-');
  try {
    const seen = [];
    const report = await buildProbeKit({
      policy: {},
      outDir,
      warnTree: async (path) => {
        seen.push(path);
        return true;
      },
    });
    assert.deepEqual(seen, [report.outDir]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('人读文本给出落盘清单、响应模式与限制说明，缺字段时给占位不抛错', async () => {
  const { root, outDir } = await freshOutDir('anti-rea-probe-text-');
  try {
    const report = await buildProbeKit({ policy: {}, outDir });
    const text = renderProbeKitText(report);
    assert.match(text, /^集成包输出目录：/);
    assert.match(text, /状态：已生成/);
    for (const file of report.files) {
      assert.ok(text.includes(file.name), `人读文本应列出产物 ${file.name}`);
      assert.ok(text.includes(String(file.bytes)), '人读文本应给出每个产物的字节数');
    }
    assert.match(text, /响应模式：report-only（拒绝未开启，联合判定阈值 2）/);
    assert.match(text, new RegExp(DEFAULT_PROBE_EXCEPTIONS[0]));
    assert.match(text, /限制说明：\d+ 项/);
    assert.equal(text.endsWith('\n'), true);

    // 层开关关闭时人读文本说明未生成原因，不列出产物。
    const skipped = await buildProbeKit({ policy: { layers: { 'runtime-observation-resistance': false } }, outDir });
    const skippedText = renderProbeKitText(skipped);
    assert.match(skippedText, /状态：未生成/);
    assert.match(skippedText, /未生成原因：/);
    assert.equal(skippedText.includes('产物：'), false);

    // 空报告与畸形输入都不抛错，只给占位。
    assert.match(renderProbeKitText({}), /集成包输出目录：未知/);
    assert.equal(renderProbeKitText(null).includes('未知'), true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('生成的检测代码：良性环境记录并继续，不判定观察到', async () => {
  const { root, outDir } = await freshOutDir('anti-rea-probe-benign-');
  try {
    await buildProbeKit({ policy: {}, outDir });
    const kit = await importGenerated(outDir);
    const probe = kit.createRuntimeProbe({
      env: { TERM: 'xterm' },
      argv: ['/usr/bin/node', '/opt/app/main.js'],
      execArgv: [],
      stream: { isTTY: false },
      platform: 'linux',
      ppid: 1,
      readText: (path) => (path === '/proc/self/status' ? 'Name:\tnode\nTracerPid:\t0\n' : 'bash\n'),
    });
    const outcome = probe.check();
    assert.equal(outcome.observed, false);
    assert.deepEqual(outcome.hits, []);
    assert.equal(outcome.mode, 'report-only');
    assert.equal(probe.records().length, 1, 'report-only 模式把判定结果记进内存后继续');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('生成的检测代码：默认依赖路径在本机不抛错', async () => {
  const { root, outDir } = await freshOutDir('anti-rea-probe-defaults-');
  try {
    await buildProbeKit({ policy: {}, outDir });
    const kit = await importGenerated(outDir);
    const probe = kit.createRuntimeProbe();
    const outcome = probe.check();
    assert.equal(typeof outcome.observed, 'boolean');
    assert.equal(outcome.details.length, PROBE_CHECKS.length);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('生成的检测代码：多迹象联合判定命中，report-only 只记录不拒绝', async () => {
  const { root, outDir } = await freshOutDir('anti-rea-probe-joint-');
  try {
    await buildProbeKit({ policy: {}, outDir });
    const kit = await importGenerated(outDir);
    const probe = kit.createRuntimeProbe({
      env: { CAPTURE_SESSION: '1', TERM: 'xterm' },
      argv: ['/usr/bin/node', '/opt/inject-hook.js'],
      execArgv: [],
      stream: { isTTY: false },
      platform: 'linux',
      readText: () => 'bash\n',
    });
    const outcome = probe.check();
    assert.equal(outcome.observed, true);
    assert.deepEqual(outcome.hits, ['env-write-marker', 'injected-script-prefix']);
    assert.equal(probe.records().length, 1, '默认响应是记录并继续，不抛错');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('生成的检测代码：例外抑制后单项迹象不判定', async () => {
  const { root, outDir } = await freshOutDir('anti-rea-probe-except-');
  try {
    await buildProbeKit({ policy: {}, outDir });
    const kit = await importGenerated(outDir);
    const signals = kit.collectSignals({
      env: { CI: 'true', CAPTURE_SESSION: '1', TERM: 'xterm' },
      argv: ['/usr/bin/node', '/opt/app/main.js'],
      execArgv: [],
      stream: { isTTY: false },
      platform: 'linux',
      readText: () => 'bash\n',
    });
    assert.deepEqual(signals.activeExceptions, ['CI']);
    const outcome = kit.evaluate(signals);
    assert.equal(outcome.observed, false, '被抑制的迹象不计入联合判定');
    const envSignal = signals.checks.find((signal) => signal.id === 'env-write-marker');
    assert.equal(envSignal.hit, true);
    assert.equal(envSignal.suppressed, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('生成的检测代码：report-and-refuse 联合命中时拒绝，单项不拒绝', async () => {
  const { root, outDir } = await freshOutDir('anti-rea-probe-refuse-');
  try {
    await buildProbeKit({
      policy: { observation: { mode: 'report-and-refuse', refusalEnabled: true } },
      outDir,
    });
    const kit = await importGenerated(outDir);
    assert.equal(kit.RESPONSE_MODE, 'report-and-refuse');
    assert.equal(kit.REFUSAL_ENABLED, true);

    const seen = [];
    const probe = kit.createRuntimeProbe({
      env: { CAPTURE_SESSION: '1', TERM: 'xterm' },
      argv: ['/usr/bin/node', '/opt/inject-hook.js'],
      execArgv: [],
      stream: { isTTY: false },
      platform: 'linux',
      readText: () => 'bash\n',
      onRefuse: (outcome) => {
        seen.push(outcome);
      },
    });
    probe.check();
    assert.equal(seen.length, 1);
    assert.equal(seen[0].observed, true);

    // 未提供 onRefuse 时默认抛可捕获的类型化错误：不是崩溃，不清数据，不是静默失败。
    const bare = kit.createRuntimeProbe({
      env: { CAPTURE_SESSION: '1', TERM: 'xterm' },
      argv: ['/usr/bin/node', '/opt/inject-hook.js'],
      execArgv: [],
      stream: { isTTY: false },
      platform: 'linux',
      readText: () => 'bash\n',
    });
    assert.throws(() => bare.check(), (error) => error instanceof kit.ProbeRefusalError && error.name === 'ProbeRefusalError');
    assert.equal(bare.records().length, 0, '拒绝路径不走记录路径');

    // 单项迹象在拒绝模式下也不拒绝。
    const single = kit.createRuntimeProbe({
      env: { TERM: 'xterm' },
      argv: ['/usr/bin/node', '/opt/app/main.js'],
      execArgv: ['--inspect=9229'],
      stream: { isTTY: false },
      platform: 'linux',
      readText: () => 'bash\n',
    });
    const outcome = single.check();
    assert.equal(outcome.observed, false);
    assert.deepEqual(outcome.hits, ['inspector-port']);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('生成的检测代码：traced-state 只在 Linux 可检查', async () => {
  const { root, outDir } = await freshOutDir('anti-rea-probe-traced-');
  try {
    await buildProbeKit({ policy: {}, outDir });
    const kit = await importGenerated(outDir);
    const status = 'Name:\tnode\nTracerPid:\t4242\n';
    const traced = kit.checkTracedState(() => status, 'linux');
    assert.equal(traced.hit, true);
    assert.match(traced.detail, /4242/);
    const clean = kit.checkTracedState(() => 'TracerPid:\t0\n', 'linux');
    assert.equal(clean.hit, false);
    const unreadable = kit.checkTracedState(() => {
      throw new Error('EACCES');
    }, 'linux');
    assert.equal(unreadable.hit, false);
    assert.match(unreadable.limitation, /不等于没有跟踪/);
    const other = kit.checkTracedState(() => status, 'win32');
    assert.equal(other.hit, false);
    assert.match(other.limitation, /只在 Linux/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('生成的检测代码：伪终端迹象按终端类型、窗口尺寸与会话首进程判定', async () => {
  const { root, outDir } = await freshOutDir('anti-rea-probe-pty-');
  try {
    await buildProbeKit({ policy: {}, outDir });
    const kit = await importGenerated(outDir);
    const noTerm = kit.checkPseudoTerminalSigns({ TERM: '' }, { isTTY: true, columns: 80, rows: 24 }, 1, () => 'bash\n', 'linux');
    assert.equal(noTerm.hit, true);
    const noSize = kit.checkPseudoTerminalSigns({ TERM: 'xterm' }, { isTTY: true, columns: 0, rows: 0 }, 1, () => 'bash\n', 'linux');
    assert.equal(noSize.hit, true);
    const normal = kit.checkPseudoTerminalSigns({ TERM: 'xterm' }, { isTTY: true, columns: 80, rows: 24 }, 1, () => 'bash\n', 'linux');
    assert.equal(normal.hit, false);
    const captured = kit.checkPseudoTerminalSigns({ TERM: 'xterm' }, { isTTY: true, columns: 80, rows: 24 }, 1, () => 'script\n', 'linux');
    assert.equal(captured.hit, true);
    const piped = kit.checkPseudoTerminalSigns({ TERM: '' }, { isTTY: false }, 1, () => 'bash\n', 'linux');
    assert.equal(piped.hit, false, '非终端标准流不构成伪终端迹象');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('生成的检测代码：注入脚本前缀与检查器参数', async () => {
  const { root, outDir } = await freshOutDir('anti-rea-probe-inject-');
  try {
    await buildProbeKit({ policy: {}, outDir });
    const kit = await importGenerated(outDir);
    assert.equal(kit.checkInjectedScriptPrefix(['/usr/bin/node', '/opt/inject-hook.js'], {}).hit, true);
    assert.equal(kit.checkInjectedScriptPrefix(['/usr/bin/node', '/opt/app/main.js'], {}).hit, false);
    assert.equal(kit.checkInjectedScriptPrefix(['/usr/bin/node', '/opt/app/main.js'], { NODE_OPTIONS: '--require /tmp/instrument.js' }).hit, true);
    // Windows 路径分隔符也要能取到文件名。
    assert.equal(kit.checkInjectedScriptPrefix(['C:\\node.exe', 'C:\\tools\\observer.js'], {}).hit, true);

    assert.equal(kit.checkInspectorPort(['--inspect=9229'], {}).hit, true);
    assert.equal(kit.checkInspectorPort(['--inspect-brk'], {}).hit, true);
    assert.equal(kit.checkInspectorPort([], { NODE_OPTIONS: '--inspect-port 9229' }).hit, true);
    assert.equal(kit.checkInspectorPort(['--max-old-space-size=4096'], {}).hit, false);

    assert.equal(kit.checkEnvWriteMarker({ CAPTURE_SESSION: '1' }).hit, true);
    assert.equal(kit.checkEnvWriteMarker({ OTEL_SERVICE_NAME: 'app' }).hit, false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
