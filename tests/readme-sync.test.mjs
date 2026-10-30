// README 翻译同步守护。
// 参照 REA 的一批缺陷：#7655 一条就列出十五种语言的 README 丢了英文版里的限定语
// （集成仅在 Linux 上验证过），另有 #7659、#7658、#7657、#7656、#7654、#7653 同类。
// 翻译漂移的代价不在文采，在它会悄悄改掉一句会误导人的限定。
//
// 本文件不比对全文——那要求每种语言都由维护者重译，成本高，还会把用词差异误判成不同步。
// 只锁定少数几句“丢了就会让人做出错误决定”的限定，各自给出关键词判据：
// 译文用词不同，但关键事实必须还在。新增语言时把判据补进来即可。

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** 英文主文档与十份译文的路径。 */
const READMES = Object.freeze([
  { file: 'README.md', label: '英文' },
  { file: 'docs/readme/README_zh.md', label: '简体中文' },
  { file: 'docs/readme/README_zh-TW.md', label: '繁体中文' },
  { file: 'docs/readme/README_ja.md', label: '日语' },
  { file: 'docs/readme/README_ko.md', label: '韩语' },
  { file: 'docs/readme/README_de.md', label: '德语' },
  { file: 'docs/readme/README_fr.md', label: '法语' },
  { file: 'docs/readme/README_es.md', label: '西班牙语' },
  { file: 'docs/readme/README_pt-BR.md', label: '葡萄牙语' },
  { file: 'docs/readme/README_ru.md', label: '俄语' },
  { file: 'docs/readme/README_it.md', label: '意大利语' },
]);

/** 读取全部 README 文本，键为相对路径。@returns {Promise<Map<string, string>>} */
async function readAll() {
  const texts = new Map();
  for (const readme of READMES) {
    texts.set(readme.file, await readFile(join(REPO_ROOT, readme.file), 'utf8'));
  }
  return texts;
}

/**
 * 断言每份 README 都命中给定判据。至少命中一个才算通过：
 * 译文用词不同，不可能要求逐字一致。
 * @param {Map<string, string>} texts 全部 README 文本
 * @param {string} what 判据说明，用于失败信息
 * @param {readonly string[]} patterns 正则或字符串判据
 */
function assertEveryReadme(texts, what, patterns) {
  const missing = [];
  for (const readme of READMES) {
    const text = texts.get(readme.file);
    if (!patterns.some((pattern) => (typeof pattern === 'string' ? text.includes(pattern) : pattern.test(text)))) {
      missing.push(readme.label);
    }
  }
  assert.deepEqual(missing, [], `以下语言版本的 README 缺少${what}：${missing.join('、')}`);
}

test('每份 README 都说明主机覆盖的修复已在推进，而不是只说尚未验证', async () => {
  // 旧表述是“macOS 与 Linux 预计可用，尚未验证”，读起来像没人管。
  // 加了持续集成之后必须说明修复已在推进，否则用户仍会以为这是被搁置的限制。
  const texts = await readAll();
  assertEveryReadme(texts, '主机覆盖修复进展', ['GitHub Actions']);
  // 反向：不得再出现“尚未验证”这类把限制说成搁置的措辞。
  const stale = READMES.filter((readme) =>
    /尚未验证|尚未驗證|まだ検証されていません|아직 검증되지는 않았다|noch nicht verifiziert|ne sont pas encore vérifiés|aún no están verificados|non sono ancora verificati|ainda não foram verificados|ещё не проверено/.test(
      texts.get(readme.file),
    ),
  ).map((readme) => readme.label);
  assert.deepEqual(stale, [], `以下语言版本仍把主机覆盖说成尚未验证：${stale.join('、')}`);
});

test('每份 README 都说明 APK 内的 DEX 会被递归解析', async () => {
  // 这条锁定的是一个从“看不见”到“看得见”的覆盖变化：APK 此前只按普通 ZIP 处理，
  // classes.dex 里的类名与方法名完全不在报告里。现在递归进 DEX 读取器，
  // 文档必须说清这件事，否则用户仍会以为 Android 应用的命名暴露面没被覆盖。
  const texts = await readAll();
  assertEveryReadme(texts, 'APK 内 DEX 递归说明', ['app.apk!classes.dex']);
});

test('每份 README 都按九类格式描述令牌扫描覆盖面', async () => {
  // 实测结果表里有一句“令牌扫描器覆盖全部 N 类格式”。新增读取器时这句话最容易漏改，
  // 而它会直接告诉用户自己的凭据有没有被扫到——说少了比说多了更危险。
  const texts = await readAll();
  const perLanguage = Object.freeze({
    'README.md': /all nine formats/,
    'docs/readme/README_zh.md': /九类格式/,
    'docs/readme/README_zh-TW.md': /九種格式/,
    'docs/readme/README_ja.md': /9 つのフォーマット/,
    'docs/readme/README_ko.md': /아홉 가지 형식/,
    'docs/readme/README_de.md': /neun Formate/,
    'docs/readme/README_fr.md': /neuf formats/,
    'docs/readme/README_es.md': /nueve formatos/,
    'docs/readme/README_pt-BR.md': /nove formatos/,
    'docs/readme/README_ru.md': /девяти форматам/,
    'docs/readme/README_it.md': /nove formati/,
  });
  for (const readme of READMES) {
    const pattern = perLanguage[readme.file];
    assert.ok(pattern !== undefined, `新增语言 ${readme.label} 时要把格式数判据补进 perLanguage`);
    assert.match(texts.get(readme.file), pattern, `${readme.label} 未按九类格式描述令牌扫描覆盖面`);
  }
  // 反向：任何语言都不得再写八类，那说明漏改或回退。
  const stale = READMES.filter((readme) =>
    /eight formats|acht Formate|huit formats|ocho formatos|oito formatos|восьми форматам|otto formati|八类格式|八種格式|8 つのフォーマット|여덟 가지 형식/.test(
      texts.get(readme.file),
    ),
  ).map((readme) => readme.label);
  assert.deepEqual(stale, [], `以下语言版本仍按八类格式描述：${stale.join('、')}`);
});

test('每份 README 都不再把内容保护说成“反编译只看到存根”', async () => {
  // 内容保护层此前在防御层表格里承诺“静态反编译看到的是桩而不是程序”。
  // 实测该层发现数为零：没有读取器产出过它，唯一措施只覆盖用户手工指定的字节区间，
  // 审计到加固的流程永远到不了这一层。这与 IL2CPP 那三行同属虚假承诺，已改。
  const texts = await readAll();
  const offenders = READMES.filter((readme) =>
    /stubs, not the program|sieht Stubs|ve stubs|vede stub|スタブだけで|스텁만 본다|veja stubs|видит заглушки|只看到存根|只看得到存根| voit des talons/.test(
      texts.get(readme.file),
    ),
  ).map((readme) => readme.label);
  assert.deepEqual(offenders, [], `以下语言版本仍把内容保护说成反编译只看到存根：${offenders.join('、')}`);
});

test('每份 README 都说明内容保护只覆写用户亲自指定的范围', async () => {
  const texts = await readAll();
  assertEveryReadme(texts, '内容保护边界的如实描述', [
    'byte ranges you name yourself',
    'Bytebereiche, die du selbst benennst',
    'rangos de bytes que tú mismo indicas',
    'que vous nommez vous-même',    'intervalli di byte che nomini tu stesso',
    'intervalos de bytes que você mesmo informa',
    'диапазоны байтов, которые вы называете',
    'バイト範囲をゼロクリアするだけで',
    '지정한 바이트 범위만',
    '只覆写你亲自指名的字节范围',
    '只會覆寫你親自指名的位元組範圍',
  ]);
});

test('每份 README 都写明测试套件只在 Windows 上跑过', async () => {
  // 这是最容易被译丢的一句限定：它决定用户要不要自己承担未验证平台的风险。
  const texts = await readAll();
  assertEveryReadme(texts, 'Windows 主机限定', [
    'Windows',
    'Windows 上',
    'Windowsで',
    'Windows에서',
    'Windows 主機',
    'Windows 主机',
    '尚未',
    '未驗證',
    '未验证',
    '尚未覆盖',
    ' exercised',
    'exercised',
  ]);
});

test('每份 README 都不承诺 IL2CPP、.NET、JavaScript 三类内置读取器', async () => {
  // 这三类格式在源码里登记为能力边界（v1 读取器集之外）。
  // README 一度写成“内置读取器”，那是对用户作假，本次已删。
  // 这里锁定：任何语言版本都不得再把它们写成已实现的读取器。
  const texts = await readAll();
  const offenders = [];
  for (const readme of READMES) {
    const text = texts.get(readme.file);
    // 允许在“能力边界”段落里提到它们（说明为什么不覆盖），
    // 但不允许出现在“内置读取器”这类已实现的口吻里。
    const claims = [
      /内置\s*IL2CPP\s*读取器/,
      /內建\s*IL2CPP\s*讀取器/,
      /IL2CPP\s*(reader|Leser|lector|Lecteur|Lettore|lettore|リーダー|리더|leitor|средство чтения)/i,
      /Built-in\s*(IL2CPP|managed|JavaScript)\s*reader/i,
      /内置托管代码读取器/,
      /内置\s*JavaScript\s*读取器/,
      /內建\s*JavaScript\s*讀取器/,
    ];
    if (claims.some((pattern) => pattern.test(text))) {
      offenders.push(readme.label);
    }
  }
  assert.deepEqual(offenders, [], `以下语言版本仍把范围外格式写成内置读取器：${offenders.join('、')}`);
});

test('每份 README 都说明读取器集之外的格式会被报告而不是跳过', async () => {
  // 与上一条配对：删掉虚假承诺之后，必须补上真实的做法，否则用户会以为
  // 遇到不认识的格式就是空结果、就是没有暴露。
  const texts = await readAll();
  assertEveryReadme(texts, '能力边界说明', ['global-metadata.dat']);
});

test('每份 README 都不把 SQLite 列为已覆盖的容器格式', async () => {
  const texts = await readAll();
  const offenders = READMES.filter((readme) => texts.get(readme.file).includes('SQLite')).map((readme) => readme.label);
  assert.deepEqual(offenders, [], `以下语言版本仍把 SQLite 列为已覆盖格式：${offenders.join('、')}`);
});

test('每份 README 的审计报告表格数据行数一致', async () => {
  // 漏改一行表格，行数就对不上——这是发现漏改最直接的信号。
  // 定位方式与语言无关：能力边界段落必然紧跟表格，且必然提到 global-metadata.dat
  // （这一点由上一个测试锁定），所以从那段往回找最后一张表即可。
  const texts = await readAll();
  const counts = [];
  for (const readme of READMES) {
    const lines = texts.get(readme.file).split('\n');
    const anchor = lines.findIndex((line) => line.includes('global-metadata.dat'));
    assert.ok(anchor > 0, `${readme.label} 找不到能力边界段落，无法定位审计报告表格`);
    // 锚点在段落中间某一行。先往上跨过整个段落（连续非空行），
    // 再跳过空行，最后收拢连续的表格行。
    let cursor = anchor;
    while (cursor >= 0 && lines[cursor].trim() !== '') {
      cursor -= 1;
    }
    while (cursor >= 0 && lines[cursor].trim() === '') {
      cursor -= 1;
    }
    assert.ok(lines[cursor].startsWith('|'), `${readme.label} 能力边界段落之前不是表格`);
    let start = cursor;
    while (start >= 0 && lines[start].startsWith('|')) {
      start -= 1;
    }
    const rows = cursor - start; // 含表头与分隔行
    counts.push({ label: readme.label, dataRows: rows - 2 });
  }
  const expected = counts[0].dataRows;
  assert.ok(expected >= 5, `英文 README 的数据行数判据异常：${expected}`);
  for (const entry of counts) {
    assert.equal(entry.dataRows, expected, `${entry.label} 的审计报告表格数据行数与英文版不一致（${entry.dataRows} 对 ${expected}）`);
  }
});
