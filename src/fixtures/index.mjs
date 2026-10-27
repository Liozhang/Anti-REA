// 夹具规格登记表。
// 登记“要有哪些夹具、各自覆盖哪条路径、字节由谁生成”：字节级夹具由 tests/fixtures/build.mjs
// 的确定性构造器生成并提交，摘要登记在 tests/fixtures/manifest.json；
// 稳定性用例断言每个夹具的 sha256 与清单记录一致，保证测试跑的是固定真实字节。

/** v1 八类格式各至少一个夹具，另加覆盖特定路径的附加夹具与两类范围外格式夹具。 */
export const FIXTURE_SPECS = Object.freeze([
  { id: 'elf-basic', container: 'elf', path: 'elf/basic.elf', covers: 'ELF 节表与符号表解析', status: 'committed' },
  { id: 'elf-go-buildinfo-inline', container: 'elf', path: 'elf/go-buildinfo-inline.elf', covers: 'Go 构建信息 inline 编码', status: 'committed' },
  { id: 'elf-go-buildinfo-pointer', container: 'elf', path: 'elf/go-buildinfo-pointer.elf', covers: 'Go 构建信息 pointer 编码（魔数落在可写且非执行的 load region）', status: 'committed' },
  { id: 'elf-rust-dep-v0', container: 'elf', path: 'elf/rust-dep-v0.elf', covers: '.dep-v0 依赖节命中与等长覆写', status: 'committed' },
  { id: 'pe-basic', container: 'pe', path: 'pe/basic.pe', covers: 'PE 可选头、节表与数据目录', status: 'committed' },
  { id: 'pe-security-directory', container: 'pe', path: 'pe/security-directory.pe', covers: '带安全目录时默认跳过改写', status: 'committed' },
  { id: 'pe-checksum-nonzero', container: 'pe', path: 'pe/checksum-nonzero.pe', covers: '非零 CheckSum 等长重算', status: 'committed' },
  { id: 'mach-o-basic', container: 'mach-o', path: 'mach-o/basic.macho', covers: 'Mach-O 加载命令与节表', status: 'committed' },
  { id: 'mach-o-code-signature', container: 'mach-o', path: 'mach-o/code-signature.macho', covers: 'LC_CODE_SIGNATURE 默认跳过改写', status: 'committed' },
  { id: 'zip-mixed-entries', container: 'zip', path: 'zip/mixed-entries.zip', covers: '存储条目与 deflate 条目分别标记，改写后同帧重算 CRC32', status: 'committed' },
  { id: 'gguf-basic', container: 'gguf', path: 'gguf/basic.gguf', covers: 'GGUF 元数据重布局后按原 alignment 重新对齐', status: 'committed' },
  { id: 'safetensors-basic', container: 'safetensors', path: 'safetensors/basic.safetensors', covers: '写入 __metadata__ 后 tensor_data_offset 与各 data_offsets', status: 'committed' },
  { id: 'pyc-hash-based-check-source', container: 'pyc', path: 'pyc/hash-based-check-source.pyc', covers: 'hash_based 且 check_source 时的标志与哈希一致性', status: 'committed' },
  { id: 'beam-basic', container: 'beam', path: 'beam/basic.beam', covers: 'BEAM 块结构解析', status: 'committed' },
  { id: 'il2cpp-metadata', container: 'unsupported', path: 'unsupported/global-metadata.dat', covers: '范围外格式返回 unsupported 与能力边界说明', status: 'committed' },
  { id: 'apk-signature-scheme', container: 'unsupported', path: 'unsupported/apk-signature-scheme.apk', covers: '范围外格式返回 unsupported 与能力边界说明', status: 'committed' },
  { id: 'sample-app', container: 'directory', path: 'sample-app', covers: '端到端：普通应用目录审计正常完成', status: 'committed' },
]);

/**
 * 按容器取夹具规格。
 * @param {string} container 容器标识
 * @returns {readonly Record<string, unknown>[]}
 */
export function fixtureSpecsFor(container) {
  return FIXTURE_SPECS.filter((spec) => spec.container === container);
}

/**
 * 按状态取夹具规格。
 * @param {'pending' | 'committed'} status
 * @returns {readonly Record<string, unknown>[]}
 */
export function fixtureSpecsByStatus(status) {
  return FIXTURE_SPECS.filter((spec) => spec.status === status);
}

/**
 * 按标识取夹具规格。
 * @param {string} id 夹具标识
 * @returns {Record<string, unknown> | null}
 */
export function fixtureSpecById(id) {
  return FIXTURE_SPECS.find((spec) => spec.id === id) ?? null;
}
