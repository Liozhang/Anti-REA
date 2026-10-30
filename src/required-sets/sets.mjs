// 按格式的必需集数据。
// 必需集回答一个问题：施加缓解措施之后，制品里哪些结构必须仍然可解析，
// 否则就是伤害了合法用户。规则只有一条：已施加缓解清单中列名的节与字段从必需集移除，
// 其余必须保持可解析。这条规则由 index.mjs 的豁免推导实现，本文件只提供数据。
//
// 每项字段：
//   id           必需项编号，全局唯一；复审提供结构事实时以它为键
//   kind         类别，取值在 REQUIRED_ITEM_KINDS 封闭集合内
//   label        人读名称
//   requirement  为什么这项必须保持可解析，即伤害合法用户的判定依据
//   exemptedBy   施加后会破坏该项的缓解措施编号，全部在 audit/finding.mjs 的
//               MITIGATION_IDS 封闭集合内；施加这些措施时该项从必需集移除

/** 必需集模式版本。 */
export const REQUIRED_SET_SCHEMA = 'anti-rea.required-set/1';

/** 必需项类别封闭集合。 */
export const REQUIRED_ITEM_KINDS = Object.freeze([
  'header',
  'table',
  'section',
  'segment',
  'command',
  'directory',
  'chunk',
  'field',
  'index',
  'entry',
]);

/** 必需集登记状态。registered 表示数据已登记，可被复审按项消费。 */
export const REQUIRED_SET_STATUS = Object.freeze(['registered']);

/**
 * 构造一个容器的必需集。
 * @param {string} container 容器标识
 * @param {readonly Record<string, unknown>[]} items 必需项清单
 * @param {string} note 覆盖面与边界说明
 */
function requiredSet(container, items, note) {
  return Object.freeze({
    container,
    status: 'registered',
    items: Object.freeze(items.map((item) => Object.freeze(item))),
    note,
  });
}

/** v1 九类格式的必需集。键为容器标识，与 container/detect.mjs 的 SUPPORTED_CONTAINERS 对应。 */
export const REQUIRED_SETS = Object.freeze({
  elf: requiredSet(
    'elf',
    [
      {
        id: 'elf.elf-header',
        kind: 'header',
        label: 'ELF 头',
        requirement: 'e_ident 与 e_phoff、e_shoff 等字段决定整份制品如何解析，损坏后任何读取器都无法定位后续结构',
        exemptedBy: [],
      },
      {
        id: 'elf.program-headers',
        kind: 'table',
        label: '程序头表',
        requirement: '动态加载器按程序头表映射 PT_LOAD 段，表偏移或条目数损坏时制品无法加载',
        exemptedBy: [],
      },
      {
        id: 'elf.segment-load',
        kind: 'segment',
        label: 'PT_LOAD 段',
        requirement: '入口地址与各个可映射节必须落在某个 PT_LOAD 描述的范围内',
        exemptedBy: [],
      },
      {
        id: 'elf.segment-dynamic',
        kind: 'segment',
        label: 'PT_DYNAMIC 段',
        requirement: '动态链接信息入口，指向 .dynamic 节，缺失时动态符号解析失败',
        exemptedBy: [],
      },
      {
        id: 'elf.segment-interp',
        kind: 'segment',
        label: 'PT_INTERP 段',
        requirement: '动态可执行文件需要的解释器路径，静态制品可以没有这一项',
        exemptedBy: [],
      },
      {
        id: 'elf.section-table',
        kind: 'table',
        label: '节表',
        requirement: '多数静态工具按节表定位内容，节表损坏后按节检索全部失败',
        exemptedBy: [],
      },
      {
        id: 'elf.section.interp',
        kind: 'section',
        label: '.interp 节',
        requirement: '与 PT_INTERP 对应的解释器路径字符串',
        exemptedBy: [],
      },
      {
        id: 'elf.section.note',
        kind: 'section',
        label: '.note 节',
        requirement: '构建标识等 note 段；构建标识清零措施只清零描述符字节、note 结构仍可解析，该项对它豁免；符号表清零不触及 note，不豁免',
        exemptedBy: ['metadata.elf-build-id-note-overwrite'],
      },
      {
        id: 'elf.section.dynamic',
        kind: 'section',
        label: '.dynamic 节',
        requirement: '动态链接的节内容，运行期重定位依赖其中的条目',
        exemptedBy: [],
      },
      {
        id: 'elf.section.dynsym',
        kind: 'section',
        label: '.dynsym 节',
        requirement: '运行期重定位需要的动态符号表',
        exemptedBy: [],
      },
      {
        id: 'elf.section.dynstr',
        kind: 'section',
        label: '.dynstr 节',
        requirement: '动态符号名字符串表',
        exemptedBy: [],
      },
      {
        id: 'elf.section.reloc',
        kind: 'section',
        label: '.rela 节',
        requirement: '.rela.dyn 与 .rela.plt 的重定位条目，缺失时加载期重定位失败',
        exemptedBy: [],
      },
      {
        id: 'elf.section.got',
        kind: 'section',
        label: '.got 节',
        requirement: '全局偏移表，运行期符号绑定的写入处',
        exemptedBy: [],
      },
      {
        id: 'elf.section.init-array',
        kind: 'section',
        label: '.init_array 与 .fini_array 节',
        requirement: '运行期初始化与收尾函数指针表',
        exemptedBy: [],
      },
      {
        id: 'elf.section.text',
        kind: 'section',
        label: '.text 节',
        requirement: '代码节；等长覆写只改字节不改结构，节本身必须仍可定位',
        exemptedBy: [],
      },
      {
        id: 'elf.section.symtab',
        kind: 'section',
        label: '.symtab 节',
        requirement: '静态符号表；符号表清零措施会清零节头条目，施加后该项从必需集移除',
        exemptedBy: ['metadata.elf-symtab-clear'],
      },
      {
        id: 'elf.section.strtab',
        kind: 'section',
        label: '.strtab 节',
        requirement: '静态符号名字符串表，其载荷被符号表清零措施覆写',
        exemptedBy: ['metadata.elf-symtab-clear'],
      },
      {
        id: 'elf.section.go-buildinfo',
        kind: 'section',
        label: '.go.buildinfo 节',
        requirement: 'Go 构建信息所在节；构建信息覆写措施命中后该项从必需集移除，节表其余项仍须可解析',
        exemptedBy: [
          'metadata.go-buildinfo-inline-overwrite',
          'metadata.go-buildinfo-pointer-overwrite',
          'metadata.go-buildinfo-writable-region-overwrite',
        ],
      },
      {
        id: 'elf.section.dep-v0',
        kind: 'section',
        label: '.dep-v0 节',
        requirement: 'Rust 依赖清单所在节；依赖节覆写措施会改写节名与节类型，施加后该项从必需集移除',
        exemptedBy: ['metadata.rust-dep-section-overwrite'],
      },
    ],
    '必需集覆盖程序头、段与动态链接所需节，另登记符号表、Go 构建信息与 Rust 依赖节三类可豁免项；运行期行为不在静态可判定范围内。',
  ),
  pe: requiredSet(
    'pe',
    [
      {
        id: 'pe.dos-header',
        kind: 'header',
        label: 'DOS 头',
        requirement: 'MZ 签名与 e_lfanew 定位 PE 头，损坏后无法找到 PE 签名',
        exemptedBy: [],
      },
      {
        id: 'pe.pe-signature',
        kind: 'field',
        label: 'PE 签名',
        requirement: 'PE\\0\\0 四字节标记，COFF 头的起点',
        exemptedBy: [],
      },
      {
        id: 'pe.coff-header',
        kind: 'header',
        label: 'COFF 文件头',
        requirement: '节数、可选头大小与特征位决定后续结构如何遍历',
        exemptedBy: [],
      },
      {
        id: 'pe.optional-header',
        kind: 'header',
        label: '可选头',
        requirement: '魔数、入口地址、镜像基址与数据目录表',
        exemptedBy: [],
      },
      {
        id: 'pe.optional-header.checksum',
        kind: 'field',
        label: '可选头 CheckSum',
        requirement: '非零时必须与改写后字节的重算结果一致；无法重算时按签名制品同等对待',
        exemptedBy: [],
      },
      {
        id: 'pe.section-table',
        kind: 'table',
        label: '节表',
        requirement: '节头数组，损坏后按节定位与基址重定位全部失败',
        exemptedBy: [],
      },
      {
        id: 'pe.entry-point',
        kind: 'field',
        label: '入口地址',
        requirement: 'AddressOfEntryPoint 必须落在某个已映射节内',
        exemptedBy: [],
      },
      {
        id: 'pe.import-directory',
        kind: 'directory',
        label: '导入表数据目录',
        requirement: '运行期符号绑定入口',
        exemptedBy: [],
      },
      {
        id: 'pe.export-directory',
        kind: 'directory',
        label: '导出表数据目录',
        requirement: '动态库导出符号入口',
        exemptedBy: [],
      },
      {
        id: 'pe.reloc-directory',
        kind: 'directory',
        label: '重定位表数据目录',
        requirement: '基址重定位入口',
        exemptedBy: [],
      },
      {
        id: 'pe.debug-directory',
        kind: 'directory',
        label: '调试目录',
        requirement: '其中的符号文件路径被覆写后该项从必需集移除',
        exemptedBy: ['metadata.pe-debug-directory-overwrite'],
      },
      {
        id: 'pe.security-directory',
        kind: 'directory',
        label: '安全目录',
        requirement: '证书表所在位置；签名制品默认跳过改写，改写后需重新签名',
        exemptedBy: [],
      },
      {
        id: 'pe.section.go-buildinfo',
        kind: 'section',
        label: 'Go 构建信息所在节',
        requirement: '按节特征位 0xc0000040 识别；特征位覆写措施命中后该节不再被识别为构建信息载体',
        exemptedBy: ['metadata.go-buildinfo-pe-characteristics-overwrite'],
      },
    ],
    '必需集覆盖 DOS 头、PE 签名、COFF 头、可选头、节表与导入、导出、重定位、调试、安全五类数据目录，另登记 Go 构建信息节为可豁免项。',
  ),
  'mach-o': requiredSet(
    'mach-o',
    [
      {
        id: 'mach-o.header',
        kind: 'header',
        label: 'Mach-O 头',
        requirement: '魔数、cputype、filetype 与 ncmds 决定加载命令区如何遍历',
        exemptedBy: [],
      },
      {
        id: 'mach-o.load-commands',
        kind: 'table',
        label: '加载命令表',
        requirement: 'sizeofcmds 覆盖的全部加载命令，损坏后动态链接器拒绝加载',
        exemptedBy: [],
      },
      {
        id: 'mach-o.load-command.segment',
        kind: 'command',
        label: 'LC_SEGMENT_64 加载命令',
        requirement: '各段的映射范围与段内节表',
        exemptedBy: [],
      },
      {
        id: 'mach-o.load-command.dyld-info',
        kind: 'command',
        label: '动态链接信息加载命令',
        requirement: 'LC_DYLD_INFO_ONLY 或其替代形式承载的导出与重定位信息',
        exemptedBy: [],
      },
      {
        id: 'mach-o.load-command.dylinker',
        kind: 'command',
        label: 'LC_LOAD_DYLINKER 加载命令',
        requirement: '动态链接器路径',
        exemptedBy: [],
      },
      {
        id: 'mach-o.load-command.uuid',
        kind: 'command',
        label: 'LC_UUID 加载命令',
        requirement: '制品唯一标识',
        exemptedBy: [],
      },
      {
        id: 'mach-o.load-command.code-signature',
        kind: 'command',
        label: 'LC_CODE_SIGNATURE 加载命令',
        requirement: '签名载荷位置；签名制品默认跳过改写，改写后需重新签名',
        exemptedBy: [],
      },
      {
        id: 'mach-o.sections',
        kind: 'table',
        label: '节表',
        requirement: '各段内的节数组，按节名检索的入口',
        exemptedBy: [],
      },
      {
        id: 'mach-o.section.go-buildinfo',
        kind: 'section',
        label: 'Go 构建信息所在节',
        requirement: '首个可写映射中的构建信息被覆写后该项从必需集移除',
        exemptedBy: ['metadata.go-buildinfo-macho-rw-overwrite'],
      },
      {
        id: 'mach-o.section.dep-v0',
        kind: 'section',
        label: '__DATA,.dep-v0 节',
        requirement: 'Rust 依赖清单所在节；依赖节覆写措施会改写节名与节类型',
        exemptedBy: ['metadata.rust-dep-section-overwrite'],
      },
    ],
    '必需集覆盖 Mach-O 头、加载命令表、段、动态链接信息、动态链接器、唯一标识、代码签名与节表，另登记 Go 构建信息节与 Rust 依赖节为可豁免项。',
  ),
  'mach-o-fat': requiredSet(
    'mach-o-fat',
    [
      {
        id: 'mach-o-fat.fat-header',
        kind: 'header',
        label: '胖二进制头',
        requirement: '魔数与 nfat_arch 决定分片表如何遍历',
        exemptedBy: [],
      },
      {
        id: 'mach-o-fat.arch-table',
        kind: 'table',
        label: '分片表',
        requirement: '各分片的 cputype、偏移与大小，损坏后无法定位分片',
        exemptedBy: [],
      },
      {
        id: 'mach-o-fat.slice-header',
        kind: 'header',
        label: '分片 Mach-O 头',
        requirement: '每个分片自身的头',
        exemptedBy: [],
      },
      {
        id: 'mach-o-fat.slice-load-commands',
        kind: 'table',
        label: '分片加载命令表',
        requirement: '每个分片的加载命令必须可解析',
        exemptedBy: [],
      },
      {
        id: 'mach-o-fat.slice-code-signature',
        kind: 'command',
        label: '分片 LC_CODE_SIGNATURE 加载命令',
        requirement: '任一构成分片带签名时按签名制品对待，默认跳过改写',
        exemptedBy: [],
      },
      {
        id: 'mach-o-fat.slice-go-buildinfo',
        kind: 'section',
        label: '分片 Go 构建信息所在节',
        requirement: '分片内首个可写映射中的构建信息被覆写后该项从必需集移除',
        exemptedBy: ['metadata.go-buildinfo-macho-rw-overwrite'],
      },
      {
        id: 'mach-o-fat.slice-dep-v0',
        kind: 'section',
        label: '分片 __DATA,.dep-v0 节',
        requirement: '分片内 Rust 依赖清单所在节',
        exemptedBy: ['metadata.rust-dep-section-overwrite'],
      },
    ],
    '胖二进制的必需集按分片表加各分片自身结构登记；任一构成分片被破坏即视为伤害合法用户。',
  ),
  zip: requiredSet(
    'zip',
    [
      {
        id: 'zip.local-file-headers',
        kind: 'table',
        label: '本地文件头序列',
        requirement: '每个条目数据前的本地头，损坏后条目无法定位',
        exemptedBy: [],
      },
      {
        id: 'zip.central-directory',
        kind: 'table',
        label: '中央目录',
        requirement: '条目名、偏移与属性的权威记录',
        exemptedBy: [],
      },
      {
        id: 'zip.end-of-central-directory',
        kind: 'header',
        label: '中央目录结束记录',
        requirement: '定位中央目录起点，损坏后归档无法打开',
        exemptedBy: [],
      },
      {
        id: 'zip.entry-table',
        kind: 'index',
        label: '条目索引',
        requirement: '逐条目本地头与中央目录项一致：名称、压缩方法与数据偏移',
        exemptedBy: [],
      },
      {
        id: 'zip.entry-crc32',
        kind: 'entry',
        label: '条目 CRC32',
        requirement: '改写条目数据后必须同帧重算，否则判定复审不通过',
        exemptedBy: [],
      },
      {
        id: 'zip.entry-data',
        kind: 'entry',
        label: '条目数据区',
        requirement: '按声明的压缩方法可解压或按存储读取；不可解压时附限制说明，不冒充已扫描',
        exemptedBy: [],
      },
    ],
    'ZIP 必需集按本地头、中央目录、结束记录与逐条目一致性登记；条目改写后 CRC32 由校验和一致性检查族复验。',
  ),
  gguf: requiredSet(
    'gguf',
    [
      {
        id: 'gguf.header',
        kind: 'header',
        label: 'GGUF 头',
        requirement: '魔数、版本、张量数与元数据键值数决定后续如何遍历',
        exemptedBy: [],
      },
      {
        id: 'gguf.metadata-kv',
        kind: 'index',
        label: '元数据键值表',
        requirement: '模型层真实信号的写入位，读取方按文件声明取出',
        exemptedBy: [],
      },
      {
        id: 'gguf.tensor-index',
        kind: 'index',
        label: '张量索引',
        requirement: '各张量的名称、维度、类型与相对偏移',
        exemptedBy: [],
      },
      {
        id: 'gguf.alignment',
        kind: 'field',
        label: '对齐值',
        requirement: '重布局后按原对齐值重新对齐，并重算 tensor_data_offset 与派生 file_offset',
        exemptedBy: [],
      },
      {
        id: 'gguf.tensor-data',
        kind: 'entry',
        label: '张量数据区',
        requirement: '按索引可寻址，无越界',
        exemptedBy: [],
      },
    ],
    'GGUF 必需集按头部、元数据键值表、张量索引、对齐值与数据区登记；元数据重布局后全部五项仍须可解析。',
  ),
  safetensors: requiredSet(
    'safetensors',
    [
      {
        id: 'safetensors.header-length-prefix',
        kind: 'field',
        label: '头部长度前缀',
        requirement: '8 字节小端整数，决定头部 JSON 的边界',
        exemptedBy: [],
      },
      {
        id: 'safetensors.header-json',
        kind: 'header',
        label: '头部 JSON',
        requirement: '张量索引与 __metadata__ 的载体，必须可解析',
        exemptedBy: [],
      },
      {
        id: 'safetensors.tensor-index',
        kind: 'index',
        label: '张量索引',
        requirement: '各张量的 dtype 与 data_offsets；重布局后 data_offsets 保持原值不变',
        exemptedBy: [],
      },
      {
        id: 'safetensors.data-bounds',
        kind: 'entry',
        label: '数据区边界',
        requirement: '无越界、无间隙、无重叠、无未索引尾部',
        exemptedBy: [],
      },
      {
        id: 'safetensors.metadata',
        kind: 'field',
        label: '__metadata__ 槽位',
        requirement: '模型层真实信号的写入位；重布局写入后仍必须可解析',
        exemptedBy: [],
      },
    ],
    'safetensors 必需集按长度前缀、头部 JSON、张量索引、数据区边界与 __metadata__ 槽位登记；重布局写入不豁免任何一项。',
  ),
  pyc: requiredSet(
    'pyc',
    [
      {
        id: 'pyc.magic',
        kind: 'field',
        label: '魔数',
        requirement: '四字节魔数决定字节码版本，损坏后无法反序列化',
        exemptedBy: [],
      },
      {
        id: 'pyc.header-flags',
        kind: 'field',
        label: '标志位',
        requirement: 'hash_based 与 check_source 两个标志',
        exemptedBy: [],
      },
      {
        id: 'pyc.source-hash',
        kind: 'field',
        label: '源文件哈希',
        requirement: 'hash_based 制品的源文件哈希；清零后该项从必需集移除',
        exemptedBy: ['metadata.pyc-source-hash-clear'],
      },
      {
        id: 'pyc.check-source-flag',
        kind: 'field',
        label: 'check_source 标志',
        requirement: '清零 source_hash 时必须一并清除该标志，否则标志与哈希状态不一致',
        exemptedBy: ['metadata.pyc-source-hash-clear'],
      },
      {
        id: 'pyc.code-object',
        kind: 'index',
        label: '码对象载荷',
        requirement: '魔数与头字段之后的序列化码对象，必须可解析',
        exemptedBy: [],
      },
    ],
    'pyc 必需集按魔数、标志位、源文件哈希、check_source 标志与码对象载荷登记；哈希清零措施同时豁免哈希与标志两项。',
  ),
  beam: requiredSet(
    'beam',
    [
      {
        id: 'beam.for1-chunk',
        kind: 'chunk',
        label: 'FOR1 外层块',
        requirement: 'IFF 外层块，损坏后无法定位内部块',
        exemptedBy: [],
      },
      {
        id: 'beam.beam-chunk',
        kind: 'chunk',
        label: 'BEAM 块',
        requirement: '编译单元头所在块',
        exemptedBy: [],
      },
      {
        id: 'beam.chunk-table',
        kind: 'table',
        label: '块表',
        requirement: '块序列可解析，至少含 Atom 与 Code 两类必需块',
        exemptedBy: [],
      },
      {
        id: 'beam.chunk.atom',
        kind: 'chunk',
        label: 'Atom 块',
        requirement: '原子表，函数名与模块名的检索入口',
        exemptedBy: [],
      },
      {
        id: 'beam.chunk.code',
        kind: 'chunk',
        label: 'Code 块',
        requirement: '编译后的指令流',
        exemptedBy: [],
      },
    ],
    'BEAM 必需集按最小可加载子集登记：外层块、编译单元块、块表与 Atom、Code 两类必需块；其余块缺失不阻断加载。',
  ),
  dex: requiredSet(
    'dex',
    [
      {
        id: 'dex.header',
        kind: 'header',
        label: 'DEX 头部',
        requirement: '头部给出各张表的偏移与计数，损坏后无法定位字符串表、类型表与方法表',
        exemptedBy: [],
      },
      {
        id: 'dex.endian-tag',
        kind: 'field',
        label: '字节序标记',
        requirement: '固定为 0x12345678，标记不符时后续字段的小端解释全部不成立',
        exemptedBy: [],
      },
      {
        id: 'dex.string-ids',
        kind: 'index',
        label: '字符串索引表',
        requirement: '类型描述符与方法名都经它取出，索引表损坏后名字全部不可恢复',
        exemptedBy: [],
      },
      {
        id: 'dex.type-ids',
        kind: 'index',
        label: '类型索引表',
        requirement: '类型描述符的入口，运行期类加载依赖它',
        exemptedBy: [],
      },
      {
        id: 'dex.method-ids',
        kind: 'index',
        label: '方法索引表',
        requirement: '方法表的入口，运行期方法解析依赖它',
        exemptedBy: [],
      },
    ],
    'DEX 必需集按最小可加载子集登记：头部、字节序标记与字符串、类型、方法三张索引表；字段表、原型表、类定义表与 map 缺失不阻断加载。',
  ),
});

/**
 * 列出某容器登记的全部必需项。
 * @param {string} containerType 容器标识
 * @returns {readonly Record<string, unknown>[]}
 */
export function requiredItemsOf(containerType) {
  const set = REQUIRED_SETS[containerType];
  return set === undefined ? Object.freeze([]) : set.items;
}
