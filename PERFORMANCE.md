# rasc 与参考实现性能对比

在一份 343 MiB 的真实 APK 上按使用场景实测：四种模式的引用搜索、类反编译（早期/晚期 DEX）、
错误路径、二进制 Manifest 解码，以及完整类索引。

**结论：11 个场景几何平均加速 6.8×**：引用搜索快 6.9–10.4×，`classes` 索引 11.7×、
`manifest` 解码 18.7×、`getclass` 1.4–3.1×，**没有任何落后场景**。

> 下表是当前构建（自身主指标 **110 ms**、二进制 **1704 KB**）的完整重测，与
> `getclass` 的 scoped-parse 改动同一轮；Python ASC 侧数字与之前各轮一致。

## 环境

| | |
|---|---|
| 机器 | Apple M3 Pro，12 逻辑核，36 GiB 内存，macOS 26.5.1（arm64） |
| rasc | `rustc 1.98.0`；release 配置 `lto="fat"`、`codegen-units=1`、`panic="abort"`、`strip`；运行时不依赖 Python/JVM（下文表格测于 2676 KB 版本，当前二进制 1704 KB） |
| 原 ASC | CPython 3.12.14 + androguard 4.1.4（另有 lxml、loguru、mutf8） |
| 输入 | 343 MiB 生产 APK：56 个根 `classes*.dex`，解压后共 478 MB DEX |
| 并发 | 两者均使用 `--threads 8` |

## 方法

* **先校验正确性。** 每个场景在计时之前都会校验退出码、输出大小，并在语义可比的场景下直接
  比对结果集。因此一次失败的调用绝不可能被误报成加速比。
* **每个样本都是全新进程**，由同一时钟计时，所以进程启动、ZIP 发现、解压、DEX 分析、
  格式化与写出全部计入。
* **随机交错执行**：每轮中两个实现以随机顺序运行，机器漂移与热状态对双方影响相同。
  这一步很重要——同一份代码重复运行也会有约 ±10 ms 的漂移。
* **取 N 次中位数**（N ≥ 3）个全新进程，文件缓存已预热，stdout 重定向到 `/dev/null`
  （格式化与写系统调用仍被计入）。

已知不对称：原实现的输出顺序取决于各 DEX 的完成顺序，因此比较的是**行集合**而非行顺序。

## 结果

N 个全新进程的中位数；加速比 = asc / rasc。

| 场景 | rasc | asc | 加速比 |
|---|---:|---:|---:|
| `findrefs string Authorization`（53 行） | **114 ms** | 786 ms | **6.9×** |
| `findrefs string <包名前缀>`（31 行） | **105 ms** | 1054 ms | **10.1×** |
| `findrefs type Gson`（2924 行） | **140 ms** | 1208 ms | **8.6×** |
| `findrefs method onCreate`（7091 行） | **168 ms** | 1526 ms | **9.1×** |
| `findrefs method onCreate --class <包名前缀> --fuzzy-class`（2393 行） | **157 ms** | 1635 ms | **10.4×** |
| `findrefs field INSTANCE`（170830 行） | **191 ms** | 1951 ms | **10.2×** |
| `getclass` 早期类（`classes.dex`） | **71 ms** | 100 ms | **1.4×** |
| `getclass` 晚期类（`classes56.dex`） | **78 ms** | 242 ms | **3.1×** |
| `getclass` 不存在的类（错误路径） | **96 ms** | 235 ms | **2.4×** |
| `manifest`（二进制 AXML → XML，4075 行） | **14 ms** | 262 ms | **18.7×** |
| `classes`（完整索引，567192 个类） | **194 ms** | 2266 ms | **11.7×** |
| **几何平均** | | | **6.8×** |

上表用本仓库的复现脚本实测（2026-09-12，当前构建；表格中的行数取 rasc 一侧）。
parity 列（行集合差异）与本轮改动前完全一致：`classes` 567192/567192，`type Gson`、模糊类过滤
逐行相同，`field INSTANCE` / `method onCreate` 的少量差异来自参考实现的两处**过度报告**
（见附录，有 Androguard 指令级仲裁为证）。
每一项在计时前都会校验退出码与输出，且每个场景都是全新进程、随机交错、取 N 次中位数。

本项目自身的主指标（固定 `Authorization` 查询、取 3 次中位数）：表中那一轮为 **120–130 ms**，
当前构建为 **110 ms**（会话开始时为 180 ms）。上表的数字来自交错配对测量，是更可靠的对比。

## 分析

rasc 搜索时间的实际构成（用 `--debug` 采集全部 56 个 DEX 的分阶段耗时）：

| 阶段 | 占墙钟比例 |
|---|---:|
| ZIP 解压（libdeflate，按已知大小整块解压） | ~80% |
| 指令扫描（查表化解码 + 操作数预筛，仅 ~0.1% 方法真正解码指令） | ~15% |
| 字符串表目标匹配（memchr 字面量匹配） | ~4% |
| 启动 + 打开 APK + 串行工作 + 负载不均 | 其余 |

（上表为 2026-09-12 的当前构建；早期版本的占比为解压 ~60% / 扫描 ~25% / 字符串匹配 ~7%。
解压已是后端极限：libdeflate 在本机实测 910 MB/s，与独立 bench 调用 libdeflate 的耗时一致。）

* **搜索（7–10×）**：rasc 用 libdeflate 把每个 DEX 一次性解压到精确大小的缓冲区，再用专用的
  借用缓冲区读取器扫描；原实现则在 worker 进程内用 zlib 逐 DEX 解压，并把整个 DEX 重新解析成
  Python 对象后再定位引用。由于解压占大头，宽查询对 rasc 的额外开销很小——所以结果越多
  优势越大（宽查询 10.3×，输出 17 万行时 10.1×）。
* **类索引（11.6×）与 Manifest（21.0×）**：这两条正是原实现最慢的路径（建索要要对每个 DEX
  做完整 `tinydex` 解析；Manifest 走 Androguard AXML）。rasc 只遍历 `class_defs`，Manifest 由
  原生 Rust AXML 解码器处理。
* **`getclass`（1.4–3.1×）**：早期类 71 ms 对 100 ms，晚期类 78 ms 对 242 ms。原实现把目标类
  抽出来重建成一个只含该类的迷你 DEX，再用自己的反编译器；rasc 改用 vendored 补丁
  （见 `vendor/droidsaw-dex/PATCHES.md`）让 `droidsaw-dex` 只解析目标类自己的
  class_data / code_item / 静态值表，并跳过只有 emit 路径才消费的整包 SHA-1 与 map 段走查：
  9.8 MiB DEX 的解析从 120.7 ms 降到 23.7 ms，而按类的 CFG/SSA 反编译成本（约 21 ms）不变，
  所以 rasc 仍然输出更完整的 Java 风格源码（此处 32 行对 29 行）却整体更快。
  该改动的安全性由 `bench/decompile_equivalence.py` 守着：基准 APK 的 56 个 DEX 抽样 1176 个类、
  4 个真实 APK 再抽 194 个类，与未打补丁的二进制逐字节比对，差异 0（描述符拼写不规范时
  解析器回退到全量解析，不会退化成"没有方法体"的 DEX）。
* **输出顺序**：rasc 输出确定且有序；原实现的 CLI/编辑器行顺序会随每次运行的 DEX 完成顺序变化。
* **语料 parity 复跑（2026-09-12，6 个真实 APK）**：`classes` 集合全部一致（4,957 / 5,383 /
  8,949 / 53,214 / 70,133 / 226,123，另有基准包 567,192），两个 `findrefs` 查询的**行身份集合**
  全部一致，`manifest` 内容一致（仅格式差异）。参考实现的匹配文本会被截断，且被截断字符串常量的
  剩余行会作为额外 fragment 行打印；`bench/corpus_parity.py` 把 fragment 单独计数，并在文本差异
  无法解释为"参考侧截断"时判失败。`bench/mutation_check.py` 200 次确定性损坏 × 全部子命令 = 0 问题。
* **端到端冒烟（9 个 APK，0.03–974 MB）**：`classes` 全部成功且重复运行逐字节确定，按 DEX 分层的
  抽样 `getclass` 全部成功，`manifest` 与 `findrefs` 全部正常（6 – 567,192 个类；含 974 MB 游戏包、
  343 MB 与 243 MB 的两个第三方应用包）。`classes` 耗时从 9 ms（0.03 MB）到 505 ms（343 MB）。
* **重名 ZIP 条目**：ZIP 允许同名条目（重打包或构造的归档会出现）。原实现的 `classes*.dex`
  扫描按首次出现去重，rasc 现在一致（此前会把两份都扫一遍，凭空多出类与重复行）；而
  `AndroidManifest.xml` 原实现经 CPython `zipfile` 读取（同名取末次），rasc 也已对齐。
  三项行为都有单测固定（`duplicate_*_use_the_*_copy`）。
* **损坏/非 DEX 的 `classes*.dex` 条目**：rasc 明确报错并退出 1（"invalid DEX header"），不会静默跳过该条目后继续——
  一个坏条目说明归档与它声称的不符，静默按"其余部分"分析会掩盖"有一部分从未被分析"这件事。参考实现的
  findrefs 同样报错（消息不同），但它的类查找路径会静默跳过 magic 损坏的条目，两条路径行为不一致。四个
  形态（全垃圾、截断、magic 损坏、空条目）都有实测记录，且由单测固定（`an_entry_that_is_not_a_dex_is_a_clean_error`）。
* **与 JADX 的对照（反编译源码以 JADX 为准）**：`bench/jadx_parity.py` 把 JADX 当权威，逐类比较
  字符串字面量集合；只在 JADX 自身输出干净（无 bad-code 标记）**且类身份一致**时才判定 rasc（JADX 的
  `--single-class` 会把 `$Inner` 解析成外部类，缺这层校验就会误报）。在一个 124 DEX / 139,503 类的
  真实 `services.jar` 抽样上 rasc 与 JADX 一致，唯一确认的差异是
  `com.android.server.DiskStatsService#reportFreeSpace`：JADX 的 `catch (IllegalArgumentException)`
  分支里有 `pw.print("-Error: ")`，rasc（droidsaw 反编译器）漏掉了该分支语句。用**未打 vendored 补丁的
  旧二进制**复验：该差异与 rasc 的按类解析无关，属反编译器自身的完整性缺口。
  同时 JADX 在框架代码上自身局限明显（同一个 `ActiveServices` 有 295 处 bad-code 标记、8 个错误，大量
  `$$ExternalSyntheticLambda*` 无法反编译），所以对照必须先把这些类排除。
* **取值渲染的正确性优先**：未知/保留的 AXML 取值类型不再让整篇 manifest 解码失败，而是渲染
  `<0x.., type 0x..>`（修复前整篇失败，等于丢数据）；radix 倍数与保留类型的处理**故意不跟**参考实现
  的近似或猜测（见上）。`defines_class` 也按每个 `class_def` 自己的 type id 解析描述符，因此重复
  描述符的构造 DEX 不会再出现 `classes` 列出、`getclass` 找不到的自相矛盾（参考实现会漏）。
* **DEX 041 容器**：容器内每个逻辑 DEX 带 0x78 字节头，`droidsaw-dex` 只接受标准
  0x70 头（报 `invalid DEX header_size: 120`），所以 `getclass` 此前在 041 APK 上直接失败
  （`findrefs`/`classes` 用 rasc 自己的扫描器，不受影响，因此这个缺口一直没暴露）。
  现在交给反编译器的是一份规范化视图：头部声明 0x70、`file_size` 覆盖整个容器（段偏移本就是
  容器相对）、Adler-32 按视图重算；容器内所有成员因此都能反编译。单元测试覆盖了两个成员
  （`decompiles_a_class_from_every_logical_dex_of_a_041_container`）。
* **退化 ZIP 形态**：ZIP64 归档（APK 不能是 ZIP64）在普通 EOCD 里只有
  `0xFFFF`/`0xFFFFFFFF` 占位符，rasc 报 "bad central directory range" 并退出 1（参考实现此时
  静默返回空结果，两者都不产出错误数据）；中央目录越过 EOF、`name_len` 越界、缺 EOCD 同样干净
  报错；两个归档拼接时取末个 EOCD（与参考实现的 `rfind` 相同），数据描述符标志（本地头尺寸为 0）
  按中央目录尺寸解析。这些形态随机变异构造不出来，全部由 `src/zip.rs` 的单测固定。

## 字符串类命令的前缀解压与惰性解压（2026-09-12）

字符串类命令（`classes`、`getclass` 的定位阶段）只需要 DEX 的头部、id 表、`class_defs` 与 string 段
——在 343 MiB 基准包上实测占 **31.7%** 的字节，其余 68.3% 可以不解压。实现：

- **全量解压改为惰性**（`InflatedDex::data()` 首次访问才解压）：前缀路径完全不触碰 code 段。
- **增量流式前缀解压**（`zip::inflate_until`，走系统 zlib 735 MB/s；libdeflate 更快但只有一次性 API，
  且其 `InsufficientSpace` 时输出缓冲**不可依赖**——实测 12 组只有 3 组前缀正确）。
- **每归档一次探测**决定策略（`PrefixPolicy`）：同一 APK 的 DEX 布局同质，第一个条目测出的比例决定
  其余条目。基准包 26–65%（全部值得走前缀），另一个 243 MiB 应用包 90–95%（一律回退，只付一次约
  4 ms 的探测）。
- **正确性不靠猜**：前缀读取器（`dex::prefix`）只在三张表齐全、且每个描述符都完整解码时才给出答案，
  否则返回 `None` 回退到全量路径；`class_names`/`defines_class` 与全量路径共用同一套解码规则。
- 另外 vendored `droidsaw-dex` 的字符串池解码改为并行（rayon），把按类解析里约 9.4 ms 的池解码
  降到亚毫秒级。

实测（16 对配对交错 A/B，对照为同一棵树只回退这些改动）：`getclass` 早期类 73.5 → **61.1 ms**（−17%）、
晚期类 100.1 → **77.1 ms**（−23%）、`classes` 基准包 226.6 → **184.7 ms**（−18%）；`findrefs` **不变**
（必须读 code 段，0% 可跳，见下）。7 项命令输出逐字节一致，67 项测试与全部门禁通过。

## 解压后端实测（2026-09-12，同机同一份 456 MiB DEX 数据，输出全部逐字节校验）

| 后端 | 全量 456 MiB（56 条目） | 前缀 145 MiB（31.7%） |
|---|---:|---:|
| libdeflate（一次性；rasc 全量路径） | 539–550 ms → **830–846 MB/s** | 无流式 API（其 `InsufficientSpace` 输出不可依赖） |
| Apple 系统 zlib（流式；rasc 前缀路径） | 627 ms → 727 MB/s | 194 ms → **744 MB/s** |
| zlib-ng（流式；`WITH_OPTIM/NEON/ARMV8=ON`、`-O3`，已核对 CMakeCache） | 862 ms → **529 MB/s** | 261 ms → 555 MB/s |

结论：在 Apple Silicon 上 libdeflate 仍是全量最快的（比系统 zlib 快 ~16%、比 zlib-ng 快 ~60%）；
流式前缀用系统 zlib 最划算。zlib-ng 的 SIMD 优势集中在 **x86**、**压缩侧**与**校验和**，
而 inflate 的热路径是串行 Huffman 解码 + LZ77 拷贝，NEON 能帮的地方有限；且 macOS 的系统 zlib
本身就是 arm64 深度优化过的分支，所以 zlib-ng 在这台机器上没有位置——这也正是没把它接进 rasc
构建链（需要 CMake 构 C 库）的原因。换到 x86_64 Linux 排序可能变化，但目标机就是这台。

### 为什么前缀路径不用 libdeflate（实测否决，2026-09-12）

libdeflate 的一次性 API 在输出缓冲不足时**不发布已写出的字节数** ✗，但它的快循环会“尽量写满” ✓：
给缓冲留出**余量**、只取前 `limit` 字节，前缀就是**逐字节正确**的 ✓ —— 实测（56 个流、31.7%）：

| 余量 | 前缀正确的条目 |
|---:|---:|
| 0 字节 | 11/56 ✗ |
| 8 / 16 / 32 字节 | 50 / 54 / 55 |
| **64 字节及以上** | **56/56** ✓ |

且单字节速度确实更快：145 MiB 前缀 **168 ms → 862 MB/s** ✓（系统 zlib 194 ms / 744 MB/s ✓）。

**但它端到端更慢**（16 对配对 A/B：`classes` 基准包 +7 ms、另一个 243 MiB 应用包 +14 ms、
`getclass` 早期类 +7 ms，胜率 3/16、0/16、1/16 ✗）。原因是结构性的：一次性 API **不能“接着解”**，
而决定策略需要先读到 id 表 ✓ → 必须“探测一趟 + 重新解到需要的长度”两趟 ✗，而**id 表约占整个前缀的
80%**（基准包 needed 31.7%，其中表约 25%）→ 多解一趟（+80% 字节）远超 libdeflate 那 16% 的单字节
优势 ✗。**能续解的流式 zlib 一趟到位才是最优** ✓。

推论：只有“**打过补丁、可续解的 libdeflate**”（同事那条路 ✓）才能吃到那 ~11%（前缀 194.5 → ~174 ms，
端到端 2–3 ms ✗），代价是维护 C fork ✗；一次性 API 的各种绕法都不划算 ✓。

## 复现

需要本仓库、一份参考实现 的检出，以及装有 `androguard` 的 Python 环境：

```sh
# 一次性准备：给原实现建 Python 环境
uv venv /tmp/ref-venv --python 3.12
uv pip install --python /tmp/ref-venv/bin/python androguard lxml loguru mutf8

cargo build --release --locked

REF_ROOT=/path/to/reference \
APK=/path/to/app.apk \
RASC_BIN=target/release/rasc \
REF_PY=/tmp/ref-venv/bin/python \
python3 bench/compare_vs_reference.py
```

* `bench/compare_vs_reference.py` —— 对比 harness：校验、交错计时、结果集对比报告。
* `bench/reference_scenario.py` —— 调用原实现的 Manifest 与类索引代码路径（这两个功能只存在于它的
  GUI 中，所以驱动脚本调用的是 GUI 所用的同一批函数）。

两个脚本都是开发工具；`src/` 不会读取它们，也没有任何代码对 APK、查询或预期结果做特判。

## 附录：观察到的结果集差异

仅为记录完整性，**不属于性能结论**，上面的对比不依赖这些内容。

* `classes`：双方描述符完全一致，均为 567192 个。
* `type Gson`、`method … --fuzzy-class`：结果集完全一致。
* `field INSTANCE`：rasc 170923 行 vs 原实现 170927 行（原实现多出的 4 行见下）。
* `method onCreate`：原实现同样多出 5 行。
  这类差异有**两个互不相同的成因**，均由 `bench/row_oracle.py`（用 Androguard 的指令解码逐行仲裁）
  实测确认。两者都是参考实现的过度报告，而不是 rasc 的缺陷——**参考实现不是基准真值**：

  1. **字节级定位**（其源码已确认）：它的引用定位器对 code item 做**单字节正则扫描**
     （`STRINGIDX_OPS = re.compile(b"[\x1a\x1b]")`，type/field/method 同理），命中后直接取后两个
     字节当索引，**不检查命中位置是否在指令边界上、也不检查字节对齐**。操作数中间、switch payload
     数据里的字节只要恰好构成"opcode 字节 + 目标索引"就被报成引用。仲裁结果：`method <init>` 抽查
     100 行**全部**属于此类，`field INSTANCE` 1/1 亦然。
  2. **匹配对象是整个 `类->成员` 字符串**：rasc 的 `field`/`method` 查询匹配**成员名**（与 CLI 的
     `field <NAME>` / `method <NAME>` 文档一致；要限定在某个类里，用 `--class` 组合即可），而参考
     实现把 `Lcls;->name` 整体当匹配对象，于是查询 `m` 会命中 `Lcom/…;->P`（"com" 里的 `m`），
     查询 `com` 会命中几乎所有引用。仲裁结果：`field m` 抽查 100 行里 35 行属于此类。

  两类成因下**均未发现 rasc 漏报**：仲裁器把"真实指令引用的成员名里含查询"计为漏报，201 行抽查中
  该计数为 0。
* `string Authorization`：双方各有 1 行不同——原实现把一处非 ASCII 字符串常量截断为
  `…去除 Au`，而 rasc 输出完整的 `…去除 Authorization header`。
* `manifest`：**内容与参考实现一致**（树结构、标签、属性与取值），差异仅在格式——rasc 输出 XML 声明、
  4 空格缩进、` />` 自闭合标签；原实现省略声明、用 2 空格并写 `/>`。类型化取值的渲染现在由内联的解码库
  完成（`vendor/axmldecoder`，MIT OR Apache-2.0，见其 `PATCHES.md`），按 Androguard `format_value`
  的规则渲染，但**以数据正确为准**，有两处有意分歧：radix 倍数用精确的 2 的幂（参考实现舍入到 7 位，
  大尾数会偏到第 6 位小数），保留类型 0x13–0x1B 走 `<0x.., type 0x..>` 兜底（参考实现按整数猜，
  但这些类型在 AOSP 里是保留的）。其余规则一致：资源引用 `@7F0E0004`、框架 id `@android:01030007`、有符号整数、
  `0x%08X` 十六进制、`%f` 浮点、尺寸/分数按打包的 mantissa/radix/unit 还原（`16.000000dip`、`50.000000%`）、
  颜色 `#AARRGGBB`、布尔，以及未识别类型的 `<0x.., type 0x..>` 兜底。字符串池的扩展长度形式
  （长度 ≥ 0x80）也由同一补丁支持——本地语料里一个 289 MiB 的重打包包此前 rasc 直接 abort，
  现在输出 3581 行且内容与参考实现一致。`bench/contracts.sh` 仍会拒绝任何残留的解码器占位符。
  在 6 个语料 APK（8,949–567,192 类）与一个重打包包上，类集合、字面量查询行集合与 manifest 内容
  均与参考实现一致；剩余的 manifest 差异来自参考实现自身（它会漏掉个别元素，如基准 APK 里的
  `android.max_aspect` meta-data）。

* 含正则元字符的查询无法直接对比：原实现按正则匹配，例如某个含 `.` 的包名前缀（`.` 作通配符）
  匹配 65 行，而 rasc 为 31 行。rasc 匹配字面量，这是预期行为。类名过滤同样如此：
  `--class pkg/sub --fuzzy-class` 在原实现里得到 11 行，与 `pkg/sub` 相同，
  但把 `.` 换成非元字符（`pkgXsub`）就变成 0 行——证明那个 `.` 是正则通配符在起作用。
  作为对比，`$` 在正则里是行尾锚点，因此原实现**无法**用 `--class 'a1.a$b'` 之类的模式按内部类名过滤，
  而 rasc 的字面量匹配可以。rasc 把 `.` 统一视作包分隔符，正是为了在这些输入上给出与原实现相同的行集。
  更宽的类过滤（如 `--class a1`）会放大原实现字节级扫描的假阳性：该例中 rasc 16 行、原实现 30 行，
  且 rasc 的行集是原实现的**子集**，多出的 14 行属于上面附录里的两类过度报告。
