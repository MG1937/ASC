# rasc 与原 Python ASC 性能对比

在一个生产 APK 上按真实使用场景实测：四种模式的引用搜索、类反编译（早期/晚期 DEX）、
错误路径、二进制 Manifest 解码，以及完整类索引。

**结论：11 个场景几何平均加速 5.7–5.8×**，其中引用搜索（主要用途）快 7–10×。
有一个场景更慢：对定义在首个 DEX 中的类执行 `getclass`（0.6×），原因见[分析](#分析)。

> **注（2026-09-12）**：下表是在早前版本上测得的，当时 rasc 自身主指标为 120–130 ms、二进制
> 2676 KB。此后 rasc 又做了两轮优化（查表化指令扫描 + 操作数预筛），自身主指标降到
> **110 ms**、二进制 **1704 KB**；Python ASC 侧数字未变，因此实际加速比只会高于表中数值。
> 表中 rasc 的时间数字未重新测过，用于复现的脚本仍是 `bench/compare_vs_reference.py`。

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
| `findrefs string Authorization`（53 行） | **115 ms** | 821 ms | **7.1×** |
| `findrefs string com.example.sdk`（31 行） | **105 ms** | 1084 ms | **10.3×** |
| `findrefs type Gson`（2924 行） | **150 ms** | 1272 ms | **8.5×** |
| `findrefs method onCreate`（7091 行） | **170 ms** | 1590 ms | **9.4×** |
| `findrefs method onCreate --class com.example --fuzzy-class`（2393 行） | **157 ms** | 1632 ms | **10.4×** |
| `findrefs field INSTANCE`（170830 行） | **190 ms** | 1923 ms | **10.1×** |
| `getclass` 早期类（`classes.dex`） | 176 ms | **103 ms** | **0.6×** |
| `getclass` 晚期类（`classes56.dex`） | **244 ms** | 264 ms | **1.1×** |
| `getclass` 不存在的类（错误路径） | **98 ms** | 253 ms | **2.6×** |
| `manifest`（二进制 AXML → XML，4075 行） | **13 ms** | 277 ms | **21.0×** |
| `classes`（完整索引，567192 个类） | **206 ms** | 2386 ms | **11.6×** |
| **几何平均** | | | **5.8×** |

上表用本仓库的复现脚本实测（2026-09-12，本项目自身主指标 110 ms 的构建；表格中的行数取 rasc 一侧）。
三次完整运行的几何平均为 5.8× / 5.7× / 5.8×。
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
* **`getclass`（0.6–1.1×）**：唯一的落后项。原实现会抽取目标类、重建一个只含该类的迷你 DEX，
  再走它自己的反编译器，对单个小类非常快（约 100 ms），输出也相应更简（此处约 29 行）。
  rasc 解析完整 DEX 并运行原生 CFG/SSA 分析，输出更完整的 Java 风格源码（约 32 行），
  因此为同一请求做了更多工作。实测拆解（`--debug`，单线程，目标类在 `classes.dex`）：
  启动约 10 ms + 定位 72 ms（**早退生效**：55 个候选条目只解压了 9 个）+ **反编译约 124 ms（占 60%）**。
  反编译成本来自 `droidsaw-dex` 的全量 DEX 解析 + CFG/SSA；该 crate 的
  `DexFile::parse(data, budget)` 第二个参数是资源预算而不是类过滤，无法只解析目标类，
  所以这部分只能等依赖改进（8 线程下早期类整体约 165–175 ms）。当目标类位于晚期 DEX 时两者基本持平：原实现必须先解压并扫描
  之前所有 DEX（248 ms），而 rasc 的 DEX 扫描是并行的（222 ms）。错误路径——扫描整个归档后
  得出类不存在的结论——rasc 快 2.5×。
* **输出顺序**：rasc 输出确定且有序；原实现的 CLI/编辑器行顺序会随每次运行的 DEX 完成顺序变化。

## 复现

需要本仓库、一份原 Python ASC 的检出，以及装有 `androguard` 的 Python 环境：

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
  这类差异的成因已在原实现源码中确认：它的引用定位器是对 code item 做**单字节正则扫描**
  （`STRINGIDX_OPS = re.compile(b"[\x1a\x1b]")`，type/field/method 同理），命中后直接取后两个
  字节当索引，**不检查命中位置是否在指令边界上、也不检查字节对齐**。因此操作数中间、switch
  payload 数据里的字节只要恰好构成"opcode 字节 + 目标索引"，就会被报成一条引用。rasc 则严格按
  opcode 宽度逐条解码指令，只统计真正的指令。这些行属于原实现的假阳性，不是 rasc 的漏报；
  按项目决定不再为此调整 rasc 的行为。
* `string Authorization`：双方各有 1 行不同——原实现把一处非 ASCII 字符串常量截断为
  `…去除 Au`，而 rasc 输出完整的 `…去除 Authorization header`。
* `manifest`：**内容与参考实现一致**（树结构、标签、属性与取值），差异仅在格式——rasc 输出 XML 声明、
  4 空格缩进、` />` 自闭合标签；原实现省略声明、用 2 空格并写 `/>`。类型化取值的渲染现在由内联的解码库
  完成（`vendor/axmldecoder`，MIT OR Apache-2.0，见其 `PATCHES.md`），规则逐条对齐参考实现
  （Androguard `format_value`）：资源引用 `@7F0E0004`、框架 id `@android:01030007`、有符号整数、
  `0x%08X` 十六进制、`%f` 浮点、尺寸/分数按打包的 mantissa/radix/unit 还原（`16.000000dip`、`50.000000%`）、
  颜色 `#AARRGGBB`、布尔，以及未识别类型的 `<0x.., type 0x..>` 兜底。字符串池的扩展长度形式
  （长度 ≥ 0x80）也由同一补丁支持——本地语料里那个 289 MiB 的某个应用重打包包此前 rasc 直接 abort，
  现在输出 3581 行且内容与参考实现一致。`bench/contracts.sh` 仍会拒绝任何残留的解码器占位符。
  在 6 个语料 APK（8,949–567,192 类）与重打包某个应用包上，类集合、字面量查询行集合与 manifest 内容
  均与参考实现一致；剩余的 manifest 差异来自参考实现自身（它会漏掉个别元素，如基准 APK 里的
  `android.max_aspect` meta-data）。

* 含正则元字符的查询无法直接对比：原实现按正则匹配，例如 `com.example.sdk`（`.` 作通配符）
  匹配 65 行，而 rasc 为 31 行。rasc 匹配字面量，这是预期行为。类名过滤同样如此：
  `--class com.example/compass --fuzzy-class` 在原实现里得到 11 行，与 `com/example/compass` 相同，
  但把 `.` 换成非元字符（`comXexample/compass`）就变成 0 行——证明那个 `.` 是正则通配符在起作用。
  作为对比，`$` 在正则里是行尾锚点，因此原实现**无法**用 `--class 'a1.a$b'` 之类的模式按内部类名过滤，
  而 rasc 的字面量匹配可以。rasc 把 `.` 统一视作包分隔符，正是为了在这些输入上给出与原实现相同的行集。
  更宽的类过滤（如 `--class a1`）会放大原实现字节级扫描的假阳性：该例中 rasc 16 行、原实现 30 行，
  且 rasc 的行集是原实现的**子集**，多出的 14 行都是原实现把操作数中间或 payload 里的字节当成引用。
