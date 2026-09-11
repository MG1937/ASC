# rasc 与原 Python ASC 性能对比

在一个生产 APK 上按真实使用场景实测：四种模式的引用搜索、类反编译（早期/晚期 DEX）、
错误路径、二进制 Manifest 解码，以及完整类索引。

**结论：11 个场景几何平均加速 5.5×**，其中引用搜索（主要用途）快 6–9×。
有一个场景更慢：对定义在首个 DEX 中的类执行 `getclass`（0.6×），原因见[分析](#分析)。

## 环境

| | |
|---|---|
| 机器 | Apple M3 Pro，12 逻辑核，36 GiB 内存，macOS 26.5.1（arm64） |
| rasc | `rustc 1.98.0`；release 配置 `lto="fat"`、`codegen-units=1`、`panic="abort"`、`strip`；二进制 2676 KB，运行时不依赖 Python/JVM |
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
| `findrefs string Authorization`（53 行） | **132 ms** | 822 ms | **6.2×** |
| `findrefs string com.example.sdk` | **116 ms** | 1081 ms | **9.3×** |
| `findrefs type Gson`（2924 行） | **167 ms** | 1309 ms | **7.9×** |
| `findrefs method onCreate`（7096 行） | **195 ms** | 1661 ms | **8.5×** |
| `findrefs method onCreate --class com.example --fuzzy-class`（2393 行） | **177 ms** | 1581 ms | **9.0×** |
| `findrefs field INSTANCE`（170834 行） | **203 ms** | 1854 ms | **9.1×** |
| `getclass` 早期类（`classes.dex`） | 166 ms | **99 ms** | **0.6×** |
| `getclass` 晚期类（`classes56.dex`） | **222 ms** | 248 ms | **1.1×** |
| `getclass` 不存在的类（错误路径） | **95 ms** | 239 ms | **2.5×** |
| `manifest`（二进制 AXML → XML，4075 行） | **12 ms** | 260 ms | **20.8×** |
| `classes`（完整索引，567192 个类） | **201 ms** | 2307 ms | **11.5×** |
| **几何平均** | | | **5.5×** |

多次完整运行的波动范围：5.4–5.6×。

本项目自身的主指标（固定 `Authorization` 查询、取 3 次中位数）测得 rasc 为 **120–130 ms**；
上表的数字来自交错配对测量，是更可靠的对比。

## 分析

rasc 搜索时间的实际构成（用 `--debug` 采集全部 56 个 DEX 的分阶段耗时）：

| 阶段 | 占墙钟比例 |
|---|---:|
| ZIP 解压（libdeflate，按已知大小整块解压） | ~60% |
| 指令扫描（严格按 opcode 宽度解码） | ~25% |
| 字符串表目标匹配 | ~7% |
| 串行工作 + 负载不均 | 其余 |

* **搜索（6–9×）**：rasc 用 libdeflate 把每个 DEX 一次性解压到精确大小的缓冲区，再用专用的
  借用缓冲区读取器扫描；原实现则在 worker 进程内用 zlib 逐 DEX 解压，并把整个 DEX 重新解析成
  Python 对象后再定位引用。由于解压占大头，宽查询对 rasc 的额外开销很小——所以结果越多
  优势越大（宽查询 9.3×，输出 17 万行时 9.1×）。
* **类索引（11.5×）与 Manifest（20.8×）**：这两条正是原实现最慢的路径（建索要要对每个 DEX
  做完整 `tinydex` 解析；Manifest 走 Androguard AXML）。rasc 只遍历 `class_defs`，Manifest 由
  原生 Rust AXML 解码器处理。
* **`getclass`（0.6–1.1×）**：唯一的落后项。原实现会抽取目标类、重建一个只含该类的迷你 DEX，
  再走它自己的反编译器，对单个小类非常快（约 100 ms），输出也相应更简（此处约 29 行）。
  rasc 解析完整 DEX 并运行原生 CFG/SSA 分析，输出更完整的 Java 风格源码（约 32 行），
  因此为同一请求做了更多工作。当目标类位于晚期 DEX 时两者基本持平：原实现必须先解压并扫描
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
* `field INSTANCE`：170830 vs 170834 行（4 行为原实现独有）。
* `method onCreate`：7091 vs 7096 行（5 行为原实现独有）。
* `string Authorization`：双方各有 1 行不同——原实现把一处非 ASCII 字符串常量截断为
  `…去除 Au`，而 rasc 输出完整的 `…去除 Authorization header`。
* 含正则元字符的查询无法直接对比：原实现按正则匹配，例如 `com.example.sdk`（`.` 作通配符）
  匹配 65 行，而 rasc 为 31 行。rasc 匹配字面量，这是预期行为。
