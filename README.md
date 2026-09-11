# rasc

原生 Rust 实现的 APK/DEX 分析 CLI。二进制运行时不依赖 Python、Androguard、JADX 或 JVM。

## 构建

```sh
cargo build --release
```

## 命令行

```sh
# 定位并反编译一个类
rasc getclass app.apk com.example.Main
rasc getclass --threads 16 -o Main.java app.apk 'Lcom/example/Main;'

# 在所有根 DEX 中查找指令引用
rasc findrefs app.apk string Authorization
rasc findrefs app.apk type com.example.Model
rasc findrefs app.apk method onCreate --class com.example.Main
rasc findrefs app.apk field INSTANCE --class example --fuzzy-class

# 列出或过滤已定义的类
rasc classes app.apk
rasc classes --filter com.example --threads 16 app.apk

# 解码二进制 AndroidManifest.xml
rasc manifest app.apk
rasc manifest -o AndroidManifest.xml app.apk
```

`findrefs` 把查询文本当作字面子串做模糊匹配，支持 DEX MUTF-8，并行扫描多 DEX APK，
并输出确定性的引用行。DEX 041 逻辑容器会被归一化为可独立搜索的视图；`getclass` 既接受
Java 类名也接受 Dalvik 类名，并通过原生 Rust 反编译器输出 Java 风格源码。

## 验证

```sh
# 含 tests/self_contained.rs：生产代码不得派生进程、依赖清单不得出现 Python/JVM 绑定
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# 需要一份真实 APK：检查 CLI 契约（退出码与输出、-o 文件与 stdout 一致、
# --debug 只写 stderr、缺失类走错误路径）
bash bench/contracts.sh app.apk target/release/rasc   # 含点号/斜杠描述符一致性门禁

# 需要原 Python ASC 检出与其环境：对任意 APK 做与原实现的 parity 对比
# （类集合、字面量查询行集合必须一致；manifest 比较内容而非格式）
RASC_BIN=target/release/rasc REF_ROOT=/path/to/reference REF_PY=/path/to/python \
  python3.10+ bench/corpus_parity.py app.apk [more.apk ...]

# 健壮性：确定性损坏一个 APK（截断/翻转/DEX 头/中央目录/manifest）并要求
# rasc 干净报错而不是 panic（退出码不得为崩溃值）
RASC_BIN=target/release/rasc python3 bench/mutation_check.py app.apk 200

# 退化 ZIP 形态（随机变异构造不出来的那些）由单元测试固定：ZIP64 占位符、
# 中央目录越界、name_len 越界、缺 EOCD 都必须干净报错；拼接归档取末个 EOCD、
# 数据描述符标志按中央目录尺寸解析

# 行级仲裁：用 Androguard 的指令解码逐行判断参考实现多出的行属于哪种过度报告
# （字节级假阳性 / 它把整个 class->member 当匹配对象），并把"真实指令引用的成员名
# 命中"计为 rasc 漏报 —— 参考实现不是基准真值，这个脚本才是仲裁者
RASC_BIN=target/release/rasc REF_ROOT=/path/to/reference REF_PY=/path/to/python \
  python3 bench/row_oracle.py app.apk "field INSTANCE" 100

# 反编译等价性：vendored droidsaw-dex 补丁（只解析目标类）必须与未打补丁的
# 二进制输出逐字节一致；按 DEX 分层抽样
RASC_BIN=target/release/rasc SAMPLE=1200 \
  python3 bench/decompile_equivalence.py /path/to/unpatched-rasc app.apk
```

## 架构

| 模块 | 职责 |
|---|---|
| `src/main.rs` | CLI 入口：分发子命令、统一输出（`-o` 与 stdout 同一份字节，`--debug` 只写 stderr） |
| `src/cli.rs` | 参数定义与校验（clap） |
| `src/query.rs` | 查询模型与类名归一化，`cli` 与各分析层共用 |
| `src/zip.rs` | 手写中央目录解析与已知大小解压（libdeflate）；重名条目与退化形态在此处理 |
| `src/dex/` | DEX 读取与引用扫描（`mod`）、opcode 宽度/种类表（`opcodes`）、操作数预筛（`filter`）、MUTF-8（`mutf8`）、041 容器（`container`） |
| `src/apk.rs` | 编排：条目调度（rayon，支持命中即早退）与 `findrefs`/`classes`/`getclass` 入口 |
| `src/manifest.rs` | 二进制 AXML → XML |
| `src/bytes.rs` | 有界小端读取 |

依赖方向只向下：`main -> {cli, apk, manifest, query}`、`cli -> query`、`apk -> {query, dex, zip}`、
`dex -> query`。引用搜索不经过反编译依赖，只有 `getclass` 用 `droidsaw-dex`。

`vendor/` 下是两个带补丁的第三方 crate，各带 `PATCHES.md`：`axmldecoder`（字符串池扩展长度、
CDATA 崩溃）与 `droidsaw-dex`（只解析目标类、跳过只有 emit 消费的工作）。两者的行为都由仓库内
测试与 bench 脚本守着；上游若接受这些改动（`vendor/droidsaw-dex/UPSTREAM.md` 是现成的请求文本），
vendor 目录即可删除。

## 性能

见 [PERFORMANCE.md](PERFORMANCE.md)：在 343 MiB 生产 APK 的 11 个真实场景上，相对原
参考实现的几何平均加速为 **5.7–5.8×**；可用 `bench/compare_vs_reference.py` 复现（三项
仓库内检查见下：CLI 契约、与原实现的逐 APK parity、畸形输入健壮性）。
