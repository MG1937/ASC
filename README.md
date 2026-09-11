# rasc

the reference implementation 的原生 Rust 实现。二进制运行时不依赖 Python、Androguard、JADX 或 JVM。

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
bash bench/contracts.sh app.apk target/release/rasc

# 需要原 Python ASC 检出与其环境：对任意 APK 做与原实现的 parity 对比
# （类集合、字面量查询行集合必须一致；manifest 比较内容而非格式）
RASC_BIN=target/release/rasc REF_ROOT=/path/to/reference REF_PY=/path/to/python \
  python3 bench/corpus_parity.py app.apk [more.apk ...]

# 健壮性：确定性损坏一个 APK（截断/翻转/DEX 头/中央目录/manifest）并要求
# rasc 干净报错而不是 panic（退出码不得为崩溃值）
RASC_BIN=target/release/rasc python3 bench/mutation_check.py app.apk 200
```

## 性能

见 [PERFORMANCE.md](PERFORMANCE.md)：在 343 MiB 生产 APK 的 11 个真实场景上，相对原
Python ASC 的几何平均加速为 **5.7–5.8×**；可用 `bench/compare_vs_reference.py` 复现（三项
仓库内检查见下：CLI 契约、与原实现的逐 APK parity、畸形输入健壮性）。
