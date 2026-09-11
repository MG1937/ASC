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
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

## 性能

见 [PERFORMANCE.md](PERFORMANCE.md)：在 343 MiB 生产 APK 的 11 个真实场景上，相对原
Python ASC 的几何平均加速为 5.5×；可用 `bench/compare_vs_reference.py` 复现。
