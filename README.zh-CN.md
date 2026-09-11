# rasc

[English](README.md)（主文档）

## rasc 是什么

rasc 是 ASC 的 Rust 重构实现，一个**出于测试目的、但确实可用**的 APK/DEX 分析工具。
它用来探索原生实现的性能表现，以及 Agent 在重构代码、围绕明确目标优化性能时的能力。

大部分实现与迭代由 Agent 参照 ASC 完成，少部分情况由人介入。因此，它既是一个可用的工具，
也是一次 Agent Coding 实践，而不是完全无人参与的自动生成成果。

## rasc CLI-only

出于测试目的，rasc 以简为主，只提供 CLI，围绕 Agent 使用场景优化，不做 GUI。

## 性能与取舍

在一份 343 MiB APK 的 11 个测试场景中，rasc 相对 ASC 的几何平均加速比为 **8.0×**。
测量方法与详细结果见[英文版「性能与取舍」](README.md#performance-and-trade-offs)中的折叠区。

这个结果并非没有代价。随着优化推进，rasc 的部分设计已经与 ASC 不同，不再是逐行翻译。
它更偏向吞吐性能，愿意用更多内存换取速度；例如，多线程引用搜索的峰值内存高于 ASC。
这是一种取舍，不代表每个场景都更省资源。

理解这一速度优势时，首先应考虑从 Python 转向 Rust 原生实现的差别，而不是把它当作 Rust
优于其他语言、或 Agent 优于人工开发的证明。实际结果也受算法、并行方式和内存策略影响。
换用 Zig、C++ 等语言，性能也可能进一步提升。

## 构建

```sh
cargo build --release
./target/release/rasc --help
```

## 命令行

```sh
rasc getclass app.apk com.example.Main                 # 单个类 → Java 风格源码
rasc getclass --threads 16 -o Main.java app.apk 'Lcom/example/Main;'
rasc findrefs app.apk string Authorization             # 在所有根 DEX 中查找引用
rasc findrefs app.apk method onCreate --class com.example.Main
rasc findrefs app.apk field INSTANCE --class example --fuzzy-class
rasc classes app.apk                                   # 类索引
rasc manifest app.apk                                  # 二进制 AndroidManifest.xml → XML
```

更多用法见 `rasc --help`，具体命令的参数可通过 `rasc <命令> --help` 查看。
