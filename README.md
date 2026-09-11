# rasc

[中文说明](README.zh-CN.md)

## What rasc is

rasc is a Rust re-implementation of ASC: an APK/DEX analysis tool **built as an experiment,
but usable in practice**. It explores native performance and the ability of coding agents
to refactor code and optimize performance toward clearly defined goals.

Most implementation and iteration are carried out by agents using ASC as a reference,
with occasional human intervention. It is both a working tool and an exercise in
agent-driven development, not a claim of fully autonomous software generation.

## rasc is CLI-only

For testing purposes, rasc stays simple: CLI only, optimized for agent workflows, with
no GUI.

## Performance and trade-offs

Across 11 test scenarios on a 343 MiB APK, rasc achieves a geometric mean speedup of
**8.0×** over ASC. Detailed measurements are included below.

That speed is not free. Optimization has led some of rasc's designs away from ASC;
it is no longer a line-by-line translation. It favors throughput and is willing to spend
more memory for speed: multithreaded reference searches, for example, have a higher peak
memory footprint than ASC. This is a trade-off, not a claim of lower resource use everywhere.

The speedup should first be understood in the context of moving from Python to a native
Rust implementation—not as proof that Rust beats other languages or that agents beat
human developers. Algorithms, parallelism, and memory strategies also affect the result.
An implementation in Zig or C++ might go further.

<details>
<summary>Benchmark results, memory usage, and reproduction</summary>

### Test conditions

- Apple M3 Pro (6 performance + 6 efficiency cores), 36 GiB RAM, macOS 26.5.1.
- ASC: CPython 3.12.14, Androguard 4.1.4. rasc: Rust release build with FatLTO.
- Input: 56 root DEXes, 567,192 classes. Both implementations use 8 workers.
- End-to-end wall time: fresh process per sample, randomized execution order, median of
  at least 3 runs. Output is discarded, but formatting and writing are included.
- Exit status and output are checked before timing; result sets are compared where applicable.

### Execution time

| Scenario | rasc | ASC | Speedup |
|---|---:|---:|---:|
| `findrefs string Authorization` | 117 ms | 830 ms | 7.1× |
| `findrefs string okhttp` | 121 ms | 880 ms | 7.3× |
| `findrefs type Gson` | 141 ms | 1,292 ms | 9.1× |
| `findrefs method onCreate` | 178 ms | 1,620 ms | 9.1× |
| `findrefs method onCreate --class androidx --fuzzy-class` | 140 ms | 1,604 ms | 11.5× |
| `findrefs field INSTANCE` | 191 ms | 1,978 ms | 10.4× |
| `getclass` early class (`classes.dex`) | 45 ms | 124 ms | 2.7× |
| `getclass` late class (`classes56.dex`) | 77 ms | 259 ms | 3.4× |
| `getclass` missing class | 62 ms | 245 ms | 4.0× |
| `manifest` | 13 ms | 268 ms | 20.3× |
| `classes` | 98 ms | 2,318 ms | 23.7× |
| **Geometric mean** | | | **8.0×** |

ASC has no CLI command for `manifest` or `classes`; the benchmark calls the underlying
functions used by its GUI. Search semantics also differ: rasc uses literal queries and
instruction-boundary scanning, so arbitrary queries need not produce identical results.

### Memory

Peak RSS on the same APK with 8 workers:

| Scenario | rasc | ASC |
|---|---:|---:|
| `findrefs string Authorization` | 343 MiB | 220 MiB |
| `findrefs field INSTANCE` | 364 MiB | 239 MiB |
| `getclass` early / late | 105 / 151 MiB | 208 / 425 MiB |
| `manifest` | 8 MiB | 16 MiB |
| `classes` | 233 MiB | Not measured |

rasc uses more memory for parallel reference searches, but less for class decompilation
and manifest decoding in these measurements. Reducing workers trades speed for memory:
a separate `findrefs field INSTANCE` run with `--threads 2` used 256 MiB and remained
3.3× faster than ASC.

### Reproduce

Build rasc with `cargo build --release`. Set `RASC_BIN`, `APK`, `REF_ROOT`, and `REF_PY`
to absolute paths; `REF_PY` must point to a Python environment with ASC's dependencies.

```sh
APK=/path/to/app.apk RASC_BIN=/path/to/rasc/target/release/rasc \
  REF_ROOT=/path/to/ASC REF_PY=/path/to/venv/bin/python \
  THREADS=8 python3 bench/compare_vs_reference.py
```

</details>

## Build

```sh
cargo build --release
./target/release/rasc --help
```

## Usage

```sh
rasc getclass app.apk com.example.Main                 # one class -> Java-like source
rasc getclass --threads 16 -o Main.java app.apk 'Lcom/example/Main;'
rasc findrefs app.apk string Authorization             # references across every root DEX
rasc findrefs app.apk method onCreate --class com.example.Main
rasc findrefs app.apk field INSTANCE --class example --fuzzy-class
rasc classes app.apk                                   # class index
rasc manifest app.apk                                  # binary AndroidManifest.xml -> XML
```

See `rasc --help` for more usage information, or `rasc <command> --help` for command-specific options.
