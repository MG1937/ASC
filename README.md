# Droid ASC: R8 Compiler Optimization as a DeCompiler Primitive
https://blackhat.com/europe/arsenal/schedule/index.html#droid-asc-r8-compiler-optimization-as-a-decompiler-primitive-54834  

When decompiling massive Android APKs, the standard procedure is to wait. We wait for tools to eat gigabytes of RAM, fully inflate the artifacts, and spend tens of minutes building heavy global indexes and cross references... All of this is just to guarantee fast code searches later, but here is the contradiction. A compiled artifact is already highly structured, modern decompilers never utilize this, they waste massive amounts of time and memory reconstructing a bloated database of code relationships over already structured data. This engineering approach defies common sense. When I can directly extract any code relationship from the APK in milliseconds, does this preprocessing still hold any value?  

Instead of forcing decompilers into heavy preprocessing, we choose to query the compiled artifact directly as a database. We built a stateless, zero-overhead engine that extracts and searches code on demand in milliseconds. In this briefing, we will explore the underlying engineering required to bypass traditional bottlenecks. We will demonstrate how to abandon full inflate by probing directly within the Deflate bitstream, building dense Huffman lookup tables to extract core metadata without touching irrelevant data blocks. Furthermore, we will explain optimization details of the R8 compiler, especially how deterministic constant relocation and instruction deduplication leave behind highly concentrated physical layouts, we weaponize this compiler behavior to execute lightning-fast cross DEX code searches. To map these raw bytecode offsets back to methods, we engineered an O(1) instruction locating primitive, achieving constant-time method resolution without building heavy mapping tables. Finally, upon hitting a target, Droid ASC extracts only the specific bytecodes and its dependencies, dynamically reconstructing a minimal and self consistent DEX entirely in memory for instant decompilation.  

We will demonstrate this architecture live against a 352MB commercial APK. Droid ASC executes global cross reference searches in 1.79 seconds and decompiles target classes in 177 milliseconds using only 141MB of RAM. By treating the artifact as a read only database and operating with zero preprocessing, we return the decompiler to its core essence. It is no longer a bloated indexing tool, but a lightning fast, on demand decompilation engine that fundamentally redefines how we analyze compiled code.  

# Benchmark
![Benchmark](./docs/benchmark_all_en.png)
[ASC_Benchmark.mp4](https://github.com/MG1937/ASC/blob/main/docs/ASC_Benchmark.mp4)


# Running the current implementation

Requires Python 3.11 or newer (the instruction verifier uses atomic regex groups).
Reference searches use only the Python standard library. Class decompilation and
Manifest viewing require the tested Androguard version:

```sh
python -m venv .venv
# Windows: .venv\Scripts\activate
. .venv/bin/activate
python -m pip install -r requirements.txt
python main.py findrefs app.apk string token
python main.py getclass app.apk com.example.Main -o Main.java
python main.py app.apk --gui
```

The GUI also needs Tkinter, which some Linux distributions package separately
(e.g. `python3-tk` on Debian/Ubuntu).

In this checkout, compressed DEX entries are inflated with zlib before lookup;
class lookup can cancel other entries after a hit. Reference searches build
in-memory lookup tables on demand, including a 16-byte instruction bucket map.
The bucket lookup is constant time, but building the map and validating instruction
boundaries still costs work. The GUI loads DEX buffers and maintains class/source
caches. Decompilation retains the dummy-module import shortcuts and pure-Python
MUTF-8 shim; the GUI restores its module snapshot after decompilation. The benchmark above is the author's reported result, not a guarantee for
all APKs or an automated benchmark reproduced by the regression suite.

# Tests

```sh
python tests/run_tests.py
```

Tests generate a small DEX and temporary stored/Deflate multidex APKs, so no
commercial APK is required. With `requirements.txt` installed, the suite also
checks CLI decompilation, the dummy-module fast path, and the GUI data store without
opening a window. Without Androguard, those integration tests are explicitly
skipped; the reference and checksum regressions still run.
