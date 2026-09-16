# Droid ASC: R8 Compiler Optimization as a DeCompiler Primitive
https://blackhat.com/europe/arsenal/schedule/index.html#droid-asc-r8-compiler-optimization-as-a-decompiler-primitive-54834  

When decompiling massive Android APKs, the standard procedure is to wait. We wait for tools to eat gigabytes of RAM, fully inflate the artifacts, and spend tens of minutes building heavy global indexes and cross references... All of this is just to guarantee fast code searches later, but here is the contradiction. A compiled artifact is already highly structured, modern decompilers never utilize this, they waste massive amounts of time and memory reconstructing a bloated database of code relationships over already structured data. This engineering approach defies common sense. When I can directly extract any code relationship from the APK in milliseconds, does this preprocessing still hold any value?  

Instead of forcing decompilers into heavy preprocessing, we choose to query the compiled artifact directly as a database. We built a stateless, zero-overhead engine that extracts and searches code on demand in milliseconds. In this briefing, we will explore the underlying engineering required to bypass traditional bottlenecks. We will demonstrate how to abandon full inflate by probing directly within the Deflate bitstream, building dense Huffman lookup tables to extract core metadata without touching irrelevant data blocks. Furthermore, we will explain optimization details of the R8 compiler, especially how deterministic constant relocation and instruction deduplication leave behind highly concentrated physical layouts, we weaponize this compiler behavior to execute lightning-fast cross DEX code searches. To map these raw bytecode offsets back to methods, we engineered an O(1) instruction locating primitive, achieving constant-time method resolution without building heavy mapping tables. Finally, upon hitting a target, Droid ASC extracts only the specific bytecodes and its dependencies, dynamically reconstructing a minimal and self consistent DEX entirely in memory for instant decompilation.  

We will demonstrate this architecture live against a 352MB commercial APK. Droid ASC executes global cross reference searches in 1.79 seconds and decompiles target classes in 177 milliseconds using only 141MB of RAM. By treating the artifact as a read only database and operating with zero preprocessing, we return the decompiler to its core essence. It is no longer a bloated indexing tool, but a lightning fast, on demand decompilation engine that fundamentally redefines how we analyze compiled code.  

# Benchmark
![Benchmark](./docs/benchmark_all_en.png)

https://github.com/user-attachments/assets/4c4a6813-8561-490c-a573-ef113da861b6

# Install
```bash
# from PyPI
pip install droidasc

# or from source
pip install .
```

After installation, the `droidasc` CLI command is available globally:

```
usage: droidasc [-h] {getclass,getmanifest,findrefs} ...

ASC tooling entry.

positional arguments:
  {getclass,getmanifest,findrefs}
    getclass            Locate the target class in APK, extract one DEX in memory, then decompile.
    getmanifest         Decode AndroidManifest.xml from APK and print it as XML.
    findrefs            Find code references for string/type/method/field across all DEX entries in APK.

options:
  -h, --help            show this help message and exit

examples:
  droidasc app.apk --gui
  droidasc getclass app.apk Lcom/poc/Main; -o Main.java
  droidasc getclass app.apk com.poc.Main --threads 16
  droidasc getmanifest app.apk -o AndroidManifest.xml
  droidasc findrefs app.apk string token -o string_refs.txt
  droidasc findrefs app.apk type com.poc.Main
  droidasc findrefs app.apk method onCreate --class com.poc.Main
  droidasc findrefs app.apk method notify --class MainActivity --fuzzy-class -o method_refs.txt
  droidasc findrefs app.apk field apiKey -o field_refs.txt
```

You can also use `python main.py` as before — it delegates to the same entry point.

## macOS GUI setup

The GUI uses `tkinter`, including Python's native `_tkinter` module and Tcl/Tk.
These are interpreter dependencies, not pip packages; installing
`requirements.txt` does not add Tk to a Python build that lacks it.

Check the **same interpreter** used to run ASC:

```sh
python -m tkinter
```

This should open a small test window. If it reports `No module named '_tkinter'`
or `tkinter`, use a Python installation with Tk support. For example, with
[Homebrew Python 3.12](https://formulae.brew.sh/formula/python@3.12):

```sh
brew install python@3.12 python-tk@3.12
"$(brew --prefix python@3.12)/bin/python3.12" -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m tkinter
.venv/bin/python -m droidasc test.apk --gui
```

Alternatively, the [python.org macOS installer](https://www.python.org/download/mac/tcltk/)
includes Tcl/Tk; create a virtual environment using that installation.
An existing virtual environment made with pyenv continues to use its original
Python. Installing Homebrew's Tk package does **not** retrofit that pyenv Python;
rebuild it with Tcl/Tk support or create a new environment with a Tk-enabled
interpreter as above.

Use `--gui` to launch the GUI. On macOS, the GUI runs in the foreground;
the terminal stays attached until the window closes, and startup failures are
printed with a nonzero exit status. Add `--debug` to include a traceback.
Missing Tk support is checked before any background launch on other platforms.
