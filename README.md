# Droid ASC: R8 Compiler Optimization as a DeCompiler Primitive
https://blackhat.com/europe/arsenal/schedule/index.html#droid-asc-r8-compiler-optimization-as-a-decompiler-primitive-54834  

When decompiling massive Android APKs, the standard procedure is to wait. We wait for tools to eat gigabytes of RAM, fully inflate the artifacts, and spend tens of minutes building heavy global indexes and cross references... All of this is just to guarantee fast code searches later, but here is the contradiction. A compiled artifact is already highly structured, modern decompilers never utilize this, they waste massive amounts of time and memory reconstructing a bloated database of code relationships over already structured data. This engineering approach defies common sense. When I can directly extract any code relationship from the APK in milliseconds, does this preprocessing still hold any value?  

Instead of forcing decompilers into heavy preprocessing, we choose to query the compiled artifact directly as a database. We built a stateless, zero-overhead engine that extracts and searches code on demand in milliseconds. In this briefing, we will explore the underlying engineering required to bypass traditional bottlenecks. We will demonstrate how to abandon full inflate by probing directly within the Deflate bitstream, building dense Huffman lookup tables to extract core metadata without touching irrelevant data blocks. Furthermore, we will explain optimization details of the R8 compiler, especially how deterministic constant relocation and instruction deduplication leave behind highly concentrated physical layouts, we weaponize this compiler behavior to execute lightning-fast cross DEX code searches. To map these raw bytecode offsets back to methods, we engineered an O(1) instruction locating primitive, achieving constant-time method resolution without building heavy mapping tables. Finally, upon hitting a target, Droid ASC extracts only the specific bytecodes and its dependencies, dynamically reconstructing a minimal and self consistent DEX entirely in memory for instant decompilation.  

We will demonstrate this architecture live against a 352MB commercial APK. Droid ASC executes global cross reference searches in 1.79 seconds and decompiles target classes in 177 milliseconds using only 141MB of RAM. By treating the artifact as a read only database and operating with zero preprocessing, we return the decompiler to its core essence. It is no longer a bloated indexing tool, but a lightning fast, on demand decompilation engine that fundamentally redefines how we analyze compiled code.  

# Benchmark
![Benchmark](./docs/benchmark_all_en.png)

https://github.com/user-attachments/assets/4c4a6813-8561-490c-a573-ef113da861b6

# Machine-readable output

Emit JSON from the same `getclass` / `findrefs` commands agents already know:

```sh
python main.py getclass app.apk com.poc.Main --json
python main.py findrefs app.apk string token --json
```

Success envelopes look like `{"ok": true, "command": "...", ...}`. Failures look like `{"ok": false, "error": "..."}` on stdout with exit code 1. Debug logs stay on stderr when `--json` is set.

# MCP (stdio)

Serve the same operations over MCP for Cursor and other clients:

```sh
python main.py mcp --apk /path/to/app.apk
```

Cursor `mcpServers` example:

```json
{
  "mcpServers": {
    "droid-asc": {
      "command": "python",
      "args": ["/absolute/path/to/ASC/main.py", "mcp", "--apk", "/absolute/path/to/app.apk"]
    }
  }
}
```

Tools:

- `get_class` with `class_name` (and optional `apk_path`, `threads`)
- `find_refs` with `find_type` (`string` | `type` | `method` | `field`), optional `value` / `class_name` / `fuzzy_class` / `apk_path` / `threads`

