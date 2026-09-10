# Test commands

Use Python 3.11+ and install `requirements.txt` in a virtual environment.

```sh
python tests/run_tests.py --require-decompiler
python tests/benchmark_startup.py --samples 9
python tests/benchmark_reference.py --samples 9
```

The regression runner fails if Androguard is missing or any test is skipped in
strict mode. It covers index zero, empty/fallback instruction maps, string layout,
zeroed reconstructed DEX signatures/checksums, dummy imports, the MUTF-8 shim,
CLI stored/Deflate multidex operation, GUI data-store reuse, and reference searches
without site packages. It does not open GUI windows.

The synthetic startup gate measures `getclass --debug` in nine fresh interpreters.
Its median budgets are 100 ms internal time and 250 ms wall time on Linux CI.

`fixtures/reference-workload.zip` is the supplied archive, unchanged. Its SHA-256
is recorded in `fixtures/reference-baseline.json`. The reference runner extracts
its three files into a temporary directory and executes the original `test.py`
and `test_findrefs.py` with this checkout's core on `PYTHONPATH`.

- `test.py` must output `ClockFaceView` source. The median of nine script-reported
  times must be at most **0.0880 s**. Every measurement and the maximum are retained.
- Every `test_findrefs.py` run must match all **16 count metrics** exactly and
  emit all **20 timing metrics**. Median timing differences from the supplied
  baseline are reported; these individual times are not hard performance budgets.
- Both benchmark commands fail on process errors, missing output, or timeouts.

These are fresh interpreter measurements with warm filesystem caches, not cold
storage measurements or a guarantee on arbitrary hardware. CI runs both Python
3.11 and 3.12, including real-DEX checks. Reports and stdout/stderr are uploaded
from `artifacts/startup/` and `artifacts/reference/` even when a gate fails.
