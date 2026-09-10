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

## Zero-regression comparison

```sh
python tests/run_tests.py --require-decompiler --suite unit
python tests/run_tests.py --require-decompiler --suite integration
python tests/benchmark_compare.py --baseline /path/to/base-checkout --samples 31
```

CI checks out the PR's exact base SHA. Direct pushes to `dev-0.1.0` compare
against the pre-push SHA, so the candidate cannot become its own baseline.
Other push/manual builds compare against `MG1937/ASC:dev-0.1.0`. A missing
baseline fails the job. The same interpreter,
runner, DEX, original scripts and query arguments exercise both revisions. On
Linux the comparison and its child processes use one fixed available CPU; both
sides use `PYTHONHASHSEED=0`. These controls are recorded in the report.

The comparison covers 20 module timings from `test_findrefs.py`, core decompilation
from `test.py`, and real-APK CLI `getclass` / `findrefs`: **23 metrics** in total.
Each workload records an explicit warmup pair, then 31 independent-process pairs
in alternating base/candidate order. Warmups are retained in raw logs but excluded
from statistics. Reference counts and decompiled/CLI outputs must match before
any performance result can pass.

There is **no allowed percentage slowdown**. A one-sided exact paired sign test
checks whether the candidate is consistently slower, with a 5% family-wise error
budget divided across the metrics in that run (Bonferroni correction). A significant
slowdown fails CI even if it is only 0.1%; balanced noise or one isolated scheduling
outlier does not. Passing means no statistically significant regression was
observed in these workloads, not proof of identical timing on every machine.

The comparison's unit tests exercise small/large regressions, improvements,
identical timings, noise, outliers and incomplete/invalid measurements. The
original absolute startup and 0.0880 s gates remain mandatory. Paired timings,
base/candidate SHAs, p-values and raw logs are saved in `artifacts/comparison/`.
