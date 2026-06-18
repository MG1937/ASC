import os
import sys


_PKG_DIR = os.path.dirname(os.path.abspath(__file__))

# Allow internal legacy imports like `from core...` while exposing the package
# as `src.asc_core...` to external callers.
if _PKG_DIR not in sys.path:
    sys.path.insert(0, _PKG_DIR)
