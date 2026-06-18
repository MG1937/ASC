import sys

def print_success(code: str):
    print(code)

def print_error(msg: str):
    print(f"ERROR: {msg}", file=sys.stderr)

def print_verbose(msg: str, verbose: bool):
    if verbose:
        print(f"[INFO] {msg}", file=sys.stdout)
