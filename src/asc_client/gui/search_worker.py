import json
import os
import sys

from src.asc_client.apk_handler import _findrefs_worker


def main():
    payload = json.load(sys.stdin)
    entry = tuple(payload["entry"])
    dex_name, lines, inflate_us, process_us, pid = _findrefs_worker(
        payload["apk_path"],
        entry,
        payload["find_type"],
        payload["find"],
    )

    result = {
        "dex_name": dex_name,
        "lines": lines,
        "inflate_us": inflate_us,
        "process_us": process_us,
        "pid": pid,
    }

    with open(payload["result_path"], "w", encoding="utf-8") as fp:
        json.dump(result, fp, ensure_ascii=False)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
