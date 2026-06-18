import os
import time

from dex_agent.domain.models import TaskName, ClassName
from dex_agent.domain.paths import WorkspacePaths
from dex_agent.infra.config_store import ConfigStore
from dex_agent.infra.fs import file_exists, read_file
from dex_agent.infra.apk_handler import find_and_extract
from dex_agent.infra.dex_decompiler import decompile_class

def execute_get_class(
    apk_path: str,
    clazz_name: str,
    config_store: ConfigStore,
    verbose: bool = False,
    threads: int = 8,
) -> str:
    task = TaskName(apk_path)
    task_name = task.name
    clazz = ClassName(clazz_name)
    paths = config_store.paths

    def log(msg: str):
        if verbose:
            print(f"[INFO] {msg}")

    total_start_time = time.time()

    task_list = config_store.load_task_list()
    task_data = task_list.get_task(task_name)

    # Cache check: look for an already-decompiled .java
    if task_data:
        log("Checking cache...")
        step_start = time.time()
        for java_path in task_data.java:
            expected_suffix = clazz.to_dot_format().replace(".", os.sep) + ".java"
            if java_path.endswith(expected_suffix) and file_exists(java_path):
                log(f"Cache hit: {java_path} ({time.time() - step_start:.2f}s)")
                log(f"Total: {time.time() - total_start_time:.2f}s")
                return read_file(java_path)
        log(f"Cache check: {time.time() - step_start:.2f}s")

    # Locate the DEX containing the target class. On miss, scans APK entries
    # in memory with concurrency and only writes the winning DEX to disk.
    already_extracted = list(task_data.dex) if task_data else []

    log("Locating class (concurrent in-memory scan)...")
    step_start = time.time()
    dex_path = find_and_extract(
        apk_path=apk_path,
        clazz_name=clazz.formatted,
        paths=paths,
        already_extracted=already_extracted,
        max_workers=threads,
        verbose=verbose,
    )
    log(f"Locate+extract: {time.time() - step_start:.2f}s")

    if not dex_path:
        log(f"Total: {time.time() - total_start_time:.2f}s")
        return "Class not found in any dex file."

    config_store.add_dex_record(task_name, dex_path)

    log(f"Found in '{os.path.basename(dex_path)}', decompiling...")
    step_start = time.time()
    source_code = decompile_class(
        task_name=task_name,
        dex_file=dex_path,
        clazz_name=clazz.to_dot_format(),
        paths=paths,
        config_store=config_store
    )
    log(f"Decompile: {time.time() - step_start:.2f}s")

    if source_code:
        log(f"Total: {time.time() - total_start_time:.2f}s")
        return source_code

    log(f"Total: {time.time() - total_start_time:.2f}s")
    return "Failed to decompile class."
