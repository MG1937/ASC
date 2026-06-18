import subprocess
import os
import time
from typing import Tuple, Optional, Callable

from dex_agent.domain.errors import TaskExecutionError

_shell_logger: Optional[Callable[[str], None]] = None

def set_shell_logger(logger: Callable[[str], None]):
    global _shell_logger
    _shell_logger = logger

def run_command(command: str, cwd: str = None, check: bool = True) -> Tuple[int, str, str]:
    start_time = time.time()
    if _shell_logger:
        _shell_logger(f"[EXEC] {command} (cwd: {cwd or 'default'})")
        
    try:
        process = subprocess.run(
            command,
            shell=True,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        elapsed = time.time() - start_time
        if _shell_logger:
            _shell_logger(f"[DONE] {command} (Time: {elapsed:.2f}s, ReturnCode: {process.returncode})")
            
        if check and process.returncode != 0:
            raise TaskExecutionError(
                f"Command failed with code {process.returncode}:\n"
                f"Command: {command}\n"
                f"Stdout: {process.stdout}\n"
                f"Stderr: {process.stderr}"
            )
        return process.returncode, process.stdout, process.stderr
    except Exception as e:
        elapsed = time.time() - start_time
        if _shell_logger:
            _shell_logger(f"[FAIL] {command} (Time: {elapsed:.2f}s, Error: {str(e)})")
            
        if isinstance(e, TaskExecutionError):
            raise
        raise TaskExecutionError(f"Failed to execute command '{command}': {str(e)}")

def find_executable(name: str) -> str:
    from shutil import which
    path = which(name)
    return path if path else ""
