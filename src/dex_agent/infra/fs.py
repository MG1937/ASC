import os
import shutil

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def read_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def file_exists(path: str) -> bool:
    return os.path.isfile(path)

def dir_exists(path: str) -> bool:
    return os.path.isdir(path)

def remove_dir(path: str):
    if os.path.isdir(path):
        shutil.rmtree(path)
