import os
from dataclasses import dataclass

@dataclass
class WorkspacePaths:
    base_dir: str
    
    @property
    def config_json(self) -> str:
        return os.path.join(self.base_dir, "config.json")
        
    def task_dir(self, task_name: str) -> str:
        return os.path.join(self.base_dir, str(task_name))
        
    def dexes_dir(self, task_name: str) -> str:
        return os.path.join(self.task_dir(task_name), "dexes")
        
    def pesudo_dir(self, task_name: str) -> str:
        return os.path.join(self.task_dir(task_name), "pesudo")
        
    def dex_pesudo_dir(self, task_name: str, dex_file_name: str) -> str:
        return os.path.join(self.pesudo_dir(task_name), dex_file_name)
        
    def get_java_path(self, task_name: str, dex_file_name: str, class_dot_format: str) -> str:
        rel_path = class_dot_format.replace(".", os.sep) + ".java"
        return os.path.join(self.dex_pesudo_dir(task_name, dex_file_name), "sources", rel_path)
