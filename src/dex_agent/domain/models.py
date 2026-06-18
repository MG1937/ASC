import re
from typing import Dict, List, Optional
from dataclasses import dataclass, field

from .errors import InvalidClassFormatError

class ClassName:
    def __init__(self, raw_name: str):
        self._raw = raw_name
        self.formatted = self._format(raw_name)
    
    @staticmethod
    def _format(name: str) -> str:
        if not name:
            raise InvalidClassFormatError("Class name cannot be empty")
            
        if name.startswith("L") and name.endswith(";") and "/" in name:
            return name
            
        formatted = name.replace(".", "/")
        if not formatted.startswith("L"):
            formatted = f"L{formatted}"
        if not formatted.endswith(";"):
            formatted = f"{formatted};"
            
        return formatted
        
    def to_dot_format(self) -> str:
        name = self.formatted
        if name.startswith("L"):
            name = name[1:]
        if name.endswith(";"):
            name = name[:-1]
        return name.replace("/", ".")
        
    def __str__(self) -> str:
        return self.formatted

class TaskName:
    def __init__(self, apk_path: str):
        self._raw = apk_path
        self.name = self._format(apk_path)
        
    @staticmethod
    def _format(path: str) -> str:
        filename = path.replace("\\", "/").split("/")[-1]
        
        if filename.endswith(".apk") or filename.endswith(".jar"):
            filename = filename[:-4]
            
        formatted = re.sub(r'[^a-zA-Z0-9]', '_', filename)
        return formatted
        
    def __str__(self) -> str:
        return self.name

@dataclass
class TaskData:
    dex: List[str] = field(default_factory=list)
    java: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, List[str]]:
        return {"DEX": self.dex, "JAVA": self.java}
        
    @classmethod
    def from_dict(cls, data: Dict[str, List[str]]) -> 'TaskData':
        return cls(
            dex=data.get("DEX", []),
            java=data.get("JAVA", [])
        )

class TaskList:
    def __init__(self, initial_data: Optional[Dict[str, Dict[str, List[str]]]] = None):
        self._tasks: Dict[str, TaskData] = {}
        if initial_data:
            for task_name, task_dict in initial_data.items():
                self._tasks[task_name] = TaskData.from_dict(task_dict)
                
    def get_task(self, task_name: str) -> Optional[TaskData]:
        return self._tasks.get(task_name)
        
    def add_java_record(self, task_name: str, java_path: str):
        if task_name not in self._tasks:
            self._tasks[task_name] = TaskData()
        if java_path not in self._tasks[task_name].java:
            self._tasks[task_name].java.append(java_path)
            
    def add_dex_record(self, task_name: str, dex_path: str):
        if task_name not in self._tasks:
            self._tasks[task_name] = TaskData()
        if dex_path not in self._tasks[task_name].dex:
            self._tasks[task_name].dex.append(dex_path)
            
    def to_dict(self) -> Dict[str, Dict[str, List[str]]]:
        return {name: task.to_dict() for name, task in self._tasks.items()}
