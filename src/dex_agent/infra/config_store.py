import json
import os
import sys
import threading

from dex_agent.domain.paths import WorkspacePaths
from dex_agent.domain.models import TaskList
from dex_agent.infra.fs import ensure_dir

class ConfigStore:
    def __init__(self, workspace_path: str = "./temp"):
        self.workspace_path = os.path.abspath(workspace_path)
        self.paths = WorkspacePaths(self.workspace_path)
        self._task_list_lock = threading.RLock()
        self._ensure_workspace()
        
    def _ensure_workspace(self):
        ensure_dir(self.workspace_path)
        if not os.path.exists(self.paths.config_json):
            self.save_task_list(TaskList())
            
    def load_task_list(self) -> TaskList:
        with self._task_list_lock:
            if not os.path.exists(self.paths.config_json):
                return TaskList()

            with open(self.paths.config_json, "r", encoding="utf-8") as f:
                try:
                    data = json.load(f)
                    task_list_data = data.get("TASK_LIST", {})
                    return TaskList(task_list_data)
                except json.JSONDecodeError:
                    return TaskList()
                
    def save_task_list(self, task_list: TaskList):
        with self._task_list_lock:
            data = {}
            if os.path.exists(self.paths.config_json):
                with open(self.paths.config_json, "r", encoding="utf-8") as f:
                    try:
                        data = json.load(f)
                    except json.JSONDecodeError:
                        pass

            data["WORKSPACE"] = self.workspace_path
            data["TASK_LIST"] = task_list.to_dict()

            temp_file = self.paths.config_json + ".tmp"
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            os.replace(temp_file, self.paths.config_json)

    def add_dex_record(self, task_name: str, dex_path: str):
        with self._task_list_lock:
            task_list = self.load_task_list()
            task_list.add_dex_record(task_name, dex_path)
            self.save_task_list(task_list)

    def add_java_record(self, task_name: str, java_path: str):
        with self._task_list_lock:
            task_list = self.load_task_list()
            task_list.add_java_record(task_name, java_path)
            self.save_task_list(task_list)
