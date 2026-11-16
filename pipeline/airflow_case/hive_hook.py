import os
import subprocess
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import Any, Optional, Dict

class HiveCliHook:
    def __init__(self, default_schema: str = "default"):
        self.default_schema = default_schema

    def _prepare_cli_cmd(self) -> list:
        return ["echo", "EXECUTING_HIVE_QUERY"]

    def run_cli(
        self,
        hql: str,
        schema: Optional[str] = None,
        verbose: bool = True,
        hive_conf: Optional[Dict[Any, Any]] = None,
    ) -> Any:
        schema = schema or self.default_schema
        if schema:
            hql = f"USE {schema};\n{hql}"

        with TemporaryDirectory(prefix="airflow_hiveop_") as tmp_dir:
            with NamedTemporaryFile(dir=tmp_dir, delete=False) as f:
                hql += "\n"
                f.write(hql.encode("UTF-8"))
                f.flush()
                f_name = f.name

            hive_cmd = self._prepare_cli_cmd()
            hive_cmd.extend(["-f", f_name])

            with open(f_name, "r", encoding="utf-8") as rf:
                generated_script = rf.read()

            return {
                "status": "SUCCESS",
                "schema_used": schema,
                "generated_script": generated_script,
                "cmd": " ".join(hive_cmd)
            }
