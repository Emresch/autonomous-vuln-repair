import time
import json
from pathlib import Path
from typing import List, Dict, Any

from pipeline.controller import SelfHealingController

# ==============================================================================
# GÖREVLERİN ORİJİNAL (ZAFİYETLİ) BAŞLANGIÇ KODLARI
# ==============================================================================
SAMPLE_TASK_VULN_CODE = """import sqlite3
import hashlib

def init_db(db_path=":memory:"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT
        )
    ''')
    cursor.execute("INSERT OR IGNORE INTO users (username, email) VALUES ('alice', 'alice@example.com')")
    cursor.execute("INSERT OR IGNORE INTO users (username, email) VALUES ('bob', 'bob@example.com')")
    conn.commit()
    return conn

def hash_username(username: str) -> str:
    return hashlib.sha256(username.encode()).hexdigest()

def get_user_by_username(conn, username: str):
    cursor = conn.cursor()
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()

def count_total_users(conn) -> int:
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    res = cursor.fetchone()
    return res[0] if res else 0
"""

STARLETTE_VULN_CODE = """import os
import typing
from pathlib import Path

class StaticFiles:
    def __init__(self, directory: str, follow_symlink: bool = False):
        self.directory = os.path.realpath(directory)
        self.all_directories = [self.directory]
        self.follow_symlink = follow_symlink

    def lookup_path(
        self, path: str
    ) -> typing.Tuple[str, typing.Optional[os.stat_result]]:
        for directory in self.all_directories:
            joined_path = os.path.join(directory, path)
            if self.follow_symlink:
                full_path = os.path.abspath(joined_path)
            else:
                full_path = os.path.realpath(joined_path)
            directory = os.path.realpath(directory)
            if os.path.commonprefix([full_path, directory]) != directory:
                continue
            try:
                return full_path, os.stat(full_path)
            except (FileNotFoundError, NotADirectoryError):
                continue
        return "", None
"""

AIRFLOW_VULN_CODE = r"""import os
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
"""

MULTI_VULN_CODE = r"""import os
import sqlite3
import re
from typing import Optional, Tuple, Dict, Any

def validate_email_format(email: str) -> bool:
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return bool(re.match(pattern, email))

def get_user_account(conn: sqlite3.Connection, username: str) -> Optional[Tuple]:
    cursor = conn.cursor()
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()

def calculate_user_storage_quota(account_type: str) -> int:
    quotas = {"free": 500, "premium": 5000, "enterprise": 50000}
    return quotas.get(account_type.lower(), 500)

def read_user_attachment(base_directory: str, filename: str) -> Optional[str]:
    base_dir = os.path.realpath(base_directory)
    target_path = os.path.realpath(os.path.join(base_dir, filename))
    if os.path.commonprefix([target_path, base_dir]) != base_dir:
        return None
    if not os.path.exists(target_path):
        return None
    try:
        with open(target_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return None

def format_security_audit_log(user_id: int, action: str, ip_address: str) -> Dict[str, Any]:
    return {"user_id": user_id, "action": action, "ip": ip_address, "status": "LOGGED"}
"""

BENCHMARK_SUITE = [
    {
        "id": "TASK-1",
        "name": "SQLi Authentication",
        "dir": "pipeline/sample_task",
        "file": "app.py",
        "reset_code": SAMPLE_TASK_VULN_CODE,
        "type": "CWE-89 (SQL Injection)"
    },
    {
        "id": "TASK-2",
        "name": "Starlette CVE-2023-29159",
        "dir": "pipeline/starlette_case",
        "file": "staticfiles.py",
        "reset_code": STARLETTE_VULN_CODE,
        "type": "CWE-22 (Path Traversal)"
    },
    {
        "id": "TASK-3",
        "name": "Airflow CVE-2022-41131",
        "dir": "pipeline/airflow_case",
        "file": "hive_hook.py",
        "reset_code": AIRFLOW_VULN_CODE,
        "type": "CWE-78 (OS Command Inj / RCE)"
    },
    {
        "id": "TASK-4",
        "name": "Multi-Vuln Microservice",
        "dir": "pipeline/multi_vuln_case",
        "file": "service.py",
        "reset_code": MULTI_VULN_CODE,
        "type": "CWE-89 + CWE-22 (Çoklu Açık)"
    }
]

def reset_task_file(task_info: Dict[str, Any]):
    """Görevin kaynak dosyasını orijinal zafiyetli haline sıfırlar."""
    file_path = Path(task_info["dir"]) / task_info["file"]
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(task_info["reset_code"])

def print_summary_table(results: List[Dict[str, Any]], total_elapsed: float):
    """Terminalde jüriye sunulabilecek profesyonel özet tablosunu basar."""
    print("\n" + "="*95)
    print("🏆 OTONOM GÜVENLİK YAMA MOTORU - SUSVIBES & CVE BENCHMARK DEĞERLENDİRME RAPORU")
    print("="*95)
    
    header = f"{'GÖREV ADI':<26} | {'ZAFİYET TÜRÜ':<28} | {'MOTOR':<10} | {'TUR':<4} | {'SÜRE':<8} | {'DURUM'}"
    print(header)
    print("-" * 95)

    passed_count = 0
    for r in results:
        status_str = "BAŞARILI ✅" if r["repaired"] else "BAŞARISIZ ❌"
        if r["repaired"]:
            passed_count += 1
        engines_str = ",".join(r["engines"]) if r["engines"] else "None"
        time_str = f"{r['duration']:.2f}s"
        row = f"{r['name']:<26} | {r['type']:<28} | {engines_str:<10} | {r['turns']:<4} | {time_str:<8} | {status_str}"
        print(row)

    print("-" * 95)
    success_rate = (passed_count / len(results)) * 100
    print(f"Toplam Başarı Oranı : %{success_rate:.1f} ({passed_count}/{len(results)} Görev Onarıldı)")
    print(f"Toplam Süre         : {total_elapsed:.2f} saniye")
    print(f"Yerel Model         : Qwen-2.5-Coder:7b (Ollama / RTX 3050)")
    print("="*95 + "\n")

def run_all_benchmarks():
    print("\n" + "#"*70)
    print("🚀 TÜM BENCHMARK GÖREVLERİ SIRAYLA ÇALIŞTIRILIYOR")
    print("#"*70)

    overall_start = time.time()
    results = []

    for task in BENCHMARK_SUITE:
        print(f"\n[+] Görev Hazırlanıyor: {task['name']} ({task['type']})...")
        reset_task_file(task)

        task_start = time.time()
        controller = SelfHealingController(
            task_dir=task["dir"],
            target_file=task["file"],
            max_turns=3
        )
        task_report = controller.run()
        duration = time.time() - task_start

        findings = task_report.get("findings", [])
        if not findings and "rule_id" in task_report:
            engines = ["Bandit"]
        else:
            engines = list(set(f.get("engine", "SAST") for f in findings))

        results.append({
            "id": task["id"],
            "name": task["name"],
            "type": task["type"],
            "engines": engines,
            "repaired": task_report.get("repaired", False),
            "turns": task_report.get("turns_used", 1),
            "duration": duration
        })

    overall_elapsed = time.time() - overall_start

    # Özet tablosunu bas
    print_summary_table(results, overall_elapsed)

    # Sonuçları JSON olarak kaydet
    out_json = Path("pipeline/benchmark_summary.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_tasks": len(results),
            "success_rate": f"%{(sum(1 for r in results if r['repaired']) / len(results)) * 100:.1f}",
            "total_time_seconds": overall_elapsed,
            "results": results
        }, f, indent=2, ensure_ascii=False)

    print(f"[Rapor] Toplu sonuçlar kaydedildi: {out_json}")

if __name__ == "__main__":
    run_all_benchmarks()
