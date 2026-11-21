import argparse
import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional

from pipeline.benchmark.benchmark_ingestion import BenchmarkIngestion
from pipeline.config import AVRConfig, detect_runtime_environment
from pipeline.controller import SelfHealingController

# ==============================================================================
# KONTROLLÜ MİKRO-KIYASLAMA (CONTROLLED MICRO-BENCHMARK) BAŞLANGIÇ KODLARI
# Gerçek SusVibes CVE'lerinden izole edilmiş ve sentetik çoklu-açık görevleri
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
        "type": "CWE-89 (SQL Injection)",
        "provenance": "Synthetic Micro-Benchmark",
        "cve_id": None,
        "susvibes_instance_id": None,
    },
    {
        "id": "TASK-2",
        "name": "Starlette CVE-2023-29159",
        "dir": "pipeline/starlette_case",
        "file": "staticfiles.py",
        "reset_code": STARLETTE_VULN_CODE,
        "type": "CWE-22 (Path Traversal)",
        "provenance": "Isolated SusVibes Real CVE",
        "cve_id": "CVE-2023-29159",
        "susvibes_instance_id": "encode__starlette_1797de464124b090f10cf570441e8292936d63e3",
    },
    {
        "id": "TASK-3",
        "name": "Airflow CVE-2022-41131",
        "dir": "pipeline/airflow_case",
        "file": "hive_hook.py",
        "reset_code": AIRFLOW_VULN_CODE,
        "type": "CWE-78 (OS Command Inj / RCE)",
        "provenance": "Isolated SusVibes Real CVE",
        "cve_id": "CVE-2022-41131",
        "susvibes_instance_id": None,
    },
    {
        "id": "TASK-4",
        "name": "Multi-Vuln Microservice",
        "dir": "pipeline/multi_vuln_case",
        "file": "service.py",
        "reset_code": MULTI_VULN_CODE,
        "type": "CWE-89 + CWE-22 (Çoklu Açık)",
        "provenance": "Synthetic Multi-Vuln Case",
        "cve_id": None,
        "susvibes_instance_id": None,
    },
]


def reset_task_file(task_info: Dict[str, Any]) -> None:
    """Görevin kaynak dosyasını orijinal zafiyetli haline sıfırlar."""
    file_path = Path(task_info["dir"]) / task_info["file"]
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(task_info["reset_code"])


def print_summary_table(
    results: List[Dict[str, Any]],
    total_elapsed: float,
    config: AVRConfig,
    env_info: Dict[str, str],
) -> None:
    """Terminalde jüriye sunulabilecek özet kıyaslama tablosunu basar."""
    print("\n" + "=" * 102)
    print("🏆 OTONOM GÜVENLİK YAMA MOTORU - CONTROLLED MICRO-BENCHMARK DEĞERLENDİRME RAPORU")
    print("=" * 102)

    header = (
        f"{'GÖREV ADI':<26} | {'ZAFİYET TÜRÜ':<28} | {'MOTOR':<14} | "
        f"{'TUR':<4} | {'SÜRE':<8} | {'DURUM'}"
    )
    print(header)
    print("-" * 102)

    passed_count = 0
    for r in results:
        status_str = "BAŞARILI ✅" if r["repaired"] else "BAŞARISIZ ❌"
        if r["repaired"]:
            passed_count += 1
        engines_str = ",".join(sorted(r["engines"])) if r["engines"] else "None"
        time_str = f"{r['duration']:.2f}s"
        row = (
            f"{r['name']:<26} | {r['type']:<28} | {engines_str:<14} | "
            f"{r['turns']:<4} | {time_str:<8} | {status_str}"
        )
        print(row)

    print("-" * 102)
    success_rate = (passed_count / len(results)) * 100 if results else 0.0
    verify_mode = "Paralel (ThreadPoolExecutor)" if config.parallel_verification else "Sıralı"
    print(f"Toplam Başarı Oranı : %{success_rate:.1f} ({passed_count}/{len(results)} Görev Onarıldı)")
    print(f"Toplam Süre         : {total_elapsed:.2f} saniye")
    print(f"LLM Arka Ucu / Model: {config.backend} / {config.model_name}")
    print(f"Doğrulama Modu      : {verify_mode} | Sealed Sandbox (--network none, :ro)")
    print(f"Çalışma Ortamı      : {env_info['hardware_hint']} | Python {env_info['python_version']}")
    print("=" * 102 + "\n")


def run_all_benchmarks(
    config: Optional[AVRConfig] = None,
    task_filter: Optional[str] = None,
) -> Dict[str, Any]:
    cfg = config or AVRConfig()
    env_info = detect_runtime_environment()
    ingestion = BenchmarkIngestion()
    susvibes_stats = ingestion.get_dataset_stats(allow_download=False)

    tasks_to_run = BENCHMARK_SUITE
    if task_filter:
        needle = task_filter.lower()
        tasks_to_run = [
            t
            for t in BENCHMARK_SUITE
            if needle in t["id"].lower() or needle in t["name"].lower() or needle in t["dir"].lower()
        ]
        if not tasks_to_run:
            raise ValueError(f"'{task_filter}' filtresine uyan benchmark görevi bulunamadı.")

    print("\n" + "#" * 76)
    print("🚀 CONTROLLED MICRO-BENCHMARK GÖREVLERİ ÇALIŞTIRILIYOR")
    if susvibes_stats.get("available"):
        print(
            f"   SusVibes Veri Kümesi Bağlandı: {susvibes_stats['total_tasks']} toplam kayıt "
            f"({susvibes_stats['dataset_file']})"
        )
    print("#" * 76)

    overall_start = time.time()
    results: List[Dict[str, Any]] = []

    for task in tasks_to_run:
        susvibes_meta = None
        if task.get("susvibes_instance_id") or task.get("cve_id"):
            susvibes_meta = ingestion.get_task_metadata(
                instance_id=task.get("susvibes_instance_id"),
                cve_id=task.get("cve_id"),
                allow_download=False,
            )

        print(f"\n[+] Görev Hazırlanıyor: {task['name']} ({task['type']}) [{task['provenance']}]...")
        if susvibes_meta:
            print(
                f"    └─ SusVibes Referansı: {susvibes_meta['project']} "
                f"({susvibes_meta['cve_id']} | {susvibes_meta['instance_id']})"
            )

        reset_task_file(task)

        task_start = time.time()
        controller = SelfHealingController(
            task_dir=task["dir"],
            target_file=task["file"],
            config=cfg,
        )
        task_report = controller.run()
        duration = time.time() - task_start

        findings = task_report.get("findings", [])
        engines = sorted({f.get("engine", "SAST") for f in findings}) if findings else []

        results.append({
            "id": task["id"],
            "name": task["name"],
            "type": task["type"],
            "provenance": task["provenance"],
            "susvibes_metadata": susvibes_meta,
            "engines": engines,
            "status": task_report.get("status"),
            "repaired": task_report.get("repaired", False),
            "turns": task_report.get("turns_used", 0),
            "duration": round(duration, 3),
            "rolled_back_to_original": task_report.get("rolled_back_to_original", False),
            "llm_metrics_summary": task_report.get("llm_metrics_summary", {}),
            "unified_diff": task_report.get("unified_diff", {}),
        })

    overall_elapsed = time.time() - overall_start
    print_summary_table(results, overall_elapsed, cfg, env_info)

    summary_payload = {
        "benchmark_mode": "controlled_micro_benchmark",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "backend": cfg.backend,
        "model_name": cfg.model_name,
        "parallel_verification": cfg.parallel_verification,
        "environment": env_info,
        "susvibes_dataset": susvibes_stats,
        "total_tasks": len(results),
        "success_rate": f"%{(sum(1 for r in results if r['repaired']) / len(results)) * 100:.1f}",
        "total_time_seconds": round(overall_elapsed, 3),
        "results": results,
    }

    out_json = Path("pipeline/benchmark_summary.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(summary_payload, f, indent=2, ensure_ascii=False)

    print(f"[Rapor] Toplu sonuçlar kaydedildi: {out_json.as_posix()}")
    return summary_payload


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AVR Controlled Micro-Benchmark & SusVibes Ingestion Runner"
    )
    parser.add_argument("--backend", choices=["ollama", "transformers"], default=None)
    parser.add_argument("--model", default=None, help="Kullanılacak LLM modeli")
    parser.add_argument("--max-turns", type=int, default=None)
    parser.add_argument("--task", default=None, help="Sadece eşleşen görevi çalıştır (örn. TASK-2, airflow)")
    parser.add_argument("--sequential", action="store_true", help="func/sec testlerini sıralı koştur")
    parser.add_argument(
        "--list-susvibes",
        metavar="CWE",
        nargs="?",
        const="",
        default=None,
        help="SusVibes veri kümesindeki uygun görevleri listele (opsiyonel CWE filtresi, örn. CWE-22)",
    )
    args = parser.parse_args()

    if args.list_susvibes is not None:
        ingestion = BenchmarkIngestion()
        cwe_filter = args.list_susvibes or None
        stats = ingestion.get_dataset_stats(allow_download=False)
        print(f"\nSusVibes Veri Kümesi: {stats}")
        candidates = ingestion.filter_tasks(cwe=cwe_filter, max_patch_lines=30, allow_download=False)
        print(f"Eşleşen kompakt görev sayısı ({cwe_filter or 'TÜMÜ'}): {len(candidates)}")
        for item in candidates[:15]:
            print(
                f"  - {item['instance_id']} | {item['project']} | "
                f"{item['cve_id']} | {item['cwe']} ({item['patch_lines']} satır)"
            )
        return

    cfg = AVRConfig()
    if args.backend:
        cfg.backend = args.backend
    if args.model:
        cfg.model_name = args.model
    if args.max_turns is not None:
        cfg.max_turns = args.max_turns
    if args.sequential:
        cfg.parallel_verification = False

    run_all_benchmarks(config=cfg, task_filter=args.task)


if __name__ == "__main__":
    main()
