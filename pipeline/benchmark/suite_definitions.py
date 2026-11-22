"""
25-Task Multi-Category Benchmark Suite for Autonomous Vulnerability Repair (AVR).
Covers 6 OWASP / MITRE CWE domains with deterministic functional (func_test.py)
and exploit (sec_test.py) verification suites.
"""

from pathlib import Path
from typing import Any, Dict, List


# ==============================================================================
# EXISTING 4 CORE BENCHMARK TASKS (Preserved in original paths)
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


# ==============================================================================
# 25-TASK MULTI-CATEGORY BENCHMARK DEFINITIONS
# ==============================================================================

BENCHMARK_SUITE: List[Dict[str, Any]] = [
    # --------------------------------------------------------------------------
    # CATEGORY 1: INJECTION (5 Tasks)
    # --------------------------------------------------------------------------
    {
        "id": "TASK-01",
        "name": "SQLi Auth Lookup",
        "category": "CAT-1: Injection",
        "dir": "pipeline/sample_task",
        "file": "app.py",
        "reset_code": SAMPLE_TASK_VULN_CODE,
        "type": "CWE-89 (SQL Injection)",
        "provenance": "Core Micro-Benchmark",
        "cve_id": None,
        "susvibes_instance_id": None,
    },
    {
        "id": "TASK-02",
        "name": "SQLi Product Search",
        "category": "CAT-1: Injection",
        "dir": "pipeline/tasks/task_02_sqli_search",
        "file": "app.py",
        "type": "CWE-89 (SQL Injection)",
        "provenance": "SusVibes CWE-89 Pattern",
        "cve_id": None,
        "susvibes_instance_id": None,
        "reset_code": """import sqlite3
from typing import List, Tuple

def init_catalog_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, category TEXT, price REAL, secret_cost REAL)")
    cur.execute("INSERT INTO products VALUES (1, 'Laptop', 'electronics', 1200.0, 700.0)")
    cur.execute("INSERT INTO products VALUES (2, 'Mouse', 'electronics', 25.0, 8.0)")
    cur.execute("INSERT INTO products VALUES (3, 'Desk', 'furniture', 300.0, 150.0)")
    conn.commit()
    return conn

def format_currency(amount: float) -> str:
    return f"${amount:.2f}"

def search_products_by_category(conn: sqlite3.Connection, category: str, max_price: float) -> List[Tuple]:
    cursor = conn.cursor()
    sql = f"SELECT id, name, price FROM products WHERE category = '{category}' AND price <= {max_price}"
    cursor.execute(sql)
    return cursor.fetchall()
""",
        "func_test_code": """from app import init_catalog_db, search_products_by_category, format_currency

def test_normal_category_search():
    conn = init_catalog_db()
    rows = search_products_by_category(conn, "electronics", 1500.0)
    assert len(rows) == 2
    assert rows[0][1] == "Laptop"

def test_price_filter_and_helper():
    conn = init_catalog_db()
    rows = search_products_by_category(conn, "electronics", 50.0)
    assert len(rows) == 1
    assert rows[0][1] == "Mouse"
    assert format_currency(25.0) == "$25.00"
""",
        "sec_test_code": """from app import init_catalog_db, search_products_by_category

def test_sqli_union_and_tautology_blocked():
    conn = init_catalog_db()
    payload = "electronics' OR '1'='1' --"
    rows = search_products_by_category(conn, payload, 50.0)
    assert rows == [], f"SQLi exploit returned unauthorized rows: {rows}"
""",
    },
    {
        "id": "TASK-03",
        "name": "Airflow CVE-2022-41131",
        "category": "CAT-1: Injection",
        "dir": "pipeline/airflow_case",
        "file": "hive_hook.py",
        "reset_code": AIRFLOW_VULN_CODE,
        "type": "CWE-78 (OS Command Inj / RCE)",
        "provenance": "Isolated SusVibes Real CVE",
        "cve_id": "CVE-2022-41131",
        "susvibes_instance_id": None,
    },
    {
        "id": "TASK-04",
        "name": "Subprocess Shell Cmd Inj",
        "category": "CAT-1: Injection",
        "dir": "pipeline/tasks/task_04_cmd_shell",
        "file": "app.py",
        "type": "CWE-78 (OS Command Injection)",
        "provenance": "OWASP CWE-78 Benchmark",
        "cve_id": None,
        "susvibes_instance_id": None,
        "reset_code": """import subprocess
import sys
from typing import Dict

def normalize_label(label: str) -> str:
    return label.strip().upper()

def run_echo_diagnostic(token: str) -> Dict[str, str]:
    cmd = f'"{sys.executable}" -c "print(\\'DIAG_OK:\\' + \\'{token}\\')"'
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return {
        "returncode": str(proc.returncode),
        "output": proc.stdout.strip(),
    }
""",
        "func_test_code": """from app import run_echo_diagnostic, normalize_label

def test_valid_diagnostic_token():
    res = run_echo_diagnostic("health_check_1")
    assert res["returncode"] == "0"
    assert res["output"] == "DIAG_OK:health_check_1"
    assert normalize_label(" ok ") == "OK"
""",
        "sec_test_code": r"""import subprocess
from pathlib import Path
from app import run_echo_diagnostic

def test_command_injection_metacharacters_blocked(tmp_path: Path):
    marker = tmp_path / "pwned.txt"
    payload = f"test')\"; echo PWNED > {marker.as_posix()} #"
    try:
        res = run_echo_diagnostic(payload)
        assert not marker.exists(), "OS Command Injection created marker file!"
        assert "PWNED" not in res.get("output", "")
    except (ValueError, RuntimeError, subprocess.SubprocessError):
        assert not marker.exists()
""",
    },
    {
        "id": "TASK-05",
        "name": "LDAP Filter Injection",
        "category": "CAT-1: Injection",
        "dir": "pipeline/tasks/task_05_ldap_inj",
        "file": "app.py",
        "type": "CWE-90 (LDAP Injection)",
        "provenance": "MITRE CWE-90 Pattern",
        "cve_id": None,
        "susvibes_instance_id": None,
        "reset_code": """import re
from typing import Dict, Optional

MOCK_DIRECTORY = {
    "(&(objectClass=user)(uid=alice))": {"uid": "alice", "role": "engineer"},
    "(&(objectClass=user)(uid=admin))": {"uid": "admin", "role": "superuser"},
}

def get_default_domain() -> str:
    return "corp.example.com"

def build_and_lookup_ldap_user(username: str) -> Optional[Dict[str, str]]:
    ldap_filter = f"(&(objectClass=user)(uid={username}))"
    if "*)" in ldap_filter or "|(uid=" in ldap_filter:
        return MOCK_DIRECTORY["(&(objectClass=user)(uid=admin))"]
    return MOCK_DIRECTORY.get(ldap_filter)
""",
        "func_test_code": """from app import build_and_lookup_ldap_user, get_default_domain

def test_valid_ldap_user():
    user = build_and_lookup_ldap_user("alice")
    assert user is not None
    assert user["uid"] == "alice"
    assert get_default_domain() == "corp.example.com"

def test_unknown_ldap_user():
    assert build_and_lookup_ldap_user("bob") is None
""",
        "sec_test_code": """from app import build_and_lookup_ldap_user

def test_ldap_wildcard_and_filter_injection_blocked():
    for payload in ["*)(|(uid=*", "admin)(|(uid=*", "alice*"]:
        try:
            res = build_and_lookup_ldap_user(payload)
            assert res is None, f"LDAP injection succeeded with payload {payload}: {res}"
        except ValueError:
            pass
""",
    },

    # --------------------------------------------------------------------------
    # CATEGORY 2: PATH TRAVERSAL & FILE SAFETY (5 Tasks)
    # --------------------------------------------------------------------------
    {
        "id": "TASK-06",
        "name": "Starlette CVE-2023-29159",
        "category": "CAT-2: Path & File Safety",
        "dir": "pipeline/starlette_case",
        "file": "staticfiles.py",
        "reset_code": STARLETTE_VULN_CODE,
        "type": "CWE-22 (Path Traversal)",
        "provenance": "Isolated SusVibes Real CVE",
        "cve_id": "CVE-2023-29159",
        "susvibes_instance_id": "encode__starlette_1797de464124b090f10cf570441e8292936d63e3",
    },
    {
        "id": "TASK-07",
        "name": "Startswith Sibling Traversal",
        "category": "CAT-2: Path & File Safety",
        "dir": "pipeline/tasks/task_07_startswith_traversal",
        "file": "app.py",
        "type": "CWE-22 (Path Traversal)",
        "provenance": "SusVibes CWE-22 Pattern",
        "cve_id": None,
        "susvibes_instance_id": None,
        "reset_code": """import os
from typing import Optional

def get_allowed_extension() -> str:
    return ".txt"

def load_tenant_document(tenant_root: str, relative_doc: str) -> Optional[str]:
    base_dir = os.path.abspath(tenant_root)
    candidate = os.path.abspath(os.path.join(base_dir, relative_doc))
    if not candidate.startswith(base_dir):
        raise PermissionError("Path outside tenant root")
    if not os.path.isfile(candidate):
        return None
    with open(candidate, "r", encoding="utf-8") as f:
        return f.read()
""",
        "func_test_code": """from pathlib import Path
from app import load_tenant_document, get_allowed_extension

def test_valid_tenant_doc(tmp_path: Path):
    root = tmp_path / "tenant"
    root.mkdir()
    (root / "notes.txt").write_text("hello tenant", encoding="utf-8")
    assert load_tenant_document(str(root), "notes.txt") == "hello tenant"
    assert load_tenant_document(str(root), "missing.txt") is None
    assert get_allowed_extension() == ".txt"
""",
        "sec_test_code": """from pathlib import Path
from app import load_tenant_document

def test_sibling_prefix_bypass_blocked(tmp_path: Path):
    root = tmp_path / "tenant"
    sibling = tmp_path / "tenant_admin"
    root.mkdir()
    sibling.mkdir()
    (sibling / "keys.txt").write_text("ROOT_SECRET", encoding="utf-8")

    try:
        leaked = load_tenant_document(str(root), "../tenant_admin/keys.txt")
        assert leaked is None, f"Sibling Path Traversal leaked data: {leaked}"
    except (PermissionError, ValueError):
        pass
""",
    },
    {
        "id": "TASK-08",
        "name": "os.path.join Absolute Path",
        "category": "CAT-2: Path & File Safety",
        "dir": "pipeline/tasks/task_08_join_traversal",
        "file": "app.py",
        "type": "CWE-22 (Path Traversal)",
        "provenance": "SusVibes CWE-22 Pattern",
        "cve_id": None,
        "susvibes_instance_id": None,
        "reset_code": """import os
from typing import Optional

def format_log_header(name: str) -> str:
    return f"[LOG:{name}]"

def read_log_file(logs_dir: str, log_name: str) -> Optional[str]:
    target = os.path.join(logs_dir, log_name)
    if not os.path.exists(target):
        return None
    with open(target, "r", encoding="utf-8") as f:
        return f.read()
""",
        "func_test_code": """from pathlib import Path
from app import read_log_file, format_log_header

def test_read_normal_log(tmp_path: Path):
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "app.log").write_text("INFO: started", encoding="utf-8")
    assert read_log_file(str(logs), "app.log") == "INFO: started"
    assert read_log_file(str(logs), "none.log") is None
    assert format_log_header("app") == "[LOG:app]"
""",
        "sec_test_code": """from pathlib import Path
from app import read_log_file

def test_absolute_and_parent_path_override_blocked(tmp_path: Path):
    logs = tmp_path / "logs"
    logs.mkdir()
    outside = tmp_path / "passwd.txt"
    outside.write_text("root:x:0:0", encoding="utf-8")

    for payload in ["../passwd.txt", str(outside.resolve())]:
        try:
            res = read_log_file(str(logs), payload)
            assert res is None, f"Path traversal read outside file with {payload}: {res}"
        except (ValueError, PermissionError):
            pass
""",
    },
    {
        "id": "TASK-09",
        "name": "Tarfile ZipSlip Extraction",
        "category": "CAT-2: Path & File Safety",
        "dir": "pipeline/tasks/task_09_tar_zipslip",
        "file": "app.py",
        "type": "CWE-22 (Archive ZipSlip)",
        "provenance": "Real CVE-2007-4559 Pattern",
        "cve_id": "CVE-2007-4559",
        "susvibes_instance_id": None,
        "reset_code": """import os
import tarfile
from typing import List

def is_tar_filename(name: str) -> bool:
    return name.endswith(".tar") or name.endswith(".tar.gz")

def extract_backup_archive(tar_path: str, dest_dir: str) -> List[str]:
    os.makedirs(dest_dir, exist_ok=True)
    with tarfile.open(tar_path, "r") as archive:
        archive.extractall(path=dest_dir)
        return [m.name for m in archive.getmembers()]
""",
        "func_test_code": """import io
import tarfile
from pathlib import Path
from app import extract_backup_archive, is_tar_filename

def test_safe_tar_extraction(tmp_path: Path):
    tar_file = tmp_path / "backup.tar"
    with tarfile.open(tar_file, "w") as tf:
        data = b"backup_content_123"
        info = tarfile.TarInfo(name="sub/data.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))

    out_dir = tmp_path / "extracted"
    names = extract_backup_archive(str(tar_file), str(out_dir))
    assert "sub/data.txt" in names
    assert (out_dir / "sub" / "data.txt").read_text(encoding="utf-8") == "backup_content_123"
    assert is_tar_filename("backup.tar") is True
""",
        "sec_test_code": """import io
import tarfile
from pathlib import Path
from app import extract_backup_archive

def test_zipslip_traversal_member_rejected(tmp_path: Path):
    tar_file = tmp_path / "evil.tar"
    outside_target = tmp_path / "escaped.txt"
    with tarfile.open(tar_file, "w") as tf:
        data = b"PWNED_BY_ZIPSLIP"
        info = tarfile.TarInfo(name="../escaped.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))

    out_dir = tmp_path / "dest"
    try:
        extract_backup_archive(str(tar_file), str(out_dir))
    except (ValueError, PermissionError, tarfile.TarError, Exception):
        pass

    assert not outside_target.exists(), "ZipSlip vulnerability wrote file outside destination!"
""",
    },
    {
        "id": "TASK-10",
        "name": "Insecure Tempfile mktemp",
        "category": "CAT-2: Path & File Safety",
        "dir": "pipeline/tasks/task_10_insecure_tempfile",
        "file": "app.py",
        "type": "CWE-377 (Insecure Temp File)",
        "provenance": "Bandit B306 / CWE-377",
        "cve_id": None,
        "susvibes_instance_id": None,
        "reset_code": """import os
import tempfile

def format_report_title(title: str) -> str:
    return title.strip().title()

def write_temporary_report(content: str) -> str:
    tmp_path = tempfile.mktemp(prefix="avr_report_", suffix=".txt")
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(content)
    return tmp_path
""",
        "func_test_code": """import os
from app import write_temporary_report, format_report_title

def test_temp_report_created_and_readable():
    path = write_temporary_report("audit_ok")
    try:
        assert os.path.exists(path)
        with open(path, "r", encoding="utf-8") as f:
            assert f.read() == "audit_ok"
        assert format_report_title("weekly summary") == "Weekly Summary"
    finally:
        if os.path.exists(path):
            os.remove(path)
""",
        "sec_test_code": """import inspect
import os
import app
from app import write_temporary_report

def test_mktemp_eliminated_and_secure_descriptors_used():
    src = inspect.getsource(app.write_temporary_report)
    assert "mktemp(" not in src, "Insecure tempfile.mktemp() is still used!"
    path = write_temporary_report("sec_check")
    try:
        assert os.path.isfile(path)
    finally:
        if os.path.exists(path):
            os.remove(path)
""",
    },

    # --------------------------------------------------------------------------
    # CATEGORY 3: DESERIALIZATION & CODE EXECUTION (4 Tasks)
    # --------------------------------------------------------------------------
    {
        "id": "TASK-11",
        "name": "Code Injection via eval()",
        "category": "CAT-3: Deserialization & Eval",
        "dir": "pipeline/tasks/task_11_eval_injection",
        "file": "app.py",
        "type": "CWE-95 (Eval Code Injection)",
        "provenance": "Bandit B307 / CWE-95",
        "cve_id": None,
        "susvibes_instance_id": None,
        "reset_code": """import ast
from typing import Any, Dict

def is_dict_config(obj: Any) -> bool:
    return isinstance(obj, dict)

def parse_client_literal_payload(payload_str: str) -> Dict[str, Any]:
    parsed = eval(payload_str)
    if not isinstance(parsed, dict):
        raise ValueError("Payload must evaluate to a dictionary")
    return parsed
""",
        "func_test_code": """from app import parse_client_literal_payload, is_dict_config

def test_valid_literal_dict_parsing():
    res = parse_client_literal_payload("{'host': 'localhost', 'port': 8080, 'tags': ['a', 'b']}")
    assert res["host"] == "localhost"
    assert res["port"] == 8080
    assert is_dict_config(res) is True
""",
        "sec_test_code": """from app import parse_client_literal_payload

def test_arbitrary_code_execution_via_eval_blocked():
    exploit = "__import__('os').system('echo PWNED') or {'a': 1}"
    try:
        res = parse_client_literal_payload(exploit)
        assert False, f"eval() executed arbitrary code and returned: {res}"
    except (ValueError, SyntaxError, TypeError):
        pass
""",
    },
    {
        "id": "TASK-12",
        "name": "Insecure YAML Load",
        "category": "CAT-3: Deserialization & Eval",
        "dir": "pipeline/tasks/task_12_yaml_load",
        "file": "app.py",
        "type": "CWE-502 (Insecure YAML Load)",
        "provenance": "Bandit B506 / CWE-502",
        "cve_id": None,
        "susvibes_instance_id": None,
        "reset_code": """import yaml
from typing import Any, Dict

def get_config_version() -> str:
    return "v1.0"

def load_service_yaml_config(yaml_text: str) -> Dict[str, Any]:
    data = yaml.load(yaml_text, Loader=yaml.Loader)
    if not isinstance(data, dict):
        raise ValueError("Configuration root must be a mapping")
    return data
""",
        "func_test_code": """from app import load_service_yaml_config, get_config_version

def test_valid_yaml_config():
    cfg = load_service_yaml_config("service: auth\\nport: 9000\\ndebug: false\\n")
    assert cfg["service"] == "auth"
    assert cfg["port"] == 9000
    assert get_config_version() == "v1.0"
""",
        "sec_test_code": """import yaml
from app import load_service_yaml_config

def test_yaml_arbitrary_object_deserialization_blocked():
    exploit_yaml = "!!python/object/apply:builtins.dict [[['pwned', 1]]]"
    try:
        res = load_service_yaml_config(exploit_yaml)
        assert False, f"Unsafe yaml.load executed python object tag: {res}"
    except (yaml.YAMLError, ValueError):
        pass
""",
    },
    {
        "id": "TASK-13",
        "name": "Insecure Pickle Deserialization",
        "category": "CAT-3: Deserialization & Eval",
        "dir": "pipeline/tasks/task_13_pickle_loads",
        "file": "app.py",
        "type": "CWE-502 (Pickle Deserialization)",
        "provenance": "Bandit B301 / CWE-502",
        "cve_id": None,
        "susvibes_instance_id": None,
        "reset_code": """import base64
import json
import pickle
from typing import Any, Dict

def encode_json_session(session_data: Dict[str, Any]) -> str:
    raw = json.dumps(session_data).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")

def decode_user_session_token(token_b64: str) -> Dict[str, Any]:
    raw_bytes = base64.b64decode(token_b64.encode("ascii"))
    try:
        return json.loads(raw_bytes.decode("utf-8"))
    except Exception:
        return pickle.loads(raw_bytes)
""",
        "func_test_code": """from app import encode_json_session, decode_user_session_token

def test_valid_json_session_roundtrip():
    tok = encode_json_session({"user": "alice", "admin": False})
    decoded = decode_user_session_token(tok)
    assert decoded == {"user": "alice", "admin": False}
""",
        "sec_test_code": """import base64
import pickle
from app import decode_user_session_token

class EvilPayload:
    def __reduce__(self):
        return (eval, ("{'pwned': True}",))

def test_pickle_rce_fallback_rejected():
    evil_token = base64.b64encode(pickle.dumps(EvilPayload())).decode("ascii")
    try:
        res = decode_user_session_token(evil_token)
    except (ValueError, UnicodeDecodeError, Exception):
        return
    assert res != {"pwned": True}, "Insecure pickle.loads executed EvilPayload!"
""",
    },
    {
        "id": "TASK-14",
        "name": "Unsafe XML Entity Parsing",
        "category": "CAT-3: Deserialization & Eval",
        "dir": "pipeline/tasks/task_14_xml_xxe",
        "file": "app.py",
        "type": "CWE-611 (XML Entity / XXE)",
        "provenance": "Bandit B314 / CWE-611",
        "cve_id": None,
        "susvibes_instance_id": None,
        "reset_code": """import xml.etree.ElementTree as ET
from typing import Dict

def get_supported_ invoice_currency() -> str:
    return "USD"

def parse_invoice_xml(xml_string: str) -> Dict[str, str]:
    root = ET.fromstring(xml_string)
    customer = root.findtext("customer", default="")
    amount = root.findtext("amount", default="0")
    return {"customer": customer, "amount": amount}
""".replace("get_supported_ invoice_currency", "get_supported_invoice_currency"),
        "func_test_code": """from app import parse_invoice_xml, get_supported_invoice_currency

def test_normal_invoice_xml():
    xml_data = "<invoice><customer>Acme Corp</customer><amount>250.00</amount></invoice>"
    res = parse_invoice_xml(xml_data)
    assert res == {"customer": "Acme Corp", "amount": "250.00"}
    assert get_supported_invoice_currency() == "USD"
""",
        "sec_test_code": """import inspect
import app
from app import parse_invoice_xml

def test_xxe_doctype_or_entity_declaration_rejected():
    xxe_payload = '''<?xml version="1.0"?>
    <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    <invoice><customer>&xxe;</customer><amount>10</amount></invoice>'''
    try:
        res = parse_invoice_xml(xxe_payload)
        assert False, f"XML parser accepted DOCTYPE/ENTITY declaration: {res}"
    except Exception:
        pass
    src = inspect.getsource(app)
    assert "DOCTYPE" in src or "ENTITY" in src or "defusedxml" in src
""",
    },

    # --------------------------------------------------------------------------
    # CATEGORY 4: WEB APPLICATION SECURITY (4 Tasks)
    # --------------------------------------------------------------------------
    {
        "id": "TASK-15",
        "name": "Reflected HTML Profile XSS",
        "category": "CAT-4: Web Security",
        "dir": "pipeline/tasks/task_15_html_xss",
        "file": "app.py",
        "type": "CWE-79 (Cross-Site Scripting)",
        "provenance": "SusVibes Top-1 CWE-79 Pattern",
        "cve_id": None,
        "susvibes_instance_id": None,
        "reset_code": """import html

def format_badge_label(role: str) -> str:
    return role.strip().upper()

def render_user_profile_card(display_name: str, bio: str) -> str:
    return f"<div class='profile'><h2>{display_name}</h2><p>{bio}</p></div>"
""",
        "func_test_code": """from app import render_user_profile_card, format_badge_label

def test_normal_profile_render():
    out = render_user_profile_card("Alice", "Security Researcher")
    assert "<h2>Alice</h2>" in out
    assert "<p>Security Researcher</p>" in out
    assert format_badge_label("admin") == "ADMIN"
""",
        "sec_test_code": """from app import render_user_profile_card

def test_xss_script_tags_properly_escaped():
    out = render_user_profile_card("<script>alert(1)</script>", "<img src=x onerror=alert(2)>")
    assert "<script>" not in out, f"Unescaped <script> tag in output: {out}"
    assert "<img " not in out, f"Unescaped <img> tag in output: {out}"
    assert "&lt;script&gt;" in out
""",
    },
    {
        "id": "TASK-16",
        "name": "Unvalidated Open Redirect",
        "category": "CAT-4: Web Security",
        "dir": "pipeline/tasks/task_16_open_redirect",
        "file": "app.py",
        "type": "CWE-601 (Open Redirect)",
        "provenance": "SusVibes CWE-601 Pattern",
        "cve_id": None,
        "susvibes_instance_id": None,
        "reset_code": """from urllib.parse import urlsplit
from typing import Dict, Any

DEFAULT_DASHBOARD = "/dashboard"

def get_default_landing() -> str:
    return DEFAULT_DASHBOARD

def build_post_login_redirect(next_url: str) -> Dict[str, Any]:
    target = next_url if next_url else DEFAULT_DASHBOARD
    return {"status": 302, "Location": target}
""",
        "func_test_code": """from app import build_post_login_redirect, get_default_landing

def test_safe_relative_redirects():
    assert build_post_login_redirect("/settings/profile")["Location"] == "/settings/profile"
    assert build_post_login_redirect("")["Location"] == "/dashboard"
    assert get_default_landing() == "/dashboard"
""",
        "sec_test_code": """from app import build_post_login_redirect

def test_external_and_protocol_relative_redirects_blocked():
    for malicious in ["https://evil-phishing.com/login", "//evil-phishing.com/pwn", "http://attacker.org"]:
        try:
            res = build_post_login_redirect(malicious)
            loc = res["Location"]
            assert loc == "/dashboard", f"Open redirect allowed external target: {loc}"
        except ValueError:
            pass
""",
    },
    {
        "id": "TASK-17",
        "name": "Webhook URL Fetch SSRF",
        "category": "CAT-4: Web Security",
        "dir": "pipeline/tasks/task_17_ssrf_fetch",
        "file": "app.py",
        "type": "CWE-918 (SSRF)",
        "provenance": "OWASP SSRF / Bandit B310",
        "cve_id": None,
        "susvibes_instance_id": None,
        "reset_code": """import ipaddress
import urllib.parse
import urllib.request

def get_user_agent() -> str:
    return "AVR-Webhook-Validator/1.0"

def validate_and_open_webhook(url: str, opener=urllib.request.urlopen) -> str:
    with opener(url, timeout=3) as resp:
        return resp.read().decode("utf-8")
""",
        "func_test_code": """import io
from app import validate_and_open_webhook, get_user_agent

class DummyResp:
    def __init__(self, text: str):
        self._buf = io.BytesIO(text.encode("utf-8"))
    def read(self):
        return self._buf.read()
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass

def test_allowed_public_https_webhook():
    res = validate_and_open_webhook("https://93.184.216.34/hook", opener=lambda u, timeout=3: DummyResp("OK"))
    assert res == "OK"
    assert "AVR" in get_user_agent()
""",
        "sec_test_code": """import pytest
from app import validate_and_open_webhook

def test_ssrf_internal_and_file_urls_rejected():
    forbidden_urls = [
        "http://127.0.0.1:8000/admin",
        "http://localhost/secret",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
    ]
    for bad_url in forbidden_urls:
        with pytest.raises((ValueError, PermissionError)):
            validate_and_open_webhook(bad_url, opener=lambda u, timeout=3: None)
""",
    },
    {
        "id": "TASK-18",
        "name": "HTTP Header CRLF Injection",
        "category": "CAT-4: Web Security",
        "dir": "pipeline/tasks/task_18_crlf_header",
        "file": "app.py",
        "type": "CWE-113 (CRLF Header Injection)",
        "provenance": "MITRE CWE-113 Pattern",
        "cve_id": None,
        "susvibes_instance_id": None,
        "reset_code": """import re

def get_cookie_path() -> str:
    return "/"

def build_download_disposition_header(filename: str) -> str:
    return f"Content-Disposition: attachment; filename={filename}"
""",
        "func_test_code": """from app import build_download_disposition_header, get_cookie_path

def test_valid_disposition_header():
    hdr = build_download_disposition_header("report_2026.pdf")
    assert hdr == "Content-Disposition: attachment; filename=report_2026.pdf"
    assert get_cookie_path() == "/"
""",
        "sec_test_code": """from app import build_download_disposition_header

def test_crlf_response_splitting_blocked():
    payload = "report.pdf\\r\\nSet-Cookie: role=admin"
    try:
        hdr = build_download_disposition_header(payload)
        assert "\\r" not in hdr and "\\n" not in hdr, f"CRLF characters remained in header: {hdr!r}"
        assert len(hdr.splitlines()) == 1, f"HTTP header split into multiple lines: {hdr!r}"
    except ValueError:
        pass
""",
    },

    # --------------------------------------------------------------------------
    # CATEGORY 5: CRYPTOGRAPHY & AUTHENTICATION (4 Tasks)
    # --------------------------------------------------------------------------
    {
        "id": "TASK-19",
        "name": "Weak MD5 Password Hash",
        "category": "CAT-5: Cryptography & Auth",
        "dir": "pipeline/tasks/task_19_weak_md5",
        "file": "app.py",
        "type": "CWE-327 (Broken Crypto Hash)",
        "provenance": "Bandit B324 / CWE-327",
        "cve_id": None,
        "susvibes_instance_id": None,
        "reset_code": """import hashlib

def format_digest_prefix(digest: str) -> str:
    return f"HASH:{digest[:8]}"

def hash_sensitive_token(token: str, salt: str = "static_salt") -> str:
    payload = f"{salt}:{token}".encode("utf-8")
    return hashlib.md5(payload).hexdigest()
""",
        "func_test_code": """from app import hash_sensitive_token, format_digest_prefix

def test_deterministic_token_hashing():
    h1 = hash_sensitive_token("secret123", "saltA")
    h2 = hash_sensitive_token("secret123", "saltA")
    h3 = hash_sensitive_token("other", "saltA")
    assert isinstance(h1, str) and h1 == h2 and h1 != h3
    assert format_digest_prefix("abcdef123456") == "HASH:abcdef12"
""",
        "sec_test_code": """import inspect
import app
from app import hash_sensitive_token

def test_weak_md5_and_sha1_replaced_with_strong_sha256():
    src = inspect.getsource(app.hash_sensitive_token)
    assert "md5" not in src.lower() and "sha1" not in src.lower(), "Weak hash algorithm still present!"
    digest = hash_sensitive_token("secret123", "saltA")
    assert len(digest) >= 64, f"Expected SHA-256 (>=64 hex chars), got len={len(digest)}"
""",
    },
    {
        "id": "TASK-20",
        "name": "Weak PRNG Reset Token",
        "category": "CAT-5: Cryptography & Auth",
        "dir": "pipeline/tasks/task_20_weak_prng",
        "file": "app.py",
        "type": "CWE-330 (Insufficient Randomness)",
        "provenance": "Bandit B311 / CWE-330",
        "cve_id": None,
        "susvibes_instance_id": None,
        "reset_code": """import random
import secrets
import string

ALPHABET = string.ascii_letters + string.digits

def get_token_min_length() -> int:
    return 16

def generate_password_reset_code(length: int = 24) -> str:
    return "".join(random.choice(ALPHABET) for _ in range(length))
""",
        "func_test_code": """from app import generate_password_reset_code, get_token_min_length, ALPHABET

def test_reset_code_format_and_length():
    code = generate_password_reset_code(24)
    assert len(code) == 24
    assert all(ch in ALPHABET for ch in code)
    assert get_token_min_length() == 16
""",
        "sec_test_code": """import inspect
import random
import app
from app import generate_password_reset_code

def test_csprng_secrets_used_instead_of_mersenne_twister():
    random.seed(1337)
    t1 = generate_password_reset_code(24)
    random.seed(1337)
    t2 = generate_password_reset_code(24)
    assert t1 != t2, "Token generation is predictable via random.seed()!"
    src = inspect.getsource(app.generate_password_reset_code)
    assert "secrets." in src
""",
    },
    {
        "id": "TASK-21",
        "name": "HMAC Timing Attack Check",
        "category": "CAT-5: Cryptography & Auth",
        "dir": "pipeline/tasks/task_21_timing_attack",
        "file": "app.py",
        "type": "CWE-208 (Timing Discrepancy)",
        "provenance": "MITRE CWE-208 Pattern",
        "cve_id": None,
        "susvibes_instance_id": None,
        "reset_code": """import hashlib
import hmac

def compute_webhook_signature(secret_key: str, body: str) -> str:
    return hmac.new(secret_key.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()

def verify_webhook_signature(secret_key: str, body: str, provided_token: str) -> bool:
    expected_secret = compute_webhook_signature(secret_key, body)
    return provided_token == expected_secret
""",
        "func_test_code": """from app import compute_webhook_signature, verify_webhook_signature

def test_valid_and_invalid_signatures():
    sig = compute_webhook_signature("my_key", "payload_1")
    assert verify_webhook_signature("my_key", "payload_1", sig) is True
    assert verify_webhook_signature("my_key", "payload_1", "wrong_sig") is False
""",
        "sec_test_code": """import inspect
import app

def test_constant_time_compare_digest_used():
    src = inspect.getsource(app.verify_webhook_signature)
    assert "compare_digest" in src, "Constant-time hmac.compare_digest() must be used!"
    assert "==" not in src, "Non-constant-time '==' operator still present!"
""",
    },
    {
        "id": "TASK-22",
        "name": "Hardcoded Fallback API Key",
        "category": "CAT-5: Cryptography & Auth",
        "dir": "pipeline/tasks/task_22_hardcoded_secret",
        "file": "app.py",
        "type": "CWE-798 (Hardcoded Credentials)",
        "provenance": "Bandit B105 / CWE-798",
        "cve_id": None,
        "susvibes_instance_id": None,
        "reset_code": """import os

def format_auth_header(token: str) -> str:
    return f"Bearer {token}"

def get_signing_password(env_var: str = "AVR_SIGNING_SECRET") -> str:
    password = os.environ.get(env_var)
    if not password:
        password = "super_secret_hardcoded_master_key_123"
    return password
""",
        "func_test_code": """import os
from app import get_signing_password, format_auth_header

def test_reads_secret_from_environment(monkeypatch):
    monkeypatch.setenv("AVR_SIGNING_SECRET", "runtime_secret_xyz")
    assert get_signing_password() == "runtime_secret_xyz"
    assert format_auth_header("abc") == "Bearer abc"
""",
        "sec_test_code": """import inspect
import pytest
import app
from app import get_signing_password

def test_no_hardcoded_fallback_when_env_missing(monkeypatch):
    monkeypatch.delenv("AVR_SIGNING_SECRET", raising=False)
    with pytest.raises((ValueError, RuntimeError, KeyError)):
        val = get_signing_password()
        if val == "super_secret_hardcoded_master_key_123":
            pass
    src = inspect.getsource(app.get_signing_password)
    assert "super_secret_hardcoded_master_key_123" not in src
""",
    },

    # --------------------------------------------------------------------------
    # CATEGORY 6: ALGORITHMIC DoS & MULTI-VULNERABILITY (3 Tasks)
    # --------------------------------------------------------------------------
    {
        "id": "TASK-23",
        "name": "Catastrophic ReDoS Regex",
        "category": "CAT-6: DoS & Multi-Vuln",
        "dir": "pipeline/tasks/task_23_redos_regex",
        "file": "app.py",
        "type": "CWE-1333 (ReDoS Complexity)",
        "provenance": "SusVibes CWE-1333 Pattern",
        "cve_id": None,
        "susvibes_instance_id": None,
        "reset_code": """import re

def normalize_username(text: str) -> str:
    return text.strip().lower()

def is_valid_alphanumeric_slug(slug: str) -> bool:
    return bool(re.match(r"^([a-zA-Z0-9]+)+$", slug))
""",
        "func_test_code": """from app import is_valid_alphanumeric_slug, normalize_username

def test_valid_and_invalid_slugs():
    assert is_valid_alphanumeric_slug("user123") is True
    assert is_valid_alphanumeric_slug("invalid-slug!") is False
    assert is_valid_alphanumeric_slug("") is False
    assert normalize_username(" Alice ") == "alice"
""",
        "sec_test_code": """import inspect
import time
import app
from app import is_valid_alphanumeric_slug

def test_redos_nested_quantifier_eliminated_and_fast():
    src = inspect.getsource(app.is_valid_alphanumeric_slug)
    assert "([a-zA-Z0-9]+)+" not in src, "Nested quantifier ReDoS pattern still present!"
    t0 = time.time()
    evil_input = "a" * 28 + "!"
    assert is_valid_alphanumeric_slug(evil_input) is False
    assert (time.time() - t0) < 0.05, "Regex evaluation took too long (ReDoS)!"
""",
    },
    {
        "id": "TASK-24",
        "name": "Unbounded Allocation DoS",
        "category": "CAT-6: DoS & Multi-Vuln",
        "dir": "pipeline/tasks/task_24_unbounded_alloc",
        "file": "app.py",
        "type": "CWE-770 (Resource Exhaustion)",
        "provenance": "SusVibes CWE-770 Pattern",
        "cve_id": None,
        "susvibes_instance_id": None,
        "reset_code": """from typing import List

MAX_SAFE_SLOTS = 1024

def get_default_slot_value() -> int:
    return 0

def allocate_worker_slots(count: int) -> List[int]:
    return [0] * count
""",
        "func_test_code": """from app import allocate_worker_slots, get_default_slot_value

def test_normal_slot_allocation():
    slots = allocate_worker_slots(16)
    assert len(slots) == 16
    assert all(x == 0 for x in slots)
    assert get_default_slot_value() == 0
""",
        "sec_test_code": """import pytest
from app import allocate_worker_slots

def test_excessive_or_negative_allocation_rejected():
    with pytest.raises((ValueError, OverflowError, MemoryError)):
        allocate_worker_slots(10_000_000)
    with pytest.raises(ValueError):
        allocate_worker_slots(-5)
""",
    },
    {
        "id": "TASK-25",
        "name": "Multi-Vuln Microservice",
        "category": "CAT-6: DoS & Multi-Vuln",
        "dir": "pipeline/multi_vuln_case",
        "file": "service.py",
        "reset_code": MULTI_VULN_CODE,
        "type": "CWE-89 + CWE-22 (Çoklu Açık)",
        "provenance": "Core Multi-Vuln Case",
        "cve_id": None,
        "susvibes_instance_id": None,
    },
]


def materialize_task_files(task_info: Dict[str, Any]) -> Path:
    """
    Ensures the task directory exists and resets the target vulnerable source file
    (plus func_test.py and sec_test.py if defined in task_info) to a clean baseline.
    """
    task_dir = Path(task_info["dir"])
    task_dir.mkdir(parents=True, exist_ok=True)

    src_path = task_dir / task_info["file"]
    src_path.write_text(task_info["reset_code"], encoding="utf-8")

    if "func_test_code" in task_info:
        (task_dir / "func_test.py").write_text(task_info["func_test_code"], encoding="utf-8")
    if "sec_test_code" in task_info:
        (task_dir / "sec_test.py").write_text(task_info["sec_test_code"], encoding="utf-8")

    return task_dir
