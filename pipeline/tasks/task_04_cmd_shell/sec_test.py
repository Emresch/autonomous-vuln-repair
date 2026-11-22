import subprocess
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
