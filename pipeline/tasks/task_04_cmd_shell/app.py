import subprocess
import sys
from typing import Dict

def normalize_label(label: str) -> str:
    return label.strip().upper()

def run_echo_diagnostic(token: str) -> Dict[str, str]:
    cmd = f'"{sys.executable}" -c "print(\'DIAG_OK:\' + \'{token}\')"'
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return {
        "returncode": str(proc.returncode),
        "output": proc.stdout.strip(),
    }
