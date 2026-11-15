import subprocess
import os
import shutil
from pathlib import Path
from typing import Tuple, Dict, Any

class DockerSandbox:
    def __init__(self, image_name: str = "bitirme-sandbox"):
        self.image_name = image_name
        self.docker_bin = self._find_docker()

    def _find_docker(self) -> str:
        """Sistemdeki docker.exe yolunu bulur ve PATH'e ekler."""
        docker_path = shutil.which("docker")
        if not docker_path:
            local_app_data = os.environ.get("LOCALAPPDATA", "")
            candidate = Path(local_app_data) / "Programs/DockerDesktop/resources/bin/docker.exe"
            if candidate.exists():
                docker_path = str(candidate)
                # Docker yardımcı programları için bin klasörünü PATH'e ekle
                bin_dir = str(candidate.parent)
                if bin_dir not in os.environ.get("PATH", ""):
                    os.environ["PATH"] = bin_dir + ";" + os.environ.get("PATH", "")
        return docker_path or "docker"

    def run_pytest(self, task_dir: str, test_file: str) -> Tuple[bool, str]:
        """
        Verilen test dosyasını izole Docker konteyneri içinde çalıştırır.
        Dönüş: (başarılı_mı, konsol_çıktısı)
        """
        abs_task_dir = Path(task_dir).resolve()
        # Windows path'ini Docker volume formatına çevir (örn: C:/Users/... -> c:/users/...)
        mount_path = str(abs_task_dir).replace("\\", "/")

        cmd = [
            self.docker_bin,
            "run", "--rm",
            "-v", f"{mount_path}:/app",
            self.image_name,
            "pytest", test_file, "-q"
        ]

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8"
        )

        passed = (result.returncode == 0)
        output = result.stdout + "\n" + result.stderr
        return passed, output.strip()

    def run_dual_verification(self, task_dir: str) -> Dict[str, Any]:
        """
        Çift Doğrulama (Dual-Verification):
        1. func_test.py (Orijinal işlevsellik / regresyon testi)
        2. sec_test.py (Exploit / güvenlik açığı testi)
        """
        func_passed, func_log = self.run_pytest(task_dir, "func_test.py")
        sec_passed, sec_log = self.run_pytest(task_dir, "sec_test.py")

        return {
            "func_pass": func_passed,
            "func_output": func_log,
            "sec_pass": sec_passed,
            "sec_output": sec_log,
            "all_passed": (func_passed and sec_passed)
        }

if __name__ == "__main__":
    sandbox = DockerSandbox()
    res = sandbox.run_dual_verification("pipeline/sample_task")
    print(f"func_test (İşlevsellik): {'PASS' if res['func_pass'] else 'FAIL'}")
    print(f"sec_test (Güvenlik): {'PASS' if res['sec_pass'] else 'FAIL'}")
    print(f"Tüm Testler Başarılı mı: {res['all_passed']}")
