from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import platform
import shutil
import subprocess
from typing import Tuple, Dict, Any, List
import uuid


class DockerSandbox:
    """
    Docker Sealed Sandbox:
    - Ağ izolasyonu (--network none)
    - Bellek, CPU ve süreç (PID) sınırları
    - Salt-okunur kod bağlama (/app:ro) + salt-okunur kök dosya sistemi (--read-only) + geçici /tmp
    - Timeout ve sonsuz döngü durumunda zorunlu konteyner temizliği (docker rm -f)
    - ThreadPoolExecutor ile gerçek paralel çift doğrulama (func_test & sec_test)
    - Windows ve macOS (Intel / Apple Silicon) çapraz platform uyumu
    """

    def __init__(
        self,
        image_name: str = "bitirme-sandbox",
        timeout: int = 30,
        memory_limit: str = "512m",
        cpu_limit: str = "1.0",
        pids_limit: int = 64,
        parallel: bool = True,
    ):
        self.image_name = image_name
        self.timeout = timeout
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.pids_limit = pids_limit
        self.parallel = parallel
        self.docker_bin = self._find_docker()

    def _find_docker(self) -> str:
        """Sistemdeki Docker CLI yolunu Windows, macOS ve Linux üzerinde otomatik bulur."""
        docker_path = shutil.which("docker")
        if docker_path:
            return docker_path

        system = platform.system()
        candidates: List[Path] = []

        if system == "Windows":
            local_app_data = os.environ.get("LOCALAPPDATA", "")
            program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
            if local_app_data:
                candidates.append(
                    Path(local_app_data) / "Programs/DockerDesktop/resources/bin/docker.exe"
                )
            candidates.append(Path(program_files) / "Docker/Docker/resources/bin/docker.exe")
        elif system == "Darwin":
            candidates.extend([
                Path.home() / ".docker/bin/docker",
                Path("/usr/local/bin/docker"),
                Path("/opt/homebrew/bin/docker"),
                Path("/Applications/Docker.app/Contents/Resources/bin/docker"),
            ])
        else:
            candidates.extend([
                Path("/usr/bin/docker"),
                Path("/usr/local/bin/docker"),
            ])

        for candidate in candidates:
            if candidate.exists():
                bin_dir = str(candidate.parent)
                current_path = os.environ.get("PATH", "")
                if bin_dir not in current_path.split(os.pathsep):
                    os.environ["PATH"] = bin_dir + os.pathsep + current_path
                return str(candidate)

        return "docker"

    def is_daemon_running(self) -> bool:
        """Docker Engine (Docker Desktop) servisinin çalışır durumda olup olmadığını kontrol eder."""
        try:
            res = subprocess.run(
                [self.docker_bin, "info"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
            return res.returncode == 0
        except Exception:
            return False

    def verify_docker_ready(self, auto_build: bool = True) -> None:
        """
        Docker Engine'in açık olduğunu ve sandbox imajının hazır olduğunu doğrular.
        Docker kapalıysa sessizce yerel ortama düşmek yerine açık RuntimeError fırlatır!
        """
        if not self.is_daemon_running():
            raise RuntimeError(
                "\n" + "!" * 76 + "\n"
                "🚨 [KRİTİK HATA] DOCKER ENGINE (DOCKER DESKTOP) ÇALIŞMIYOR!\n"
                "Sealed Sandbox (--network none, --read-only) doğrulaması Docker olmadan yapılamaz.\n"
                "Lütfen Docker Desktop uygulamasını başlatın ve Engine hazır olduğunda tekrar deneyin.\n"
                + "!" * 76
            )
        if not self.ensure_image(auto_build=auto_build):
            raise RuntimeError(
                f"Docker imajı '{self.image_name}' bulunamadı ve otomatik oluşturulamadı. "
                f"Lütfen 'docker build -t {self.image_name} pipeline/sandbox' komutunu çalıştırın."
            )

    def ensure_image(self, auto_build: bool = False) -> bool:
        """Sandbox Docker imajının yerel olarak mevcut olup olmadığını kontrol eder."""
        inspect = subprocess.run(
            [self.docker_bin, "image", "inspect", self.image_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if inspect.returncode == 0:
            return True

        if not auto_build:
            return False

        sandbox_dir = Path(__file__).parent
        build_res = subprocess.run(
            [self.docker_bin, "build", "-t", self.image_name, str(sandbox_dir)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            check=False,
        )
        return build_res.returncode == 0

    def _build_docker_cmd(
        self, mount_path: str, test_file: str, container_name: str
    ) -> List[str]:
        """Sealed Sandbox güvenlik bayraklarıyla docker run komutunu oluşturur."""
        return [
            self.docker_bin,
            "run",
            "--rm",
            "--name", container_name,
            "--network", "none",
            "--memory", self.memory_limit,
            "--memory-swap", self.memory_limit,
            "--cpus", str(self.cpu_limit),
            "--pids-limit", str(self.pids_limit),
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--read-only",
            "--tmpfs", "/tmp:rw,nosuid,size=64m",
            "-e", "PYTHONDONTWRITEBYTECODE=1",
            "-v", f"{mount_path}:/app:ro",
            self.image_name,
            "pytest", test_file, "-q", "-o", "cache_dir=/tmp/pytest_cache",
        ]

    def _cleanup_container(self, container_name: str) -> None:
        """Timeout veya kesinti sonrasında asılı kalabilecek konteyneri zorla siler."""
        try:
            subprocess.run(
                [self.docker_bin, "rm", "-f", container_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
        except Exception:
            pass

    def run_pytest(self, task_dir: str, test_file: str) -> Tuple[bool, str]:
        """
        Verilen test dosyasını yalıtılmış (sealed) Docker konteyneri içinde çalıştırır.
        Dönüş: (başarılı_mı, konsol_çıktısı)
        """
        abs_task_dir = Path(task_dir).resolve()
        # Windows ve POSIX yollarını Docker volume formatına normalize et
        mount_path = str(abs_task_dir).replace("\\", "/")
        container_name = f"avr-sandbox-{uuid.uuid4().hex[:12]}"
        cmd = self._build_docker_cmd(mount_path, test_file, container_name)

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=False,
            )
            passed = result.returncode == 0
            output = (result.stdout + "\n" + result.stderr).strip()

            lower_out = output.lower()
            daemon_unavailable = any(
                marker in lower_out
                for marker in (
                    "failed to connect to the docker api",
                    "dockerdesktoplinuxengine",
                    "cannot connect to the docker daemon",
                    "error during connect",
                    "is the docker daemon running",
                )
            )
            if not passed and daemon_unavailable:
                err_msg = (
                    "🚨 [KRİTİK HATA] DOCKER ENGINE KAPALI! "
                    "Testler yerel ortamda ÇALIŞTIRILMADI (Sessiz fallback devre dışı). "
                    "Lütfen Docker Desktop'ı başlatın!\n" + output
                )
                print(f"\n  [!] {err_msg}")
                return False, err_msg

            return passed, output

        except subprocess.TimeoutExpired as exc:
            self._cleanup_container(container_name)
            stdout_part = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr_part = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            timeout_msg = (
                f"SANDBOX TIMEOUT ({self.timeout}s): '{test_file}' yürütmesi süre sınırını aştı "
                f"(olası sonsuz döngü veya aşırı kaynak tüketimi). Konteyner sonlandırıldı."
            )
            combined = "\n".join(p for p in [timeout_msg, stdout_part.strip(), stderr_part.strip()] if p)
            return False, combined

        except FileNotFoundError:
            return False, (
                f"Docker CLI bulunamadı ('{self.docker_bin}'). "
                "Lütfen Docker Desktop'ın kurulu ve çalışır durumda olduğunu doğrulayın."
            )

    def run_dual_verification(
        self, task_dir: str, parallel: bool | None = None
    ) -> Dict[str, Any]:
        """
        Çift Doğrulama (Dual-Verification):
        1. func_test.py (Orijinal işlevsellik / regresyon testi)
        2. sec_test.py (Exploit / güvenlik açığı testi)

        UML v3 'par' bloğuna uygun olarak varsayılan şekilde ThreadPoolExecutor ile
        paralel yürütülür (salt-okunur /app:ro bağlama sayesinde yarış koşulu yoktur).
        """
        use_parallel = self.parallel if parallel is None else parallel

        if use_parallel:
            with ThreadPoolExecutor(max_workers=2) as executor:
                func_future = executor.submit(self.run_pytest, task_dir, "func_test.py")
                sec_future = executor.submit(self.run_pytest, task_dir, "sec_test.py")
                func_passed, func_log = func_future.result()
                sec_passed, sec_log = sec_future.result()
        else:
            func_passed, func_log = self.run_pytest(task_dir, "func_test.py")
            sec_passed, sec_log = self.run_pytest(task_dir, "sec_test.py")

        return {
            "func_pass": func_passed,
            "func_output": func_log,
            "sec_pass": sec_passed,
            "sec_output": sec_log,
            "all_passed": (func_passed and sec_passed),
            "execution_mode": "parallel" if use_parallel else "sequential",
        }


if __name__ == "__main__":
    sandbox = DockerSandbox()
    res = sandbox.run_dual_verification("pipeline/sample_task")
    print(f"Mod: {res['execution_mode']}")
    print(f"func_test (İşlevsellik): {'PASS' if res['func_pass'] else 'FAIL'}")
    print(f"sec_test (Güvenlik): {'PASS' if res['sec_pass'] else 'FAIL'}")
    print(f"Tüm Testler Başarılı mı: {res['all_passed']}")
