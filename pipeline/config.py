"""Central cross-platform configuration for the Autonomous Vulnerability Repair (AVR) pipeline."""

from dataclasses import dataclass, field
import os
import platform
from typing import Dict


def detect_runtime_environment() -> Dict[str, str]:
    """Returns portable OS, architecture, and accelerator metadata for reporting."""
    system = platform.system()
    machine = platform.machine()
    py_ver = platform.python_version()

    accelerator = "CPU / External Runtime"
    if system == "Darwin" and machine == "arm64":
        accelerator = "Apple Silicon (arm64)"
    elif system == "Windows":
        accelerator = f"Windows ({machine})"
    else:
        accelerator = f"{system} ({machine})"

    return {
        "os": system,
        "os_release": platform.release(),
        "arch": machine,
        "python_version": py_ver,
        "hardware_hint": accelerator,
    }


@dataclass
class AVRConfig:
    """Configuration container configurable via constructor args or environment variables."""

    # LLM synthesis settings
    backend: str = field(default_factory=lambda: os.environ.get("AVR_BACKEND", "ollama"))
    model_name: str = field(
        default_factory=lambda: os.environ.get("AVR_MODEL", "qwen2.5-coder:7b")
    )
    ollama_base_url: str = field(
        default_factory=lambda: os.environ.get("AVR_OLLAMA_URL", "http://localhost:11434")
    )
    llm_timeout: int = field(
        default_factory=lambda: int(os.environ.get("AVR_LLM_TIMEOUT", "180"))
    )
    temperature: float = field(
        default_factory=lambda: float(os.environ.get("AVR_TEMPERATURE", "0.2"))
    )
    top_p: float = field(
        default_factory=lambda: float(os.environ.get("AVR_TOP_P", "0.95"))
    )

    # Self-healing loop settings
    max_turns: int = field(
        default_factory=lambda: int(os.environ.get("AVR_MAX_TURNS", "3"))
    )
    rollback_on_failure: bool = True

    # Docker Sealed Sandbox settings
    docker_image: str = field(
        default_factory=lambda: os.environ.get("AVR_DOCKER_IMAGE", "bitirme-sandbox")
    )
    sandbox_timeout: int = field(
        default_factory=lambda: int(os.environ.get("AVR_SANDBOX_TIMEOUT", "30"))
    )
    sandbox_memory: str = field(
        default_factory=lambda: os.environ.get("AVR_SANDBOX_MEMORY", "512m")
    )
    sandbox_cpus: str = field(
        default_factory=lambda: os.environ.get("AVR_SANDBOX_CPUS", "1.0")
    )
    sandbox_pids_limit: int = field(
        default_factory=lambda: int(os.environ.get("AVR_SANDBOX_PIDS", "64"))
    )
    parallel_verification: bool = field(
        default_factory=lambda: os.environ.get("AVR_PARALLEL_VERIFY", "true").lower()
        in ("1", "true", "yes")
    )
