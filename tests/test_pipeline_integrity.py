import json
from pathlib import Path
import subprocess
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

from pipeline.benchmark.benchmark_ingestion import BenchmarkIngestion
from pipeline.config import AVRConfig
from pipeline.controller import SelfHealingController
from pipeline.pruner.ast_pruner import ASTContextPruner
from pipeline.sandbox.docker_runner import DockerSandbox
from pipeline.synthesizer.synthesizer import (
    BaseLLMBackend,
    GenerationResult,
    PatchSynthesizer,
    TransformersBackend,
)


class ScriptedMockBackend(BaseLLMBackend):
    """Deterministik birim testleri için önceden tanımlı yanıtlar dönen sahte LLM arka ucu."""

    backend_name = "mock-transformers"

    def __init__(self, responses: List[str], confidence: float = 0.91, entropy: float = 0.18):
        super().__init__(model_name="mock-qwen-coder")
        self._responses = list(responses)
        self.confidence = confidence
        self.entropy = entropy
        self.received_histories: List[List[Dict[str, str]]] = []

    def generate(self, messages: List[Dict[str, str]], temperature=None) -> GenerationResult:
        # Konuşma geçmişinin derin kopyasını kaydet
        self.received_histories.append([dict(m) for m in messages])
        raw = self._responses.pop(0) if self._responses else ""
        return GenerationResult(
            raw_response=raw,
            extracted_code=PatchSynthesizer.extract_code_block(raw),
            duration_seconds=0.05,
            backend=self.backend_name,
            model_name=self.model_name,
            confidence_score=self.confidence,
            entropy=self.entropy,
            attention_summary={"focused_token": "execute", "peak_weight": 0.74},
            token_count=42,
        )


class MockSASTEngine:
    def __init__(self, findings: List[Dict[str, Any]]):
        self._findings = findings

    def scan(self, target=None) -> List[Dict[str, Any]]:
        return list(self._findings)


class LocalPytestSandbox:
    """Docker olmadan yerel pytest ile controller davranışını deterministik test eden sandbox."""

    parallel = True

    def __init__(self, verifier_fn):
        self.verifier_fn = verifier_fn
        self.calls = 0

    def run_dual_verification(self, task_dir: str, parallel=None) -> Dict[str, Any]:
        self.calls += 1
        return self.verifier_fn(Path(task_dir), self.calls)


def test_syntax_guard_prevents_disk_corruption_and_self_heals(tmp_path: Path):
    """
    Tur 1: Model SyntaxError içeren yama üretir -> diske yazılmaz, AST patlamaz.
    Tur 2: Model önceki hatalı yamayı (assistant) + SyntaxError geri bildirimini (user) görür
           ve geçerli yamayı üretip testi geçer.
    """
    app_file = tmp_path / "app.py"
    original_code = (
        "def get_user(conn, username):\n"
        "    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
        "    return conn.execute(query)\n"
    )
    app_file.write_text(original_code, encoding="utf-8")

    broken_turn1 = "```python\ndef get_user(conn, username)\n    return None\n```"  # eksik ':'
    fixed_turn2 = (
        "```python\ndef get_user(conn, username):\n"
        "    return conn.execute('SELECT * FROM users WHERE username = ?', (username,))\n```"
    )

    mock_backend = ScriptedMockBackend([broken_turn1, fixed_turn2])
    synthesizer = PatchSynthesizer(llm_backend=mock_backend)
    sast = MockSASTEngine([
        {
            "engine": "Bandit",
            "tool": "bandit",
            "filename": str(app_file),
            "file_path": str(app_file),
            "line_number": 2,
            "test_id": "B608",
            "cwe": "CWE-89",
            "issue_text": "SQL injection risk",
        }
    ])

    def verify(task_dir: Path, call_num: int):
        code = (task_dir / "app.py").read_text(encoding="utf-8")
        if call_num == 1:
            return {"func_pass": True, "sec_pass": False, "func_output": "ok", "sec_output": "SQLi!"}
        is_fixed = "?" in code and "f\"" not in code
        return {
            "func_pass": True,
            "sec_pass": is_fixed,
            "func_output": "ok",
            "sec_output": "ok" if is_fixed else "SQLi!",
            "execution_mode": "parallel",
        }

    controller = SelfHealingController(
        task_dir=str(tmp_path),
        target_file="app.py",
        config=AVRConfig(max_turns=3),
        sast=sast,
        synthesizer=synthesizer,
        sandbox=LocalPytestSandbox(verify),
    )
    report = controller.run()

    assert report["repaired"] is True
    assert report["turns_used"] == 2
    assert report["turn_history"][0]["stage_failed"] == "SYNTAX_OR_LLM_ERROR"
    assert report["turn_history"][0]["patches"][0]["syntax_valid"] is False
    # Tur 2'deki konuşma geçmişi önceki başarısız yamayı 'assistant' rolüyle içermeli
    turn2_messages = mock_backend.received_histories[1]
    roles = [m["role"] for m in turn2_messages]
    assert roles == ["system", "user", "assistant", "user"]
    assert "def get_user(conn, username)" in turn2_messages[2]["content"]
    assert "SyntaxError" in turn2_messages[3]["content"]
    # Telemetri ve unified_diff kaydedilmeli
    assert report["llm_metrics_summary"]["mean_confidence_score"] == 0.91
    assert report["llm_metrics_summary"]["mean_entropy"] == 0.18
    assert report["unified_diff"]


def test_rollback_to_original_and_failure_report_when_all_turns_fail(tmp_path: Path):
    """Tüm turlar başarısız olduğunda dosya temiz orijinal haline döner ve detaylı hata raporu kaydedilir."""
    app_file = tmp_path / "app.py"
    original_code = (
        "def get_user(conn, username):\n"
        "    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
        "    return conn.execute(query)\n"
    )
    app_file.write_text(original_code, encoding="utf-8")

    # Her turda sentaksı geçerli ama hâlâ zafiyetli/bozuk yama dön
    bad_patch = (
        "```python\ndef get_user(conn, username):\n"
        "    # Still vulnerable\n"
        "    return conn.execute(f\"SELECT * FROM users WHERE username = '{username}'\")\n```"
    )
    mock_backend = ScriptedMockBackend([bad_patch, bad_patch])
    synthesizer = PatchSynthesizer(llm_backend=mock_backend)
    sast = MockSASTEngine([
        {
            "engine": "Bandit",
            "tool": "bandit",
            "filename": str(app_file),
            "file_path": str(app_file),
            "line_number": 2,
            "test_id": "B608",
            "cwe": "CWE-89",
            "issue_text": "SQL injection risk",
        }
    ])

    def verify(task_dir: Path, call_num: int):
        return {
            "func_pass": True,
            "sec_pass": False,
            "func_output": "1 passed",
            "sec_output": "AssertionError: Exploit succeeded!",
            "execution_mode": "parallel",
        }

    controller = SelfHealingController(
        task_dir=str(tmp_path),
        target_file="app.py",
        config=AVRConfig(max_turns=2, rollback_on_failure=True),
        sast=sast,
        synthesizer=synthesizer,
        sandbox=LocalPytestSandbox(verify),
    )
    report = controller.run()

    assert report["repaired"] is False
    assert report["status"] == "FAILED"
    assert report["rolled_back_to_original"] is True
    assert app_file.read_text(encoding="utf-8") == original_code
    assert report["failure_summary"]["turns_attempted"] == 2
    assert "Exploit succeeded" in report["failure_summary"]["last_error_feedback"]
    assert len(report["turn_history"]) == 2
    # sonuc.json diske yazılmış olmalı
    saved = json.loads((tmp_path / "sonuc.json").read_text(encoding="utf-8"))
    assert saved["rolled_back_to_original"] is True


def test_multi_vuln_line_shift_resolved_by_function_name(tmp_path: Path):
    """
    1. zafiyete +10 satır ekleyen yama uygulandığında 2. zafiyetin satır numarası kayar;
    ASTContextPruner.prune_function_by_name ile 2. fonksiyon hatasız yamalanmalıdır.
    """
    svc_file = tmp_path / "service.py"
    original_code = (
        "import os\n\n"
        "def vuln_one(x):\n"
        "    return f'SELECT {x}'\n\n"
        "def safe_helper():\n"
        "    return 42\n\n"
        "def vuln_two(base, path):\n"
        "    return os.path.commonprefix([base, path])\n"
    )
    svc_file.write_text(original_code, encoding="utf-8")

    # 1. yama kasıtlı olarak çok satırlı (satır kayması oluşturur!)
    long_patch_one = (
        "```python\ndef vuln_one(x):\n"
        "    # line 1\n"
        "    # line 2\n"
        "    # line 3\n"
        "    # line 4\n"
        "    # line 5\n"
        "    # line 6\n"
        "    # line 7\n"
        "    # line 8\n"
        "    # line 9\n"
        "    # line 10\n"
        "    return ('SELECT ?', (x,))\n```"
    )
    patch_two = (
        "```python\ndef vuln_two(base, path):\n"
        "    return os.path.commonpath([base, path])\n```"
    )

    mock_backend = ScriptedMockBackend([long_patch_one, patch_two])
    synthesizer = PatchSynthesizer(llm_backend=mock_backend)
    sast = MockSASTEngine([
        {
            "engine": "Bandit",
            "tool": "bandit",
            "filename": str(svc_file),
            "file_path": str(svc_file),
            "line_number": 4,
            "test_id": "B608",
            "cwe": "CWE-89",
            "issue_text": "SQLi",
        },
        {
            "engine": "Semgrep",
            "tool": "semgrep",
            "filename": str(svc_file),
            "file_path": str(svc_file),
            "line_number": 10,
            "test_id": "insecure-commonprefix-path-traversal",
            "cwe": "CWE-22",
            "issue_text": "Path traversal",
        },
    ])

    def verify(task_dir: Path, call_num: int):
        src = (task_dir / "service.py").read_text(encoding="utf-8")
        if call_num == 1:
            return {"func_pass": True, "sec_pass": False, "func_output": "ok", "sec_output": "fail"}
        valid_syntax, _ = ASTContextPruner.validate_syntax(src)
        both_fixed = ("'SELECT ?'" in src) and ("commonpath" in src) and ("def safe_helper" in src)
        return {
            "func_pass": valid_syntax and ("def safe_helper" in src),
            "sec_pass": both_fixed,
            "func_output": "ok",
            "sec_output": "ok" if both_fixed else "fail",
            "execution_mode": "parallel",
        }

    controller = SelfHealingController(
        task_dir=str(tmp_path),
        target_file="service.py",
        config=AVRConfig(max_turns=2),
        sast=sast,
        synthesizer=synthesizer,
        sandbox=LocalPytestSandbox(verify),
    )
    report = controller.run()

    assert report["repaired"] is True
    final_src = svc_file.read_text(encoding="utf-8")
    assert "os.path.commonpath" in final_src
    assert "os.path.commonprefix" not in final_src
    assert "def safe_helper():" in final_src


def test_docker_sealed_sandbox_flags_and_timeout_cleanup():
    """DockerSandbox komutunda tüm izolasyon bayraklarını ve timeout sonrası konteyner temizliğini doğrular."""
    sandbox = DockerSandbox(
        image_name="bitirme-sandbox",
        timeout=5,
        memory_limit="256m",
        cpu_limit="0.5",
        pids_limit=32,
        parallel=True,
    )
    cmd = sandbox._build_docker_cmd("/tmp/task", "sec_test.py", "avr-sandbox-test123")

    assert "--network" in cmd and cmd[cmd.index("--network") + 1] == "none"
    assert "--memory" in cmd and cmd[cmd.index("--memory") + 1] == "256m"
    assert "--cpus" in cmd and cmd[cmd.index("--cpus") + 1] == "0.5"
    assert "--pids-limit" in cmd and cmd[cmd.index("--pids-limit") + 1] == "32"
    assert "--read-only" in cmd
    assert "--cap-drop" in cmd and cmd[cmd.index("--cap-drop") + 1] == "ALL"
    assert "/tmp/task:/app:ro" in cmd
    assert "cache_dir=/tmp/pytest_cache" in cmd

    # TimeoutExpired durumunda _cleanup_container çağrılmalı
    with patch("pipeline.sandbox.docker_runner.subprocess.run") as mock_run, patch.object(
        sandbox, "_cleanup_container"
    ) as mock_cleanup:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=cmd, timeout=5)
        passed, output = sandbox.run_pytest("/tmp", "sec_test.py")

    assert passed is False
    assert "SANDBOX TIMEOUT" in output
    mock_cleanup.assert_called_once()


def test_transformers_backend_model_mapping_and_telemetry():
    """
    TransformersBackend:
    1. Ollama formatındaki model adını ('qwen2.5-coder:7b') Hugging Face repo kimliğine dönüştürmeli.
    2. apply_chat_template + generate(output_scores=True, output_attentions=True) üzerinden
       confidence_score, Shannon entropy ve attention_summary metriklerini doğru hesaplamalı.
    """
    synth = PatchSynthesizer(backend="transformers", model_name="qwen2.5-coder:7b")
    assert isinstance(synth.backend, TransformersBackend)
    assert synth.model_name == "Qwen/Qwen2.5-Coder-7B-Instruct"
    assert synth.backend.model_name == "Qwen/Qwen2.5-Coder-7B-Instruct"

    class DummyTokenizer:
        pad_token = "<pad>"
        eos_token = "<eos>"
        pad_token_id = 0

        def apply_chat_template(self, messages, tokenize=False, add_generation_prompt=True):
            return "prompt_text"

        def __call__(self, text, return_tensors="pt"):
            # 4 prompt token: [10, 11, 12, 13]
            return {"input_ids": [[10, 11, 12, 13]]}

        def convert_ids_to_tokens(self, ids):
            mapping = {10: "<|im_start|>", 11: "def", 12: "execute_query", 13: "username"}
            return [mapping.get(i, f"t{i}") for i in ids]

        def decode(self, token_ids, skip_special_tokens=True):
            return "```python\ndef get_user(conn, u):\n    return conn.execute('SELECT ?', (u,))\n```"

    class DummyOutputs:
        # 4 prompt token + 2 yeni üretilen token (id=1 ve id=2)
        sequences = [[10, 11, 12, 13, 1, 2]]
        # Her adım için 4 kelimelik sözlük logitleri: seçilen indeks (1 ve 2) yüksek logit (4.0)
        scores = [
            [[0.0, 4.0, 0.0, 0.0]],
            [[0.0, 0.0, 4.0, 0.0]],
        ]
        # 2 üretim adımı x 2 katman x [batch=1, heads=2, q_len=1, kv_len=4]
        # İndeks 2 ('execute_query') en yüksek attention ağırlığına (0.70) sahip
        attentions = [
            (
                [[[[0.10, 0.10, 0.70, 0.10]], [[0.05, 0.15, 0.65, 0.15]]]],
                [[[[0.05, 0.10, 0.75, 0.10]], [[0.05, 0.15, 0.65, 0.15]]]],
            ),
            (
                [[[[0.10, 0.10, 0.70, 0.10]], [[0.10, 0.10, 0.70, 0.10]]]],
                [[[[0.05, 0.15, 0.70, 0.10]], [[0.05, 0.15, 0.70, 0.10]]]],
            ),
        ]

    class DummyModel:
        device = "cpu"

        def generate(self, **kwargs):
            assert kwargs.get("return_dict_in_generate") is True
            assert kwargs.get("output_scores") is True
            return DummyOutputs()

    backend = synth.backend
    backend._tokenizer = DummyTokenizer()
    backend._model = DummyModel()

    res = synth.synthesize([{"role": "user", "content": "fix sql injection"}])
    assert res.backend == "transformers"
    assert res.model_name == "Qwen/Qwen2.5-Coder-7B-Instruct"
    assert res.token_count == 2
    assert "SELECT ?" in res.extracted_code
    assert res.confidence_score is not None and res.confidence_score > 0.90
    assert res.entropy is not None and 0.0 < res.entropy < 0.50
    assert res.attention_summary is not None
    assert res.attention_summary["focused_token"] == "execute_query"
    assert res.attention_summary["peak_weight"] == 0.7
    assert res.attention_summary["num_layers"] == 2
    assert res.attention_summary["num_heads"] == 2
    assert res.attention_summary["hallucination_risk"] == "LOW"


def test_multi_target_feedback_isolates_healthy_function():
    """
    Çoklu zafiyet onarımında hata yalnızca 2. fonksiyondan kaynaklanıyorsa,
    1. fonksiyona 'CRITICAL: DO NOT repeat your previous implementation unchanged!' denmemelidir.
    """
    tb = "FAILED sec_test.py::test_traversal - AssertionError in read_user_attachment"

    msg_healthy = PatchSynthesizer.build_feedback_message(
        tb, turn_number=1, target_function="get_user_account", is_multi_target=True
    )
    msg_broken = PatchSynthesizer.build_feedback_message(
        tb, turn_number=1, target_function="read_user_attachment", is_multi_target=True
    )

    assert "NOT referenced in the failure above" in msg_healthy["content"]
    assert "CRITICAL: DO NOT repeat" not in msg_healthy["content"]
    assert "CRITICAL: DO NOT repeat" in msg_broken["content"]


def test_benchmark_ingestion_metadata_lookup(tmp_path: Path):
    """BenchmarkIngestion yerel SusVibes veri kümesinden Starlette CVE metadata'sını çekebilmelidir."""
    ingestion = BenchmarkIngestion()
    stats = ingestion.get_dataset_stats(allow_download=False)
    assert stats["available"] is True
    assert stats["total_tasks"] > 0

    meta = ingestion.get_task_metadata(cve_id="CVE-2023-29159", allow_download=False)
    assert meta is not None
    assert meta["project"] == "encode/starlette"
    assert "CWE-22" in meta["cwe_ids"]

    manifest_path = ingestion.export_task_manifest(
        meta["instance_id"], str(tmp_path / "export"), allow_download=False
    )
    assert manifest_path is not None and manifest_path.exists()


def test_extract_and_patch_indented_class_method_preserves_valid_syntax():
    """Sınıf metodu + yardımcı metot dönen LLM kod bloğunda ilk satır girintisi bozulmamalıdır."""
    original_src = (
        "class Hook:\n"
        "    def run_cli(self, schema):\n"
        "        return f'USE {schema};'\n"
    )
    llm_response = (
        "```python\n"
        "    def run_cli(self, schema):\n"
        "        if '!' in schema or ';' in schema:\n"
        "            raise ValueError('invalid')\n"
        "        return f'USE {schema};'\n"
        "\n"
        "    def _helper(self):\n"
        "        return True\n"
        "```"
    )
    extracted = PatchSynthesizer.extract_code_block(llm_response)
    patched = PatchSynthesizer.build_patched_content(original_src, 2, 3, extracted)
    ok, err = ASTContextPruner.validate_syntax(patched)
    assert ok is True, f"Unexpected syntax error: {err}\n{patched}"

