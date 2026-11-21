from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import json
import re
import textwrap
import time
from typing import Any, Dict, List, Optional
import urllib.request

from pipeline.pruner.ast_pruner import ASTContextPruner


@dataclass
class GenerationResult:
    """Standart LLM yama üretim çıktısı ve telemetri şeması (Ollama & Transformers ortak)."""

    raw_response: str
    extracted_code: str
    duration_seconds: float
    backend: str
    model_name: str
    confidence_score: Optional[float] = None
    entropy: Optional[float] = None
    attention_summary: Optional[Dict[str, Any]] = None
    token_count: Optional[int] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_metrics_dict(self) -> Dict[str, Any]:
        return {
            "backend": self.backend,
            "model_name": self.model_name,
            "duration_seconds": round(self.duration_seconds, 3),
            "token_count": self.token_count,
            "confidence_score": self.confidence_score,
            "entropy": self.entropy,
            "attention_summary": self.attention_summary,
        }


class BaseLLMBackend(ABC):
    """Tüm LLM sağlayıcıları (Ollama, Hugging Face Transformers vb.) için ortak arayüz."""

    backend_name: str = "base"

    def __init__(self, model_name: str, temperature: float = 0.2, top_p: float = 0.95):
        self.model_name = model_name
        self.temperature = temperature
        self.top_p = top_p

    @abstractmethod
    def generate(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
    ) -> GenerationResult:
        """Çok turlu chat mesaj listesini alıp GenerationResult döndürür."""


class OllamaBackend(BaseLLMBackend):
    """Yerel Ollama /api/chat uç noktası üzerinden çok turlu yama üretici."""

    backend_name = "ollama"

    def __init__(
        self,
        model_name: str = "qwen2.5-coder:7b",
        base_url: str = "http://localhost:11434",
        timeout: int = 180,
        temperature: float = 0.2,
        top_p: float = 0.95,
    ):
        super().__init__(model_name=model_name, temperature=temperature, top_p=top_p)
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def generate(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
    ) -> GenerationResult:
        url = f"{self.base_url}/api/chat"
        effective_temp = self.temperature if temperature is None else temperature
        payload = {
            "model": self.model_name,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": effective_temp,
                "top_p": self.top_p,
            },
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
        )

        start_t = time.time()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                result = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            raise RuntimeError(f"Ollama /api/chat ile iletişim kurulamadı ({url}): {exc}") from exc
        duration = time.time() - start_t

        raw_text = result.get("message", {}).get("content", "")
        eval_count = result.get("eval_count")

        return GenerationResult(
            raw_response=raw_text,
            extracted_code=PatchSynthesizer.extract_code_block(raw_text),
            duration_seconds=duration,
            backend=self.backend_name,
            model_name=self.model_name,
            confidence_score=None,  # Ollama ham logit/attention tensörü dönmez
            entropy=None,
            attention_summary=None,
            token_count=eval_count,
        )


class TransformersBackend(BaseLLMBackend):
    """
    [İSKELET / SÖZLEŞME — HUGGING FACE TRANSFORMERS GÖREVİ]

    Arkadaşınızın geliştireceği doğrudan Python / PyTorch (`transformers`) arka ucu için
    hazırlanmış arayüz iskeletidir. `generate(messages)` metodu doldurulduğunda,
    `SelfHealingController`, çok turlu konuşma geçmişi ve `sonuc.json` raporlaması
    hiçbir ek değişiklik gerektirmeden `confidence_score`, `entropy` ve `attention_summary`
    metriklerini otomatik olarak kaydedecektir.

    Uygulama Adımları (TODO):
      1. `__init__` veya lazy `_load_model()` içinde:
         - `from transformers import AutoTokenizer, AutoModelForCausalLM`
         - Donanım tespiti:
           * CUDA (ör. Windows RTX 3050): `BitsAndBytesConfig(load_in_4bit=True, ...)`
             ile 4-bit quantization (veya VRAM'e göre `Qwen/Qwen2.5-Coder-1.5B-Instruct` / `3B-Instruct`).
           * Apple Silicon (macOS `torch.backends.mps.is_available()`): `torch.float16` ile `mps` cihazı.
           * Fallback: `cpu`.
      2. `generate(messages, temperature=None)` içinde:
         - `prompt_text = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)`
         - `inputs = self.tokenizer(prompt_text, return_tensors="pt").to(self.device)`
         - `outputs = self.model.generate(..., return_dict_in_generate=True, output_scores=True, output_attentions=True)`
         - Üretilen yeni token'ları decode edip `raw_response` oluşturun.
         - `outputs.scores` üzerinden token olasılıklarını (softmax) hesaplayıp:
           * `confidence_score`: üretilen token'ların ortalama maksimum olasılığı (0.0 - 1.0)
           * `entropy`: ortalama Shannon entropisi (yüksek entropi -> yüksek halüsinasyon riski)
         - `outputs.attentions` üzerinden özet dikkat dağılımını (`attention_summary` sözlüğü) çıkarın.
      3. `GenerationResult(...)` nesnesini doldurup döndürün.
    """

    backend_name = "transformers"

    def __init__(
        self,
        model_name: str = "Qwen/Qwen2.5-Coder-1.5B-Instruct",
        device: str = "auto",
        load_in_4bit: bool = True,
        max_new_tokens: int = 1024,
        temperature: float = 0.2,
        top_p: float = 0.95,
    ):
        super().__init__(model_name=model_name, temperature=temperature, top_p=top_p)
        self.device = device
        self.load_in_4bit = load_in_4bit
        self.max_new_tokens = max_new_tokens
        self._tokenizer = None
        self._model = None

    def _load_model(self) -> None:
        """TODO: AutoTokenizer ve AutoModelForCausalLM yüklemesini burada gerçekleştirin."""
        raise NotImplementedError(
            "TransformersBackend henüz uygulanmadı. "
            "Lütfen 'pipeline/synthesizer/synthesizer.py' içindeki TransformersBackend._load_model() "
            "ve generate() metotlarını Hugging Face transformers ile tamamlayın "
            "(detaylar sınıf docstring'inde yer almaktadır)."
        )

    def generate(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
    ) -> GenerationResult:
        """TODO: apply_chat_template + model.generate(output_scores=True, output_attentions=True)."""
        self._load_model()
        raise NotImplementedError("TransformersBackend.generate() henüz uygulanmadı.")


class PatchSynthesizer:
    """
    Hibrit Yama Sentezleyici:
    - Seçilen backend (Ollama veya Hugging Face Transformers) üzerinden çok turlu yama üretir.
    - Üretilen yamayı diske yazmadan önce bellekte birleştirip AST sözdizimi doğrulamasını destekler.
    """

    SYSTEM_PROMPT = (
        "You are an expert automated program repair system specializing in Python application security. "
        "Your goal is to repair security vulnerabilities cleanly while strictly preserving the original "
        "function signature, argument names, return structure, and all existing functional behavior. "
        "Always output ONLY the complete repaired Python function inside a single ```python ... ``` code block."
    )

    def __init__(
        self,
        model_name: str = "qwen2.5-coder:7b",
        base_url: str = "http://localhost:11434",
        backend: str = "ollama",
        timeout: int = 180,
        temperature: float = 0.2,
        top_p: float = 0.95,
        llm_backend: Optional[BaseLLMBackend] = None,
    ):
        self.model_name = model_name
        self.base_url = base_url
        self.backend_name = backend.lower()

        if llm_backend is not None:
            self.backend = llm_backend
            self.backend_name = llm_backend.backend_name
            self.model_name = llm_backend.model_name
        elif self.backend_name == "ollama":
            self.backend = OllamaBackend(
                model_name=model_name,
                base_url=base_url,
                timeout=timeout,
                temperature=temperature,
                top_p=top_p,
            )
        elif self.backend_name == "transformers":
            self.backend = TransformersBackend(
                model_name=model_name,
                temperature=temperature,
                top_p=top_p,
            )
        else:
            raise ValueError(
                f"Desteklenmeyen backend: '{backend}'. Geçerli seçenekler: 'ollama', 'transformers'."
            )

    def _format_findings_block(self, sast_findings: List[Dict[str, Any]]) -> str:
        blocks = []
        for idx, finding in enumerate(sast_findings, start=1):
            blocks.append(
                f"Finding #{idx}:\n"
                f"- Engine: {finding.get('engine', finding.get('tool', 'SAST'))}\n"
                f"- Target File: {finding.get('filename', finding.get('file_path'))}\n"
                f"- Vulnerability Type: {finding.get('cwe', finding.get('cwe_id'))} "
                f"({finding.get('test_id', finding.get('rule_id'))})\n"
                f"- Problematic Line: {finding.get('line_number')}\n"
                f"- Diagnosis: {finding.get('issue_text', finding.get('message'))}"
            )
        return "\n\n".join(blocks)

    def build_initial_messages(
        self,
        ast_chunk: Dict[str, Any],
        sast_findings: List[Dict[str, Any]],
    ) -> List[Dict[str, str]]:
        """İlk onarım turu için [system, user] konuşma geçmişini oluşturur."""
        diagnosis_block = self._format_findings_block(sast_findings)
        user_content = f"""Fix the security vulnerability(ies) in the Python function below.

### VULNERABILITY DIAGNOSIS (From SAST Engine)
{diagnosis_block}

### CODE CONTEXT (File Imports)
```python
{ast_chunk.get('imports', '')}
```

### VULNERABLE FUNCTION (To be repaired: `{ast_chunk.get('qualified_name', ast_chunk.get('function_name'))}`)
```python
{ast_chunk.get('function_code', '')}
```

### INSTRUCTIONS:
1. Repair all reported security vulnerabilities completely using standard, safe Python practices.
2. DO NOT change the function name, signature, argument names, or return contract. Existing functional tests must continue to pass.
3. Keep all logic self-contained inside this single function (do NOT define extra sibling methods outside it) and maintain valid Python indentation.
4. Provide ONLY the complete, repaired Python function inside a single ```python ... ``` code block without extra prose.
"""
        return [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ]

    @staticmethod
    def build_feedback_message(feedback: str, turn_number: int) -> Dict[str, str]:
        """Başarısız bir tur sonrası modele önceki yamasıyla birlikte iletilecek geri bildirim mesajı."""
        return {
            "role": "user",
            "content": (
                f"Your previous patch candidate (Turn {turn_number}) FAILED verification with the error below:\n\n"
                f"{feedback}\n\n"
                "CRITICAL: DO NOT repeat your previous implementation unchanged! "
                "Identify the exact root cause in the error/assertion above, change your approach to fix it completely, "
                "preserve the full original functional contract, keep everything inside the target function, "
                "and return ONLY the complete repaired Python function inside a single ```python ... ``` code block."
            ),
        }

    def generate_repair_prompt(
        self,
        ast_chunk: Dict[str, Any],
        sast_report: Dict[str, Any],
        feedback: Optional[str] = None,
    ) -> str:
        """Geriye dönük uyumluluk: tek string prompt üretir."""
        messages = self.build_initial_messages(ast_chunk, [sast_report])
        prompt = messages[1]["content"]
        if feedback:
            prompt += f"\n\n### FEEDBACK FROM PREVIOUS VERIFICATION FAILURE\n{feedback}\n"
        return prompt

    def synthesize(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
    ) -> GenerationResult:
        """Aktif backend üzerinden çok turlu yama üretir."""
        return self.backend.generate(messages, temperature=temperature)

    def query_ollama(self, prompt: str) -> str:
        """Geriye dönük uyumluluk: tek prompt ile aktif backend'i sorgular."""
        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        return self.synthesize(messages).raw_response

    @staticmethod
    def extract_code_block(response_text: str) -> str:
        """
        Model yanıtından ```python ... ``` kod bloğunu ayıklar.
        ÖNEMLİ: İlk satırın baştaki girinti boşluklarını KORUR (sadece satır sonlarını kırpar),
        böylece textwrap.dedent() sınıf metotlarında girintiyi bozmadan temizleyebilir.
        """
        pattern = r"```(?:python)?[ \t]*\r?\n(.*?)\r?\n?[ \t]*```"
        match = re.search(pattern, response_text, re.DOTALL)
        if match:
            return match.group(1).strip("\r\n")
        return response_text.strip("\r\n")

    @staticmethod
    def _normalize_dedent(new_code: str) -> str:
        """
        LLM kod bloğunu güvenli biçimde 0 girinti seviyesine çeker.
        Eğer model yalnızca ilk satırı 0 girintide yazıp kalan satırları fazladan
        girintilediyse (ör. sınıf metodu kopyalama hatası), kalan bloktaki ortak
        fazla girintiyi de temizler.
        """
        raw = new_code.strip("\r\n")
        dedented = textwrap.dedent(raw)

        # İlk satır zaten 0 girintideyse ama kod ast.parse() ile IndentationError veriyorsa
        # (örn. ilk satır 0, ikinci satırdan itibaren +4 fazla girinti), akıllı düzeltme dene.
        ok, _ = ASTContextPruner.validate_syntax(dedented)
        if ok:
            return dedented

        lines = dedented.splitlines()
        if len(lines) >= 2 and lines[0] and not lines[0][0].isspace():
            rest_dedented = textwrap.dedent("\n".join(lines[1:]))
            candidate = lines[0] + "\n" + textwrap.indent(rest_dedented, "    ")
            ok_fixed, _ = ASTContextPruner.validate_syntax(candidate)
            if ok_fixed:
                return candidate

        return dedented

    @staticmethod
    def build_patched_content(
        original_source: str,
        start_line: int,
        end_line: int,
        new_code: str,
    ) -> str:
        """
        Orijinal kaynak metindeki start_line..end_line aralığını yeni kodla bellekte değiştirir.
        Diske yazmadan önce ast.parse() doğrulaması yapılabilmesi için tam dosya metnini döner.
        """
        lines = original_source.splitlines(keepends=True)
        if not lines:
            return PatchSynthesizer._normalize_dedent(new_code) + "\n"

        target_first_line = lines[start_line - 1] if 0 <= start_line - 1 < len(lines) else ""
        indent_len = len(target_first_line) - len(target_first_line.lstrip())
        base_indent = target_first_line[:indent_len]

        clean_code = PatchSynthesizer._normalize_dedent(new_code)
        aligned_code = textwrap.indent(clean_code, base_indent)

        before = lines[: start_line - 1]
        after = lines[end_line:]

        patched_lines = before + [aligned_code + "\n"] + after
        return "".join(patched_lines)

    def apply_patch_to_file(
        self,
        file_path: str,
        start_line: int,
        end_line: int,
        new_code: str,
        validate_syntax: bool = True,
    ) -> str:
        """
        Yamayı hedef dosyaya uygular.
        validate_syntax=True ise diske yazmadan önce ast.parse() ile sözdizimi doğrulaması yapar;
        hatalı sözdizimi durumunda dosyaya DOKUNMADAN SyntaxError fırlatır.
        """
        with open(file_path, "r", encoding="utf-8") as f:
            original_source = f.read()

        candidate_source = self.build_patched_content(
            original_source, start_line, end_line, new_code
        )

        if validate_syntax:
            is_valid, err_msg = ASTContextPruner.validate_syntax(candidate_source, filename=file_path)
            if not is_valid:
                raise SyntaxError(err_msg or "Üretilen yama geçersiz Python sözdizimi içeriyor.")

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(candidate_source)

        return candidate_source


if __name__ == "__main__":
    import sys
    from pipeline.sast.sast_engine import SASTEngine

    target_file = "pipeline/sample_task/app.py"
    sast = SASTEngine(target_file)
    findings = sast.scan_with_bandit()

    if not findings:
        print("Zafiyet bulunamadı.")
        sys.exit(0)

    f = findings[0]
    pruner = ASTContextPruner(target_file)
    chunk = pruner.prune_enclosing_function(f["line_number"])

    synthesizer = PatchSynthesizer()
    messages = synthesizer.build_initial_messages(chunk, [f])
    print(f"\n[Synthesizer] Model sorgulanıyor ({synthesizer.backend_name} / {synthesizer.model_name})...")
    result = synthesizer.synthesize(messages)

    print(f"\n[Üretilen Güvenli Yama ({result.duration_seconds:.2f} sn)]:")
    print(result.extracted_code)
