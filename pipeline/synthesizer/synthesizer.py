from abc import ABC, abstractmethod
import ast
from dataclasses import dataclass, field
import gc
import importlib.util
import json
import math
import re
import textwrap
import time
from typing import Any, Dict, List, Optional, Tuple
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

    def unload_model(self) -> None:
        """Bellek/VRAM üzerindeki model ağırlıklarını serbest bırakır (varsayılan no-op)."""


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
    Hugging Face `transformers` + `PyTorch` yerel LLM arka ucu.

    Özellikler:
    - Ollama formatındaki model adlarını (örn. `qwen2.5-coder:7b`) otomatik olarak resmi
      Hugging Face repo kimliklerine (`Qwen/Qwen2.5-Coder-7B-Instruct`) dönüştürür.
    - Donanım tespiti (CUDA / Apple Silicon MPS / CPU) ve 8 GB VRAM dostu 4-bit NF4
      quantization (`BitsAndBytesConfig`) desteği sunar.
    - `output_scores=True` ve `output_attentions=True` ile her onarım turunda:
      * `confidence_score`: Üretilen token'ların ortalama olasılığı (0.0 - 1.0)
      * `entropy`: Ortalama Shannon entropisi (-sum(p * log(p))) — halüsinasyon göstergesi
      * `attention_summary`: Multi-Head Attention katmanının girdi kodundaki hangi
        token'lara odaklandığının özeti (`focused_token`, `top_attended_tokens`,
        `peak_weight`, `attention_entropy`, `hallucination_risk`)
      metriklerini hesaplar.
    """

    backend_name = "transformers"

    OLLAMA_TO_HF_MODEL_MAP: Dict[str, str] = {
        "qwen2.5-coder:7b": "Qwen/Qwen2.5-Coder-7B-Instruct",
        "qwen2.5-coder:3b": "Qwen/Qwen2.5-Coder-3B-Instruct",
        "qwen2.5-coder:1.5b": "Qwen/Qwen2.5-Coder-1.5B-Instruct",
        "qwen2.5-coder:0.5b": "Qwen/Qwen2.5-Coder-0.5B-Instruct",
        "qwen2.5-coder": "Qwen/Qwen2.5-Coder-7B-Instruct",
        "qwen2.5-coder:latest": "Qwen/Qwen2.5-Coder-7B-Instruct",
    }

    def __init__(
        self,
        model_name: str = "Qwen/Qwen2.5-Coder-1.5B-Instruct",
        device: str = "auto",
        load_in_4bit: bool = True,
        max_new_tokens: int = 512,
        temperature: float = 0.2,
        top_p: float = 0.95,
    ):
        normalized_name = self.normalize_model_name(model_name)
        super().__init__(model_name=normalized_name, temperature=temperature, top_p=top_p)
        self.requested_model_name = model_name
        self.device = device
        self.load_in_4bit = load_in_4bit
        self.max_new_tokens = max_new_tokens
        self._tokenizer: Any = None
        self._model: Any = None
        self._resolved_device: str = "cpu"

    @classmethod
    def normalize_model_name(cls, model_name: str) -> str:
        """
        Ollama tarzı iki nokta üst üste (`:`) içeren model etiketlerini
        geçerli Hugging Face Hub repo kimliklerine dönüştürür.
        """
        cleaned = (model_name or "").strip()
        if not cleaned:
            return "Qwen/Qwen2.5-Coder-1.5B-Instruct"

        lower_key = cleaned.lower()
        if lower_key in cls.OLLAMA_TO_HF_MODEL_MAP:
            return cls.OLLAMA_TO_HF_MODEL_MAP[lower_key]

        # Genel 'qwen2.5-coder:<size>' kalıbı
        match = re.match(r"^qwen2\.5-coder:(\d+(?:\.\d+)?)b$", lower_key)
        if match:
            size = match.group(1)
            return f"Qwen/Qwen2.5-Coder-{size}B-Instruct"

        return cleaned

    @staticmethod
    def _detect_device(requested_device: str, torch_module: Any) -> str:
        if requested_device and requested_device != "auto":
            return requested_device
        if torch_module.cuda.is_available():
            return "cuda"
        if hasattr(torch_module.backends, "mps") and torch_module.backends.mps.is_available():
            return "mps"
        return "cpu"

    def _load_model(self) -> None:
        """AutoTokenizer ve AutoModelForCausalLM yüklemesini donanıma uygun olarak gerçekleştirir."""
        if self._model is not None and self._tokenizer is not None:
            return

        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as exc:
            raise RuntimeError(
                "Hugging Face Transformers arka ucu için 'torch' ve 'transformers' "
                "paketleri gereklidir. Kurulum için: pip install -r requirements-transformers.txt"
            ) from exc

        self._resolved_device = self._detect_device(self.device, torch)

        self._tokenizer = AutoTokenizer.from_pretrained(
            self.model_name,
            trust_remote_code=True,
        )
        if getattr(self._tokenizer, "pad_token", None) is None:
            self._tokenizer.pad_token = self._tokenizer.eos_token

        model_kwargs: Dict[str, Any] = {
            "trust_remote_code": True,
            "attn_implementation": "eager",  # output_attentions=True için SDPA yerine eager gerekli
        }

        has_bnb = importlib.util.find_spec("bitsandbytes") is not None
        use_4bit = self._resolved_device == "cuda" and self.load_in_4bit and has_bnb
        cuda_dtype = (
            torch.bfloat16
            if (
                self._resolved_device == "cuda"
                and hasattr(torch.cuda, "is_bf16_supported")
                and torch.cuda.is_bf16_supported()
            )
            else torch.float16
        )

        if use_4bit:
            from transformers import BitsAndBytesConfig

            model_kwargs["quantization_config"] = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_compute_dtype=cuda_dtype,
                bnb_4bit_use_double_quant=True,
                bnb_4bit_quant_type="nf4",
                llm_int8_enable_fp32_cpu_offload=True,
            )
            model_kwargs["torch_dtype"] = cuda_dtype
            model_kwargs["device_map"] = {"": 0}
            model_kwargs["low_cpu_mem_usage"] = True
        elif self._resolved_device == "cuda":
            model_kwargs["torch_dtype"] = cuda_dtype
            model_kwargs["device_map"] = "auto"
        elif self._resolved_device == "mps":
            model_kwargs["torch_dtype"] = torch.float16
        else:
            model_kwargs["torch_dtype"] = torch.float32

        try:
            self._model = AutoModelForCausalLM.from_pretrained(self.model_name, **model_kwargs)
        except TypeError:
            # Bazı model sınıfları attn_implementation parametresini kabul etmeyebilir
            model_kwargs.pop("attn_implementation", None)
            self._model = AutoModelForCausalLM.from_pretrained(self.model_name, **model_kwargs)

        if "device_map" not in model_kwargs and hasattr(self._model, "to"):
            self._model = self._model.to(self._resolved_device)

        if hasattr(self._model, "eval"):
            self._model.eval()

    def unload_model(self) -> None:
        """Yüklü Hugging Face modelini ve tokenizer'ı VRAM / RAM'den tamamen temizler."""
        self._model = None
        self._tokenizer = None
        gc.collect()
        if importlib.util.find_spec("torch") is not None:
            import torch
            try:
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
            except Exception:
                pass

    @staticmethod
    def _softmax_and_entropy_from_1d(logits_list: List[float], chosen_id: Optional[int]) -> Tuple[float, float]:
        """Saf Python / math tabanlı numerik kararlı softmax ve Shannon entropi hesaplayıcı."""
        if not logits_list:
            return 0.0, 0.0
        finite_vals = [v for v in logits_list if math.isfinite(v)]
        if not finite_vals:
            return 0.0, 0.0
        max_logit = max(finite_vals)
        exps = [math.exp(v - max_logit) if math.isfinite(v) else 0.0 for v in logits_list]
        sum_exps = sum(exps)
        if sum_exps <= 0.0:
            return 0.0, 0.0

        probs = [e / sum_exps for e in exps]
        if chosen_id is not None and 0 <= int(chosen_id) < len(probs):
            chosen_prob = probs[int(chosen_id)]
        else:
            chosen_prob = max(probs)

        step_entropy = -sum(p * math.log(p) for p in probs if p > 1e-12)
        return float(chosen_prob), float(step_entropy)

    @classmethod
    def compute_token_metrics(
        cls,
        scores: Any,
        generated_ids: Any,
    ) -> Tuple[Optional[float], Optional[float]]:
        """
        Modelin adım adım ürettiği logit'lerden (`outputs.scores`):
        1. `confidence_score`: Seçilen token olasılıklarının ortalaması (0.0 - 1.0)
        2. `entropy`: Ortalama Shannon entropisi H = -sum(p * log(p))
        hesaplar. Hem PyTorch tensörleriyle hem de birim testi mock dizileriyle çalışır.
        """
        if not scores:
            return None, None

        torch_mod = None
        if importlib.util.find_spec("torch") is not None:
            import torch as torch_mod  # type: ignore

        gen_id_list: List[int] = []
        if generated_ids is not None:
            if hasattr(generated_ids, "tolist"):
                raw_ids = generated_ids.tolist()
            else:
                raw_ids = list(generated_ids)
            if raw_ids and isinstance(raw_ids[0], list):
                raw_ids = raw_ids[0]
            gen_id_list = [int(x) for x in raw_ids]

        confidences: List[float] = []
        entropies: List[float] = []

        for step_idx, step_logits in enumerate(scores):
            chosen_id = gen_id_list[step_idx] if step_idx < len(gen_id_list) else None

            if (
                torch_mod is not None
                and isinstance(step_logits, torch_mod.Tensor)
            ):
                vec = step_logits[0].detach().float() if step_logits.ndim >= 2 else step_logits.detach().float()
                probs = torch_mod.softmax(vec, dim=-1)
                log_probs = torch_mod.log_softmax(vec, dim=-1)

                if chosen_id is not None and 0 <= chosen_id < probs.shape[-1]:
                    conf = float(probs[chosen_id].item())
                else:
                    conf = float(probs.max().item())

                ent_tensor = -(probs * log_probs).nan_to_num(0.0).sum()
                ent = float(ent_tensor.item())
            else:
                raw = step_logits.tolist() if hasattr(step_logits, "tolist") else list(step_logits)
                if raw and isinstance(raw[0], list):
                    raw = raw[0]
                conf, ent = cls._softmax_and_entropy_from_1d([float(v) for v in raw], chosen_id)

            confidences.append(conf)
            entropies.append(ent)

        if not confidences:
            return None, None

        mean_conf = round(sum(confidences) / len(confidences), 4)
        mean_ent = round(sum(entropies) / len(entropies), 4)
        return mean_conf, mean_ent

    @classmethod
    def compute_attention_summary(
        cls,
        attentions: Any,
        prompt_token_ids: List[int],
        tokenizer: Any = None,
        confidence_score: Optional[float] = None,
        entropy: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        `outputs.attentions` üzerinden son Transformer katmanındaki Multi-Head Attention
        ağırlıklarını analiz ederek modelin girdi kodundaki hangi token'lara odaklandığını
        ve dikkat dağılımı entropisini (halüsinasyon risk göstergesi) özetler.
        """
        if not attentions:
            return None

        prompt_len = len(prompt_token_ids)
        if prompt_len == 0:
            return None

        torch_mod = None
        if importlib.util.find_spec("torch") is not None:
            import torch as torch_mod  # type: ignore

        num_layers = 0
        num_heads = 0
        accumulated_prompt_attn = [0.0] * prompt_len
        valid_steps = 0

        # Birden fazla üretim adımı varsa 0. adımı (prompt prefill) atlayıp yalnızca
        # yeni üretilen kod token'larının girdi prompt'una dikkatini ölç
        steps_to_iter = attentions[1:] if len(attentions) > 1 else attentions

        for step_attn in steps_to_iter:
            if not step_attn:
                continue
            num_layers = max(num_layers, len(step_attn))
            last_layer = step_attn[-1]
            if last_layer is None:
                continue

            if torch_mod is not None and isinstance(last_layer, torch_mod.Tensor):
                # Şekil: [batch, num_heads, q_len, kv_len]
                num_heads = max(num_heads, int(last_layer.shape[1]))
                usable = min(prompt_len, int(last_layer.shape[-1]))
                mean_head_vec = (
                    last_layer[0, :, -1, :usable]
                    .detach()
                    .float()
                    .mean(dim=0)
                    .cpu()
                    .tolist()
                )
                for idx in range(usable):
                    accumulated_prompt_attn[idx] += float(mean_head_vec[idx])
                valid_steps += 1
                continue

            raw = last_layer.detach().cpu().tolist() if hasattr(last_layer, "detach") else (
                last_layer.tolist() if hasattr(last_layer, "tolist") else last_layer
            )
            # Beklenen şekil: [batch, num_heads, q_len, kv_len]
            if not raw or not isinstance(raw, list):
                continue
            batch_0 = raw[0] if isinstance(raw[0], list) else raw
            if not batch_0:
                continue
            num_heads = max(num_heads, len(batch_0))

            step_vec = [0.0] * prompt_len
            head_count = 0
            for head_matrix in batch_0:
                if not head_matrix:
                    continue
                last_query_row = head_matrix[-1] if isinstance(head_matrix[0], list) else head_matrix
                if not last_query_row:
                    continue
                usable = min(prompt_len, len(last_query_row))
                for idx in range(usable):
                    step_vec[idx] += float(last_query_row[idx])
                head_count += 1

            if head_count > 0:
                for idx in range(prompt_len):
                    accumulated_prompt_attn[idx] += step_vec[idx] / head_count
                valid_steps += 1

        if valid_steps == 0:
            return None

        avg_attn = [val / valid_steps for val in accumulated_prompt_attn]
        total_mass = sum(avg_attn)
        norm_attn = [val / total_mass for val in avg_attn] if total_mass > 0 else avg_attn

        # Dikkat dağılımı entropisi (dağınık attention = yüksek entropi)
        attn_entropy = -sum(p * math.log(p) for p in norm_attn if p > 1e-12)

        # Token metinlerini çöz
        tokens: List[str] = []
        if tokenizer is not None and hasattr(tokenizer, "convert_ids_to_tokens"):
            try:
                raw_tokens = tokenizer.convert_ids_to_tokens(prompt_token_ids)
                tokens = [str(t).replace("Ġ", " ").replace("Ċ", "\n").strip() for t in raw_tokens]
            except Exception:
                tokens = []
        if not tokens and tokenizer is not None and hasattr(tokenizer, "decode"):
            try:
                tokens = [str(tokenizer.decode([tid])).strip() for tid in prompt_token_ids]
            except Exception:
                tokens = []
        if len(tokens) != prompt_len:
            tokens = [f"tok_{i}" for i in range(prompt_len)]

        # Noktalama işaretlerini (attention sink), özel şablon etiketlerini ve
        # İngilizce prompt talimat kelimelerini eleyerek gerçek kod token'larını öne çıkar
        prompt_stopwords = {
            "", "<|im_start|>", "<|im_end|>", "<|endoftext|>", "system", "user", "assistant",
            "```", "python", "you", "are", "an", "a", "the", "in", "to", "of", "and", "for",
            "with", "below", "fix", "security", "vulnerability", "vulnerabilities", "function",
            "instructions", "diagnosis", "engine", "target", "file", "line", "problematic",
            "context", "imports", "vulnerable", "repaired", "complete", "single", "block",
            "code", "without", "extra", "prose", "maintain", "valid", "indentation",
            "signature", "return", "contract", "existing", "functional", "tests", "must",
            "continue", "pass", "expert", "automated", "program", "repair", "specializing",
            "application", "goal", "cleanly", "while", "strictly", "preserving", "original",
            "argument", "names", "structure", "all", "behavior", "always", "output", "only",
            "inside", "from", "sast", "finding", "type", "cwe", "b608", "possible", "vector",
            "through", "string", "based", "construction", "keep", "logic", "self", "contained",
            "do", "not", "define", "sibling", "methods", "outside", "it", "using", "standard",
            "safe", "practices", "reported", "completely", "provide", "change", "name", "be",
            "is", "or", "as", "by", "on", "that", "this", "import", "Band", "pipeline",
        }

        def _is_meaningful_code_token(tok: str) -> bool:
            cleaned = tok.strip()
            if not cleaned or cleaned.startswith("<|"):
                return False
            if cleaned.lower() in prompt_stopwords:
                return False
            # En az bir harf veya alt çizgi içermeli (saf noktalama / sayı elenir)
            if not any(ch.isalpha() or ch == "_" for ch in cleaned):
                return False
            return True

        scored_indices = sorted(range(prompt_len), key=lambda i: norm_attn[i], reverse=True)
        meaningful_indices = [i for i in scored_indices if _is_meaningful_code_token(tokens[i])] or scored_indices

        top_attended = [
            {
                "token": tokens[i],
                "token_index": i,
                "weight": round(norm_attn[i], 4),
            }
            for i in meaningful_indices[:5]
        ]
        best_idx = meaningful_indices[0]

        # Halüsinasyon risk değerlendirmesi (Attention Is All You Need Bölüm 3.2.2 raporuyla uyumlu)
        risk = "LOW"
        if (entropy is not None and entropy > 1.2) or (confidence_score is not None and confidence_score < 0.55):
            risk = "HIGH"
        elif (entropy is not None and entropy > 0.65) or (confidence_score is not None and confidence_score < 0.78):
            risk = "MEDIUM"

        return {
            "focused_token": tokens[best_idx],
            "peak_weight": round(norm_attn[best_idx], 4),
            "attention_entropy": round(attn_entropy, 4),
            "num_layers": num_layers,
            "num_heads": num_heads,
            "hallucination_risk": risk,
            "top_attended_tokens": top_attended,
        }

    def _format_chat_prompt(self, messages: List[Dict[str, str]]) -> str:
        """Tokenizer chat şablonunu uygular; şablon yoksa ChatML formatına düşer."""
        if self._tokenizer is not None and hasattr(self._tokenizer, "apply_chat_template"):
            try:
                return self._tokenizer.apply_chat_template(
                    messages,
                    tokenize=False,
                    add_generation_prompt=True,
                )
            except Exception:
                pass

        parts = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            parts.append(f"<|im_start|>{role}\n{content}<|im_end|>")
        parts.append("<|im_start|>assistant\n")
        return "\n".join(parts)

    def generate(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
    ) -> GenerationResult:
        """
        Hugging Face `transformers` modeliyle çok turlu yama üretir ve
        `confidence_score`, `entropy`, `attention_summary` telemetrilerini hesaplar.
        """
        self._load_model()

        effective_temp = self.temperature if temperature is None else temperature
        prompt_text = self._format_chat_prompt(messages)

        inputs = self._tokenizer(prompt_text, return_tensors="pt")
        target_device = getattr(self._model, "device", self._resolved_device)
        if hasattr(inputs, "to") and target_device and str(target_device) != "meta":
            inputs = inputs.to(target_device)
        elif isinstance(inputs, dict) and target_device and str(target_device) != "meta":
            inputs = {
                k: (v.to(target_device) if hasattr(v, "to") else v)
                for k, v in inputs.items()
            }

        input_ids = inputs["input_ids"]
        prompt_token_ids: List[int] = (
            input_ids[0].tolist() if hasattr(input_ids[0], "tolist") else list(input_ids[0])
        )
        prompt_len = len(prompt_token_ids)

        do_sample = effective_temp > 0.0
        gen_kwargs: Dict[str, Any] = {
            "max_new_tokens": self.max_new_tokens,
            "do_sample": do_sample,
            "return_dict_in_generate": True,
            "output_scores": True,
            "output_attentions": True,
        }
        if getattr(self._tokenizer, "pad_token_id", None) is not None:
            gen_kwargs["pad_token_id"] = self._tokenizer.pad_token_id
        if do_sample:
            gen_kwargs["temperature"] = float(effective_temp)
            gen_kwargs["top_p"] = float(self.top_p)
            gen_kwargs["remove_invalid_values"] = True

        torch_mod = None
        if importlib.util.find_spec("torch") is not None:
            import torch as torch_mod  # type: ignore

        start_t = time.time()
        if torch_mod is not None:
            with torch_mod.no_grad():
                try:
                    outputs = self._model.generate(**inputs, **gen_kwargs)
                except RuntimeError as exc:
                    if "out of memory" in str(exc).lower():
                        if torch_mod.cuda.is_available():
                            torch_mod.cuda.empty_cache()
                        gen_kwargs["output_attentions"] = False
                        outputs = self._model.generate(**inputs, **gen_kwargs)
                    else:
                        raise
        else:
            outputs = self._model.generate(**inputs, **gen_kwargs)
        duration = time.time() - start_t

        sequences = outputs.sequences
        first_seq = sequences[0]
        generated_ids = first_seq[prompt_len:]

        if hasattr(self._tokenizer, "decode"):
            raw_text = self._tokenizer.decode(generated_ids, skip_special_tokens=True)
        else:
            raw_text = str(generated_ids)

        gen_id_list = generated_ids.tolist() if hasattr(generated_ids, "tolist") else list(generated_ids)
        token_count = len(gen_id_list)

        scores = getattr(outputs, "scores", None)
        attentions = getattr(outputs, "attentions", None)

        confidence_score, entropy = self.compute_token_metrics(scores, generated_ids)
        attention_summary = self.compute_attention_summary(
            attentions=attentions,
            prompt_token_ids=prompt_token_ids,
            tokenizer=self._tokenizer,
            confidence_score=confidence_score,
            entropy=entropy,
        )

        del outputs, scores, attentions, sequences, first_seq, generated_ids, inputs, input_ids
        if torch_mod is not None and torch_mod.cuda.is_available():
            torch_mod.cuda.empty_cache()

        return GenerationResult(
            raw_response=raw_text,
            extracted_code=PatchSynthesizer.extract_code_block(raw_text),
            duration_seconds=duration,
            backend=self.backend_name,
            model_name=self.model_name,
            confidence_score=confidence_score,
            entropy=entropy,
            attention_summary=attention_summary,
            token_count=token_count,
        )


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
            self.model_name = self.backend.model_name
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
    def build_feedback_message(
        feedback: str,
        turn_number: int,
        target_function: Optional[str] = None,
        is_multi_target: bool = False,
    ) -> Dict[str, str]:
        """
        Başarısız bir tur sonrası modele önceki yamasıyla birlikte iletilecek geri bildirim mesajı.
        Çoklu fonksiyon (is_multi_target=True) senaryosunda hata başka bir fonksiyondan kaynaklanıyorsa,
        doğru yamalanmış fonksiyonun bozulmasını önleyen hedefe özgü yönlendirme yapar.
        """
        if is_multi_target and target_function:
            short_fn = target_function.split(".")[-1]
            if short_fn not in (feedback or ""):
                return {
                    "role": "user",
                    "content": (
                        f"Verification in Turn {turn_number} reported a failure elsewhere in the multi-function file:\n\n"
                        f"{feedback}\n\n"
                        f"NOTE: Your target function `{target_function}` was NOT referenced in the failure above. "
                        f"If your previous patch for `{target_function}` already fixed its vulnerability and preserved "
                        f"its functional contract, keep that working implementation intact; otherwise fix any remaining "
                        f"defect in `{target_function}`. Return ONLY the complete repaired Python function inside a "
                        f"single ```python ... ``` code block."
                    ),
                }

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

    @staticmethod
    def build_sibling_syntax_abort_message(turn_number: int, target_function: str) -> Dict[str, str]:
        """
        Çoklu fonksiyon onarımında başka bir fonksiyon SyntaxError verdiğinde,
        sözdizimi geçerli olan fonksiyonun yamasını bozmaması için kullanılan mesaj.
        """
        return {
            "role": "user",
            "content": (
                f"Your patch for `{target_function}` in Turn {turn_number} passed Python AST syntax validation, "
                "but another function in the same file had a syntax error so Docker verification was deferred. "
                f"Please output your valid, secure implementation for `{target_function}` inside a single "
                "```python ... ``` code block."
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

    def unload_model(self) -> None:
        """Aktif backend üzerindeki modeli VRAM / RAM'den temizler."""
        self.backend.unload_model()

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
    def _sanitize_patch_for_target(
        clean_code: str,
        target_first_line: str,
    ) -> Tuple[str, List[str]]:
        """
        Model bazen yamalanan fonksiyonun tepesine dosya importlarını (`import os` vb.) tekrar yazar
        veya sınıf metodunu `class Foo:` bloğu içine sararak döndürür.
        Bu metot:
        1. Fazlalık üst-düzey import satırlarını fonksiyondan ayırır (gerekirse dosya başına eklemek üzere döner).
        2. Hedef satır bir `def ...` fonksiyonu/metodu iken model `class ...:` sarmalayıcısı döndürdüyse,
           sınıfın içindeki metot gövdesini soyarak çıkarır.
        """
        hoisted_imports: List[str] = []
        raw_lines = clean_code.splitlines()

        # Ön-temizlik: Model 0 girintide 'import ...' yazıp altına +4 girintili sınıf metodu ('    def ...')
        # koyduysa, ast.parse() IndentationError vermesin diye baştaki 0 girintili importları soyup kalanı dedent et.
        idx = 0
        while idx < len(raw_lines):
            stripped_l = raw_lines[idx].strip()
            if not stripped_l or stripped_l.startswith("#"):
                idx += 1
                continue
            if not raw_lines[idx][0].isspace() and (
                stripped_l.startswith("import ") or stripped_l.startswith("from ")
            ):
                hoisted_imports.append(stripped_l)
                idx += 1
                continue
            break

        if hoisted_imports and idx < len(raw_lines):
            remainder = textwrap.dedent("\n".join(raw_lines[idx:])).strip("\r\n")
            if remainder:
                clean_code = remainder

        try:
            tree = ast.parse(clean_code)
        except SyntaxError:
            return clean_code, hoisted_imports

        if not tree.body:
            return clean_code, hoisted_imports

        code_lines = clean_code.splitlines()
        target_stripped = target_first_line.lstrip()
        target_is_def = target_stripped.startswith("def ") or target_stripped.startswith("async def ")

        # 1) Eğer hedef bir def/metot ise ve model tek bir ClassDef içine sarmışsa, sınıfın içini aç
        non_import_nodes = [
            n for n in tree.body if not isinstance(n, (ast.Import, ast.ImportFrom))
        ]
        import_nodes = [
            n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))
        ]

        for imp_node in import_nodes:
            s_idx = imp_node.lineno - 1
            e_idx = getattr(imp_node, "end_lineno", imp_node.lineno)
            hoisted_imports.extend(code_lines[s_idx:e_idx])

        if target_is_def and len(non_import_nodes) == 1 and isinstance(non_import_nodes[0], ast.ClassDef):
            cls_node = non_import_nodes[0]
            func_nodes = [
                n for n in cls_node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            if func_nodes:
                first_f = func_nodes[0]
                decos = [d.lineno for d in getattr(first_f, "decorator_list", [])]
                s_line = min([first_f.lineno] + decos)
                e_line = getattr(func_nodes[-1], "end_lineno", func_nodes[-1].lineno)
                extracted_methods = "\n".join(code_lines[s_line - 1 : e_line])
                return textwrap.dedent(extracted_methods), hoisted_imports

        # 2) Hedef bir def/metot ise, üstteki importları ve alttaki örnek kullanım (if __name__, try, print vb.)
        # ifadelerini temizleyip yalnızca fonksiyon tanımlamalarını koru
        func_only = [
            n for n in non_import_nodes if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        if target_is_def and func_only and (import_nodes or len(non_import_nodes) > len(func_only)):
            first_node = func_only[0]
            decos = [d.lineno for d in getattr(first_node, "decorator_list", [])]
            s_line = min([first_node.lineno] + decos)
            last_node = func_only[-1]
            e_line = getattr(last_node, "end_lineno", last_node.lineno)
            stripped_body = "\n".join(code_lines[s_line - 1 : e_line])
            return textwrap.dedent(stripped_body), hoisted_imports

        return clean_code, hoisted_imports

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
        sanitized_code, hoisted_imports = PatchSynthesizer._sanitize_patch_for_target(
            clean_code, target_first_line
        )
        aligned_code = textwrap.indent(sanitized_code, base_indent)

        before = list(lines[: start_line - 1])
        after = list(lines[end_line:])

        # Modelin eklediği ama orijinal dosyada olmayan üst-düzey importları dosyanın en başına ekle
        if hoisted_imports:
            existing_top = "".join(before)
            missing_imports = [
                imp.strip() + "\n"
                for imp in hoisted_imports
                if imp.strip() and imp.strip() not in existing_top
            ]
            if missing_imports:
                before = missing_imports + before

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
