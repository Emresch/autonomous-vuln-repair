import json
import urllib.request
import re
import textwrap
from typing import Dict, Any, Optional

class PatchSynthesizer:
    def __init__(self, model_name: str = "qwen2.5-coder:7b", base_url: str = "http://localhost:11434"):
        self.model_name = model_name
        self.base_url = base_url

    def generate_repair_prompt(self, ast_chunk: Dict[str, Any], sast_report: Dict[str, Any], feedback: Optional[str] = None) -> str:
        """
        AST'den kırpılan fonksiyon ve SAST'tan gelen zafiyet raporunu birleştirerek
        Qwen için cerrahi bir prompt oluşturur.
        """
        prompt = f"""You are an expert automated program repair system specializing in software security.
Your task is to fix a security vulnerability in the Python function provided below.

### VULNERABILITY DIAGNOSIS (From SAST Engine)
- Target File: {sast_report.get('filename')}
- Vulnerability Type: {sast_report.get('cwe')} ({sast_report.get('test_id')})
- Diagnosis: {sast_report.get('issue_text')}
- Problematic Line: {sast_report.get('line_number')}

### CODE CONTEXT (Imports)
```python
{ast_chunk.get('imports', '')}
```

### VULNERABLE FUNCTION (To be repaired)
```python
{ast_chunk.get('function_code', '')}
```
"""

        if feedback:
            prompt += f"""
### FEEDBACK FROM PREVIOUS DOCKER TEST FAILURE
The previous patch candidate failed the verification tests with the following error:
{feedback}
Please analyze this failure, keep the original functional contract, and fix the remaining issue.
"""

        prompt += """
### INSTRUCTIONS:
1. Repair the vulnerability completely (e.g. use secure parameterized queries).
2. DO NOT change the function signature, argument names, or return format. Existing functional tests must continue to pass!
3. Provide ONLY the complete, repaired Python function inside a single ```python ... ``` code block. Do not include unnecessary explanations.
"""
        return prompt

    def query_ollama(self, prompt: str) -> str:
        """Ollama yerel REST API'sine istek gönderir."""
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.2,
                "top_p": 0.95
            }
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})

        try:
            with urllib.request.urlopen(req) as response:
                result = json.loads(response.read().decode("utf-8"))
                return result.get("response", "")
        except Exception as e:
            raise RuntimeError(f"Ollama API ile iletişim kurulamadı: {e}")

    def extract_code_block(self, response_text: str) -> str:
        """Model yanıtından ```python ``` bloğunu ayıklar."""
        pattern = r"```(?:python)?\s*(.*?)\s*```"
        match = re.search(pattern, response_text, re.DOTALL)
        if match:
            return match.group(1).strip()
        return response_text.strip()

    def apply_patch_to_file(self, file_path: str, start_line: int, end_line: int, new_code: str) -> None:
        """
        Orijinal dosyada start_line ile end_line arasındaki zafiyetli fonksiyonu
        Qwen'in ürettiği güvenli fonksiyonla yer değiştirir.
        textwrap ile girinti seviyesini kusursuz şekilde korur.
        """
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        target_first_line = lines[start_line - 1] if start_line - 1 < len(lines) else ""
        indent_len = len(target_first_line) - len(target_first_line.lstrip())
        base_indent = target_first_line[:indent_len]

        # Önce modelin ürettiği kodun fazlalık girintilerini temizle (0 seviyesine çek)
        clean_code = textwrap.dedent(new_code.strip())
        # Ardından orijinal satırın girinti seviyesine göre hizala
        aligned_code = textwrap.indent(clean_code, base_indent)

        # 1-indexed to 0-indexed
        before = lines[: start_line - 1]
        after = lines[end_line:]

        patched_lines = before + [aligned_code + "\n"] + after

        with open(file_path, "w", encoding="utf-8") as f:
            f.writelines(patched_lines)

if __name__ == "__main__":
    import sys
    from pathlib import Path

    # Test amaçlı doğrudan çağırma
    from pipeline.sast.sast_engine import SASTEngine
    from pipeline.pruner.ast_pruner import ASTContextPruner

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
    prompt = synthesizer.generate_repair_prompt(chunk, f)
    print("\n[Synthesizer] Qwen modeline prompt gönderiliyor (Ollama)...")
    raw_response = synthesizer.query_ollama(prompt)
    clean_patch = synthesizer.extract_code_block(raw_response)

    print("\n[Qwen Tarafından Üretilen Güvenli Yama]:")
    print(clean_patch)
