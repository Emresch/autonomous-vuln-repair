import json
import subprocess
import sys
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional

class SASTEngine:
    def __init__(self, target_path: str):
        self.target_path = Path(target_path)
        self.rules_file = Path(__file__).parent / "rules.yaml"

    def scan_with_bandit(self, target: Optional[Path] = None) -> List[Dict[str, Any]]:
        """Bandit ile statik kural analizi yapar."""
        scan_target = target or self.target_path
        cmd = [
            sys.executable, "-m", "bandit",
            "-r", str(scan_target),
            "-f", "json",
            "-q"
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
        output = result.stdout.strip()
        if not output:
            return []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return []

        findings = []
        for item in data.get("results", []):
            cwe_info = item.get("issue_cwe", {})
            cwe_id = f"CWE-{cwe_info.get('id')}" if isinstance(cwe_info, dict) and cwe_info.get("id") else "Unknown"

            findings.append({
                "engine": "Bandit",
                "filename": item.get("filename"),
                "line_number": item.get("line_number"),
                "test_id": item.get("test_id"),
                "cwe": cwe_id,
                "severity": item.get("issue_severity"),
                "issue_text": item.get("issue_text"),
                "code": item.get("code")
            })
        return findings

    def scan_with_semgrep(self, target: Optional[Path] = None) -> List[Dict[str, Any]]:
        """Semgrep ile semantik kural ve örüntü analizi yapar."""
        scan_target = target or self.target_path
        semgrep_bin = shutil.which("semgrep") or "semgrep"
        cmd = [
            semgrep_bin,
            "--config", str(self.rules_file),
            str(scan_target),
            "--json"
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
        output = result.stdout.strip()
        if not output:
            return []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return []

        findings = []
        for item in data.get("results", []):
            extra = item.get("extra", {})
            meta = extra.get("metadata", {})
            findings.append({
                "engine": "Semgrep",
                "filename": item.get("path"),
                "line_number": item.get("start", {}).get("line"),
                "test_id": item.get("check_id", "").split(".")[-1],
                "cwe": meta.get("cwe", "CWE-Unknown").split(":")[0],
                "severity": extra.get("severity"),
                "issue_text": extra.get("message"),
                "code": extra.get("lines", "")
            })
        return findings

    def scan(self, target: Optional[Path] = None) -> List[Dict[str, Any]]:
        """
        Hibrit (Ensemble) Tarama:
        Hem Bandit'i hem de Semgrep'i çalıştırır.
        Tüm tespitleri dosya ve satır bazında tek bir listede birleştirir.
        """
        all_findings = []
        
        # 1. Bandit Taraması (Python sözdizim ve tehlikeli kütüphane analizleri)
        bandit_res = self.scan_with_bandit(target)
        all_findings.extend(bandit_res)

        # 2. Semgrep Taraması (Semantik örüntüler ve yol ayracı / CWE denetimleri)
        if self.rules_file.exists():
            semgrep_res = self.scan_with_semgrep(target)
            all_findings.extend(semgrep_res)

        # Satır numarasına göre sırala
        all_findings.sort(key=lambda x: (x.get("filename", ""), x.get("line_number", 0)))
        return all_findings

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "pipeline/sample_task"
    engine = SASTEngine(target)
    findings = engine.scan()
    print(f"\n[SAST Hibrit Motor] {len(findings)} zafiyet tespit edildi:")
    for f in findings:
        print(f"[-] Motor: {f['engine']} | Dosya: {f['filename']} | Satır: {f['line_number']}")
        print(f"    Kural: {f['test_id']} ({f['cwe']})")
        print(f"    Mesaj: {f['issue_text']}\n")
