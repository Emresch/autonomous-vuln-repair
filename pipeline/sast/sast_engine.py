import json
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Any

class SASTEngine:
    def __init__(self, target_path: str):
        self.target_path = Path(target_path)

    def scan_with_bandit(self) -> List[Dict[str, Any]]:
        """
        Belirtilen hedef dosya veya klasör üzerinde Bandit SAST taraması yapar.
        Sonuçları yapılandırılmış bir liste olarak döndürür.
        """
        cmd = [
            sys.executable, "-m", "bandit",
            "-r", str(self.target_path),
            "-f", "json",
            "-q"  # Sessiz mod (sadece json çıktısını al)
        ]

        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
        
        # Bandit bulgu bulduğunda exit code 1 döner, bu yüzden returncode!=0 normaldir.
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
                "filename": item.get("filename"),
                "line_number": item.get("line_number"),
                "test_id": item.get("test_id"),
                "cwe": cwe_id,
                "severity": item.get("issue_severity"),
                "issue_text": item.get("issue_text"),
                "code": item.get("code")
            })

        return findings

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "sample_task/app.py"
    engine = SASTEngine(target)
    findings = engine.scan_with_bandit()
    print(f"\n[SAST Motoru] {len(findings)} zafiyet tespit edildi:\n")
    for f in findings:
        print(f"[-] Dosya: {f['filename']} | Satır: {f['line_number']}")
        print(f"    Kural: {f['test_id']} ({f['cwe']})")
        print(f"    Teşhis: {f['issue_text']}")
        print(f"    Kod Parçası:\n{f['code']}")
