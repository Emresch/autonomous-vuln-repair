import json
import urllib.request
from pathlib import Path
from typing import Dict, Any, List, Optional

class BenchmarkIngestion:
    SUSVIBES_DATASET_URL = "https://raw.githubusercontent.com/LeiLiLab/susvibes/main/datasets/default/susvibes_dataset.jsonl"

    def __init__(self, local_dataset_path: Optional[str] = None):
        self.benchmark_dir = Path(__file__).parent
        self.dataset_file = Path(local_dataset_path) if local_dataset_path else (self.benchmark_dir / "susvibes_dataset.jsonl")

    def download_dataset_if_missing(self) -> Path:
        """Eğer yerel JSONL veri dosyası yoksa GitHub üzerinden indirir."""
        if not self.dataset_file.exists():
            print(f"[*] SusVibes veri kümesi indiriliyor: {self.SUSVIBES_DATASET_URL}")
            req = urllib.request.Request(self.SUSVIBES_DATASET_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req) as resp:
                content = resp.read()
            with open(self.dataset_file, "wb") as f:
                f.write(content)
            print(f"[+] Veri kümesi başarıyla kaydedildi ({len(content) // 1024} KB): {self.dataset_file}")
        return self.dataset_file

    def get_task_by_id(self, instance_id: str) -> Optional[Dict[str, Any]]:
        """Belirtilen instance_id'ye sahip görevi döndürür."""
        self.download_dataset_if_missing()
        with open(self.dataset_file, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                task = json.loads(line)
                if task.get("instance_id") == instance_id:
                    return task
        return None

    def filter_tasks(self, cwe: Optional[str] = None, max_patch_lines: int = 50) -> List[Dict[str, Any]]:
        """
        Belirli bir CWE türüne ve yama uzunluğuna göre uygun görevleri listeler.
        Örn: cwe='CWE-22'
        """
        self.download_dataset_if_missing()
        matched = []
        with open(self.dataset_file, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                task = json.loads(line)
                cwes = task.get("cwe_ids", [])
                patch = task.get("security_patch", "")
                patch_len = patch.count("\n")

                if cwe and cwe not in str(cwes):
                    continue

                if patch_len <= max_patch_lines:
                    matched.append({
                        "instance_id": task.get("instance_id"),
                        "project": task.get("project"),
                        "cwe": cwes,
                        "cve_id": task.get("cve_id"),
                        "patch_lines": patch_len,
                        "docker_image": task.get("image_name")
                    })
        return matched

if __name__ == "__main__":
    ingestion = BenchmarkIngestion()
    print("\n--- SusVibes Ingestion Modülü Test Ediliyor ---")
    
    # 1. Starlette görevini çek
    starlette_id = "encode__starlette_1797de464124b090f10cf570441e8292936d63e3"
    task = ingestion.get_task_by_id(starlette_id)

    if task:
        print(f"\n[+] Görev Başarıyla Çekildi: {task['project']}")
        print(f"    ├─ Instance ID : {task['instance_id']}")
        print(f"    ├─ CVE ID      : {task['cve_id']}")
        print(f"    ├─ CWE         : {task['cwe_ids']}")
        print(f"    └─ Docker İmajı: {task['image_name']}")

    # 2. Diğer küçük CWE-22 ve CWE-89 görevlerini listele
    print("\n[+] Filtrelenen Örnek Görevler (Kompakt ve Uygun):")
    candidates = ingestion.filter_tasks(cwe="CWE-22", max_patch_lines=30)
    for c in candidates[:5]:
        print(f"  * {c['project']} | {c['cwe']} | {c['cve_id']} ({c['patch_lines']} satır diff)")
