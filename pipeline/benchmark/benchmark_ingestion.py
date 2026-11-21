from collections import Counter
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import urllib.request


class BenchmarkIngestion:
    SUSVIBES_DATASET_URL = (
        "https://raw.githubusercontent.com/LeiLiLab/susvibes/main/datasets/default/susvibes_dataset.jsonl"
    )

    def __init__(self, local_dataset_path: Optional[str] = None):
        self.benchmark_dir = Path(__file__).parent
        self.dataset_file = (
            Path(local_dataset_path)
            if local_dataset_path
            else (self.benchmark_dir / "susvibes_dataset.jsonl")
        )

    def download_dataset_if_missing(self) -> Path:
        """Eğer yerel JSONL veri dosyası yoksa GitHub üzerinden indirir."""
        if not self.dataset_file.exists():
            print(f"[*] SusVibes veri kümesi indiriliyor: {self.SUSVIBES_DATASET_URL}")
            req = urllib.request.Request(
                self.SUSVIBES_DATASET_URL, headers={"User-Agent": "Mozilla/5.0"}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                content = resp.read()
            with open(self.dataset_file, "wb") as f:
                f.write(content)
            print(
                f"[+] Veri kümesi başarıyla kaydedildi ({len(content) // 1024} KB): "
                f"{self.dataset_file.as_posix()}"
            )
        return self.dataset_file

    def _iter_tasks(self, allow_download: bool = True):
        if not self.dataset_file.exists():
            if not allow_download:
                return
            self.download_dataset_if_missing()
        with open(self.dataset_file, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                yield json.loads(line)

    def get_task_by_id(
        self, instance_id: str, allow_download: bool = True
    ) -> Optional[Dict[str, Any]]:
        """Belirtilen instance_id'ye sahip görevi döndürür."""
        for task in self._iter_tasks(allow_download=allow_download):
            if task.get("instance_id") == instance_id:
                return task
        return None

    def get_task_by_cve(
        self, cve_id: str, allow_download: bool = False
    ) -> Optional[Dict[str, Any]]:
        """Belirtilen CVE kimliğine (örn. CVE-2023-29159) sahip ilk SusVibes görevini döndürür."""
        target = cve_id.strip().upper()
        for task in self._iter_tasks(allow_download=allow_download):
            if str(task.get("cve_id", "")).strip().upper() == target:
                return task
        return None

    def get_task_metadata(
        self,
        instance_id: Optional[str] = None,
        cve_id: Optional[str] = None,
        allow_download: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """
        Kontrollü mikro-kıyaslama görevlerini SusVibes veri kümesindeki orijinal
        kayıtla ilişkilendirmek için özet metadata döndürür.
        """
        task = None
        if instance_id:
            task = self.get_task_by_id(instance_id, allow_download=allow_download)
        if not task and cve_id:
            task = self.get_task_by_cve(cve_id, allow_download=allow_download)
        if not task:
            return None

        patch = task.get("security_patch", "")
        return {
            "source": "SusVibes (susvibes_dataset.jsonl)",
            "instance_id": task.get("instance_id"),
            "project": task.get("project"),
            "cve_id": task.get("cve_id"),
            "cwe_ids": task.get("cwe_ids", []),
            "base_commit": task.get("base_commit"),
            "docker_image": task.get("image_name"),
            "reference_patch_lines": patch.count("\n"),
        }

    def get_dataset_stats(self, allow_download: bool = False) -> Dict[str, Any]:
        """Yerel SusVibes JSONL veri kümesinin toplam görev ve CWE dağılım özetini çıkarır."""
        if not self.dataset_file.exists() and not allow_download:
            return {"available": False, "total_tasks": 0, "top_cwes": {}}

        total = 0
        cwe_counter: Counter = Counter()
        for task in self._iter_tasks(allow_download=allow_download):
            total += 1
            for cwe in task.get("cwe_ids", []):
                cwe_counter[str(cwe)] += 1

        return {
            "available": True,
            "dataset_file": self.dataset_file.as_posix(),
            "total_tasks": total,
            "top_cwes": dict(cwe_counter.most_common(10)),
        }

    def filter_tasks(
        self,
        cwe: Optional[str] = None,
        max_patch_lines: int = 50,
        allow_download: bool = True,
    ) -> List[Dict[str, Any]]:
        """Belirli bir CWE türüne ve yama uzunluğuna göre uygun görevleri listeler."""
        matched = []
        for task in self._iter_tasks(allow_download=allow_download):
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
                    "docker_image": task.get("image_name"),
                })
        return matched

    def export_task_manifest(
        self, instance_id: str, output_dir: str, allow_download: bool = False
    ) -> Optional[Path]:
        """
        Gelecekteki tam otomatik SusVibes değerlendirmesi için bir görevin
        metadata, problem_statement ve referans yamasını standart manifest.json olarak dışa aktarır.
        """
        task = self.get_task_by_id(instance_id, allow_download=allow_download)
        if not task:
            return None

        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        manifest_file = out_path / "susvibes_manifest.json"
        manifest = {
            "instance_id": task.get("instance_id"),
            "project": task.get("project"),
            "cve_id": task.get("cve_id"),
            "cwe_ids": task.get("cwe_ids", []),
            "base_commit": task.get("base_commit"),
            "docker_image": task.get("image_name"),
            "problem_statement": task.get("problem_statement", ""),
            "reference_security_patch": task.get("security_patch", ""),
        }
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)
        return manifest_file


if __name__ == "__main__":
    ingestion = BenchmarkIngestion()
    print("\n--- SusVibes Ingestion Modülü Test Ediliyor ---")
    stats = ingestion.get_dataset_stats(allow_download=True)
    print(f"[+] Veri kümesi istatistikleri: {stats['total_tasks']} görev")

    starlette_id = "encode__starlette_1797de464124b090f10cf570441e8292936d63e3"
    meta = ingestion.get_task_metadata(instance_id=starlette_id)
    if meta:
        print(f"\n[+] Görev Başarıyla Çekildi: {meta['project']}")
        print(f"    ├─ Instance ID : {meta['instance_id']}")
        print(f"    ├─ CVE ID      : {meta['cve_id']}")
        print(f"    ├─ CWE         : {meta['cwe_ids']}")
        print(f"    └─ Docker İmajı: {meta['docker_image']}")

    print("\n[+] Filtrelenen Örnek Görevler (CWE-22, <=30 satır diff):")
    candidates = ingestion.filter_tasks(cwe="CWE-22", max_patch_lines=30)
    for c in candidates[:5]:
        print(
            f"  * {c['project']} | {c['cwe']} | {c['cve_id']} ({c['patch_lines']} satır diff)"
        )
