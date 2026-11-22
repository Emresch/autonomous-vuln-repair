"""
AVR Benchmark Kıyaslama Aracı (Comparison Utility)
Farklı model ve modlardaki (Zero-Shot vs Self-Healing Multi-Turn) benchmark özetlerini
karşılaştırarak akademik tez ve sunumlar için özet matrisi üretir.
"""

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


def load_summary(path: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Özet dosyası bulunamadı: {path}")
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def print_comparison_matrix(runs: List[Dict[str, Any]], labels: List[str]) -> None:
    print("\n" + "=" * 110)
    print("🔬 AVR BENCHMARK KIYASLAMA VE ABLATION ANALİZİ (Zero-Shot vs Multi-Turn)")
    print("=" * 110)

    # Genel Metrikler Tablosu
    header = f"{'METRİK':<32} | " + " | ".join(f"{lbl:^16}" for lbl in labels)
    print(header)
    print("-" * 110)

    # 1. Başarı Oranı
    pass_rates = []
    for r in runs:
        res = r.get("results", [])
        passed = sum(1 for x in res if x.get("repaired"))
        total = len(res)
        pct = (passed / total) * 100 if total else 0.0
        pass_rates.append(f"{passed}/{total} (%{pct:.1f})")
    print(f"{'Genel Başarı Oranı':<32} | " + " | ".join(f"{pr:^16}" for pr in pass_rates))

    # 2. Ortalama Tur Sayısı
    avg_turns = []
    for r in runs:
        res = r.get("results", [])
        turns = [x.get("turns", 0) for x in res]
        avg = sum(turns) / len(turns) if turns else 0.0
        avg_turns.append(f"{avg:.2f}")
    print(f"{'Ortalama Tur (Turns)':<32} | " + " | ".join(f"{at:^16}" for at in avg_turns))

    # 3. Ortalama Confidence (Güven Skoru)
    avg_confs = []
    for r in runs:
        res = r.get("results", [])
        c_list = [
            x.get("llm_metrics_summary", {}).get("mean_confidence_score")
            for x in res
            if x.get("llm_metrics_summary", {}).get("mean_confidence_score") is not None
        ]
        avg = (sum(c_list) / len(c_list)) if c_list else 0.0
        avg_confs.append(f"{avg:.4f}")
    print(f"{'Ortalama LLM Güven Skoru':<32} | " + " | ".join(f"{ac:^16}" for ac in avg_confs))

    # 4. Ortalama Entropy (Belirsizlik)
    avg_ents = []
    for r in runs:
        res = r.get("results", [])
        e_list = [
            x.get("llm_metrics_summary", {}).get("mean_entropy")
            for x in res
            if x.get("llm_metrics_summary", {}).get("mean_entropy") is not None
        ]
        avg = (sum(e_list) / len(e_list)) if e_list else 0.0
        avg_ents.append(f"{avg:.4f}")
    print(f"{'Ortalama Token Entropisi':<32} | " + " | ".join(f"{ae:^16}" for ae in avg_ents))

    # 5. Toplam Süre
    times = [f"{r.get('total_time_seconds', 0.0):.1f}s" for r in runs]
    print(f"{'Toplam Çalışma Süresi':<32} | " + " | ".join(f"{tm:^16}" for tm in times))
    print("-" * 110)

    # Görev Bazlı Karşılaştırma (Self-healing katkısını gösteren tablo)
    if len(runs) >= 2:
        print("\n🎯 GÖREV BAZLI KARŞILAŞTIRMA (Hangi Görevler Hangi Koşulda Çözüldü?):")
        print("-" * 110)
        t_header = f"{'ID':<7} | {'GÖREV ADI':<26} | " + " | ".join(f"{lbl:^16}" for lbl in labels)
        print(t_header)
        print("-" * 110)

        # İlk koşulun görev listesini referans alalım
        ref_results = runs[0].get("results", [])
        for i, ref_item in enumerate(ref_results):
            task_id = ref_item.get("id")
            name = ref_item.get("name", "")[:26]
            statuses = []
            for r in runs:
                matched = next((x for x in r.get("results", []) if x.get("id") == task_id), None)
                if matched:
                    st = "PASS ✅" if matched.get("repaired") else "FAIL ❌"
                    tr = f" (T{matched.get('turns')})"
                    statuses.append(f"{st}{tr}")
                else:
                    statuses.append("N/A")
            print(f"{task_id:<7} | {name:<26} | " + " | ".join(f"{s:^16}" for s in statuses))
        print("-" * 110)


def main() -> None:
    parser = argparse.ArgumentParser(description="AVR Benchmark JSON Kıyaslayıcı")
    parser.add_argument("files", nargs="+", help="Kıyaslanacak özet JSON dosyaları")
    parser.add_argument("--labels", nargs="+", help="Her dosya için gösterim etiketi")
    args = parser.parse_args()

    runs = [load_summary(f) for f in args.files]
    labels = args.labels if args.labels and len(args.labels) == len(runs) else [Path(f).stem for f in args.files]

    print_comparison_matrix(runs, labels)


if __name__ == "__main__":
    main()
