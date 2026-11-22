import argparse
from collections import defaultdict
import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional

from pipeline.benchmark.benchmark_ingestion import BenchmarkIngestion
from pipeline.benchmark.suite_definitions import (
    AIRFLOW_VULN_CODE,
    BENCHMARK_SUITE,
    MULTI_VULN_CODE,
    SAMPLE_TASK_VULN_CODE,
    STARLETTE_VULN_CODE,
    materialize_task_files,
)
from pipeline.config import AVRConfig, detect_runtime_environment
from pipeline.controller import SelfHealingController
from pipeline.sandbox.docker_runner import DockerSandbox
from pipeline.sast.sast_engine import SASTEngine
from pipeline.synthesizer.synthesizer import PatchSynthesizer


def reset_task_file(task_info: Dict[str, Any]) -> None:
    """Görevin kaynak dosyasını (ve varsa test dosyalarını) orijinal zafiyetli haline sıfırlar."""
    materialize_task_files(task_info)


def print_summary_table(
    results: List[Dict[str, Any]],
    total_elapsed: float,
    config: AVRConfig,
    env_info: Dict[str, str],
) -> None:
    """Terminalde jüriye sunulabilecek 25 görevlik detaylı ve kategori bazlı kıyaslama tablolarını basar."""
    print("\n" + "=" * 124)
    print("🏆 OTONOM GÜVENLİK YAMA MOTORU - 25 GÖREVLİK ÇOK-KATEGORİLİ BENCHMARK DEĞERLENDİRME RAPORU")
    print("=" * 124)

    header = (
        f"{'ID':<7} | {'GÖREV ADI':<28} | {'ZAFİYET TÜRÜ':<28} | {'MOTOR':<13} | "
        f"{'TUR':<3} | {'CONF':<6} | {'ENTROPY':<7} | {'SÜRE':<7} | {'DURUM'}"
    )
    print(header)
    print("-" * 124)

    passed_count = 0
    cat_buckets: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for r in results:
        status_str = "BAŞARILI ✅" if r["repaired"] else "BAŞARISIZ ❌"
        if r["repaired"]:
            passed_count += 1
        engines_str = ",".join(sorted(r["engines"])) if r["engines"] else "None"
        time_str = f"{r['duration']:.2f}s"

        metrics = r.get("llm_metrics_summary") or {}
        conf = metrics.get("mean_confidence_score")
        ent = metrics.get("mean_entropy")
        conf_str = f"{conf:.3f}" if conf is not None else "  -   "
        ent_str = f"{ent:.4f}" if ent is not None else "   -   "

        row = (
            f"{r['id']:<7} | {r['name'][:28]:<28} | {r['type'][:28]:<28} | {engines_str[:13]:<13} | "
            f"{r['turns']:<3} | {conf_str:<6} | {ent_str:<7} | {time_str:<7} | {status_str}"
        )
        print(row)
        cat_buckets[r.get("category", "Uncategorized")].append(r)

    print("-" * 124)

    # Kategori Bazlı Akademik Özet Tablosu
    print("\n📊 KATEGORİ BAZLI AKADEMİK BAŞARI VE TELEMETRİ ÖZETİ:")
    print("-" * 104)
    cat_header = (
        f"{'KATEGORİ':<32} | {'BAŞARI':<14} | {'ORT. TUR':<9} | "
        f"{'ORT. CONFIDENCE':<16} | {'ORT. ENTROPY':<13} | {'TOPLAM SÜRE'}"
    )
    print(cat_header)
    print("-" * 104)

    for cat_name, items in cat_buckets.items():
        cat_passed = sum(1 for x in items if x["repaired"])
        cat_rate = (cat_passed / len(items)) * 100 if items else 0.0
        avg_turns = sum(x["turns"] for x in items) / len(items) if items else 0.0
        cat_time = sum(x["duration"] for x in items)

        confs = [
            x["llm_metrics_summary"]["mean_confidence_score"]
            for x in items
            if x.get("llm_metrics_summary")
            and x["llm_metrics_summary"].get("mean_confidence_score") is not None
        ]
        ents = [
            x["llm_metrics_summary"]["mean_entropy"]
            for x in items
            if x.get("llm_metrics_summary")
            and x["llm_metrics_summary"].get("mean_entropy") is not None
        ]
        avg_conf_str = f"{sum(confs) / len(confs):.4f}" if confs else "-"
        avg_ent_str = f"{sum(ents) / len(ents):.4f}" if ents else "-"

        print(
            f"{cat_name:<32} | {cat_passed}/{len(items)} (%{cat_rate:>5.1f}) | "
            f"{avg_turns:<9.2f} | {avg_conf_str:<16} | {avg_ent_str:<13} | {cat_time:.2f}s"
        )

    print("-" * 104)
    success_rate = (passed_count / len(results)) * 100 if results else 0.0
    verify_mode = "Paralel (ThreadPoolExecutor)" if config.parallel_verification else "Sıralı"
    print(f"Toplam Başarı Oranı : %{success_rate:.1f} ({passed_count}/{len(results)} Görev Onarıldı)")
    print(f"Toplam Süre         : {total_elapsed:.2f} saniye")
    print(f"LLM Arka Ucu / Model: {config.backend} / {config.model_name}")
    print(f"Doğrulama Modu      : {verify_mode} | Sealed Sandbox (--network none, :ro)")
    print(f"Çalışma Ortamı      : {env_info['hardware_hint']} | Python {env_info['python_version']}")
    print("=" * 124 + "\n")


def verify_suite_preflight(
    task_filter: Optional[str] = None,
    category_filter: Optional[str] = None,
) -> bool:
    """
    LLM çalıştırmadan önce tüm görevlerin:
      1. Dosyalarını diske yazar (materialize),
      2. FAZ 1 Baseline kontrolünü (func_test=PASS ve sec_test=FAIL) doğrular,
      3. FAZ 2 SAST taramasında (Bandit + Semgrep) en az 1 bulgu yakalandığını doğrular.
    """
    tasks = _select_tasks(task_filter=task_filter, category_filter=category_filter)
    sandbox = DockerSandbox(parallel=False)
    sandbox.verify_docker_ready(auto_build=True)
    sast = SASTEngine()

    print("\n" + "=" * 110)
    print(f"🔍 BENCHMARK PRE-FLIGHT DOĞRULAMASI ({len(tasks)} GÖREV: BASELINE + SAST KONTROLÜ)")
    print("=" * 110)
    print(
        f"{'ID':<7} | {'KATEGORİ':<28} | {'GÖREV ADI':<26} | "
        f"{'FUNC':<6} | {'SEC (EXPLOIT)':<14} | {'SAST BULGU'}"
    )
    print("-" * 110)

    all_ok = True
    for task in tasks:
        task_dir = materialize_task_files(task)
        target_file = task_dir / task["file"]

        base = sandbox.run_dual_verification(str(task_dir), parallel=False)
        func_ok = base["func_pass"]
        sec_fail_as_expected = not base["sec_pass"]

        findings = [
            f
            for f in sast.scan(target_file)
            if f.get("test_id") not in ("B404", "B410")
        ]
        sast_ok = len(findings) >= 1
        engines = ",".join(sorted({f["engine"] for f in findings})) if findings else "YOK!"

        task_valid = func_ok and sec_fail_as_expected and sast_ok
        if not task_valid:
            all_ok = False

        func_str = "PASS✅" if func_ok else "FAIL❌"
        sec_str = "FAIL (Açık)✅" if sec_fail_as_expected else "PASS (Hata!)❌"
        sast_str = f"{len(findings)} ({engines}) ✅" if sast_ok else "0 BULGU ❌"

        print(
            f"{task['id']:<7} | {task.get('category', ''):<28} | {task['name'][:26]:<26} | "
            f"{func_str:<6} | {sec_str:<14} | {sast_str}"
        )

    print("=" * 110)
    if all_ok:
        print(f"🎯 [BAŞARILI] Tüm {len(tasks)} görev Baseline (func=PASS, sec=FAIL) ve SAST şartlarını %100 sağlıyor!\n")
    else:
        print("[!] UYARI: Bazı görevler pre-flight kontrolünden geçemedi.\n")
    return all_ok


def _select_tasks(
    task_filter: Optional[str] = None,
    category_filter: Optional[str] = None,
    limit: Optional[int] = None,
) -> List[Dict[str, Any]]:
    tasks = list(BENCHMARK_SUITE)
    if category_filter:
        c_needle = category_filter.lower()
        tasks = [t for t in tasks if c_needle in t.get("category", "").lower()]
    if task_filter:
        needle = task_filter.lower()
        tasks = [
            t
            for t in tasks
            if needle in t["id"].lower()
            or needle in t["name"].lower()
            or needle in t["dir"].lower()
            or needle in t["type"].lower()
        ]
    if limit is not None and limit > 0:
        tasks = tasks[:limit]
    if not tasks:
        raise ValueError("Filtre kriterlerine uyan benchmark görevi bulunamadı.")
    return tasks


def run_all_benchmarks(
    config: Optional[AVRConfig] = None,
    task_filter: Optional[str] = None,
    category_filter: Optional[str] = None,
    limit: Optional[int] = None,
    output_summary_path: Optional[str] = None,
) -> Dict[str, Any]:
    cfg = config or AVRConfig()
    env_info = detect_runtime_environment()
    ingestion = BenchmarkIngestion()
    susvibes_stats = ingestion.get_dataset_stats(allow_download=False)

    tasks_to_run = _select_tasks(
        task_filter=task_filter,
        category_filter=category_filter,
        limit=limit,
    )

    print("\n" + "#" * 84)
    print(f"🚀 AVR BENCHMARK GÖREVLERİ ÇALIŞTIRILIYOR (Toplam Seçilen Görev: {len(tasks_to_run)})")
    if susvibes_stats.get("available"):
        print(
            f"   SusVibes Veri Kümesi Bağlandı: {susvibes_stats['total_tasks']} toplam kayıt "
            f"({susvibes_stats['dataset_file']})"
        )
    print("#" * 84)

    # VRAM Optimizasyonu: Modeli yalnızca 1 kez oluşturup tüm görevlerde ortak kullan!
    shared_synthesizer = PatchSynthesizer(
        model_name=cfg.model_name,
        base_url=cfg.ollama_base_url,
        backend=cfg.backend,
        timeout=cfg.llm_timeout,
        temperature=cfg.temperature,
        top_p=cfg.top_p,
    )
    cfg.model_name = shared_synthesizer.model_name

    shared_sandbox = DockerSandbox(
        image_name=cfg.docker_image,
        timeout=cfg.sandbox_timeout,
        memory_limit=cfg.sandbox_memory,
        cpu_limit=cfg.sandbox_cpus,
        pids_limit=cfg.sandbox_pids_limit,
        parallel=cfg.parallel_verification,
    )
    shared_sandbox.verify_docker_ready(auto_build=True)

    overall_start = time.time()
    results: List[Dict[str, Any]] = []

    try:
        for idx, task in enumerate(tasks_to_run, 1):
            susvibes_meta = None
            if task.get("susvibes_instance_id") or task.get("cve_id"):
                susvibes_meta = ingestion.get_task_metadata(
                    instance_id=task.get("susvibes_instance_id"),
                    cve_id=task.get("cve_id"),
                    allow_download=False,
                )

            print(
                f"\n[+] [{idx}/{len(tasks_to_run)}] Görev Hazırlanıyor: "
                f"{task['id']} - {task['name']} ({task['type']}) [{task.get('category', '')}]..."
            )
            if susvibes_meta:
                print(
                    f"    └─ SusVibes Referansı: {susvibes_meta['project']} "
                    f"({susvibes_meta['cve_id']} | {susvibes_meta['instance_id']})"
                )

            reset_task_file(task)

            task_start = time.time()
            controller = SelfHealingController(
                task_dir=task["dir"],
                target_file=task["file"],
                config=cfg,
                synthesizer=shared_synthesizer,
                sandbox=shared_sandbox,
            )
            task_report = controller.run()
            duration = time.time() - task_start

            findings = task_report.get("findings", [])
            engines = sorted({f.get("engine", "SAST") for f in findings}) if findings else []

            results.append({
                "id": task["id"],
                "name": task["name"],
                "category": task.get("category", "General"),
                "type": task["type"],
                "provenance": task["provenance"],
                "susvibes_metadata": susvibes_meta,
                "engines": engines,
                "status": task_report.get("status"),
                "repaired": task_report.get("repaired", False),
                "turns": task_report.get("turns_used", 0),
                "duration": round(duration, 3),
                "rolled_back_to_original": task_report.get("rolled_back_to_original", False),
                "llm_metrics_summary": task_report.get("llm_metrics_summary", {}),
                "unified_diff": task_report.get("unified_diff", {}),
            })
    finally:
        # Benchmark tamamlandığında VRAM'i otomatik olarak serbest bırak
        shared_synthesizer.unload_model()

    overall_elapsed = time.time() - overall_start
    print_summary_table(results, overall_elapsed, cfg, env_info)

    summary_payload = {
        "benchmark_mode": "multi_category_25_benchmark",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "backend": cfg.backend,
        "model_name": cfg.model_name,
        "parallel_verification": cfg.parallel_verification,
        "environment": env_info,
        "susvibes_dataset": susvibes_stats,
        "total_tasks": len(results),
        "success_rate": f"%{(sum(1 for r in results if r['repaired']) / len(results)) * 100:.1f}",
        "total_time_seconds": round(overall_elapsed, 3),
        "results": results,
    }

    out_json = Path(output_summary_path) if output_summary_path else Path("pipeline/benchmark_summary.json")
    out_json.parent.mkdir(parents=True, exist_ok=True)
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(summary_payload, f, indent=2, ensure_ascii=False)

    print(f"[Rapor] Toplu sonuçlar kaydedildi: {out_json.as_posix()}")
    return summary_payload


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AVR 25-Task Multi-Category Benchmark & SusVibes Ingestion Runner"
    )
    parser.add_argument("--backend", choices=["ollama", "transformers"], default=None)
    parser.add_argument("--model", default=None, help="Kullanılacak LLM modeli")
    parser.add_argument("--max-turns", type=int, default=None)
    parser.add_argument("--output-summary", default=None, help="Özet JSON raporunun kaydedileceği dosya yolu")
    parser.add_argument("--task", default=None, help="Sadece eşleşen görevi çalıştır (örn. TASK-03, airflow)")
    parser.add_argument("--category", default=None, help="Sadece eşleşen kategoriyi çalıştır (örn. CAT-1, Web)")
    parser.add_argument("--limit", type=int, default=None, help="Çalıştırılacak maksimum görev sayısı")
    parser.add_argument("--sequential", action="store_true", help="func/sec testlerini sıralı koştur")
    parser.add_argument(
        "--verify-suite",
        action="store_true",
        help="LLM çalıştırmadan tüm 25 görevin Baseline (func=PASS, sec=FAIL) ve SAST durumunu doğrula",
    )
    parser.add_argument(
        "--list-susvibes",
        metavar="CWE",
        nargs="?",
        const="",
        default=None,
        help="SusVibes veri kümesindeki uygun görevleri listele (opsiyonel CWE filtresi, örn. CWE-22)",
    )
    args = parser.parse_args()

    if args.list_susvibes is not None:
        ingestion = BenchmarkIngestion()
        cwe_filter = args.list_susvibes or None
        stats = ingestion.get_dataset_stats(allow_download=False)
        print(f"\nSusVibes Veri Kümesi: {stats}")
        candidates = ingestion.filter_tasks(cwe=cwe_filter, max_patch_lines=30, allow_download=False)
        print(f"Eşleşen kompakt görev sayısı ({cwe_filter or 'TÜMÜ'}): {len(candidates)}")
        for item in candidates[:15]:
            print(
                f"  - {item['instance_id']} | {item['project']} | "
                f"{item['cve_id']} | {item['cwe']} ({item['patch_lines']} satır)"
            )
        return

    if args.verify_suite:
        ok = verify_suite_preflight(task_filter=args.task, category_filter=args.category)
        if not ok:
            raise SystemExit(1)
        return

    cfg = AVRConfig()
    if args.backend:
        cfg.backend = args.backend
    if args.model:
        cfg.model_name = args.model
    if args.max_turns is not None:
        cfg.max_turns = args.max_turns
    if args.sequential:
        cfg.parallel_verification = False

    run_all_benchmarks(
        config=cfg,
        task_filter=args.task,
        category_filter=args.category,
        limit=args.limit,
        output_summary_path=args.output_summary,
    )


if __name__ == "__main__":
    main()
