"""
Vanilla Zero-Shot (Körleme / Sıfır-Bağlam) Onarım Çalıştırıcısı.

Bu modül, AVR mimarisindeki hiçbir gelişmiş bileşeni (SAST kural tespiti, CWE teşhisi,
AST fonksiyon budama, Docker hata geri beslemesi) KULLANMAZ.

Modele sadece ham dosya ve sıfır bağlamlı tek bir prompt verilir:
"Aşağıdaki Python kodunda bir güvenlik/mantık hatası bulunmaktadır.
 Kodu incele, hatayı bul ve sadece düzeltilmiş fonksiyonu döndür."

Çıkan yama Docker sandbox içinde SADECE 1 KEZ test edilir (Turn 1).
Hata alsa dahi geri besleme yapılmaz, 2. tura geçilmez.
Bu deney, tezinizde LLM'in tek başına ne kadar yetersiz kaldığını ve
tasarladığınız otonom mimarinin kattığı net değeri (ablation) ispatlar.
"""

import argparse
import ast
from collections import defaultdict
import difflib
import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple

from pipeline.benchmark.suite_definitions import (
    BENCHMARK_SUITE,
    materialize_task_files,
)
from pipeline.config import AVRConfig, detect_runtime_environment
from pipeline.sandbox.docker_runner import DockerSandbox
from pipeline.synthesizer.synthesizer import PatchSynthesizer


def apply_vanilla_patch(original_source: str, raw_patch: str) -> Tuple[bool, str, str]:
    """
    Modelin ürettiği yama parçasını orijinal koda yerleştirir.
    - Model tek bir fonksiyon döndürdüyse AST ile o fonksiyonu bulup yerine koyar.
    - Model tüm dosyayı yeniden yazdıysa sözdizimi geçerliyse doğrudan kabul eder.
    """
    clean_code = PatchSynthesizer.extract_code_block(raw_patch).strip("\r\n")
    if not clean_code:
        return False, original_source, "Model boş kod döndürdü."

    # Yama parçasının AST analizi
    try:
        patch_ast = ast.parse(clean_code)
    except SyntaxError as exc:
        return False, original_source, f"Yama Sözdizimi Hatası (SyntaxError): {exc}"

    try:
        orig_ast = ast.parse(original_source)
    except SyntaxError as exc:
        return False, original_source, f"Orijinal Dosya Sözdizimi Hatası: {exc}"

    func_defs = [
        n for n in patch_ast.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    class_defs = [n for n in patch_ast.body if isinstance(n, ast.ClassDef)]

    # 1. Durum: Model tek bir fonksiyon döndürdü (veya sınıf içi metot)
    if len(func_defs) == 1 and not class_defs:
        target_name = func_defs[0].name
        for node in ast.walk(orig_ast):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == target_name:
                start_l = node.lineno
                end_l = getattr(node, "end_lineno", node.lineno)
                candidate = PatchSynthesizer.build_patched_content(
                    original_source, start_l, end_l, clean_code
                )
                try:
                    ast.parse(candidate)
                    return True, candidate, ""
                except SyntaxError as e:
                    return False, original_source, f"Birleştirilmiş kodda SyntaxError: {e}"

    # 2. Durum: Model bir sınıf döndürdü
    if len(class_defs) == 1:
        target_cls = class_defs[0].name
        for node in orig_ast.body:
            if isinstance(node, ast.ClassDef) and node.name == target_cls:
                start_l = node.lineno
                end_l = getattr(node, "end_lineno", node.lineno)
                candidate = PatchSynthesizer.build_patched_content(
                    original_source, start_l, end_l, clean_code
                )
                try:
                    ast.parse(candidate)
                    return True, candidate, ""
                except SyntaxError as e:
                    return False, original_source, f"Birleştirilmiş sınıfta SyntaxError: {e}"

    # 3. Durum: Model dosyanın tamamını veya birden fazla fonksiyonu yeniden yazdı
    try:
        ast.parse(clean_code)
        return True, clean_code, ""
    except SyntaxError as exc:
        return False, original_source, f"Tam kod sözdizimi geçersiz: {exc}"


def run_vanilla_task(
    task: Dict[str, Any],
    synthesizer: PatchSynthesizer,
    sandbox: DockerSandbox,
) -> Dict[str, Any]:
    task_id = task["id"]
    task_name = task["name"]
    task_dir = Path(task["dir"])
    target_file = task_dir / task["file"]

    print(f"\n[{task_id}] {task_name} (Vanilla Zero-Shot)...")

    # 1. Kaynak dosyaları orijinal zafiyetli haline sıfırla
    materialize_task_files(task)

    # 2. Docker Baseline Kontrolü
    baseline = sandbox.run_dual_verification(str(task_dir))
    if not baseline["func_pass"]:
        print("  [!] Orijinal kod baştan bozuk!")
        return {
            "id": task_id,
            "name": task_name,
            "category": task.get("category", "General"),
            "type": task.get("type", "Unknown"),
            "repaired": False,
            "turns": 0,
            "duration": 0.0,
            "status": "BASELINE_FAIL",
        }

    raw_source = target_file.read_text(encoding="utf-8")

    # 3. Sıfır Bağlamlı Körleme Prompt (Kullanıcının talep ettiği format)
    vanilla_prompt = (
        "Aşağıdaki Python kodunda bir güvenlik/mantık hatası bulunmaktadır. "
        "Kodu incele, hatayı bul ve sadece düzeltilmiş fonksiyonu döndür:\n\n"
        f"```python\n{raw_source}\n```\n\n"
        "ÖNEMLİ: Ekstra hiçbir açıklama yapma. Sadece düzeltilmiş Python fonksiyonunu tek bir "
        "```python ... ``` kod bloğu içinde ver."
    )

    messages = [
        {
            "role": "system",
            "content": (
                "You are an autonomous code repair assistant. Inspect the Python code, "
                "find any security or logic defects, and output ONLY the complete repaired Python "
                "function inside a single ```python ... ``` code block without extra prose."
            ),
        },
        {"role": "user", "content": vanilla_prompt},
    ]

    # 4. LLM Çıkarsaması (Tek Tur)
    t0 = time.time()
    gen_res = synthesizer.synthesize(messages, temperature=0.0)
    dur = time.time() - t0

    metrics_dict = gen_res.to_metrics_dict()
    conf = metrics_dict.get("confidence_score")
    ent = metrics_dict.get("entropy")
    print(f"  ├─ LLM Yanıtı Alındı ({dur:.2f}s) | Conf: {conf} | Ent: {ent}")

    # 5. Yamayı Koda Entegre Et
    ok, patched_source, err_msg = apply_vanilla_patch(raw_source, gen_res.extracted_code)
    if not ok:
        print(f"  └─ Yama Entegrasyon Hatası: {err_msg} ❌")
        # Dosyayı orijinaline geri döndür
        materialize_task_files(task)
        return {
            "id": task_id,
            "name": task_name,
            "category": task.get("category", "General"),
            "type": task.get("type", "Unknown"),
            "repaired": False,
            "turns": 1,
            "duration": dur,
            "status": "SYNTAX_OR_INTEGRATION_ERROR",
            "error_detail": err_msg,
            "llm_metrics_summary": {
                "mean_confidence_score": conf,
                "mean_entropy": ent,
            },
        }

    # Hedef dosyaya uygula
    target_file.write_text(patched_source, encoding="utf-8")

    # Diff üret
    diff = "".join(
        difflib.unified_diff(
            raw_source.splitlines(keepends=True),
            patched_source.splitlines(keepends=True),
            fromfile=f"a/{task['file']}",
            tofile=f"b/{task['file']}",
        )
    )

    # 6. Docker Sandbox Tek Seferlik Test (Turn 1 / Zero-Shot)
    test_res = sandbox.run_dual_verification(str(task_dir))
    func_ok = test_res.get("func_pass", False)
    sec_ok = test_res.get("sec_pass", False)
    repaired = func_ok and sec_ok

    status_str = "BAŞARILI ✅" if repaired else "BAŞARISIZ ❌"
    print(f"  └─ Docker Test: Func={func_ok}, Sec={sec_ok} -> {status_str}")

    # Test sonrası çalışma alanını temizle
    materialize_task_files(task)

    return {
        "id": task_id,
        "name": task_name,
        "category": task.get("category", "General"),
        "type": task.get("type", "Unknown"),
        "repaired": repaired,
        "turns": 1,
        "duration": round(dur, 3),
        "status": "REPAIRED" if repaired else "TEST_FAILED",
        "func_pass": func_ok,
        "sec_pass": sec_ok,
        "llm_metrics_summary": {
            "mean_confidence_score": conf,
            "mean_entropy": ent,
        },
        "unified_diff": diff,
    }


def run_vanilla_benchmarks(
    config: Optional[AVRConfig] = None,
    task_filter: Optional[str] = None,
    category_filter: Optional[str] = None,
    limit: Optional[int] = None,
    output_summary_path: Optional[str] = None,
) -> Dict[str, Any]:
    cfg = config or AVRConfig()
    env_info = detect_runtime_environment()

    print("\n" + "=" * 90)
    print("🧪 VANILLA ZERO-SHOT (KÖRLEMESİNE) BENCHMARK BAŞLATILIYOR")
    print(f"   Model: {cfg.model_name} | Backend: {cfg.backend}")
    print("   Koşullar: SAST yok | AST budama yok | Geri bildirim (Feedback) yok | Tek Tur (T1)")
    print("=" * 90)

    sandbox = DockerSandbox(
        image_name=cfg.docker_image,
        timeout=cfg.sandbox_timeout,
        memory_limit=cfg.sandbox_memory,
        cpu_limit=cfg.sandbox_cpus,
        pids_limit=cfg.sandbox_pids_limit,
        parallel=cfg.parallel_verification,
    )
    sandbox.verify_docker_ready(auto_build=True)

    synthesizer = PatchSynthesizer(
        backend=cfg.backend,
        model_name=cfg.model_name,
        temperature=0.0,
        top_p=cfg.top_p,
    )

    suite = list(BENCHMARK_SUITE)
    if task_filter:
        suite = [t for t in suite if task_filter.lower() in t["id"].lower() or task_filter.lower() in t["name"].lower()]
    if category_filter:
        suite = [t for t in suite if category_filter.lower() in t["category"].lower()]
    if limit:
        suite = suite[:limit]

    results: List[Dict[str, Any]] = []
    overall_start = time.time()

    try:
        for t in suite:
            res = run_vanilla_task(t, synthesizer, sandbox)
            results.append(res)
    finally:
        synthesizer.unload_model()

    overall_elapsed = time.time() - overall_start

    # Özet tablosu
    print("\n" + "=" * 110)
    print("📊 VANILLA ZERO-SHOT SONUÇ TABLOSU (SAST / AST / FEEDBACK OLMADAN)")
    print("=" * 110)
    print(f"{'ID':<7} | {'GÖREV ADI':<28} | {'ZAFİYET TÜRÜ':<28} | {'CONF':<6} | {'SÜRE':<7} | {'DURUM'}")
    print("-" * 110)

    passed_count = 0
    cat_buckets = defaultdict(list)
    for r in results:
        status_str = "BAŞARILI ✅" if r["repaired"] else "BAŞARISIZ ❌"
        if r["repaired"]:
            passed_count += 1
        conf = r.get("llm_metrics_summary", {}).get("mean_confidence_score")
        conf_str = f"{conf:.3f}" if conf is not None else "  -   "
        time_str = f"{r['duration']:.2f}s"
        print(f"{r['id']:<7} | {r['name'][:28]:<28} | {r['type'][:28]:<28} | {conf_str:<6} | {time_str:<7} | {status_str}")
        cat_buckets[r.get("category", "General")].append(r)

    print("-" * 110)
    success_rate = (passed_count / len(results)) * 100 if results else 0.0
    print(f"Genel Başarı: {passed_count}/{len(results)} (%{success_rate:.1f}) | Toplam Süre: {overall_elapsed:.2f}s\n")

    summary_payload = {
        "benchmark_mode": "vanilla_zero_shot",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "backend": cfg.backend,
        "model_name": cfg.model_name,
        "max_turns": 1,
        "environment": env_info,
        "total_tasks": len(results),
        "success_rate": f"%{success_rate:.1f}",
        "total_time_seconds": round(overall_elapsed, 3),
        "results": results,
    }

    out_path = Path(output_summary_path) if output_summary_path else Path("pipeline/benchmark_summary_vanilla.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary_payload, f, indent=2, ensure_ascii=False)

    print(f"[Rapor] Vanilla Zero-Shot sonuçları kaydedildi: {out_path.as_posix()}")
    return summary_payload


def main() -> None:
    parser = argparse.ArgumentParser(description="AVR Vanilla Zero-Shot Benchmark Runner")
    parser.add_argument("--backend", choices=["ollama", "transformers"], default=None)
    parser.add_argument("--model", default=None, help="Kullanılacak LLM modeli")
    parser.add_argument("--task", default=None, help="Sadece eşleşen görevi çalıştır")
    parser.add_argument("--category", default=None, help="Sadece eşleşen kategoriyi çalıştır")
    parser.add_argument("--limit", type=int, default=None, help="Çalıştırılacak maksimum görev sayısı")
    parser.add_argument("--output-summary", default=None, help="Özet JSON raporunun kaydedileceği dosya yolu")
    args = parser.parse_args()

    cfg = AVRConfig()
    if args.backend:
        cfg.backend = args.backend
    if args.model:
        cfg.model_name = args.model

    run_vanilla_benchmarks(
        config=cfg,
        task_filter=args.task,
        category_filter=args.category,
        limit=args.limit,
        output_summary_path=args.output_summary,
    )


if __name__ == "__main__":
    main()
