import difflib
import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple

from pipeline.config import AVRConfig, detect_runtime_environment
from pipeline.pruner.ast_pruner import ASTContextPruner
from pipeline.sandbox.docker_runner import DockerSandbox
from pipeline.sast.sast_engine import SASTEngine
from pipeline.synthesizer.synthesizer import PatchSynthesizer


class SelfHealingController:
    """
    Otonom Çift Doğrulamalı ve Kendi Kendini İyileştiren Zafiyet Onarım Orkestratörü.

    Güvenlik & Dayanıklılık Garantileri:
    - Her onarım turu başında hedef dosyalar bellekten temiz orijinal haline sıfırlanır (Rollback).
    - Hiçbir yama ast.parse() sözdizimi doğrulamasından geçmeden diske yazılmaz.
    - Çoklu zafiyet içeren dosyalarda hedef fonksiyonlar satır numarası yerine AST üzerindeki
      kalifiye fonksiyon adına (Class.method veya func) göre çözülür (satır kaymasına karşı bağışık).
    - Çok turlu konuşma geçmişi (previous failed patch + verification error) korunur.
    - Tüm turlar başarısız olursa dosyalar temiz orijinal haline geri alınır ve eksiksiz
      hata raporu sonuc.json dosyasına kaydedilir.
    """

    def __init__(
        self,
        task_dir: str,
        target_file: Optional[str] = None,
        max_turns: Optional[int] = None,
        config: Optional[AVRConfig] = None,
        sast: Optional[SASTEngine] = None,
        synthesizer: Optional[PatchSynthesizer] = None,
        sandbox: Optional[DockerSandbox] = None,
    ):
        self.task_dir = Path(task_dir)
        self.target_file_name = target_file
        self.config = config or AVRConfig()
        self.max_turns = max_turns if max_turns is not None else self.config.max_turns

        self.sast = sast or SASTEngine(str(self.task_dir))
        self.synthesizer = synthesizer or PatchSynthesizer(
            model_name=self.config.model_name,
            base_url=self.config.ollama_base_url,
            backend=self.config.backend,
            timeout=self.config.llm_timeout,
            temperature=self.config.temperature,
            top_p=self.config.top_p,
        )
        self.sandbox = sandbox or DockerSandbox(
            image_name=self.config.docker_image,
            timeout=self.config.sandbox_timeout,
            memory_limit=self.config.sandbox_memory,
            cpu_limit=self.config.sandbox_cpus,
            pids_limit=self.config.sandbox_pids_limit,
            parallel=self.config.parallel_verification,
        )

    def _resolve_finding_path(self, raw_filename: str) -> Path:
        """SAST raporundaki dosya yolunu işletim sisteminden bağımsız kesin Path'e çözümler."""
        candidate = Path(raw_filename)
        if candidate.is_absolute() and candidate.exists():
            return candidate.resolve()

        cwd_candidate = (Path.cwd() / candidate).resolve()
        if cwd_candidate.exists():
            return cwd_candidate

        task_candidate = (self.task_dir / candidate.name).resolve()
        if task_candidate.exists():
            return task_candidate

        return cwd_candidate

    def _to_portable_path(self, path: Path) -> str:
        """JSON raporlarında platformdan bağımsız POSIX yol formatı kullanır."""
        try:
            return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
        except ValueError:
            return path.as_posix()

    def filter_non_test_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test dosyalarını ve bilgi amaçlı import uyarılarını tarama sonuçlarından eler."""
        valid = []
        for f in findings:
            fn = Path(f.get("filename", "")).name.lower()
            test_id = f.get("test_id", "")
            if test_id in ["B404", "B410"]:
                continue
            if not (fn.startswith("test_") or fn.endswith("_test.py") or "conftest" in fn):
                valid.append(f)
        return valid

    def _build_repair_targets(
        self, findings: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], Dict[Path, str]]:
        """
        Her SAST bulgusunu temiz orijinal kaynak dosya üzerinde AST fonksiyon adına eşler.
        Aynı fonksiyona düşen birden fazla bulguyu tek bir hedef altında birleştirir ve
        orijinal dosya içeriklerini bellekte snapshot olarak saklar.
        """
        original_files: Dict[Path, str] = {}
        grouped_targets: Dict[Tuple[Path, Optional[str], str], Dict[str, Any]] = {}
        ordered_keys: List[Tuple[Path, Optional[str], str]] = []

        for finding in findings:
            resolved_path = self._resolve_finding_path(finding["filename"])
            if resolved_path not in original_files:
                original_files[resolved_path] = resolved_path.read_text(encoding="utf-8")

            pruner = ASTContextPruner(str(resolved_path), source_code=original_files[resolved_path])
            chunk = pruner.prune_enclosing_function(int(finding["line_number"]))
            if not chunk:
                print(
                    f"  [!] Uyarı: {resolved_path.name}:{finding['line_number']} "
                    f"bir fonksiyon bloğu içinde bulunamadı, atlanıyor."
                )
                continue

            target_key = (resolved_path, chunk["class_name"], chunk["function_name"])
            if target_key not in grouped_targets:
                grouped_targets[target_key] = {
                    "key": f"{self._to_portable_path(resolved_path)}::{chunk['qualified_name']}",
                    "file_path": resolved_path,
                    "portable_file": self._to_portable_path(resolved_path),
                    "class_name": chunk["class_name"],
                    "function_name": chunk["function_name"],
                    "qualified_name": chunk["qualified_name"],
                    "initial_chunk": chunk,
                    "findings": [],
                }
                ordered_keys.append(target_key)

            # Normalize stored finding path for portable reporting
            normalized_finding = dict(finding)
            normalized_finding["filename"] = self._to_portable_path(resolved_path)
            normalized_finding["file_path"] = normalized_finding["filename"]
            grouped_targets[target_key]["findings"].append(normalized_finding)

        targets = [grouped_targets[k] for k in ordered_keys]
        return targets, original_files

    @staticmethod
    def _restore_original_files(original_files: Dict[Path, str]) -> None:
        """Tüm hedef dosyaları bellekten temiz orijinal haline geri yükler."""
        for file_path, content in original_files.items():
            file_path.write_text(content, encoding="utf-8")

    def _compute_unified_diffs(self, original_files: Dict[Path, str]) -> Dict[str, str]:
        """Orijinal ve nihai dosyalar arasında standart unified diff üretir."""
        diffs: Dict[str, str] = {}
        for file_path, original_content in original_files.items():
            current_content = file_path.read_text(encoding="utf-8")
            portable = self._to_portable_path(file_path)
            diff_lines = difflib.unified_diff(
                original_content.splitlines(keepends=True),
                current_content.splitlines(keepends=True),
                fromfile=f"a/{portable}",
                tofile=f"b/{portable}",
            )
            diff_text = "".join(diff_lines)
            if diff_text:
                diffs[portable] = diff_text
        return diffs

    def _save_report(self, report: Dict[str, Any]) -> Path:
        out_file = self.task_dir / "sonuc.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n[Rapor] Sonuç kaydedildi: {self._to_portable_path(out_file)}")
        return out_file

    def run(self) -> Dict[str, Any]:
        pipeline_start = time.time()
        env_info = detect_runtime_environment()

        print("\n" + "=" * 70)
        print("🚀 OTONOM VE ÇOKLU-ZAFİYET ONARIM MOTORU BAŞLATILIYOR")
        print(
            f"   Backend: {self.synthesizer.backend_name} | "
            f"Model: {self.synthesizer.model_name} | "
            f"Ortam: {env_info['hardware_hint']}"
        )
        print("=" * 70)

        # -------------------------------------------------------------
        # 1. FAZ: BAŞLANGIÇ DURUM TEYİDİ (BASELINE SANITY CHECK)
        # -------------------------------------------------------------
        print("\n[FAZ 1] Başlangıç Durum Doğrulaması (Baseline Check)...")
        baseline_res = self.sandbox.run_dual_verification(str(self.task_dir))

        print(
            f"  ├─ Birim Testler (func_test) : "
            f"{'[PASS]' if baseline_res['func_pass'] else '[FAIL]'}"
        )
        print(
            f"  └─ Exploit Testi (sec_test)  : "
            f"{'[PASS]' if baseline_res['sec_pass'] else '[FAIL - Zafiyet Doğrulandı]'}"
        )

        if not baseline_res["func_pass"]:
            print("  [!] UYARI: Orijinal kod baştan kırık! Pipeline durduruluyor.")
            report = {
                "status": "ABORTED_BROKEN_CODE",
                "task_dir": self._to_portable_path(self.task_dir),
                "repaired": False,
                "turns_used": 0,
                "total_duration_seconds": round(time.time() - pipeline_start, 3),
                "baseline": baseline_res,
                "environment": env_info,
            }
            self._save_report(report)
            return report

        if baseline_res["sec_pass"]:
            print("  [*] BİLGİ: Kodda zaten açık bulunmuyor.")
            report = {
                "status": "ALREADY_SECURE",
                "task_dir": self._to_portable_path(self.task_dir),
                "repaired": False,
                "turns_used": 0,
                "total_duration_seconds": round(time.time() - pipeline_start, 3),
                "baseline": baseline_res,
                "environment": env_info,
            }
            self._save_report(report)
            return report

        # -------------------------------------------------------------
        # 2. FAZ: KÖRLEMESİNE SAST TARAMASI (HİBRİT: BANDIT + SEMGREP)
        # -------------------------------------------------------------
        print("\n[FAZ 2] Körlemesine Statik Analiz (Bandit + Semgrep Hibrit Motor)...")

        scan_target = (
            (self.task_dir / self.target_file_name)
            if self.target_file_name
            else self.task_dir
        )
        raw_findings = self.sast.scan(scan_target)
        findings = self.filter_non_test_findings(raw_findings)

        if not findings:
            print("  [!] SAST kural ihlali tespit edemedi.")
            report = {
                "status": "NO_SAST_FINDINGS",
                "task_dir": self._to_portable_path(self.task_dir),
                "repaired": False,
                "turns_used": 0,
                "total_duration_seconds": round(time.time() - pipeline_start, 3),
                "environment": env_info,
            }
            self._save_report(report)
            return report

        print(f"  [*] Toplam {len(findings)} zafiyet otomatik olarak keşfedildi:")
        for idx, f in enumerate(findings, 1):
            rel_file = Path(f["filename"]).name
            print(
                f"      {idx}. [{f['engine']}] {rel_file}:{f['line_number']} "
                f"-> {f['cwe']} ({f['test_id']})"
            )

        # Temiz orijinal dosya snapshot'larını al ve fonksiyon bazlı hedefleri çıkar
        repair_targets, original_files = self._build_repair_targets(findings)
        if not repair_targets:
            print("  [!] SAST bulguları hiçbir fonksiyon kapsamıyla eşleştirilemedi.")
            report = {
                "status": "NO_PRUNABLE_TARGETS",
                "task_dir": self._to_portable_path(self.task_dir),
                "total_findings": len(findings),
                "findings": findings,
                "repaired": False,
                "turns_used": 0,
                "total_duration_seconds": round(time.time() - pipeline_start, 3),
                "environment": env_info,
            }
            self._save_report(report)
            return report

        # Her hedef fonksiyon için ayrı çok turlu konuşma geçmişi başlat
        conversations: Dict[str, List[Dict[str, str]]] = {
            target["key"]: self.synthesizer.build_initial_messages(
                target["initial_chunk"], target["findings"]
            )
            for target in repair_targets
        }

        # -------------------------------------------------------------
        # 3. FAZ: İTERATİF ÇOKLU FONKSİYON ONARIM DÖNGÜSÜ (ROLLBACK + MULTI-TURN)
        # -------------------------------------------------------------
        print(
            f"\n[FAZ 3] İteratif Cerrahi Onarım Başlatılıyor "
            f"(Hedef Fonksiyon: {len(repair_targets)} | Maks Tur: {self.max_turns})..."
        )

        repaired_successfully = False
        turn_history: List[Dict[str, Any]] = []
        final_patches: Dict[str, str] = {}
        unified_diffs: Dict[str, str] = {}
        turns_used = 0
        last_feedback: Optional[str] = None

        for turn in range(1, self.max_turns + 1):
            turns_used = turn
            turn_start = time.time()
            print(f"\n---> [GENEL ONARIM TURU {turn}/{self.max_turns}] <---")

            # ROLLBACK: Her yeni turun başında tüm dosyaları temiz orijinal haline sıfırla
            self._restore_original_files(original_files)

            turn_patches: List[Dict[str, Any]] = []
            turn_syntax_errors: List[str] = []
            turn_llm_errors: List[str] = []

            for idx, target in enumerate(repair_targets, 1):
                file_path: Path = target["file_path"]
                target_key: str = target["key"]
                cwes = ", ".join(sorted({f["cwe"] for f in target["findings"]}))

                print(
                    f"\n  [*] [{idx}/{len(repair_targets)}] Hedef Fonksiyon: "
                    f"{target['qualified_name']} ({cwes})"
                )
                print(f"      Dosya: {file_path.name}")

                # Güncel dosya üzerinden satır numarası yerine FONKSİYON ADIYLA AST konumu çöz
                pruner = ASTContextPruner(str(file_path))
                current_chunk = pruner.prune_function_by_name(
                    target["function_name"], class_name=target["class_name"]
                )
                if not current_chunk:
                    err = (
                        f"AST konum hatası: '{target['qualified_name']}' fonksiyonu "
                        f"{file_path.name} içinde bulunamadı."
                    )
                    print(f"      [!] {err}")
                    turn_syntax_errors.append(err)
                    continue

                print(
                    f"      AST Konumu: '{current_chunk['qualified_name']}' "
                    f"({current_chunk['start_line']} - {current_chunk['end_line']}. satırlar)"
                )
                print(
                    f"      LLM sorgulanıyor ({self.synthesizer.backend_name} / "
                    f"{self.synthesizer.model_name})..."
                )

                messages = conversations[target_key]
                turn_temperature = min(self.config.temperature + 0.15 * (turn - 1), 0.6)
                try:
                    gen_result = self.synthesizer.synthesize(
                        messages, temperature=turn_temperature
                    )
                except Exception as exc:
                    err = f"LLM üretim hatası ({target['qualified_name']}): {exc}"
                    print(f"      [!] {err}")
                    turn_llm_errors.append(err)
                    turn_patches.append({
                        "target": target_key,
                        "function_name": target["qualified_name"],
                        "patch_code": "",
                        "syntax_valid": False,
                        "syntax_error": err,
                        "llm_metrics": None,
                    })
                    continue

                patch_code = gen_result.extracted_code
                print(
                    f"      Yama üretildi ({gen_result.duration_seconds:.2f} sn). "
                    "AST sözdizimi doğrulanıyor..."
                )

                # Önceki turdaki model yanıtını konuşma geçmişine (assistant rolüyle) ekle
                conversations[target_key].append({
                    "role": "assistant",
                    "content": f"```python\n{patch_code}\n```",
                })

                # Diske yazmadan önce bellekte birleştir ve ast.parse() ile doğrula
                current_source = file_path.read_text(encoding="utf-8")
                candidate_source = self.synthesizer.build_patched_content(
                    current_source,
                    current_chunk["start_line"],
                    current_chunk["end_line"],
                    patch_code,
                )
                syntax_ok, syntax_err = ASTContextPruner.validate_syntax(
                    candidate_source, filename=file_path.name
                )

                patch_entry = {
                    "target": target_key,
                    "function_name": target["qualified_name"],
                    "file": target["portable_file"],
                    "patch_code": patch_code,
                    "syntax_valid": syntax_ok,
                    "syntax_error": syntax_err,
                    "llm_metrics": gen_result.to_metrics_dict(),
                }
                turn_patches.append(patch_entry)

                if not syntax_ok:
                    print(f"      [!] SÖZDİZİMİ HATASI (diske yazılmadı): {syntax_err}")
                    turn_syntax_errors.append(
                        f"Syntax/Indentation Error in `{target['qualified_name']}`:\n{syntax_err}"
                    )
                    continue

                # Sözdizimi geçerli -> diske uygula
                file_path.write_text(candidate_source, encoding="utf-8")
                print("      Sözdizimi geçerli ✅ Dosyaya uygulandı.")

            # Sözdizimi veya LLM hatası olduysa Docker'a gitmeden geri bildirimle sonraki tura geç
            if turn_syntax_errors or turn_llm_errors:
                combined_errors = "\n\n".join(turn_syntax_errors + turn_llm_errors)
                last_feedback = combined_errors
                turn_history.append({
                    "turn": turn,
                    "duration_seconds": round(time.time() - turn_start, 3),
                    "stage_failed": "SYNTAX_OR_LLM_ERROR",
                    "patches": turn_patches,
                    "func_pass": False,
                    "sec_pass": False,
                    "func_output": "",
                    "sec_output": "",
                    "error_feedback": combined_errors,
                })
                for target in repair_targets:
                    conversations[target["key"]].append(
                        self.synthesizer.build_feedback_message(combined_errors, turn)
                    )
                print(
                    f"  [!] Tur {turn} sözdizimi/üretim hatası nedeniyle durduruldu. "
                    "Dosyalar bir sonraki turda temiz orijinal haline sıfırlanacak."
                )
                continue

            # Tüm yamalar sözdizimsel olarak geçerli -> Docker Sealed Sandbox Çift Doğrulama
            print(
                f"\n  [*] Tüm yamalar uygulandı. Docker Sealed Sandbox Çift Doğrulama "
                f"({'paralel' if self.sandbox.parallel else 'sıralı'}) koşuluyor..."
            )
            test_res = self.sandbox.run_dual_verification(str(self.task_dir))
            func_ok = test_res["func_pass"]
            sec_ok = test_res["sec_pass"]

            print(
                f"  ├─ func_test (Tüm Orijinal İşlevler) : "
                f"{'PASS ✅' if func_ok else 'FAIL ❌'}"
            )
            print(
                f"  └─ sec_test  (Tüm Exploit Testleri)  : "
                f"{'PASS ✅' if sec_ok else 'FAIL ❌'}"
            )

            error_feedback = None
            if not (func_ok and sec_ok):
                errors = []
                if not func_ok:
                    errors.append(f"Functional Regression Failure (func_test.py):\n{test_res['func_output']}")
                if not sec_ok:
                    errors.append(f"Security Exploit Not Blocked (sec_test.py):\n{test_res['sec_output']}")
                error_feedback = "\n\n".join(errors)
                last_feedback = error_feedback

            turn_history.append({
                "turn": turn,
                "duration_seconds": round(time.time() - turn_start, 3),
                "stage_failed": None if (func_ok and sec_ok) else "DOCKER_VERIFICATION_FAILED",
                "execution_mode": test_res.get("execution_mode"),
                "patches": turn_patches,
                "func_pass": func_ok,
                "sec_pass": sec_ok,
                "func_output": test_res["func_output"],
                "sec_output": test_res["sec_output"],
                "error_feedback": error_feedback,
            })

            if func_ok and sec_ok:
                print("\n" + "*" * 70)
                print("🎯 [TAM BAŞARI] TÜM ZAFİYETLER ONARILDI! ÇİFT DOĞRULAMA GEÇİLDİ.")
                print("*" * 70)
                repaired_successfully = True
                final_patches = {p["target"]: p["patch_code"] for p in turn_patches}
                unified_diffs = self._compute_unified_diffs(original_files)
                break

            # Başarısız tur: konuşma geçmişine hata geri bildirimini ekle
            for target in repair_targets:
                conversations[target["key"]].append(
                    self.synthesizer.build_feedback_message(error_feedback or "", turn)
                )
            print(
                f"  [!] Tur {turn} tamamlanamadı. Önceki yama ve hata çıktısı sonraki tura aktarılacak."
            )

        # Başarısız onarım sonrası dosyaları temiz orijinal haline geri döndür
        rolled_back_on_failure = False
        failure_summary: Optional[Dict[str, Any]] = None
        if not repaired_successfully:
            if self.config.rollback_on_failure:
                self._restore_original_files(original_files)
                rolled_back_on_failure = True
                print(
                    "\n[!] Onarım tüm turlarda başarısız oldu. "
                    "Hedef dosyalar temiz orijinal haline geri döndürüldü (Rollback)."
                )
            failure_summary = {
                "reason": "MAX_TURNS_EXHAUSTED",
                "turns_attempted": turns_used,
                "last_stage_failed": turn_history[-1]["stage_failed"] if turn_history else None,
                "last_error_feedback": last_feedback,
                "rolled_back_to_original": rolled_back_on_failure,
            }

        # Nihai metrik özetini derle (son turun ortalama confidence/entropy'si varsa)
        final_llm_metrics: Dict[str, Any] = {}
        if turn_history:
            last_patches = turn_history[-1].get("patches", [])
            confidences = [
                p["llm_metrics"]["confidence_score"]
                for p in last_patches
                if p.get("llm_metrics") and p["llm_metrics"].get("confidence_score") is not None
            ]
            entropies = [
                p["llm_metrics"]["entropy"]
                for p in last_patches
                if p.get("llm_metrics") and p["llm_metrics"].get("entropy") is not None
            ]
            final_llm_metrics = {
                "mean_confidence_score": round(sum(confidences) / len(confidences), 4)
                if confidences
                else None,
                "mean_entropy": round(sum(entropies) / len(entropies), 4)
                if entropies
                else None,
            }

        # Normalize findings paths for report
        portable_findings = []
        for f in findings:
            nf = dict(f)
            nf["filename"] = self._to_portable_path(self._resolve_finding_path(f["filename"]))
            nf["file_path"] = nf["filename"]
            portable_findings.append(nf)

        report = {
            "status": "REPAIRED" if repaired_successfully else "FAILED",
            "task_dir": self._to_portable_path(self.task_dir),
            "backend": self.synthesizer.backend_name,
            "model_name": self.synthesizer.model_name,
            "environment": env_info,
            "total_findings": len(portable_findings),
            "findings": portable_findings,
            "repaired": repaired_successfully,
            "turns_used": turns_used,
            "total_duration_seconds": round(time.time() - pipeline_start, 3),
            "rolled_back_to_original": rolled_back_on_failure,
            "final_patches": final_patches,
            "unified_diff": unified_diffs,
            "llm_metrics_summary": final_llm_metrics,
            "failure_summary": failure_summary,
            "turn_history": turn_history,
        }

        self._save_report(report)
        return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Autonomous Vulnerability Repair Controller")
    parser.add_argument("task_dir", nargs="?", default="pipeline/sample_task", help="Görev dizini")
    parser.add_argument("target_file", nargs="?", default=None, help="Opsiyonel hedef dosya adı")
    parser.add_argument("--backend", default=None, choices=["ollama", "transformers"])
    parser.add_argument("--model", default=None, help="LLM model adı")
    parser.add_argument("--max-turns", type=int, default=None)
    parser.add_argument("--sequential", action="store_true", help="func/sec testlerini sıralı çalıştır")
    args = parser.parse_args()

    cfg = AVRConfig()
    if args.backend:
        cfg.backend = args.backend
    if args.model:
        cfg.model_name = args.model
    if args.max_turns is not None:
        cfg.max_turns = args.max_turns
    if args.sequential:
        cfg.parallel_verification = False

    controller = SelfHealingController(
        task_dir=args.task_dir,
        target_file=args.target_file,
        config=cfg,
    )
    controller.run()
