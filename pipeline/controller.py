import json
import time
from pathlib import Path
from typing import Dict, Any, Optional, List

from pipeline.sast.sast_engine import SASTEngine
from pipeline.pruner.ast_pruner import ASTContextPruner
from pipeline.synthesizer.synthesizer import PatchSynthesizer
from pipeline.sandbox.docker_runner import DockerSandbox

class SelfHealingController:
    def __init__(self, task_dir: str, target_file: Optional[str] = None, max_turns: int = 3):
        self.task_dir = Path(task_dir)
        self.target_file_name = target_file
        self.max_turns = max_turns

        self.sast = SASTEngine(str(self.task_dir))
        self.synthesizer = PatchSynthesizer(model_name="qwen2.5-coder:7b")
        self.sandbox = DockerSandbox()

    def filter_non_test_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test dosyalarını ve sadece import uyarılarını (B404) tarama sonuçlarından eler."""
        valid = []
        for f in findings:
            fn = Path(f.get("filename", "")).name.lower()
            test_id = f.get("test_id", "")
            # Bilgi amaçlı import uyarıları (B404 subprocess importu gibi) ve test dosyaları elenir
            if test_id in ["B404", "B410"]:
                continue
            if not (fn.startswith("test_") or fn.endswith("_test.py") or "conftest" in fn):
                valid.append(f)
        return valid

    def run(self) -> Dict[str, Any]:
        print("\n" + "="*70)
        print("🚀 OTONOM VE ÇOKLU-ZAFİYET ONARIM MOTORU BAŞLATILIYOR")
        print("="*70)

        # -------------------------------------------------------------
        # 1. FAZ: BAŞLANGIÇ DURUM TEYİDİ (BASELINE SANITY CHECK)
        # -------------------------------------------------------------
        print("\n[FAZ 1] Başlangıç Durum Doğrulaması (Baseline Check)...")
        baseline_res = self.sandbox.run_dual_verification(str(self.task_dir))
        
        print(f"  ├─ Birim Testler (func_test) : {'[PASS]' if baseline_res['func_pass'] else '[FAIL]'}")
        print(f"  └─ Exploit Testi (sec_test)  : {'[PASS]' if baseline_res['sec_pass'] else '[FAIL - Zafiyet Doğrulandı]'}")

        if not baseline_res['func_pass']:
            print("  [!] UYARI: Orijinal kod baştan kırık! Pipeline durduruluyor.")
            return {"status": "ABORTED_BROKEN_CODE"}

        if baseline_res['sec_pass']:
            print("  [*] BİLGİ: Kodda zaten açık bulunmuyor.")
            return {"status": "ALREADY_SECURE"}

        # -------------------------------------------------------------
        # 2. FAZ: KÖRLEMESİNE SAST TARAMASI (HİBRİT: BANDIT + SEMGREP)
        # -------------------------------------------------------------
        print("\n[FAZ 2] Körlemesine Statik Analiz (Bandit + Semgrep Hibrit Motor)...")
        
        # Eğer dosya adı verilmediyse tüm klasörü tara
        scan_target = (self.task_dir / self.target_file_name) if self.target_file_name else self.task_dir
        raw_findings = self.sast.scan(scan_target)
        findings = self.filter_non_test_findings(raw_findings)

        if not findings:
            print("  [!] SAST kural ihlali tespit edemedi.")
            return {"status": "NO_SAST_FINDINGS"}

        print(f"  [*] Toplam {len(findings)} zafiyet otomatik olarak keşfedildi:")
        for idx, f in enumerate(findings, 1):
            rel_file = Path(f['filename']).name
            print(f"      {idx}. [{f['engine']}] {rel_file}:{f['line_number']} -> {f['cwe']} ({f['test_id']})")

        # -------------------------------------------------------------
        # 3. FAZ: İTERATİF ÇOKLU FONKSİYON ONARIM DÖNGÜSÜ
        # -------------------------------------------------------------
        print(f"\n[FAZ 3] İteratif Cerrahi Onarım Başlatılıyor (Zafiyet Sayısı: {len(findings)})...")
        feedback = None
        repaired_successfully = False

        for turn in range(1, self.max_turns + 1):
            print(f"\n---> [GENEL ONARIM TURU {turn}/{self.max_turns}] <---")

            # Her zafiyet için sırayla cerrahi AST kırpması ve yama üretimi
            for idx, finding in enumerate(findings, 1):
                target_file_path = Path(finding["filename"])
                if not target_file_path.is_absolute():
                    target_file_path = Path.cwd() / target_file_path

                print(f"\n  [*] [{idx}/{len(findings)}] Zafiyet Hedefe Alınıyor: {finding['cwe']} ({finding['test_id']})")
                print(f"      Dosya: {target_file_path.name} | Satır: {finding['line_number']}")

                pruner = ASTContextPruner(str(target_file_path))
                chunk = pruner.prune_enclosing_function(finding["line_number"])
                if not chunk:
                    print(f"      [!] Satır {finding['line_number']} için fonksiyon kapsamı bulunamadı, atlanıyor.")
                    continue

                print(f"      AST Kapsamı Kırpıldı: '{chunk['function_name']}' ({chunk['start_line']} - {chunk['end_line']}. satırlar)")
                print(f"      Qwen modeline gönderiliyor...")

                prompt = self.synthesizer.generate_repair_prompt(chunk, finding, feedback=feedback)
                start_t = time.time()
                raw_response = self.synthesizer.query_ollama(prompt)
                duration = time.time() - start_t

                patch_code = self.synthesizer.extract_code_block(raw_response)
                print(f"      Yama üretildi ({duration:.2f} sn). Dosyaya uygulanıyor...")

                # Güncel satırları tekrar hesapla
                pruner_recheck = ASTContextPruner(str(target_file_path))
                current_chunk = pruner_recheck.prune_enclosing_function(finding["line_number"])
                if current_chunk:
                    self.synthesizer.apply_patch_to_file(
                        str(target_file_path),
                        current_chunk["start_line"],
                        current_chunk["end_line"],
                        patch_code
                    )

            # Tüm yamalar uygulandıktan sonra Docker Sandbox Çift Doğrulama
            print("\n  [*] Tüm yamalar uygulandı. Docker Sealed Sandbox Çift Doğrulama Koşuluyor...")
            test_res = self.sandbox.run_dual_verification(str(self.task_dir))
            func_ok = test_res["func_pass"]
            sec_ok = test_res["sec_pass"]

            print(f"  ├─ func_test (Tüm Orijinal İşlevler) : {'PASS ✅' if func_ok else 'FAIL ❌'}")
            print(f"  └─ sec_test  (Tüm Exploit Testleri)  : {'PASS ✅' if sec_ok else 'FAIL ❌'}")

            if func_ok and sec_ok:
                print("\n" + "*"*70)
                print("🎯 [TAM BAŞARI] TÜM ZAFİYETLER ONARILDI! ÇİFT DOĞRULAMA GEÇİLDİ.")
                print("*"*70)
                repaired_successfully = True
                break
            else:
                errors = []
                if not func_ok:
                    errors.append(f"Regresyon Hatası:\n{test_res['func_output']}")
                if not sec_ok:
                    errors.append(f"Exploit Engellenemedi:\n{test_res['sec_output']}")
                feedback = "\n\n".join(errors)
                print(f"  [!] Tur {turn} tamamlanamadı. Hata geri bildirimi sonraki tura aktarılacak.")

        # Raporlama
        report = {
            "task_dir": str(self.task_dir),
            "total_findings": len(findings),
            "findings": findings,
            "repaired": repaired_successfully,
            "turns_used": turn
        }
        out_file = self.task_dir / "sonuc.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n[Rapor] Sonuç kaydedildi: {out_file}")
        return report

if __name__ == "__main__":
    import sys
    task_dir_arg = sys.argv[1] if len(sys.argv) > 1 else "pipeline/sample_task"
    # Dosya adı artık OPSİYONELDİR! Verilmezse klasör taranır.
    target_file_arg = sys.argv[2] if len(sys.argv) > 2 else None

    controller = SelfHealingController(
        task_dir=task_dir_arg,
        target_file=target_file_arg,
        max_turns=3
    )
    controller.run()
