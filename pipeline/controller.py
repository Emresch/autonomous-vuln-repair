import json
import time
from pathlib import Path
from typing import Dict, Any

from pipeline.sast.sast_engine import SASTEngine
from pipeline.pruner.ast_pruner import ASTContextPruner
from pipeline.synthesizer.synthesizer import PatchSynthesizer
from pipeline.sandbox.docker_runner import DockerSandbox

class SelfHealingController:
    def __init__(self, task_dir: str, target_file: str, max_turns: int = 3):
        self.task_dir = Path(task_dir)
        self.target_file = self.task_dir / target_file
        self.max_turns = max_turns

        self.sast = SASTEngine(str(self.target_file))
        self.synthesizer = PatchSynthesizer(model_name="qwen2.5-coder:7b")
        self.sandbox = DockerSandbox()

    def run(self) -> Dict[str, Any]:
        print("\n" + "="*70)
        print("🚀 OTONOM VE DOĞRULANABİLİR GÜVENLİK YAMA MOTORU BAŞLATILIYOR")
        print("="*70)

        # Orijinal kodun yedeğini hafızada tut
        with open(self.target_file, "r", encoding="utf-8") as f:
            original_code = f.read()

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
        # 2. FAZ: SAST VE AST İLE HATA LOKALİZASYONU
        # -------------------------------------------------------------
        print("\n[FAZ 2] Statik Güvenlik Analizi ve Kapsam Kırpma...")
        findings = self.sast.scan_with_bandit()
        if not findings:
            print("  [!] SAST kural ihlali tespit edemedi.")
            return {"status": "NO_SAST_FINDINGS"}

        finding = findings[0]
        print(f"  ├─ Tespit Edilen Zafiyet: {finding['cwe']} ({finding['test_id']})")
        print(f"  ├─ Teşhis               : {finding['issue_text']}")
        print(f"  └─ Hedef Satır          : {finding['line_number']}")

        pruner = ASTContextPruner(str(self.target_file))
        chunk = pruner.prune_enclosing_function(finding["line_number"])
        if not chunk:
            print("  [!] AST fonksiyon kapsamını belirleyemedi.")
            return {"status": "AST_PRUNE_ERROR"}

        print(f"  [*] AST Kapsamı Kırpıldı: '{chunk['function_name']}' ({chunk['start_line']} - {chunk['end_line']}. satırlar)")

        # -------------------------------------------------------------
        # 3. FAZ: KENDİ KENDİNİ İYİLEŞTİRME DÖNGÜSÜ (SELF-HEALING LOOP)
        # -------------------------------------------------------------
        print(f"\n[FAZ 3] Kendi Kendini İyileştirme Döngüsü Başlatılıyor (Maks {self.max_turns} Tur)...")
        feedback = None
        repaired_successfully = False
        final_patched_code = None

        for turn in range(1, self.max_turns + 1):
            print(f"\n---> [TUR {turn}/{self.max_turns}] <---")
            print("  [*] Qwen modeline prompt iletiliyor (Ollama / qwen2.5-coder:7b)...")
            prompt = self.synthesizer.generate_repair_prompt(chunk, finding, feedback=feedback)
            
            start_t = time.time()
            raw_response = self.synthesizer.query_ollama(prompt)
            duration = time.time() - start_t
            
            patch_code = self.synthesizer.extract_code_block(raw_response)
            print(f"  [*] Yama üretildi ({duration:.2f} saniye).")
            print("  [*] Yama kaynak dosyaya uygulanıyor...")

            # Dosyaya yamayı uygula
            self.synthesizer.apply_patch_to_file(
                str(self.target_file),
                chunk["start_line"],
                chunk["end_line"],
                patch_code
            )

            # Docker Sandbox içinde Çift Doğrulama koş
            print("  [*] Docker Sealed Sandbox içinde Çift Doğrulama (Pytest) çalıştırılıyor...")
            test_res = self.sandbox.run_dual_verification(str(self.task_dir))
            
            func_ok = test_res["func_pass"]
            sec_ok = test_res["sec_pass"]

            print(f"  ├─ func_test (Orijinal İşlev) : {'PASS ✅' if func_ok else 'FAIL ❌'}")
            print(f"  └─ sec_test (Zafiyet Kapatma): {'PASS ✅' if sec_ok else 'FAIL ❌'}")

            if func_ok and sec_ok:
                print("\n" + "*"*70)
                print("🎯 [BAŞARI] ÇİFT DOĞRULAMA GEÇİLDİ! KOD HEM GÜVENLİ HEM DE İŞLEVSEL.")
                print("*"*70)
                repaired_successfully = True
                with open(self.target_file, "r", encoding="utf-8") as f:
                    final_patched_code = f.read()
                break
            else:
                # Geri bildirim hazırla
                errors = []
                if not func_ok:
                    errors.append(f"Fonksiyonellik Testi Hatası (Regresyon):\n{test_res['func_output']}")
                if not sec_ok:
                    errors.append(f"Güvenlik Testi Hatası (Açık Kapanmadı):\n{test_res['sec_output']}")
                feedback = "\n\n".join(errors)
                print(f"  [!] Tur {turn} başarısız. Hata geri bildirimi Qwen'e aktarılacak.")

        # Orijinal dosyayı geri yüklemek isterseniz veya sonucu kaydetmek:
        result_report = {
            "task_file": str(self.target_file),
            "repaired": repaired_successfully,
            "turns_used": turn,
            "cwe": finding["cwe"],
            "rule_id": finding["test_id"],
            "original_code": original_code,
            "final_patched_code": final_patched_code
        }

        # Sonucu JSON olarak kaydet
        output_json_path = self.task_dir / "sonuc.json"
        with open(output_json_path, "w", encoding="utf-8") as f:
            json.dump(result_report, f, indent=2, ensure_ascii=False)

        print(f"\n[Rapor] Sonuç dosyası kaydedildi: {output_json_path}")
        return result_report

if __name__ == "__main__":
    controller = SelfHealingController(
        task_dir="pipeline/sample_task",
        target_file="app.py",
        max_turns=3
    )
    controller.run()
