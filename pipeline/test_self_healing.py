import json
import time
from pathlib import Path
from pipeline.sast.sast_engine import SASTEngine
from pipeline.pruner.ast_pruner import ASTContextPruner
from pipeline.synthesizer.synthesizer import PatchSynthesizer
from pipeline.sandbox.docker_runner import DockerSandbox

def run_self_healing_demonstration():
    print("\n" + "="*70)
    print("🔄 SELF-HEALING (KENDİ KENDİNİ İYİLEŞTİRME) TESTİ BAŞLATILIYOR")
    print("="*70)

    task_dir = Path("pipeline/sample_task")
    target_file = task_dir / "app.py"

    # 1. Adım: Orijinal zafiyetli kodu yükle
    original_vulnerable_code = """import sqlite3
import hashlib

def init_db(db_path=":memory:"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT
        )
    ''')
    cursor.execute("INSERT OR IGNORE INTO users (username, email) VALUES ('alice', 'alice@example.com')")
    cursor.execute("INSERT OR IGNORE INTO users (username, email) VALUES ('bob', 'bob@example.com')")
    conn.commit()
    return conn

def hash_username(username: str) -> str:
    return hashlib.sha256(username.encode()).hexdigest()

def get_user_by_username(conn, username: str):
    cursor = conn.cursor()
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()

def count_total_users(conn) -> int:
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    res = cursor.fetchone()
    return res[0] if res else 0
"""
    with open(target_file, "w", encoding="utf-8") as f:
        f.write(original_vulnerable_code)

    sast = SASTEngine(str(target_file))
    sandbox = DockerSandbox()
    synthesizer = PatchSynthesizer(model_name="qwen2.5-coder:7b")

    # SAST ve AST
    findings = sast.scan_with_bandit()
    finding = findings[0]
    pruner = ASTContextPruner(str(target_file))
    chunk = pruner.prune_enclosing_function(finding["line_number"])

    print(f"[*] Hedef: {finding['cwe']} ({finding['test_id']}) - Satır {finding['line_number']}")

    # -------------------------------------------------------------
    # TUR 1: Kasıtlı Fonksiyonel Regresyon Simülasyonu
    # LLM açığı kapatıyor fakat kolonları unutup regresyona sebep oluyor!
    # -------------------------------------------------------------
    print("\n" + "-"*50)
    print("🚩 [TUR 1] Hatalı Yama Simülasyonu (Regresyon Oluşturuluyor)")
    print("-"*50)
    
    flawed_patch = """def get_user_by_username(conn, username: str):
    cursor = conn.cursor()
    # Açık kapatıldı (parametreli) ANCAK yanlışlıkla sadece username seçildi! (Regresyon)
    query = "SELECT username FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchone()"""

    print("[Tur 1 Yama İçeriği]:")
    print(flawed_patch)
    
    synthesizer.apply_patch_to_file(str(target_file), chunk["start_line"], chunk["end_line"], flawed_patch)

    print("\n[*] Docker Sandbox Testi Koşuluyor...")
    t1_res = sandbox.run_dual_verification(str(task_dir))
    print(f"  ├─ func_test (Birim Testler) : {'PASS ✅' if t1_res['func_pass'] else 'FAIL ❌ (REGRESYON!)'}")
    print(f"  └─ sec_test (Exploit Testi)  : {'PASS ✅' if t1_res['sec_pass'] else 'FAIL ❌'}")

    print("\n[Docker Test Hata Çıktısı (Stderr / Traceback)]:")
    print(t1_res["func_output"][:400] + "...")

    # Geri bildirimi hazırla
    feedback = f"Fonksiyonel regresyon tespit edildi! test_get_existing_user başarısız oldu:\n{t1_res['func_output']}\nLütfen fonksiyonun döndürdüğü veri yapısını (tüm kolonları: id, username, email) koruyunuz."

    # -------------------------------------------------------------
    # TUR 2: Qwen'e Geri Bildirim Aktarılıyor ve Düzeltme İsteniyor
    # -------------------------------------------------------------
    print("\n" + "-"*50)
    print("🤖 [TUR 2] Self-Healing: Hata Çıktısı Qwen'e İletiliyor")
    print("-"*50)
    
    print("[*] Qwen modeline Traceback içeren cerrahi prompt gönderiliyor...")
    prompt_t2 = synthesizer.generate_repair_prompt(chunk, finding, feedback=feedback)
    
    start_t = time.time()
    resp_t2 = synthesizer.query_ollama(prompt_t2)
    duration = time.time() - start_t
    
    healed_patch = synthesizer.extract_code_block(resp_t2)
    print(f"[*] Qwen düzeltilmiş yeni yamayı üretti ({duration:.2f} sn):")
    print(healed_patch)

    # Dosyayı güncelle
    # Dosyadaki güncel fonksiyon sınırlarını yeniden bul
    pruner_t2 = ASTContextPruner(str(target_file))
    chunk_t2 = pruner_t2.prune_enclosing_function(finding["line_number"])
    synthesizer.apply_patch_to_file(str(target_file), chunk_t2["start_line"], chunk_t2["end_line"], healed_patch)

    print("\n[*] Docker Sandbox Testi Tekrar Koşuluyor (Çift Doğrulama)...")
    t2_res = sandbox.run_dual_verification(str(task_dir))
    print(f"  ├─ func_test (Birim Testler) : {'PASS ✅' if t2_res['func_pass'] else 'FAIL ❌'}")
    print(f"  └─ sec_test (Exploit Testi)  : {'PASS ✅' if t2_res['sec_pass'] else 'FAIL ❌'}")

    if t2_res["all_passed"]:
        print("\n" + "*"*70)
        print("🎉 [SELF-HEALING BAŞARILI] Qwen hatayı okudu, regresyonu düzeltti ve testi geçti!")
        print("*"*70)

    # Rapor kaydet
    report = {
        "scenario": "Self-Healing Multi-Turn Validation",
        "turn_1": {
            "patch": flawed_patch,
            "func_pass": t1_res["func_pass"],
            "sec_pass": t1_res["sec_pass"],
            "error_observed": "IndexError: tuple index out of range (user[2] email not selected)"
        },
        "turn_2": {
            "feedback_provided": True,
            "patch": healed_patch,
            "func_pass": t2_res["func_pass"],
            "sec_pass": t2_res["sec_pass"],
            "resolved": t2_res["all_passed"]
        }
    }
    with open(task_dir / "self_healing_rapor.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n[Rapor] Detaylı rapor kaydedildi: {task_dir / 'self_healing_rapor.json'}")

if __name__ == "__main__":
    run_self_healing_demonstration()
