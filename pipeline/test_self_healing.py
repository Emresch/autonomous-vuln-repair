import json
from pathlib import Path
from pipeline.config import AVRConfig
from pipeline.pruner.ast_pruner import ASTContextPruner
from pipeline.sandbox.docker_runner import DockerSandbox
from pipeline.sast.sast_engine import SASTEngine
from pipeline.synthesizer.synthesizer import PatchSynthesizer


def run_self_healing_demonstration():
    print("\n" + "=" * 70)
    print("🔄 SELF-HEALING (KENDİ KENDİNİ İYİLEŞTİRME) TESTİ BAŞLATILIYOR")
    print("=" * 70)

    cfg = AVRConfig()
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
    target_file.write_text(original_vulnerable_code, encoding="utf-8")

    sast = SASTEngine(str(target_file))
    sandbox = DockerSandbox(
        image_name=cfg.docker_image,
        timeout=cfg.sandbox_timeout,
        memory_limit=cfg.sandbox_memory,
        cpu_limit=cfg.sandbox_cpus,
        parallel=cfg.parallel_verification,
    )
    synthesizer = PatchSynthesizer(
        model_name=cfg.model_name,
        base_url=cfg.ollama_base_url,
        backend=cfg.backend,
    )

    # SAST ve AST
    findings = sast.scan_with_bandit()
    finding = findings[0]
    pruner = ASTContextPruner(str(target_file))
    chunk = pruner.prune_enclosing_function(finding["line_number"])

    print(
        f"[*] Hedef: {finding['cwe']} ({finding['test_id']}) - "
        f"{chunk['qualified_name']} (Satır {finding['line_number']})"
    )

    # -------------------------------------------------------------
    # TUR 1: Kasıtlı Fonksiyonel Regresyon Simülasyonu
    # -------------------------------------------------------------
    print("\n" + "-" * 50)
    print("🚩 [TUR 1] Hatalı Yama Simülasyonu (Regresyon Oluşturuluyor)")
    print("-" * 50)

    flawed_patch = """def get_user_by_username(conn, username: str):
    cursor = conn.cursor()
    # Açık kapatıldı (parametreli) ANCAK yanlışlıkla sadece username seçildi! (Regresyon)
    query = "SELECT username FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchone()"""

    print("[Tur 1 Yama İçeriği]:")
    print(flawed_patch)

    synthesizer.apply_patch_to_file(
        str(target_file), chunk["start_line"], chunk["end_line"], flawed_patch
    )

    print("\n[*] Docker Sealed Sandbox Testi Koşuluyor...")
    t1_res = sandbox.run_dual_verification(str(task_dir))
    print(
        f"  ├─ func_test (Birim Testler) : "
        f"{'PASS ✅' if t1_res['func_pass'] else 'FAIL ❌ (REGRESYON!)'}"
    )
    print(
        f"  └─ sec_test (Exploit Testi)  : "
        f"{'PASS ✅' if t1_res['sec_pass'] else 'FAIL ❌'}"
    )

    # -------------------------------------------------------------
    # TUR 2: Rollback + Çok Turlu Konuşma Geçmişiyle Self-Healing
    # -------------------------------------------------------------
    print("\n" + "-" * 50)
    print("🤖 [TUR 2] Self-Healing: Rollback + Önceki Yama & Hata Çıktısı Modele İletiliyor")
    print("-" * 50)

    # Temiz orijinal haline geri al
    target_file.write_text(original_vulnerable_code, encoding="utf-8")

    messages = synthesizer.build_initial_messages(chunk, [finding])
    messages.append({"role": "assistant", "content": f"```python\n{flawed_patch}\n```"})
    feedback = (
        f"Functional Regression Failure (func_test.py):\n{t1_res['func_output']}\n"
        "Preserve all returned columns (id, username, email)."
    )
    messages.append(synthesizer.build_feedback_message(feedback, turn_number=1))

    gen_res = synthesizer.synthesize(messages)
    healed_patch = gen_res.extracted_code
    print(f"[*] Model düzeltilmiş yeni yamayı üretti ({gen_res.duration_seconds:.2f} sn):")
    print(healed_patch)

    # Fonksiyon adına göre yeniden konumlandır ve sözdizimi doğrulayarak uygula
    pruner_t2 = ASTContextPruner(str(target_file))
    chunk_t2 = pruner_t2.prune_function_by_name(
        chunk["function_name"], class_name=chunk["class_name"]
    )
    synthesizer.apply_patch_to_file(
        str(target_file), chunk_t2["start_line"], chunk_t2["end_line"], healed_patch
    )

    print("\n[*] Docker Sealed Sandbox Testi Tekrar Koşuluyor (Çift Doğrulama)...")
    t2_res = sandbox.run_dual_verification(str(task_dir))
    print(f"  ├─ func_test (Birim Testler) : {'PASS ✅' if t2_res['func_pass'] else 'FAIL ❌'}")
    print(f"  └─ sec_test (Exploit Testi)  : {'PASS ✅' if t2_res['sec_pass'] else 'FAIL ❌'}")

    if t2_res["all_passed"]:
        print("\n" + "*" * 70)
        print("🎉 [SELF-HEALING BAŞARILI] Model hatayı okudu, regresyonu düzeltti ve testi geçti!")
        print("*" * 70)
    else:
        target_file.write_text(original_vulnerable_code, encoding="utf-8")

    report = {
        "scenario": "Self-Healing Multi-Turn Validation",
        "backend": synthesizer.backend_name,
        "model_name": synthesizer.model_name,
        "turn_1": {
            "patch": flawed_patch,
            "func_pass": t1_res["func_pass"],
            "sec_pass": t1_res["sec_pass"],
        },
        "turn_2": {
            "feedback_provided": True,
            "previous_patch_in_history": True,
            "patch": healed_patch,
            "llm_metrics": gen_res.to_metrics_dict(),
            "func_pass": t2_res["func_pass"],
            "sec_pass": t2_res["sec_pass"],
            "resolved": t2_res["all_passed"],
        },
    }
    report_path = task_dir / "self_healing_rapor.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n[Rapor] Detaylı rapor kaydedildi: {report_path.as_posix()}")


if __name__ == "__main__":
    run_self_healing_demonstration()
