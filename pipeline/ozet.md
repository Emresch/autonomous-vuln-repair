# 📋 Otonom Güvenlik Yama Motoru — Özet Rapor

## 1. Sistem Nasıl Çalışıyor?
Geliştirilen sistem, Python kodlarındaki güvenlik açıklarını **orijinal işlevi bozmadan** otonom olarak onarır:
1. **Baseline Kontrolü:** Docker içinde `func_test` (birim testi) ve `sec_test` (saldırı testi) koşturularak kodun çalıştığı (`PASS`) ama güvenlik açığı barındırdığı (`FAIL`) doğrulanır.
2. **SAST & AST Kırpma:** **Bandit** ve **Semgrep** hatanın satırını bulur; Python **AST** modülü tüm dosya yerine sadece hatalı fonksiyonu kesip yerel LLM'e (**Qwen-2.5-Coder:7b**) gönderir.
3. **Self-Healing (Kendi Kendini İyileştirme):** Üretilen yama Docker'da test edilir. Test patlarsa hata çıktısı (`Traceback`) modele geri beslenerek 3 tura kadar kendi hatasını düzeltmesi sağlanır.

---

## 2. SAST Güncellemesi: Öncesi ve Sonrası
* **Öncesi (Sadece Bandit):** Yalnızca basit sözdizimsel hataları (`SQL Injection`) bulabiliyordu. `os.path.commonprefix` gibi mantıksal açıkları (`Starlette CVE`) kaçırıyor, `import subprocess` gibi zararsız satırlarda yanlış alarm veriyordu.
* **Sonrası (Bandit + Semgrep Hibrit):** İki motor birleştirildi ve yanlış alarmlar filtrelendi. Böylece hem sözdizimsel hem de karmaşık mantıksal açıklar (`Path Traversal`, `RCE`) tek seferde ve aynı dosya içinde çoklu olarak yakalanabilir hale geldi.

---

## 3. Test Edilen 4 Görev ve Sonuçları

1. **Basit Görev — SQLi Authentication (`CWE-89`):**
   * **Sorun:** `f-string` ile yazılan güvensiz SQL sorgusu.
   * **Sonuç:** Bandit 24. satırda yakaladı, Qwen parametreli sorguya (`?`) çevirdi ve **1. turda** (12.8s) onardı.
2. **Gerçek CVE — Starlette `CVE-2023-29159` (`CWE-22 Path Traversal`):**
   * **Sorun:** `os.path.commonprefix` kullanımı nedeniyle dizin dışındaki gizli dosyaların okunabilmesi.
   * **Sonuç:** Semgrep 21. satırda yakaladı, Qwen `os.path.commonpath` kullanarak **1. turda** (14.4s) onardı.
3. **Karmaşık Gerçek CVE & Self-Healing — Airflow `CVE-2022-41131` (`CWE-78 RCE`):**
   * **Sorun:** `schema` parametresi üzerinden işletim sisteminde uzaktan komut çalıştırılabilmesi (`!` ve `;` karakterleri ile).
   * **Sonuç:** **1. turda** Qwen açığı kapattı (`sec_test: PASS`) ancak dosya yazma yapısını bozduğu için birim testi patladı (`func_test: FAIL`). Docker hata çıktısı Qwen'e geri verildi; model **2. turda** hatasını düzelterek tam başarı sağladı (29.2s).
4. **Çoklu Zafiyet — Multi-Vuln Microservice (`CWE-89` + `CWE-22`):**
   * **Sorun:** 5 fonksiyonlu tek bir dosyada 2 farklı zafiyetin aynı anda bulunması.
   * **Sonuç:** Bandit SQLi'yi, Semgrep ise Path Traversal'ı aynı anda buldu. AST Pruner sağlam olan 3 fonksiyona hiç dokunmadan sadece hatalı 2 fonksiyonu sırayla kırpıp **1. turda** (19.0s) onardı.

---

## 4. Toplu Benchmark Değerlendirme Tablosu

```text
===============================================================================================
🏆 OTONOM GÜVENLİK YAMA MOTORU - SUSVIBES & CVE BENCHMARK DEĞERLENDİRME RAPORU
===============================================================================================
GÖREV ADI                  | ZAFİYET TÜRÜ                 | MOTOR          | TUR  | SÜRE     | DURUM
-----------------------------------------------------------------------------------------------
SQLi Authentication        | CWE-89 (SQL Injection)       | Bandit         | 1    | 12.81s   | BAŞARILI ✅
Starlette CVE-2023-29159   | CWE-22 (Path Traversal)      | Semgrep        | 1    | 14.40s   | BAŞARILI ✅
Airflow CVE-2022-41131     | CWE-78 (OS Command Inj / RCE)| Semgrep        | 2    | 29.20s   | BAŞARILI ✅
Multi-Vuln Microservice    | CWE-89 + CWE-22 (Çoklu Açık) | Semgrep,Bandit | 1    | 19.03s   | BAŞARILI ✅
-----------------------------------------------------------------------------------------------
Toplam Başarı Oranı : %100.0 (4/4 Görev Onarıldı)
Toplam Süre         : 75.44 saniye
Yerel Model         : Qwen-2.5-Coder:7b (Ollama / RTX 3050)
===============================================================================================
```
