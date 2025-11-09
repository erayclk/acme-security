"""
Acme Security Incident - Timeline & IOC Builder
Bu script tüm log dosyalarını analiz edip zaman çizelgesi ve IOC listesi oluşturur.
"""

import pandas as pd
from pathlib import Path
from urllib.parse import urlparse
import re
import os
from datetime import datetime

# Script'in bulunduğu dizini bul
SCRIPT_DIR = Path(__file__).parent.absolute()
BASE_DIR = SCRIPT_DIR.parent  # acme-security-main klasörü

# Materials klasörünü bul
MATERIALS_DIR = BASE_DIR / "materials"
if not MATERIALS_DIR.exists():
    print(f"[!] Hata: 'materials' klasoru bulunamadi!")
    print(f"    Script konumu: {SCRIPT_DIR}")
    print(f"    Aranan konum: {MATERIALS_DIR}")
    exit(1)

# Çıktı klasörü (base dizinde)
OUTPUT_DIR = BASE_DIR / "analysis_output"

# Çıktı klasörünü oluştur
OUTPUT_DIR.mkdir(exist_ok=True)

print("[*] Log dosyalari yukleniyor...")

# Log dosyalarını yükle
try:
    email_df = pd.read_csv(MATERIALS_DIR / "email_logs.csv", parse_dates=["timestamp"])
    web_df = pd.read_csv(MATERIALS_DIR / "web_logs.csv", parse_dates=["timestamp"])
    waf_df = pd.read_csv(MATERIALS_DIR / "waf_logs.csv", parse_dates=["timestamp"])
    api_df = pd.read_csv(MATERIALS_DIR / "api_logs.csv", parse_dates=["timestamp"])
    print("[+] Tum log dosyalari basariyla yuklendi\n")
except Exception as e:
    print(f"[!] Hata: {e}")
    exit(1)

# Timeline olayları için liste
timeline_events = []
ioc_list = []

# ============================================================================
# 1. EMAIL LOGS - Phishing Analizi
# ============================================================================
print("[*] Email loglari analiz ediliyor...")

# Şüpheli email pattern'leri
suspicious_keywords = ["urgent", "verify", "account", "password", "invoice", "action required"]
phishing_mask = email_df["subject"].str.contains("|".join(suspicious_keywords), case=False, na=False)

phishing_emails = email_df[phishing_mask]

for _, row in phishing_emails.iterrows():
    # Timeline event
    detail = f"Phishing email from '{row['from']}' to '{row['to']}' - Subject: '{row['subject']}'"
    if pd.notna(row.get('link_clicked')) and row['link_clicked'] == 'yes':
        detail += " [LINK CLICKED]"
    
    timeline_events.append({
        "Timestamp": row["timestamp"],
        "Source": "Email",
        "Event": "Phishing Campaign",
        "Detail": detail,
        "IP": row.get("ip_address", "N/A"),
        "Severity": "HIGH"
    })
    
    # IOC'ler
    if pd.notna(row.get("ip_address")):
        ioc_list.append({
            "Type": "IP",
            "Value": row["ip_address"],
            "Source": "email_logs.csv",
            "Context": f"Phishing email sender IP - {row['from']}",
            "FirstSeen": row["timestamp"]
        })
    
    ioc_list.append({
        "Type": "Email",
        "Value": row["from"],
        "Source": "email_logs.csv",
        "Context": f"Phishing sender - Subject: {row['subject']}",
        "FirstSeen": row["timestamp"]
    })

print(f"   [+] {len(phishing_emails)} supheli email tespit edildi")

# ============================================================================
# 2. WEB LOGS - SQL Injection Analizi
# ============================================================================
print("[*] Web loglari analiz ediliyor...")

# SQL injection pattern'leri
sqli_patterns = [
    r"OR\s+1\s*=\s*1",
    r"UNION\s+SELECT",
    r"DROP\s+TABLE",
    r"--",
    r"\/\*",
    r"xp_",
    r"sleep\s*\(",
    r"waitfor\s+delay"
]

sqli_mask = web_df["query_params"].str.contains("|".join(sqli_patterns), case=False, na=False, regex=True)
sqli_attempts = web_df[sqli_mask]

for _, row in sqli_attempts.iterrows():
    # Başarılı SQLi (200 response)
    severity = "CRITICAL" if row["response_code"] == 200 else "HIGH"
    
    timeline_events.append({
        "Timestamp": row["timestamp"],
        "Source": "Web",
        "Event": "SQL Injection Attempt",
        "Detail": f"SQLi from {row['ip_address']} → {row['endpoint']}?{row['query_params']} (Status: {row['response_code']})",
        "IP": row["ip_address"],
        "Severity": severity
    })
    
    # IOC'ler
    ioc_list.append({
        "Type": "IP",
        "Value": row["ip_address"],
        "Source": "web_logs.csv",
        "Context": f"SQL injection attempt - {row['endpoint']}",
        "FirstSeen": row["timestamp"]
    })
    
    if pd.notna(row.get("user_agent")):
        ioc_list.append({
            "Type": "User-Agent",
            "Value": row["user_agent"],
            "Source": "web_logs.csv",
            "Context": "SQL injection attempt",
            "FirstSeen": row["timestamp"]
        })

# Başarılı SQLi (200 response code)
successful_sqli = sqli_attempts[sqli_attempts["response_code"] == 200]
if len(successful_sqli) > 0:
    print(f"   [!] {len(successful_sqli)} BASARILI SQL injection tespit edildi!")

print(f"   [+] {len(sqli_attempts)} SQL injection denemesi bulundu")

# ============================================================================
# 3. WAF LOGS - Saldırı Tespitleri
# ============================================================================
print("[*] WAF loglari analiz ediliyor...")

# Kritik ve yüksek öncelikli WAF olayları
critical_waf = waf_df[waf_df["severity"].isin(["CRITICAL", "HIGH"])]

for _, row in critical_waf.iterrows():
    timeline_events.append({
        "Timestamp": row["timestamp"],
        "Source": "WAF",
        "Event": f"WAF Alert: {row['signature']}",
        "Detail": f"{row['action']} from {row['source_ip']} → {row['uri']} (Rule: {row['rule_id']}, Severity: {row['severity']})",
        "IP": row["source_ip"],
        "Severity": row["severity"]
    })
    
    # IOC'ler
    ioc_list.append({
        "Type": "IP",
        "Value": row["source_ip"],
        "Source": "waf_logs.csv",
        "Context": f"WAF alert: {row['signature']}",
        "FirstSeen": row["timestamp"]
    })

# Account enumeration pattern (rapid sequential access)
enum_pattern = waf_df[waf_df["signature"].str.contains("Rapid Sequential|Account Enumeration", case=False, na=False)]
if len(enum_pattern) > 0:
    print(f"   [!] {len(enum_pattern)} hesap numaralandirma (enumeration) denemesi tespit edildi")

print(f"   [+] {len(critical_waf)} kritik WAF uyarisi bulundu")

# ============================================================================
# 4. API LOGS - Broken Access Control Analizi
# ============================================================================
print("[*] API loglari analiz ediliyor...")

# Broken Access Control: user_id ile account_id eşleşmeyen başarılı istekler
# NOT: user_id, kullanıcının kimliği; account_id, erişilen hesabın kimliği
# IDOR (Insecure Direct Object Reference) tespiti için: user_id != account_id

# user_id ve account_id'yi sayısal değerlere dönüştür (karşılaştırma için)
api_df["user_id_numeric"] = pd.to_numeric(api_df["user_id"], errors='coerce')
api_df["account_id_numeric"] = pd.to_numeric(api_df["account_id"], errors='coerce')

# user_id ile account_id eşleşmeyen başarılı istekler (IDOR)
bac_mask = (
    (api_df["response_code"].isin([200, 201])) &
    (api_df["account_id_numeric"].notna()) &  # account_id dolu olmalı
    (api_df["user_id_numeric"].notna()) &     # user_id dolu olmalı
    (api_df["user_id"] != "NULL") &            # NULL string değil
    (api_df["user_id_numeric"] != api_df["account_id_numeric"])  # user_id != account_id (IDOR!)
)

broken_access = api_df[bac_mask]

for _, row in broken_access.iterrows():
    timeline_events.append({
        "Timestamp": row["timestamp"],
        "Source": "API",
        "Event": "Broken Access Control",
        "Detail": f"User {row['user_id']} accessed account {row['account_id']} via {row['endpoint']} (Status: {row['response_code']}) from {row['ip_address']}",
        "IP": row["ip_address"],
        "Severity": "CRITICAL"
    })
    
    # IOC'ler
    ioc_list.append({
        "Type": "IP",
        "Value": row["ip_address"],
        "Source": "api_logs.csv",
        "Context": f"Broken Access Control - User {row['user_id']} accessed account {row['account_id']}",
        "FirstSeen": row["timestamp"]
    })
    
    ioc_list.append({
        "Type": "UserID",
        "Value": str(row["user_id"]),
        "Source": "api_logs.csv",
        "Context": f"Unauthorized access to account {row['account_id']}",
        "FirstSeen": row["timestamp"]
    })
    
    if pd.notna(row.get("session_token")) and row["session_token"]:
        ioc_list.append({
            "Type": "SessionToken",
            "Value": row["session_token"],
            "Source": "api_logs.csv",
            "Context": "Compromised token used for unauthorized access",
            "FirstSeen": row["timestamp"]
        })

if len(broken_access) > 0:
    print(f"   [!] {len(broken_access)} Broken Access Control vakasi tespit edildi!")

# Brute Force / Authentication Bypass Attempts
# NULL user_id ve 401 response code = başarısız authentication denemesi
brute_force_mask = (
    (api_df["user_id"].isna() | (api_df["user_id"] == "NULL")) &
    (api_df["response_code"] == 401) &
    (api_df["endpoint"].str.contains("/portfolio/|/login", na=False))
)

brute_force_attempts = api_df[brute_force_mask]

# Aynı IP'den çoklu başarısız deneme = brute force
if len(brute_force_attempts) > 0:
    brute_force_by_ip = brute_force_attempts.groupby("ip_address").size()
    suspicious_brute_force = brute_force_by_ip[brute_force_by_ip >= 3]  # 3+ deneme = şüpheli
    
    for ip, count in suspicious_brute_force.items():
        first_attempt = brute_force_attempts[brute_force_attempts["ip_address"] == ip]["timestamp"].min()
        timeline_events.append({
            "Timestamp": first_attempt,
            "Source": "API",
            "Event": "Brute Force Attempt",
            "Detail": f"Multiple failed authentication attempts ({count}) from {ip}",
            "IP": ip,
            "Severity": "HIGH"
        })
        
        # IOC'ler
        ioc_list.append({
            "Type": "IP",
            "Value": ip,
            "Source": "api_logs.csv",
            "Context": f"Brute force attempt - {count} failed auth attempts",
            "FirstSeen": first_attempt
        })
    
    if len(suspicious_brute_force) > 0:
        print(f"   [!] {len(suspicious_brute_force)} brute force denemesi tespit edildi")

# Account enumeration (rapid sequential portfolio access)
enum_api = api_df[
    (api_df["endpoint"].str.contains("/portfolio/", na=False)) &
    (api_df["response_code"] == 200) &
    (api_df["user_id"].notna())
].sort_values("timestamp")

# Aynı user_id'den kısa sürede çok sayıda farklı account_id erişimi
user_enum = enum_api.groupby("user_id").agg({
    "account_id": "nunique",
    "timestamp": ["min", "max"]
}).reset_index()
user_enum.columns = ["user_id", "unique_accounts", "first_access", "last_access"]
user_enum["duration_seconds"] = (user_enum["last_access"] - user_enum["first_access"]).dt.total_seconds()

# 10 saniyede 5'ten fazla farklı hesaba erişim = enumeration
suspicious_enum = user_enum[
    (user_enum["unique_accounts"] >= 5) &
    (user_enum["duration_seconds"] <= 60)
]

if len(suspicious_enum) > 0:
    for _, enum_row in suspicious_enum.iterrows():
        # Enumeration yapan kullanıcının IP'sini bul
        user_enum_logs = enum_api[enum_api["user_id"] == enum_row["user_id"]]
        enum_ip = user_enum_logs["ip_address"].iloc[0] if len(user_enum_logs) > 0 else "N/A"
        
        timeline_events.append({
            "Timestamp": enum_row["first_access"],
            "Source": "API",
            "Event": "Account Enumeration",
            "Detail": f"User {enum_row['user_id']} accessed {enum_row['unique_accounts']} different accounts in {enum_row['duration_seconds']:.1f} seconds",
            "IP": enum_ip,
            "Severity": "HIGH"
        })
        
        # IOC'ler
        if enum_ip != "N/A":
            ioc_list.append({
                "Type": "IP",
                "Value": enum_ip,
                "Source": "api_logs.csv",
                "Context": f"Account enumeration - User {enum_row['user_id']} accessed {enum_row['unique_accounts']} accounts",
                "FirstSeen": enum_row["first_access"]
            })
        
        ioc_list.append({
            "Type": "UserID",
            "Value": str(enum_row["user_id"]),
            "Source": "api_logs.csv",
            "Context": f"Account enumeration - {enum_row['unique_accounts']} accounts in {enum_row['duration_seconds']:.1f}s",
            "FirstSeen": enum_row["first_access"]
        })
    print(f"   [!] {len(suspicious_enum)} hesap numaralandirma (enumeration) vakasi tespit edildi")

print(f"   [+] API loglari analiz edildi")

# ============================================================================
# 5. TIMELINE OLUŞTURMA
# ============================================================================
print("\n[*] Zaman cizelgesi olusturuluyor...")

if len(timeline_events) == 0:
    print("   [!] Hic olay bulunamadi!")
else:
    timeline_df = pd.DataFrame(timeline_events)
    timeline_df = timeline_df.sort_values("Timestamp").reset_index(drop=True)
    
    # CSV olarak kaydet (dosya açıksa alternatif isimle dene)
    timeline_file = OUTPUT_DIR / "timeline.csv"
    try:
        timeline_df.to_csv(timeline_file, index=False)
        print(f"   [+] Timeline kaydedildi: {timeline_file}")
    except PermissionError:
        # Dosya açıksa alternatif isimle kaydet
        alt_file = OUTPUT_DIR / f"timeline_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        timeline_df.to_csv(alt_file, index=False)
        print(f"   [!] UYARI: timeline.csv dosyasi acik, alternatif dosya olarak kaydedildi:")
        print(f"       {alt_file}")
        print(f"   [+] Lutfen timeline.csv dosyasini kapatip script'i tekrar calistirin.")
    except Exception as e:
        print(f"   [!] Hata: Timeline kaydedilemedi: {e}")
    
    print(f"   [*] Toplam {len(timeline_df)} olay tespit edildi")
    
    # Ozet istatistikler
    print("\n[*] Olay Ozeti:")
    print(timeline_df.groupby("Source")["Event"].count().to_string())
    print("\n[*] Severity Dagitimi:")
    print(timeline_df.groupby("Severity").size().to_string())

# ============================================================================
# 6. IOC LİSTESİ OLUŞTURMA
# ============================================================================
print("\n[*] IOC listesi olusturuluyor...")

if len(ioc_list) == 0:
    print("   [!] Hic IOC bulunamadi!")
else:
    ioc_df = pd.DataFrame(ioc_list)
    
    # Duplicate'leri kaldır (aynı Type ve Value için en erken FirstSeen'i tut)
    ioc_df = ioc_df.sort_values("FirstSeen").drop_duplicates(subset=["Type", "Value"], keep="first")
    ioc_df = ioc_df.sort_values(["Type", "FirstSeen"]).reset_index(drop=True)
    
    # CSV olarak kaydet (dosya açıksa alternatif isimle dene)
    ioc_file = OUTPUT_DIR / "iocs.csv"
    try:
        ioc_df.to_csv(ioc_file, index=False)
        print(f"   [+] IOC listesi kaydedildi: {ioc_file}")
    except PermissionError:
        # Dosya açıksa alternatif isimle kaydet
        alt_file = OUTPUT_DIR / f"iocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        ioc_df.to_csv(alt_file, index=False)
        print(f"   [!] UYARI: iocs.csv dosyasi acik, alternatif dosya olarak kaydedildi:")
        print(f"       {alt_file}")
        print(f"   [+] Lutfen iocs.csv dosyasini kapatip script'i tekrar calistirin.")
    except Exception as e:
        print(f"   [!] Hata: IOC listesi kaydedilemedi: {e}")
    
    print(f"   [*] Toplam {len(ioc_df)} benzersiz IOC tespit edildi")
    
    # IOC tipi dagilimi
    print("\n[*] IOC Tipi Dagitimi:")
    print(ioc_df.groupby("Type").size().to_string())

# ============================================================================
# 7. ÖZET RAPOR
# ============================================================================
print("\n" + "="*60)
print("ANALIZ OZETI")
print("="*60)

if len(timeline_events) > 0:
    timeline_df = pd.DataFrame(timeline_events).sort_values("Timestamp")
    
    print(f"\n[*] Olay Zaman Araligi:")
    print(f"   Baslangic: {timeline_df['Timestamp'].min()}")
    print(f"   Bitis:     {timeline_df['Timestamp'].max()}")
    
    print(f"\n[!] Kritik Bulgular:")
    critical = timeline_df[timeline_df["Severity"] == "CRITICAL"]
    if len(critical) > 0:
        print(f"   [!] {len(critical)} KRITIK olay tespit edildi!")
        for _, row in critical.head(5).iterrows():
            print(f"      - {row['Timestamp']} - {row['Event']}")
    else:
        print("   [+] Kritik olay bulunamadi")
    
    print(f"\n[*] Phishing:")
    phishing_count = len(timeline_df[timeline_df["Source"] == "Email"])
    print(f"   {phishing_count} supheli email")
    
    print(f"\n[*] SQL Injection:")
    sqli_count = len(timeline_df[timeline_df["Event"] == "SQL Injection Attempt"])
    print(f"   {sqli_count} deneme")
    
    print(f"\n[*] Broken Access Control:")
    bac_count = len(timeline_df[timeline_df["Event"] == "Broken Access Control"])
    print(f"   {bac_count} yetkisiz erisim vakasi")

print("\n" + "="*60)
print("[+] Analiz tamamlandi!")
print(f"[*] Ciktilar: {OUTPUT_DIR}/ klasorunde")
print("="*60)

