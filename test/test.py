import psycopg2
from pathlib import Path
from nvd_collector import download_nvd_json, load_nvd_json_by_year, enrich_with_nvd_from_cache
from datetime import datetime

# Connexion à la DB test
conn = psycopg2.connect(
    host="localhost",
    port=5433,
    dbname="zerodaydb_test",
    user="testuser",
    password="testpass"
)
conn.autocommit = True
cur = conn.cursor()

# Échantillon de CVE
sample_cves = [
    "CVE-2025-5778",
    "CVE-2024-27074",
    "CVE-2023-51612",
    "CVE-2022-43645"
]

# --- Charger les fichiers NVD nécessaires ---
years = set(int(cve.split("-")[1]) for cve in sample_cves)
nvd_cache = {}
for year in years:
    nvd_cache.update(load_nvd_json_by_year(year))

for cve_id in sample_cves:
    # 1️⃣ Insérer la vulnérabilité de base si elle n'existe pas déjà
    cur.execute("""
        INSERT INTO vulnerabilities (canonical_id, cve_id, first_seen)
        VALUES (%s, %s, %s)
        ON CONFLICT (canonical_id) DO NOTHING
        RETURNING vuln_id
    """, (cve_id, cve_id, datetime.now()))
    
    result = cur.fetchone()
    if result:
        vuln_id = result[0]
    else:
        # si déjà existante, récupérer l'id
        cur.execute("SELECT vuln_id FROM vulnerabilities WHERE canonical_id = %s", (cve_id,))
        vuln_id = cur.fetchone()[0]

    # 2️⃣ Enrichir la vulnérabilité avec les infos NVD
    v = {"cve_id": cve_id}
    v = enrich_with_nvd_from_cache(v, nvd_cache)
    
    # Mettre à jour la DB avec les infos NVD
    cur.execute("""
        UPDATE vulnerabilities
        SET published_nvd = %s,
            cvss2_base_score = %s,
            cvss2_vector = %s,
            cvss3_base_score = %s,
            cvss3_vector = %s,
            cvss4_base_score = %s,
            cvss4_vector = %s,
            updated_at = NOW()
        WHERE vuln_id = %s
    """, (
        v.get("published_nvd"),
        v.get("cvss2_base_score"),
        v.get("cvss2_vector"),
        v.get("cvss3_base_score"),
        v.get("cvss3_vector"),
        v.get("cvss4_base_score"),
        v.get("cvss4_vector"),
        vuln_id
    ))

    print(f"[DB] CVE {cve_id} insérée/enrichie avec succès")

cur.close()
conn.close()
