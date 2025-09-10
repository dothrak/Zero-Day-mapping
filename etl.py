import psycopg2
from datetime import datetime

# Collectors
from nvd_collector import fetch_nvd, upsert_nvd_vulns
from circl_collector import fetch_circl, enrich_with_circl
from zdi_collector import upsert_zdi_vulns, fetch_zdi
from zdcz_collector import upsert_zero_day_cz, fetch_zdcz
from kev_collector import fetch_kev, mark_exploited_with_kev

def run_etl(limit=10):
    # --- Connexion PostgreSQL ---
    conn = psycopg2.connect(
        dbname="zerodaydb",
        user="postgres",
        password="postgres",
        host="localhost",
        port=5432
    )
    conn.autocommit = True
    cur = conn.cursor()

    # --- Étape 0 : récupération KEV ---
    print("=== [0] Collecte KEV CISA ===")
    kev_cves = fetch_kev()

    # --- Étape 1 : NVD ---
    print("=== [1] Collecte depuis NVD ===")
    nvd_vulns = fetch_nvd(limit=limit)

    # Pré-charger CVE ZDI et Zero-day.cz pour le marquage 0-day
    zdi_cves = fetch_zdi()
    zdcz_cves = fetch_zdcz()

    for v in nvd_vulns:
        # Marquage KEV et 0-day
        v = mark_exploited_with_kev(v, kev_cves)
        if v.get("cve_id") in zdi_cves or v.get("cve_id") in zdcz_cves:
            v["exploited_in_wild"] = True

        # Upsert dans la base
        vuln_id = upsert_nvd_vulns(cur, v)

        # Enrichissement CIRCL
        cve_id = v.get("cve", {}).get("id")
        if cve_id:
            circl_data = fetch_circl(cve_id)
            if circl_data:
                enrich_with_circl(cur, vuln_id, circl_data)

    # --- Étape 2 : ZDI ---
    print("=== [2] Collecte depuis ZDI ===")
    upsert_zdi_vulns(cur, kev_cves=kev_cves, zdcz_cves=zdi_cves)

    # --- Étape 3 : Zero-day.cz ---
    print("=== [3] Collecte depuis Zero-day.cz ===")
    upsert_zero_day_cz(cur, kev_cves=kev_cves, zdi_cves=zdcz_cves)

    print("\n✅ ETL terminé.")

if __name__ == "__main__":
    run_etl(limit=30)
