import psycopg2
from datetime import datetime
from collections import defaultdict
from zdi_collector import fetch_zdi, upsert_zdi
from zdcz_collector import fetch_zdcz, upsert_zero_day_cz
from kev_collector import fetch_kev, mark_exploited_with_kev
from nvd_collector import load_nvd_json_by_year, enrich_with_nvd_from_cache
from circl_collector import enrich_with_circl


def get_cve_year(cve_id: str) -> int:
    try:
        return int(cve_id.split("-")[1])
    except (IndexError, ValueError):
        return None


def run_etl():
    # --- Configuration de la timeline---
    YEAR_FROM = 2022
    YEAR_TO = 2025

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
    kev_cves = fetch_kev()  # dict cve_id -> date ajout KEV

    # --- Étape 1 : récupération ZDI et Zero-day.cz ---
    print("=== [1] Collecte ZDI et Zero-day.cz ===")
    zdi_vulns = fetch_zdi(YEAR_FROM, YEAR_TO)
    zdcz_vulns = fetch_zdcz(YEAR_FROM, YEAR_TO)
    all_candidates = zdi_vulns + zdcz_vulns

    # Marquer les vulnérabilités exploitées par KEV
    for v in all_candidates:
        v = mark_exploited_with_kev(v, kev_cves)
        if v.get("kev_added") and v.get("disclosed"):
            v["kev_latency_days"] = (v["kev_added"] - v["disclosed"]).days

    # --- Étape 2 : regroupement par année ---
    print("=== [2] Préparation enrichissement NVD ===")
    cves_by_year = defaultdict(list)
    for v in all_candidates:
        if v.get("cve_id"):
            year = get_cve_year(v["cve_id"])
            if year:
                cves_by_year[year].append(v)

    # Charger les fichiers NVD seulement pour les années nécessaires
    nvd_data_by_year = {}
    for year in cves_by_year.keys():
        nvd_data_by_year[year] = load_nvd_json_by_year(year)

    # --- Étape 3 : enrichissement NVD et CIRCL ---
    print("=== [3] Enrichissement NVD et CIRCL ===")
    for v in all_candidates:
        year = get_cve_year(v.get("cve_id", ""))
        if year and year in nvd_data_by_year:
            v = enrich_with_nvd_from_cache(v, nvd_data_by_year[year])
        v = enrich_with_circl(v)

    # --- Étape 4 : Upsert dans la base ---
    print("=== [4] Insertion en base ===")
    zdcz_cves = [vd["cve_id"] for vd in zdcz_vulns if vd.get("cve_id")]
    zdi_cves = [vd["cve_id"] for vd in zdi_vulns if vd.get("cve_id")]

    for v in all_candidates:
        if v.get("tags") and "ZDI" in v["tags"]:
            upsert_zdi(cur, kev_cves=kev_cves, zdcz_cves=zdcz_cves)
        elif v.get("tags") and "Zero-day.cz" in v["tags"]:
            upsert_zero_day_cz(cur, kev_cves=kev_cves, zdi_cves=zdi_cves)

    print("\n✅ ETL terminé.")


if __name__ == "__main__":
    run_etl()
