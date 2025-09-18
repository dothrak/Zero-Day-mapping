import psycopg2
from nvd_collector import NVDEnricher
from kev_collector import KEVEnricher
from zdi_collector import ZDICollector
from zdcz_collector import ZDCZCollector
from epss_collector import EPSSEnricher

YEAR_FROM = 2025
YEAR_TO = 2025

def get_cve_year(cve_id: str) -> int:
    try:
        return int(cve_id.split("-")[1])
    except (IndexError, ValueError):
        return None

def run_etl():
    # --- Connexion DB ---
    conn = psycopg2.connect(
        dbname="zerodaydb",
        user="postgres",
        password="postgres",
        host="localhost",
        port=5432
    )
    conn.autocommit = True
    cur = conn.cursor()

    # --- Initialisation des collecteurs/enrichisseurs ---
    nvd_enricher = NVDEnricher()
    kev_enricher = KEVEnricher()
    epss_enricher = EPSSEnricher()

    # --- Collecte KEV ---
    print("=== [0] Collecte KEV CISA ===")
    kev_enricher.fetch()  # charge les CVE KEV

    # --- Collecte ZDI ---
    print("=== [1] Collecte ZDI ===")
    zdi_collector = ZDICollector(YEAR_FROM, YEAR_TO)
    zdi_vulns = zdi_collector.fetch()

    # --- Collecte Zero-day.cz ---
    print("=== [2] Collecte Zero-day.cz ===")
    zdcz_collector = ZDCZCollector(YEAR_FROM, YEAR_TO)
    zdcz_vulns = zdcz_collector.fetch()

    # --- Regroupement de toutes les vulnérabilités ---
    all_candidates = zdi_vulns + zdcz_vulns

    # --- Enrichissement NVD, KEV et EPSS ---
    print("=== [3] Enrichissement NVD, KEV, EPSS ===")
    for v in all_candidates:
        v = nvd_enricher.enrich(v)
        v = kev_enricher.enrich(v)
        v = kev_enricher.compute_dates(v)
        v = epss_enricher.enrich(v)

    # --- Upsert dans la base ---
    print("=== [4] Insertion en base ===")
    zdcz_cves = [v["cve_id"] for v in zdcz_vulns if v.get("cve_id")]
    zdi_cves = [v["cve_id"] for v in zdi_vulns if v.get("cve_id")]

    zdi_collector.upsert(cur, kev_cves=kev_enricher.kev_cves, zdcz_cves=zdcz_cves)
    zdcz_collector.upsert(cur, kev_cves=kev_enricher.kev_cves, zdi_cves=zdi_cves)

    print("\n✅ ETL terminé.")
    cur.close()
    conn.close()


if __name__ == "__main__":
    run_etl()
