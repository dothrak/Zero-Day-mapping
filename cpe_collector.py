import os
import time
import psycopg2
import requests
from psycopg2.extras import execute_values

API_KEY = os.getenv("NVD_API_KEY")
HEADERS = {"apiKey": API_KEY}

DB_PARAMS = {
    "dbname": "zerodaydb",
    "user": "postgres",
    "password": "postgres",
    "host": "localhost",
    "port": 5432
}

BASE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
RESULTS_PER_PAGE = 2000

def init_db():
    with psycopg2.connect(**DB_PARAMS) as conn, conn.cursor() as cur:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS softwares (
            software_id SERIAL PRIMARY KEY,
            cpe TEXT UNIQUE NOT NULL,
            vendor TEXT,
            product TEXT,
            titles TEXT[],
            type TEXT,
            functionalities TEXT[],
            platform TEXT,
            wiki_page TEXT,
            wiki_summary TEXT,
            categories TEXT[],
            wiki_checked BOOLEAN,
            last_enriched TIMESTAMP,
            updated_at TIMESTAMP DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_softwares_vendor_product ON softwares(vendor, product);
        """)
        conn.commit()

def fetch_all_cpes():
    start_index = 0
    results = []

    while True:
        url = f"{BASE_URL}?resultsPerPage={RESULTS_PER_PAGE}&startIndex={start_index}"
        print(f"[CPE] Récupération à partir de l’index {start_index} ...")

        r = requests.get(url, headers=HEADERS)
        if r.status_code == 429:
            print("[!] Trop de requêtes — pause de 10 secondes...")
            time.sleep(10)
            continue

        r.raise_for_status()
        data = r.json()

        products = data.get("products", [])
        if not products:
            break

        for p in products:
            cpe = p.get("cpe", {})
            cpe_name = cpe.get("cpeName")
            if not cpe_name:
                continue

            parts = cpe_name.split(":")
            if len(parts) < 5:
                continue
            vendor = parts[3]
            product = parts[4]
            titles = [t["title"] for t in cpe.get("titles", [])]

            results.append((cpe_name, vendor, product, titles or None))

        start_index += RESULTS_PER_PAGE
        time.sleep(0.7)

    print(f"[CPE] {len(results)} CPE collectées.")
    return results

def insert_softwares(data):
    with psycopg2.connect(**DB_PARAMS) as conn, conn.cursor() as cur:
        query = """
            INSERT INTO softwares (cpe, vendor, product, titles)
            VALUES %s
            ON CONFLICT (cpe) DO NOTHING;
        """
        execute_values(cur, query, data)
        conn.commit()

if __name__ == "__main__":
    init_db()
    cpe_data = fetch_all_cpes()
    insert_softwares(cpe_data)
    print("[CPE] Import terminé.")
