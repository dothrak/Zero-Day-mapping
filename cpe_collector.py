import os
import time
import requests

API_KEY = os.getenv("3bf86c30-815b-423f-8b4c-a2f01c081488")
HEADERS = {"apiKey": API_KEY}

BASE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
RESULTS_PER_PAGE = 2000

def fetch_all_cpes():
    start_index = 0
    seen = set()
    results = []

    while True:
        url = f"{BASE_URL}?resultsPerPage={RESULTS_PER_PAGE}&startIndex={start_index}"
        print(f"[CPE] Récupération à partir de l’index {start_index} ...")

        r = requests.get(url, headers=HEADERS)
        if r.status_code == 429:
            print("[!] Trop de requêtes — pause de 30 secondes...")
            time.sleep(30)
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

            key = (vendor, product)
            if key not in seen:
                seen.add(key)
                results.append({
                    "vendor": vendor,
                    "product": product,
                    "titles": titles
                })

        start_index += RESULTS_PER_PAGE
        time.sleep(0.7)  # ~1.4 requêtes/sec max (clé API active)

    print(f"[CPE] {len(results)} couples uniques collectés.")
    return results


if __name__ == "__main__":
    cpe_list = fetch_all_cpes()
    for c in cpe_list[:10]:
        print(c)