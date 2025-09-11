import requests
from bs4 import BeautifulSoup
from datetime import datetime
from psycopg2.extras import Json
from kev_collector import mark_exploited_with_kev

ZDI_2025_URL = "https://www.zerodayinitiative.com/advisories/published/2022/"

def fetch_zdi(year_from: int, year_to: int):
    for year in range(year_from, year_to + 1):
        url = f"https://www.zerodayinitiative.com/advisories/published/{year}/"
        print(f"[ZDI] Collecte {year} ...")

        r = requests.get(url)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")

    results = []
    advisories = soup.select("tr#publishedAdvisories")  # plus de slicing [:limit]

    for row in advisories:
        cols = row.find_all("td")
        if len(cols) < 8:
            continue

        zdi_id = cols[0].text.strip()
        zdi_can = cols[1].text.strip()
        vendor = cols[2].text.strip()
        cve_id = cols[3].text.strip() or zdi_id  # fallback au ZDI ID s'il n'y a pas de CVE
        cvss = cols[4].text.strip()
        disclosed = datetime.strptime(cols[5].text.strip(), "%Y-%m-%d") if cols[5].text.strip() else None
        updated = datetime.strptime(cols[6].text.strip(), "%Y-%m-%d") if cols[6].text.strip() else None
        link_tag = cols[7].find("a")
        title = link_tag.text.strip() if link_tag else "No title"
        link = f"https://www.zerodayinitiative.com{link_tag['href']}" if link_tag else ""

        results.append({
            "cve_id": cve_id,
            "title": title,
            "summary": f"Publié sur ZDI le {disclosed.date() if disclosed else ''}",
            "vendors_products": [vendor] if vendor else [],
            "first_seen": disclosed,
            "disclosed": disclosed,
            "refs": [{"source": "ZDI", "url": link}] if link else [],
            "tags": ["ZDI"]
        })
    return results


def fetch_zdi_cves():
    vulns = fetch_zdi()
    return [v["cve_id"] for v in vulns]


def upsert_zdi(cur, kev_cves=None, zdcz_cves=None):
    kev_cves = kev_cves or {}
    zdcz_cves = zdcz_cves or []

    vulns = fetch_zdi()
    for v in vulns:
        # Marquer KEV et Zero-day.cz
        v = mark_exploited_with_kev(v, kev_cves)
        if v["cve_id"] in zdcz_cves:
            v["exploited_in_wild"] = True
            v["refs"].append({
                "source": "Zero-day.cz",
                "url": f"https://www.zero-day.cz/cve/{v['cve_id']}"
            })
        
        # Insertion / upsert
        cur.execute("""
            INSERT INTO vulnerabilities (canonical_id, title, summary, vendors_products, first_seen, disclosed, cve_id, exploited_in_wild, refs, tags)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (canonical_id) DO UPDATE SET
                title=EXCLUDED.title,
                summary=EXCLUDED.summary,
                vendors_products=EXCLUDED.vendors_products,
                first_seen=EXCLUDED.first_seen,
                disclosed=EXCLUDED.disclosed,
                cve_id=EXCLUDED.cve_id,
                exploited_in_wild=EXCLUDED.exploited_in_wild,
                refs=EXCLUDED.refs,
                tags=EXCLUDED.tags,
                updated_at=NOW()
            RETURNING vuln_id
        """, (
            v["cve_id"],
            v.get("title"),
            v.get("summary"),
            Json(v.get("vendors_products")),
            v.get("first_seen"),
            v.get("disclosed"),
            v.get("cve_id"),
            v.get("exploited_in_wild", False),
            Json(v.get("refs", [])),
            v.get("tags", [])
        ))
        vuln_id = cur.fetchone()[0]
        print(f"[ZDI] {v['cve_id']} inséré/mis à jour (id {vuln_id})")
