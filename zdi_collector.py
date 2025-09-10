import requests
from bs4 import BeautifulSoup
from datetime import datetime
from psycopg2.extras import Json
from kev_collector import mark_exploited_with_kev

ZDI_2025_URL = "https://www.zerodayinitiative.com/advisories/published/2025/"

def fetch_zdi(limit=5):
    """
    Récupère les vulnérabilités ZDI pour l'année 2025.
    Limit : nombre de vulnérabilités à récupérer pour tests.
    """
    r = requests.get(ZDI_2025_URL, timeout=15)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    
    results = []
    advisories = soup.select(".advisory")[:limit]  # On prend les N premières vulnérabilités
    for adv in advisories:
        cve_tag = adv.select_one(".advisory-title a")
        cve_id = cve_tag.text.strip() if cve_tag else f"ZDI-{hash(adv.text) % 10000}"
        link = cve_tag["href"] if cve_tag else ""
        title = adv.select_one(".advisory-title").text.strip() if adv.select_one(".advisory-title") else "No title"
        date_tag = adv.select_one(".advisory-date")
        disclosed = datetime.strptime(date_tag.text.strip(), "%B %d, %Y") if date_tag else None
        
        results.append({
            "cve_id": cve_id,
            "title": title,
            "summary": f"Publié sur ZDI {disclosed.date() if disclosed else ''}",
            "vendors_products": [],
            "first_seen": disclosed,
            "disclosed": disclosed,
            "refs": [{"source": "ZDI", "url": link}] if link else [],
            "tags": ["ZDI"]
        })
    return results

def fetch_zdi_cves(limit=5):
    vulns = fetch_zdi(limit)
    return [v["cve_id"] for v in vulns]

def upsert_zdi_vulns(cur, kev_cves=None, zdcz_cves=None, limit=5):
    kev_cves = kev_cves or {}
    zdcz_cves = zdcz_cves or []

    vulns = fetch_zdi(limit)
    for v in vulns:
        # Marquer KEV et Zero-day.cz
        v = mark_exploited_with_kev(v, kev_cves)
        if v["cve_id"] in zdcz_cves:
            v["exploited_in_wild"] = True
            v["refs"].append({"source": "Zero-day.cz", "url": f"https://www.zero-day.cz/cve/{v['cve_id']}"})
        
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
