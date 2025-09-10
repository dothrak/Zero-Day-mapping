import requests
from bs4 import BeautifulSoup
from psycopg2.extras import Json
from datetime import datetime
from kev_collector import mark_exploited_with_kev

ZERO_DAY_CZ_URL = "https://www.zero-day.cz/database/?set_filter=Y&arrFilter_pf%5BYEAR_FROM%5D=2025&arrFilter_pf%5BYEAR_TO%5D=2025&arrFilter_pf[SEARCH]="

def fetch_zdcz(limit=5):
    r = requests.get(ZERO_DAY_CZ_URL, timeout=15)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    
    results = []
    issues = soup.select("#issuew_wrap .issue")[:limit]
    
    for issue in issues:
        title_tag = issue.select_one(".issue-title a")
        cve_tag = issue.select_one(".issue-title .issue-code")
        desc_tag = issue.select_one(".description.for-l")
        software_tag = issue.select_one(".spec strong")
        discovered_tag = issue.select_one(".issue-status .discavered time")
        
        cve_id = cve_tag.text.strip() if cve_tag else f"ZDAYCZ-{hash(title_tag.text) % 10000}"
        title = title_tag.text.strip() if title_tag else "No title"
        summary = desc_tag.text.strip() if desc_tag else ""
        software = software_tag.text.strip() if software_tag else ""
        discovered = datetime.strptime(discovered_tag.text.strip(), "%Y-%m-%d") if discovered_tag else None
        
        results.append({
            "cve_id": cve_id,
            "title": title,
            "summary": summary,
            "vendors_products": [{"product": software}] if software else [],
            "first_seen": discovered,
            "disclosed": discovered,
            "refs": [{"source": "Zero-day.cz", "url": title_tag["href"]}] if title_tag else [],
            "tags": ["Zero-day.cz"]
        })
    return results

def upsert_zero_day_cz(cur, kev_cves=None, zdi_cves=None, limit=5):
    kev_cves = kev_cves or {}
    zdi_cves = zdi_cves or []

    vulns = fetch_zdcz(limit)
    for v in vulns:
        # Marquer KEV
        v = mark_exploited_with_kev(v, kev_cves)
        # Marquer ZDI si correspondance
        if v["cve_id"] in zdi_cves:
            v["exploited_in_wild"] = True
            v["refs"].append({"source": "ZDI", "url": f"https://www.zerodayinitiative.com/advisories/{v['cve_id']}"})

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
            Json(v.get("vendors_products", [])),
            v.get("first_seen"),
            v.get("disclosed"),
            v.get("cve_id"),
            v.get("exploited_in_wild", False),
            Json(v.get("refs", [])),
            v.get("tags", [])
        ))
        vuln_id = cur.fetchone()[0]
        print(f"[Zero-day.cz] {v['cve_id']} inséré/mis à jour (id {vuln_id})")
