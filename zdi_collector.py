import requests
from bs4 import BeautifulSoup
from datetime import datetime
from psycopg2.extras import Json

class ZDICollector:
    BASE_URL = "https://www.zerodayinitiative.com/advisories/published/{year}/"

    def __init__(self, year_from: int, year_to: int):
        self.year_from = year_from
        self.year_to = year_to
        self.vulnerabilities = []

    def fetch(self):
        for year in range(self.year_from, self.year_to + 1):
            url = self.BASE_URL.format(year=year)
            print(f"[ZDI] Collecte {year} ...")
            r = requests.get(url)
            r.raise_for_status()
            soup = BeautifulSoup(r.text, "html.parser")
            advisories = soup.select("tr#publishedAdvisories")
            for row in advisories:
                cols = row.find_all("td")
                if len(cols) < 8:
                    continue
                zdi_id = cols[0].text.strip()
                vendor = cols[2].text.strip()
                cve_id = cols[3].text.strip() or zdi_id
                disclosed = datetime.strptime(cols[5].text.strip(), "%Y-%m-%d") if cols[5].text.strip() else None
                link_tag = cols[7].find("a")
                link = f"https://www.zerodayinitiative.com{link_tag['href']}" if link_tag else ""
                self.vulnerabilities.append({
                    "cve_id": cve_id,
                    "first_seen": disclosed,
                    "disclosed": disclosed,
                    "refs": [{"source": "ZDI", "url": link}] if link else [],
                    "tags": ["ZDI"]
                })
        return self.vulnerabilities

    def upsert(self, cur, kev_cves=None, zdcz_cves=None):
        kev_cves = kev_cves or {}
        zdcz_cves = zdcz_cves or []
        for v in self.vulnerabilities:
            if v.get("cve_id") in zdcz_cves:
                v.setdefault("refs", []).append({
                    "source": "Zero-day.cz",
                    "url": f"https://www.zero-day.cz/database/{v['cve_id']}"
                })
            cur.execute("""
                INSERT INTO vulnerabilities (
                    canonical_id, title, summary, vendors_products,
                    first_seen, disclosed, cve_id,
                    exploited_in_wild, kev_added, kev_latency_days,
                    cvss2_base_score, cvss2_vector,
                    cvss3_base_score, cvss3_vector,
                    cvss4_base_score, cvss4_vector,
                    refs, tags
                )
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (canonical_id) DO UPDATE SET
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
                v.get("kev_added"),
                v.get("kev_latency_days"),
                v.get("cvss2_base_score"),
                v.get("cvss2_vector"),
                v.get("cvss3_base_score"),
                v.get("cvss3_vector"),
                v.get("cvss4_base_score"),
                v.get("cvss4_vector"),
                Json(v.get("refs", [])),
                v.get("tags", [])
            ))
            vuln_id = cur.fetchone()[0]
            print(f"[ZDI] {v['cve_id']} inséré/mis à jour (id {vuln_id})")