import requests
from bs4 import BeautifulSoup
from datetime import datetime
from psycopg2.extras import Json

class ZDCZCollector:
    BASE_URL = (
        "https://www.zero-day.cz/database/?set_filter=Y"
        "&arrFilter_pf[SEARCH]="
    )

    def __init__(self, year_from: int, year_to: int):
        self.year_from = year_from
        self.year_to = year_to
        self.vulnerabilities = []

    def fetch(self):
        url = (
            f"{self.BASE_URL}"
            f"&arrFilter_pf%5BYEAR_FROM%5D={self.year_from}"
            f"&arrFilter_pf%5BYEAR_TO%5D={self.year_to}"
        )
        print(f"[ZDCZ] Collecte de {self.year_from} à {self.year_to}...")
        r = requests.get(url)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        issues = soup.select("#issuew_wrap .issue")
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

            self.vulnerabilities.append({
                "cve_id": cve_id,
                "title": title,
                "summary": summary,
                "configurations": [{"source": "Zero-day.cz","product": software}] if software else [],
                "first_seen": discovered,
                "disclosed": discovered,
                "refs": [{"source": "Zero-day.cz", "url": title_tag["href"]}] if title_tag else [],
                "tags": ["Zero-day.cz"]
            })
        return self.vulnerabilities

    def upsert(self, cur, kev_cves=None, epss_cves=None, zdi_cves=None):
        kev_cves = kev_cves or {}
        epss_cves = epss_cves or {}
        zdi_cves = zdi_cves or []

        for v in self.vulnerabilities:
            # Ajout de références croisées avec ZDI si applicable
            if v.get("cve_id") in zdi_cves:
                v.setdefault("refs", []).append({
                    "source": "ZDI",
                    "url": f"https://www.zerodayinitiative.com/advisories/{v['cve_id']}"
                })

            # Nettoyage et suppression des doublons dans vendor_product
            vendor_products = v.get("vendor_product", [])
            seen = set()
            unique_vendor_products = []
            for vp in vendor_products:
                key = (vp.get("vendor"), vp.get("product"))
                if key not in seen:
                    seen.add(key)
                    unique_vendor_products.append(vp)
            v["vendor_product"] = unique_vendor_products

            # Exécution de l'upsert
            cur.execute("""
                INSERT INTO vulnerabilities (
                    canonical_id, title, summary, vendor_product, configurations,
                    first_seen, disclosed, published_nvd, cve_id,
                    exploited_in_wild, kev_added, kev_latency_days,
                    cvss2_base_score, cvss2_vector,
                    cvss3_base_score, cvss3_vector,
                    cvss4_base_score, cvss4_vector, 
                    epss_score, epss_percentile,
                    refs, tags
                )
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (canonical_id) DO UPDATE SET
                    refs=EXCLUDED.refs,
                    tags=EXCLUDED.tags,
                    updated_at=NOW()
                RETURNING vuln_id
            """, (
                v["cve_id"],
                v.get("title"),
                v.get("summary"),
                Json(v.get("vendor_product", [])),   # JSONB sans doublons
                Json(v.get("configurations", [])),
                v.get("first_seen"),
                v.get("disclosed"),
                v.get("published_nvd"),
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
                v.get("epss_score"),
                v.get("epss_percentile"),
                Json(v.get("refs", [])),
                v.get("tags", [])
            ))

            vuln_id = cur.fetchone()[0]
            print(f"[Zero-day.cz] {v['cve_id']} inséré/mis à jour (id {vuln_id})")
