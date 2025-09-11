import requests
from datetime import datetime

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

class KEVEnricher:
    def __init__(self):
        self.kev_cves = {}

    def fetch(self):
        """Récupère la liste des CVE connues comme exploitées selon CISA KEV."""
        try:
            resp = requests.get(CISA_KEV_URL)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            print(f"[KEV] Erreur récupération KEV : {e}")
            return {}

        kev_cves = {}
        for v in data.get("vulnerabilities", []):
            cve_id = v.get("cveID")
            date_added = v.get("dateAdded")
            if cve_id and date_added:
                try:
                    date_added = datetime.strptime(date_added, "%Y-%m-%d")
                except Exception:
                    date_added = None
                kev_cves[cve_id] = date_added

        self.kev_cves = kev_cves
        print(f"[KEV] {len(self.kev_cves)} CVE récupérées depuis KEV")
        return self.kev_cves

    def enrich(self, vuln: dict) -> dict:
        """Marque la vulnérabilité comme exploitée si elle est dans KEV et calcule kev_added / kev_latency_days."""
        if 'refs' not in vuln:
            vuln['refs'] = []

        cve_id = vuln.get("cve_id") or vuln.get("canonical_id")
        kev_date = self.kev_cves.get(cve_id)

        if kev_date:
            vuln["exploited_in_wild"] = True

            # Vérifier si une ref KEV existe déjà
            has_kev_ref = any(r.get("source") == "CISA KEV" for r in vuln["refs"])
            if not has_kev_ref:
                vuln["refs"].append({
                    "source": "CISA KEV",
                    "url": f"https://www.cisa.gov/known-exploited-vulnerabilities/cve/{cve_id}",
                    "date_added": kev_date.strftime("%Y-%m-%d")
                })

            # Stocker kev_added comme datetime
            vuln["kev_added"] = kev_date

            # Calculer kev_latency_days
            if vuln.get("first_seen"):
                try:
                    vuln["kev_latency_days"] = (kev_date - vuln["first_seen"]).days
                except Exception:
                    vuln["kev_latency_days"] = None
        else:
            vuln["exploited_in_wild"] = vuln.get("exploited_in_wild", False)

        return vuln

    def compute_dates(self, vuln: dict) -> dict:
        """S'assure que kev_added et kev_latency_days sont calculés à partir des refs existantes."""
        if not vuln.get("exploited_in_wild"):
            return vuln

        kev_dates = []
        has_kev_ref = False
        for r in vuln.get("refs", []):
            if r.get("source") == "CISA KEV":
                has_kev_ref = True
                if r.get("date_added"):
                    try:
                        kev_dates.append(datetime.fromisoformat(r["date_added"]))
                    except ValueError:
                        pass

        if not has_kev_ref:
            today = datetime.now().date().isoformat()
            vuln.setdefault("refs", []).append({
                "source": "CISA KEV",
                "url": f"https://www.cisa.gov/known-exploited-vulnerabilities/cve/{vuln['cve_id']}",
                "date_added": today
            })
            kev_dates.append(datetime.fromisoformat(today))

        kev_added = min(kev_dates) if kev_dates else datetime.now()
        vuln["kev_added"] = kev_added

        if kev_added and vuln.get("first_seen"):
            vuln["kev_latency_days"] = (kev_added - vuln["first_seen"]).days

        return vuln
