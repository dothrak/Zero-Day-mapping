import requests

class EPSSEnricher:
    def __init__(self):
        self.cache = {}  # {cve_id: (epss_score, epss_percentile)}

    def fetch(self, cve_id: str):
        """Récupère le score EPSS et percentile pour une CVE via l'API FIRST."""
        if cve_id in self.cache:
            return self.cache[cve_id]

        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        try:
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            if data.get("data"):
                epss_entry = data["data"][0]
                epss_score = float(epss_entry.get("epss"))
                epss_percentile = float(epss_entry.get("percentile"))
                self.cache[cve_id] = (epss_score, epss_percentile)
                return epss_score, epss_percentile
        except Exception as e:
            print(f"[EPSS] Impossible de récupérer EPSS pour {cve_id}: {e}")

        self.cache[cve_id] = (None, None)
        return None, None

    def enrich(self, vuln: dict) -> dict:
        """Ajoute epss_score et epss_percentile à la vulnérabilité."""
        cve_id = vuln.get("cve_id")
        if not cve_id:
            return vuln
        epss_score, epss_percentile = self.fetch(cve_id)
        vuln["epss_score"] = epss_score
        vuln["epss_percentile"] = epss_percentile
        return vuln
