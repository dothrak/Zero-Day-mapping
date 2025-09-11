import gzip
import json
import requests
from datetime import datetime
from pathlib import Path
from collections import defaultdict

class NVDEnricher:
    def __init__(self):
        self.nvd_cache_by_year = {}

    def download_nvd_json(self, year: int):
        """Télécharge le fichier NVD 2.0 pour une année donnée si nécessaire."""
        filename = Path(f"nvdcve-2.0-{year}.json.gz")
        if filename.exists():
            return filename

        url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
        print(f"[NVD] Téléchargement du fichier {url} ...")
        r = requests.get(url, stream=True)
        r.raise_for_status()
        with open(filename, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"[NVD] Téléchargement terminé : {filename}")
        return filename

    def load_nvd_json(self, year: int):
        """Charge et indexe le fichier NVD pour une année donnée."""
        if year in self.nvd_cache_by_year:
            return self.nvd_cache_by_year[year]

        filename = self.download_nvd_json(year)
        print(f"[NVD] Chargement du fichier {filename}...")
        with gzip.open(filename, "rt", encoding="utf-8") as f:
            data = json.load(f)

        cve_index = {}
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln["cve"]["id"]
            cve_index[cve_id] = vuln["cve"]
        print(f"[NVD] {len(cve_index)} CVE indexées pour {year}.")
        self.nvd_cache_by_year[year] = cve_index
        return cve_index

    def enrich(self, vuln: dict):
        """Enrichit une vulnérabilité avec les données NVD si disponibles."""
        cve_id = vuln.get("cve_id")
        if not cve_id or not cve_id.startswith("CVE-"):
            return vuln

        try:
            year = int(cve_id.split("-")[1])
        except (IndexError, ValueError):
            return vuln

        nvd_cache = self.load_nvd_json(year)
        nvd_vuln = nvd_cache.get(cve_id)
        if not nvd_vuln:
            vuln["nvd"] = None
            return vuln

        vuln["nvd"] = nvd_vuln

        try:
            # Dates
            published_str = nvd_vuln.get("published")
            vuln["published_nvd"] = (
                datetime.strptime(published_str, "%Y-%m-%dT%H:%M:%S.%f")
                if published_str else None
            )

            # Scores CVSS
            metrics = nvd_vuln.get("metrics", {})
            if "cvssMetricV2" in metrics:
                cvss2 = metrics["cvssMetricV2"][0]["cvssData"]
                vuln["cvss2_base_score"] = cvss2.get("baseScore")
                vuln["cvss2_vector"] = cvss2.get("vectorString")

            if "cvssMetricV31" in metrics:
                cvss3 = metrics["cvssMetricV31"][0]["cvssData"]
                vuln["cvss3_base_score"] = cvss3.get("baseScore")
                vuln["cvss3_vector"] = cvss3.get("vectorString")

            if "cvssMetricV40" in metrics:
                cvss4 = metrics["cvssMetricV40"][0]["cvssData"]
                vuln["cvss4_base_score"] = cvss4.get("baseScore")
                vuln["cvss4_vector"] = cvss4.get("vectorString")

        except Exception as e:
            print(f"[NVD] Erreur parsing CVE {cve_id}: {e}")

        return vuln
