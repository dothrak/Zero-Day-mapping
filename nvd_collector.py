import gzip
import json
import requests
from datetime import datetime
from pathlib import Path


def download_nvd_json(year: int, dest: Path):
    """Télécharge le fichier NVD 2.0 pour une année donnée si nécessaire."""
    if dest.exists():
        return
    url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
    print(f"[NVD] Téléchargement du fichier {url} ...")
    r = requests.get(url, stream=True)
    r.raise_for_status()
    with open(dest, "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            f.write(chunk)
    print(f"[NVD] Téléchargement terminé : {dest}")


def load_nvd_json_by_year(year: int) -> dict:
    """
    Charge et indexe le fichier NVD 2.0 d'une année donnée.
    Retourne un dict {cve_id: vuln_data}.
    """
    filename = Path(f"nvdcve-2.0-{year}.json.gz")
    download_nvd_json(year, filename)
    print(f"[NVD] Chargement du fichier {filename}...")
    with gzip.open(filename, "rt", encoding="utf-8") as f:
        data = json.load(f)
    cve_index = {}
    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln["cve"]["id"]
        cve_index[cve_id] = vuln["cve"]
    print(f"[NVD] {len(cve_index)} CVE indexées pour {year}.")
    return cve_index


def enrich_with_nvd_from_cache(v: dict, nvd_cache: dict) -> dict:
    """
    Enrichit une vulnérabilité `v` avec les données NVD si elle est trouvée dans `nvd_cache`.
    """
    cve_id = v.get("cve_id")
    if not cve_id or not cve_id.startswith("CVE-"):
        return v

    vuln = nvd_cache.get(cve_id)
    if not vuln:
        # print(f"[NVD] CVE {cve_id} non publiée dans la NVD")
        v["nvd"] = None
        return v

    v["nvd"] = vuln

    try:
        # Dates
        published_str = vuln.get("published")
        v["published_nvd"] = (
            datetime.strptime(published_str, "%Y-%m-%dT%H:%M:%S.%f")
            if published_str else None
        )

        # Scores CVSS
        metrics = vuln.get("metrics", {})
        if "cvssMetricV2" in metrics:
            cvss2 = metrics["cvssMetricV2"][0]["cvssData"]
            v["cvss2_base_score"] = cvss2.get("baseScore")
            v["cvss2_vector"] = cvss2.get("vectorString")

        if "cvssMetricV31" in metrics:
            cvss3 = metrics["cvssMetricV31"][0]["cvssData"]
            v["cvss3_base_score"] = cvss3.get("baseScore")
            v["cvss3_vector"] = cvss3.get("vectorString")

        if "cvssMetricV40" in metrics:
            cvss4 = metrics["cvssMetricV40"][0]["cvssData"]
            v["cvss4_base_score"] = cvss4.get("baseScore")
            v["cvss4_vector"] = cvss4.get("vectorString")

    except Exception as e:
        print(f"[NVD] Erreur parsing CVE {cve_id}: {e}")

    return v
