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
    Gère toutes les versions CVSS disponibles : v2, v3.0, v3.1, v4.0.
    """
    cve_id = v.get("cve_id")
    if not cve_id or not cve_id.startswith("CVE-"):
        return v

    vuln = nvd_cache.get(cve_id)
    if not vuln:
        v["nvd"] = None
        return v

    v["nvd"] = vuln

    try:
        # Date de publication
        published_str = vuln.get("published")
        v["published_nvd"] = (
            datetime.strptime(published_str, "%Y-%m-%dT%H:%M:%S.%f")
            if published_str else None
        )

        # Fonction utilitaire pour récupérer le score "Primary" si présent
        def get_primary_score(metric_list):
            for m in metric_list:
                if m.get("type") == "Primary":
                    return m["cvssData"]
            return metric_list[0]["cvssData"] if metric_list else None

        metrics = vuln.get("metrics", {})

        # CVSS v2
        if "cvssMetricV2" in metrics:
            cvss2 = get_primary_score(metrics["cvssMetricV2"])
            if cvss2:
                v["cvss2_base_score"] = cvss2.get("baseScore")
                v["cvss2_vector"] = cvss2.get("vectorString")
                print(f"[DEBUG] {cve_id} CVSS2: {v['cvss2_base_score']} {v['cvss2_vector']}")

        # CVSS v3.0
        if "cvssMetricV30" in metrics:
            cvss30 = get_primary_score(metrics["cvssMetricV30"])
            if cvss30:
                v["cvss3_base_score"] = cvss30.get("baseScore")
                v["cvss3_vector"] = cvss30.get("vectorString")
                print(f"[DEBUG] {cve_id} CVSS3.0: {v['cvss3_base_score']} {v['cvss3_vector']}")

        # CVSS v3.1
        if "cvssMetricV31" in metrics:
            cvss31 = get_primary_score(metrics["cvssMetricV31"])
            if cvss31:
                v["cvss3_base_score"] = cvss31.get("baseScore")
                v["cvss3_vector"] = cvss31.get("vectorString")
                print(f"[DEBUG] {cve_id} CVSS3.1: {v['cvss3_base_score']} {v['cvss3_vector']}")

        # CVSS v4.0
        if "cvssMetricV40" in metrics:
            cvss4 = get_primary_score(metrics["cvssMetricV40"])
            if cvss4:
                v["cvss4_base_score"] = cvss4.get("baseScore")
                v["cvss4_vector"] = cvss4.get("vectorString")
                print(f"[DEBUG] {cve_id} CVSS4: {v['cvss4_base_score']} {v['cvss4_vector']}")

    except Exception as e:
        print(f"[NVD] Erreur parsing CVE {cve_id}: {e}")

    return v

