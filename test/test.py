from pathlib import Path
from nvd_collector import download_nvd_json, load_nvd_json_by_year, enrich_with_nvd_from_cache
from datetime import datetime

# Échantillon de CVE
sample_cves = [
    "CVE-2025-5778",
    "CVE-2024-27074",
    "CVE-2023-51612",
    "CVE-2022-43645"
]

# --- Charger les fichiers NVD nécessaires ---
years = set(int(cve.split("-")[1]) for cve in sample_cves)
nvd_cache = {}
for year in years:
    nvd_cache.update(load_nvd_json_by_year(year))

# --- Débogage ---
for cve_id in sample_cves:
    v = {"cve_id": cve_id}
    print("\n=== Traitement de", cve_id, "===")
    v = enrich_with_nvd_from_cache(v, nvd_cache)
    print("Résultat complet NVD:", v.get("nvd"))
    print("CVSS2:", v.get("cvss2_base_score"), v.get("cvss2_vector"))
    print("CVSS3:", v.get("cvss3_base_score"), v.get("cvss3_vector"))
    print("CVSS4:", v.get("cvss4_base_score"), v.get("cvss4_vector"))
