import requests

CIRCL_API = "https://cve.circl.lu/api/cve/{}"

def enrich_with_circl(v):
    """
    Ajoute les informations CIRCL à une vulnérabilité, y compris EPSS, vecteurs, versions.
    """
    cve_id = v.get("cve_id")
    if not cve_id or not cve_id.startswith("CVE-"):
        return v

    url = CIRCL_API.format(cve_id)
    try:
        r = requests.get(url, timeout=20)
        if r.status_code == 404:
            print(f"[CIRCL] CVE {cve_id} non trouvée")
            return v
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        print(f"[CIRCL] Erreur pour {cve_id}: {e}")
        return v

    if not data:
        return v

    # Scores CVSS (si manquant dans NVD)
    if "cvss" in data:
        v["cvss2_base_score"] = v.get("cvss2_base_score") or data.get("cvss")
        v["cvss3_base_score"] = v.get("cvss3_base_score") or data.get("cvss3")
        v["cvss4_base_score"] = v.get("cvss4_base_score") or data.get("cvss4")

    # EPSS
    epss = data.get("epss")
    if epss:
        v["epss_score"] = epss.get("score")
        v["epss_percentile"] = epss.get("percentile")

    # On peut ajouter d'autres infos comme versions affectées si besoin
    affected = data.get("vulnerable_configuration")
    if affected:
        v["affected_config"] = affected

    return v
