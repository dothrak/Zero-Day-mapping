import requests
from datetime import datetime

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_kev():
    """
    Récupère la liste des CVE connues comme exploitées selon CISA KEV.
    Retourne un dictionnaire {cve_id: date_added}.
    """
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
            # normaliser en datetime
            try:
                date_added = datetime.strptime(date_added, "%Y-%m-%d")
            except Exception:
                date_added = None
            kev_cves[cve_id] = date_added
    print(f"[KEV] {len(kev_cves)} CVE récupérées depuis KEV")
    return kev_cves


def mark_exploited_with_kev(vuln, kev_cves):
    """
    Vérifie si une vulnérabilité est listée dans KEV et met à jour son statut.
    vuln : dict avec au moins 'cve_id' et 'refs' (liste)
    """
    if 'refs' not in vuln:
        vuln['refs'] = []
    cve_id = vuln.get("cve_id") or vuln.get("canonical_id")
    if cve_id in kev_cves:
        vuln["exploited_in_wild"] = True
        vuln["refs"].append({
            "source": "CISA KEV",
            "url": f"https://www.cisa.gov/known-exploited-vulnerabilities/cve/{cve_id}",
            "date_added": kev_cves[cve_id].strftime("%Y-%m-%d") if kev_cves[cve_id] else None
        })
    else:
        vuln["exploited_in_wild"] = vuln.get("exploited_in_wild", False)
    return vuln


def filter_kev_only(vulns, kev_cves):
    """
    Filtre une liste de vulnérabilités pour ne garder que celles présentes dans KEV
    """
    return [mark_exploited_with_kev(v, kev_cves) for v in vulns if (v.get("cve_id") in kev_cves or v.get("canonical_id") in kev_cves)]


if __name__ == "__main__":
    kev = fetch_kev()
    print(list(kev.items())[:5])