import requests

def fetch_circl(cve_id):
    """Récupère les détails d’un CVE depuis CIRCL"""
    url = f"https://cvepremium.circl.lu/api/cve/{cve_id}"
    r = requests.get(url)
    if r.status_code == 200:
        return r.json()
    return None

def enrich_with_circl(cur, vuln_id, circl_data):
    """Associe un CVE existant avec CIRCL"""
    cve_id = circl_data.get("id")
    cur.execute("""
        INSERT INTO source_mappings (vuln_id, source_name, source_id, url)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT DO NOTHING
    """, (
        vuln_id,
        "CIRCL",
        cve_id,
        f"https://cve.circl.lu/cve/{cve_id}"
    ))
    print(f"[CIRCL] {cve_id} enrichi (id {vuln_id})")
