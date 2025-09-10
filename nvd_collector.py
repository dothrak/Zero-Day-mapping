import requests
from psycopg2.extras import Json

def fetch_nvd(start_index=0, results_per_page=50, limit=10):
    """
    Récupère des CVE depuis l’API NVD filtrées sur l'année 2025.
    start_index : index de départ pour la pagination
    results_per_page : nombre de résultats par requête API
    limit : nombre total de CVE à récupérer pour les tests
    """
    url = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?startIndex={start_index}&resultsPerPage={results_per_page}"
    )
    r = requests.get(url)
    r.raise_for_status()
    vulns = r.json().get("vulnerabilities", [])
    
    # Filtrer uniquement les CVE de 2025
    filtered = [v for v in vulns if v.get("cve", {}).get("id", "").startswith("CVE-2025")]
    return filtered[:limit]  # limite pour test

def upsert_nvd_vulns(cur, cve_data):
    """Insère ou met à jour une vulnérabilité NVD dans la DB"""
    cve_id = cve_data.get("cve", {}).get("id")
    title = cve_data.get("cve", {}).get("descriptions", [{}])[0].get("value")
    summary = title
    cvss = cve_data.get("cve", {}).get("metrics", {})

    # Récupération des vendors/products
    vendors_products = []
    configs = cve_data.get("cve", {}).get("configurations", [])
    for conf in configs:
        for node in conf.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                vendors_products.append({"cpe": cpe_match.get("criteria")})

    cur.execute("""
        INSERT INTO vulnerabilities (canonical_id, title, summary, cve_id, cvss, vendors_products, refs)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (canonical_id)
        DO UPDATE SET
            title = EXCLUDED.title,
            summary = EXCLUDED.summary,
            cvss = EXCLUDED.cvss,
            vendors_products = EXCLUDED.vendors_products,
            updated_at = now()
        RETURNING vuln_id
    """, (
        cve_id,
        title,
        summary,
        cve_id,
        Json(cvss),
        Json(vendors_products),
        Json([{"source": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"}])
    ))
    vuln_id = cur.fetchone()[0]
    print(f"[NVD] {cve_id} inséré/mis à jour (id {vuln_id})")
    return vuln_id
