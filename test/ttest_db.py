import psycopg2
from psycopg2.extras import Json

conn = psycopg2.connect(
    dbname="zerodaydb_test",
    user="testuser",
    password="testpass",
    host="localhost",
    port=5433
)
cur = conn.cursor()

# Exemple : insérer une CVE
cur.execute(
    """
    INSERT INTO vulnerabilities (canonical_id, cve_id, title, summary)
    VALUES (%s, %s, %s, %s)
    RETURNING vuln_id
    """,
    ("CVE-TEST-0001", "CVE-2025-5778", "Test vuln", "Résumé test")
)
vuln_id = cur.fetchone()[0]
conn.commit()
print("Inserted vuln_id:", vuln_id)

cur.close()
conn.close()
