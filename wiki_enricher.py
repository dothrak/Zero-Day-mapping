import asyncio
import aiohttp
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2 import pool

DB_CONFIG = {
    "dbname": "zerodaydb",
    "user": "postgres",
    "password": "postgres",
    "host": "localhost",
    "port": 5432
}

WIKI_API = "https://en.wikipedia.org/w/api.php"
HEADERS = {"User-Agent": "ZeroDayWikiBot/1.0"}

BATCH_SIZE = 50
MAX_CONCURRENCY = 8  # adapté à ton VPS 4 cœurs / 8 Go
POOL_SIZE = 8  # nombre de connexions dans le pool

TYPE_KEYWORDS = {
    "Security": ["antivirus", "firewall", "ids", "ips", "malware", "endpoint protection", "security", "siem", "threat", "detection"],
    "Web Browser": ["browser", "internet", "chrome", "firefox", "edge", "opera", "safari"],
    "Database": ["database", "dbms", "sql", "nosql", "big data", "data warehouse", "oracle", "mysql", "postgres", "mongodb"],
    "Operating System": ["os", "linux", "windows", "macos", "unix", "ubuntu", "debian", "red hat", "fedora"],
    "Programming/Dev": ["sdk", "framework", "ide", "compiler", "programming language", "api", "library", "toolkit", "dev"],
    "Productivity": ["office", "productivity", "spreadsheet", "word processor", "presentation", "calendar", "email client", "notes"],
    "Graphics/Multimedia": ["graphics", "design", "photo", "video", "multimedia", "3d", "cad", "animation", "audio", "imaging", "rendering"],
    "Networking": ["network", "vpn", "proxy", "router", "switch", "load balancer", "firewall", "dns", "tcp", "udp"],
    "Virtualization": ["virtualization", "hypervisor", "vmware", "docker", "container", "kvm", "qemu", "vagrant"],
    "Cloud": ["cloud", "aws", "azure", "gcp", "openstack", "iaas", "saas", "paas", "serverless", "cloud platform"],
    "IoT/Embedded": ["iot", "embedded", "firmware", "arduino", "raspberry pi", "sensor", "microcontroller"],
    "Business": ["crm", "erp", "accounting", "finance", "hr", "management", "business", "payroll", "invoicing"],
    "Education": ["elearning", "education", "learning management", "training", "school", "university", "course"],
    "Media Player/Streaming": ["media player", "music", "audio", "video streaming", "streaming", "podcast"],
    "Email/Messaging": ["email", "mail server", "antispam", "messaging", "chat", "communication", "teams"],
    "Backup/Storage": ["backup", "storage", "sync", "file sharing", "cloud storage", "nas", "datastore"],
    "Monitoring/Logging": ["monitoring", "logging", "observability", "siem", "metrics", "tracing", "dashboard"],
    "Analytics/BI": ["analytics", "business intelligence", "reporting", "etl", "dashboard", "big data"],
    "VR/AR/Gaming": ["virtual reality", "augmented reality", "game", "gamedev", "unity", "unreal engine", "simulation"],
    "Scientific/Engineering": ["scientific", "mathematics", "statistics", "simulation", "modeling", "engineering", "lab"],
    "Mobile App": ["mobile", "android", "ios", "cross-platform app", "apk", "app store", "play store"],
    "Web App": ["web app", "saas", "website", "web platform", "web service"],
    "Automation/CI-CD": ["ci", "cd", "jenkins", "automation", "devops", "pipeline", "gitlab"],
    "API/Integration": ["api", "rest", "soap", "integration", "connector", "webhook", "sdk"]
}

PLATFORM_KEYWORDS = {
    "Windows": ["windows"],
    "Linux": ["linux", "ubuntu", "debian", "fedora", "red hat", "centos"],
    "macOS": ["macos", "macintosh"],
    "Android": ["android"],
    "iOS": ["ios"],
    "Web": ["web", "saas", "cloud platform"],
    "Cross-platform": ["cross-platform", "java", "electron", "dotnet"]
}

def infer_type_and_platform(title, vendor, categories):
    all_text = " ".join([title, vendor] + categories).lower()
    software_types = [t for t, keywords in TYPE_KEYWORDS.items() if any(k.lower() in all_text for k in keywords)]
    software_type = ", ".join(software_types) if software_types else "Other"
    platform = "Cross-platform"
    for p, keywords in PLATFORM_KEYWORDS.items():
        if any(k.lower() in all_text for k in keywords):
            platform = p
            break
    return software_type, platform

async def safe_get(session, url, params):
    async with session.get(url, params={k:str(v) for k,v in params.items()}, headers=HEADERS) as r:
        r.raise_for_status()
        return await r.json()

async def search_wikipedia(session, query):
    params = {"action":"query","list":"search","srsearch":query,"srlimit":1,"format":"json"}
    data = await safe_get(session, WIKI_API, params)
    results = data.get("query", {}).get("search", [])
    return results[0]["title"] if results else None

async def get_wiki_details(session, title):
    params = {"action":"query","prop":"categories|extracts","titles":title,"exintro":True,"explaintext":True,"cllimit":50,"format":"json"}
    data = await safe_get(session, WIKI_API, params)
    pages = data.get("query", {}).get("pages", {})
    page = next(iter(pages.values()))
    extract = page.get("extract", "")
    categories = [c["title"].replace("Category:","") for c in page.get("categories",[])]
    url = f"https://en.wikipedia.org/wiki/{title.replace(' ','_')}"
    return extract, categories, url

async def enrich_row(session, sem, row, conn_pool):
    async with sem:
        conn = conn_pool.getconn()
        try:
            cur = conn.cursor()
            query = f"{row['vendor']} {row['product']}"
            title = await search_wikipedia(session, query)
            if not title:
                print(f"[WIKI] ❌ Aucun résultat pour {query}")
                cur.execute("""
                    UPDATE softwares
                    SET last_enriched = NOW(),
                        wiki_checked = TRUE
                    WHERE software_id = %s
                """, (row["software_id"],))
                conn.commit()
                return

            print(f"[WIKI] ✅ Page trouvée : {title}")
            summary, categories, url = await get_wiki_details(session, title)
            software_type, platform = infer_type_and_platform(title, row['vendor'], categories)

            cur.execute("""
                UPDATE softwares
                SET titles = %s,
                    wiki_page = %s,
                    wiki_summary = %s,
                    categories = %s,
                    type = %s,
                    platform = %s,
                    last_enriched = NOW(),
                    wiki_checked = TRUE
                WHERE software_id = %s
            """, ([title], url, summary, categories, software_type, platform, row["software_id"]))
            conn.commit()
        finally:
            cur.close()
            conn_pool.putconn(conn)

async def process_batch(rows, conn_pool, batch_num, total_batches):
    print(f"\n🚀 Traitement du lot {batch_num}/{total_batches} ({len(rows)} entrées)")
    sem = asyncio.Semaphore(MAX_CONCURRENCY)
    async with aiohttp.ClientSession() as session:
        tasks = [enrich_row(session, sem, row, conn_pool) for row in rows]
        await asyncio.gather(*tasks)

async def main():
    # Création du pool
    conn_pool = psycopg2.pool.ThreadedConnectionPool(1, POOL_SIZE, **DB_CONFIG)

    # Nombre total d'entrées à traiter
    conn = conn_pool.getconn()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT COUNT(*) AS total FROM softwares WHERE type IS NULL;")
    total_remaining = cur.fetchone()["total"]
    cur.close()
    conn_pool.putconn(conn)

    if total_remaining == 0:
        print("✅ Tout est déjà enrichi.")
        conn_pool.closeall()
        return

    total_batches = (total_remaining // BATCH_SIZE) + 1
    batch_num = 0

    while True:
        conn = conn_pool.getconn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM softwares WHERE wiki_checked IS NULL LIMIT %s;", (BATCH_SIZE,))
        rows = cur.fetchall()
        cur.close()
        conn_pool.putconn(conn)

        if not rows:
            print("✅ Plus rien à enrichir.")
            break

        batch_num += 1
        await process_batch(rows, conn_pool, batch_num, total_batches)
        print("⏳ Pause 5s avant le prochain lot...")
        await asyncio.sleep(5)

    conn_pool.closeall()

if __name__ == "__main__":
    asyncio.run(main())
