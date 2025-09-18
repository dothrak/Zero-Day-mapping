import psycopg2
import json
import subprocess
import time
import re

# ---------------------- CONFIG ----------------------
DB_CONFIG = {
    "dbname": "zerodaydb",
    "user": "postgres",
    "password": "postgres",
    "host": "localhost",
    "port": 5432
}

BATCH_SIZE = 50

# Liste autorisée pour les fonctionnalités
ALLOWED_FUNCTIONS = [
    # ---------------------- Réseaux & télécom ----------------------
    "network management","routing","switching","firewall management","load balancing","vpn","proxy",
    "dhcp","dns","intrusion detection","intrusion prevention","traffic monitoring","bandwidth management",
    "qos","wireless access control","wifi management","network virtualization","wan optimization",
    "vpn client","vpn server","snmp monitoring","network logging","packet inspection","dns filtering",
    "ip management","port forwarding","vlan management","network segmentation","content delivery",
    "api gateway","firewall rules","ddos protection","routing protocol","nat management","network auditing",
    "network reporting","tcp/ip stack management","network troubleshooting","network simulation",
    
    # ---------------------- Sécurité & protection ----------------------
    "antivirus","anti-malware","endpoint protection","patch management","vulnerability scanning",
    "encryption","cryptography","single sign-on","identity management","multi-factor authentication",
    "siem","log management","data loss prevention","sandboxing","secure boot","trusted platform",
    "certificate management","pki","token management","access control","privilege management",
    "policy enforcement","security compliance","password management","security auditing",
    "threat intelligence","intrusion alerting","malware analysis","forensics","key management",
    "firewall","ids","ips","network security","application security","cloud security","mobile security",
    
    # ---------------------- Serveurs & infrastructure ----------------------
    "web server","mail server","database server","file server","print server","application server",
    "virtualization","hypervisor","container management","docker","kubernetes","cloud orchestration",
    "cloud provisioning","backup","disaster recovery","clustering","high availability","storage management",
    "configuration management","orchestration","monitoring","metrics","load balancing","vm provisioning",
    "system monitoring","service orchestration","resource allocation","job scheduling","container orchestration",
    "network orchestration","infra automation","devops tools","deployment","patch deployment","system reporting",
    
    # ---------------------- Applications & bureautique ----------------------
    "office suite","document editing","spreadsheet","presentation","crm","erp","project management",
    "task tracking","accounting","finance management","hr management","lms","elearning","cad","3d modeling",
    "image editing","photo retouching","video editing","rendering","audio processing","music production",
    "data visualization","dashboards","analytics","reporting","export","collaboration","whiteboard",
    "note taking","calendar management","time tracking","document management","workflow automation",
    
    # ---------------------- Développement & IT ops ----------------------
    "ide","code editor","version control","scm","ci/cd pipelines","build automation","testing","qa",
    "containerization","orchestration","api management","sdk","developer tools","scripting","automation",
    "monitoring","metrics","logging","debugging","profiling","code analysis","static analysis","dynamic analysis",
    "code review","dependency management","artifact repository","package management","build system",
    
    # ---------------------- Firmware & hardware ----------------------
    "device drivers","embedded system control","sensor management","iot device management","firmware update",
    "hardware acceleration","gpu management","storage controller","nic management","soc management",
    "peripheral management","usb","bluetooth","wifi","device provisioning","device monitoring","power management",
    "firmware patching","hardware diagnostics","bios management","chipset management","system board management",
    "hardware abstraction","fpga management","asic management","hardware security","sensor calibration",
    
    # ---------------------- Cloud & virtualisation ----------------------
    "iaas management","paas management","saas delivery","multi-cloud orchestration","cloud security",
    "casb","virtual networking","overlay networks","vm provisioning","monitoring","autoscaling",
    "resource pooling","cloud storage","cloud backup","cloud compliance","cloud reporting","cloud logging",
    "serverless management","function deployment","cloud api management","cloud auditing","cloud networking",
    
    # ---------------------- Intelligence & analyse de données ----------------------
    "machine learning","ai processing","big data processing","etl pipelines","analytics","reporting",
    "predictive analysis","anomaly detection","log correlation","data mining","data cleaning","data aggregation",
    "statistical analysis","forecasting","model training","model deployment","feature engineering","data labeling",
    "graph analysis","network analysis","pattern recognition","trend analysis","real-time analytics","batch processing",
    
    # ---------------------- Multimédia & communication ----------------------
    "messaging","chat","email client","video conferencing","voip","telephony","streaming audio","streaming video",
    "media encoding","media decoding","collaboration","whiteboard","screen sharing","file sharing","audio editing",
    "video processing","live streaming","media management","content creation","digital signage","media distribution",
    
    # ---------------------- Maintenance & support ----------------------
    "remote management","remote access","troubleshooting","diagnostic tools","monitoring","alerting",
    "configuration backup","automated remediation","logging","auditing","report generation","incident management",
    "ticketing system","service desk","support automation","patch deployment","system update","version control",
    "health monitoring","performance tuning","resource monitoring","capacity planning","maintenance scheduling",
    
    # ---------------------- IoT & systèmes embarqués ----------------------
    "sensor management","device control","embedded analytics","real-time monitoring","actuator control",
    "firmware deployment","iot communication","mqtt management","coap management","zigbee management",
    "bluetooth management","edge computing","edge analytics","iot provisioning","iot security","iot logging",
    
    # ---------------------- Divers / autres ----------------------
    "authentication","authorization","logging","monitoring","api integration","sdk integration","workflow automation",
    "reporting automation","data synchronization","data replication","service orchestration","platform integration",
    "hardware monitoring","power management","temperature management","performance analysis","system auditing",
    "compliance management","user management","license management","subscription management","billing",
    "payment processing","digital rights management","content management","notification management","event management",
    "alerting","task automation","document conversion","media conversion","data export","data import","data ingestion",
    "search indexing","search engine","recommendation engine","ad management","marketing automation","crm analytics",
    "analytics dashboard","business intelligence","predictive maintenance","quality assurance","testing automation",
    "simulation","emulation","profiling","code instrumentation","debugging automation","network simulation",
    "threat modeling","risk assessment","penetration testing","vulnerability management",
    
    # ---------------------- Divertissement & Gaming ----------------------
    "gaming platform","game engine","3d rendering","physics simulation","ai-driven npc","multiplayer support",
    "online matchmaking","leaderboards","achievements","trophies","controller support","joystick support",
    "haptic feedback","audio effects","sound engine","video effects","shader engine","streaming gameplay",
    "virtual reality","augmented reality","mixed reality","in-game chat","in-game messaging",
    "downloadable content","content packs","mods","in-app purchases","microtransactions","game analytics",
    "live events","seasonal content","user-generated content","level editor","map editor","cinematic cutscenes",
    "storytelling","narrative engine","procedural content generation","physics engine","collision detection",
    "animation engine","rigging","particle system","ai opponents","pathfinding","multiplayer server hosting",
    "game achievements","scoring system","controller mapping","input customization","save/load management",
    "game performance optimization","profiling","cheat detection","anti-cheat","cloud save synchronization",
    "streaming platform integration"
]

# Plateformes autorisées
ALLOWED_PLATFORMS = {"Windows","Linux","macOS","Android","iOS"}

PROMPT_TEMPLATE = """
Tu es un expert en cybersécurité et logiciels. 
Classe ce produit en type, plateformes et 3 à 5 fonctionnalités principales. 
Ne renvoie que du JSON, rien d'autre.

Produit :
Vendor : {vendor}
Product : {product}
Titles : {titles}

Format exact :
{{
  "type": "OS | application | library | plugin | firmware | etc.",
  "functionalities": ["fonction1","fonction2"],
  "platform": ["Windows","Linux","macOS","Android","iOS"]
}}
"""

# ---------------------- FONCTIONS ----------------------
def run_ollama(prompt, model="mistral"):
    result = subprocess.run(
        ["ollama", "run", model],
        input=prompt.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return result.stdout.decode("utf-8").strip()

def normalize_functionalities(funcs):
    if isinstance(funcs, str):
        funcs = [f.strip() for f in re.split(r',|;', funcs)]
    normalized = []
    for f in funcs:
        parts = re.split(r'&|/', f.lower().strip())
        for fc in parts:
            fc_clean = fc.strip()
            if fc_clean in ALLOWED_FUNCTIONS:
                normalized.append(fc_clean)
    return list(set(normalized))

def normalize_platforms(plats):
    if isinstance(plats, str):
        plats = [p.strip() for p in plats.split(",")]
    return [p for p in plats if p in ALLOWED_PLATFORMS]

# ---------------------- SCRIPT PRINCIPAL ----------------------
def main():
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()
    
    cur.execute("""
        SELECT software_id, vendor, product, titles
        FROM softwares
        WHERE type IS NULL OR type = ''
        ORDER BY software_id
    """)
    rows = cur.fetchall()
    
    for i in range(0, len(rows), BATCH_SIZE):
        batch = rows[i:i+BATCH_SIZE]
        prompt_lines = []
        for software_id, vendor, product, titles in batch:
            prompt_lines.append(f"""
Produit {software_id} :
Vendor: {vendor}
Product: {product}
Titles: {titles}
""")
        prompt_text = "Tu es un expert en cybersécurité et logiciels. Classe les produits suivants en type, plateformes et 3 à 5 fonctionnalités principales. Réponds uniquement en JSON avec l'ID comme clé :\n" + "\n".join(prompt_lines)
        
        print(f"⏳ Traitement batch {i//BATCH_SIZE + 1} ({len(batch)} produits)...")
        output = run_ollama(prompt_text)
        
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            print("[ERREUR] JSON non valide pour ce batch, on saute.")
            continue
        
        # Mettre à jour la DB
        for software_id, vendor, product, titles in batch:
            item = data.get(str(software_id))
            if not item:
                print(f"[ERREUR] Produit {software_id} non classé par LLM")
                continue
            
            funcs = normalize_functionalities(item.get("functionalities", []))
            plats = normalize_platforms(item.get("platform", []))
            
            cur.execute("""
                UPDATE softwares
                SET type=%s,
                    functionalities=%s,
                    platform=%s,
                    updated_at=NOW()
                WHERE software_id=%s
            """, (item.get("type"), funcs, plats, software_id))
            conn.commit()
            print(f"✅ {product} classé : {funcs} / {plats}")
        time.sleep(1)  # CPU-friendly
    
    cur.close()
    conn.close()

if __name__ == "__main__":
    main()