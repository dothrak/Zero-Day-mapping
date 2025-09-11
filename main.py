import psycopg2
from pathlib import Path
from etl import run_etl

DB_PARAMS = {
    "dbname": "zerodaydb",
    "user": "postgres",
    "password": "postgres",
    "host": "localhost",
    "port": 5432
}

SCHEMA_FILE = Path("schema.sql")

def reset_db():
    """Supprime et recrée les tables selon schema.sql"""
    conn = psycopg2.connect(**DB_PARAMS)
    conn.autocommit = True
    cur = conn.cursor()

    print("🔹 Réinitialisation de la base de données...")
    if not SCHEMA_FILE.exists():
        raise FileNotFoundError(f"{SCHEMA_FILE} introuvable !")
    
    sql = SCHEMA_FILE.read_text()
    cur.execute(sql)

    print("✅ Base réinitialisée avec succès !")
    cur.close()
    conn.close()

def main():
    reset_db()
    print("🚀 Lancement de l'ETL...")
    run_etl()

if __name__ == "__main__":
    main()
