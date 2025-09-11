DROP TABLE IF EXISTS source_mappings;
DROP TABLE IF EXISTS vulnerabilities CASCADE;

-- Table principale des vulnérabilités
CREATE TABLE IF NOT EXISTS vulnerabilities (
    vuln_id SERIAL PRIMARY KEY,
    canonical_id TEXT UNIQUE NOT NULL,
    cve_id TEXT,
    title TEXT,
    summary TEXT,
    vendors_products JSONB,
    first_seen TIMESTAMP,
    disclosed TIMESTAMP,
    published_nvd TIMESTAMP,
    exploited_in_wild BOOLEAN DEFAULT FALSE,
    kev_added TIMESTAMP,
    kev_latency_days INT,
    cvss2_base_score FLOAT,
    cvss2_vector TEXT,
    cvss3_base_score FLOAT,
    cvss3_vector TEXT,
    cvss4_base_score FLOAT,
    cvss4_vector TEXT,
    epss_score FLOAT,
    epss_percentile FLOAT,
    refs JSONB,
    tags TEXT[],
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Table pour mapper les sources
CREATE TABLE source_mappings (
    id SERIAL PRIMARY KEY,
    vuln_id INT REFERENCES vulnerabilities(vuln_id) ON DELETE CASCADE,
    source_name TEXT,
    source_id TEXT,                       -- identifiant dans la source
    url TEXT,
    retrieved TIMESTAMP DEFAULT now()
);

-- Index utiles
CREATE INDEX idx_vuln_cve ON vulnerabilities(cve_id);
CREATE INDEX idx_vuln_tags ON vulnerabilities USING gin (tags);
CREATE INDEX idx_vuln_vendor_product ON vulnerabilities USING gin (vendors_products);
