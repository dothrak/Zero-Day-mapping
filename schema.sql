-- Table principale des vulnérabilités
CREATE TABLE vulnerabilities (
    vuln_id SERIAL PRIMARY KEY,
    canonical_id TEXT UNIQUE,             -- ex: CVE-2022-1234 ou interne
    title TEXT,
    summary TEXT,
    vendors_products JSONB,               -- [{"vendor":"X","product":"Y","version":"Z"}]
    first_seen TIMESTAMP,
    disclosed TIMESTAMP,
    cve_id TEXT,
    cvss JSONB,                           -- {"baseScore":7.8,"vector":"AV:N/AC:L/..."}
    exploited_in_wild BOOLEAN DEFAULT false,
    refs JSONB,                           -- [{"source":"NVD","url":"..."}]
    tags TEXT[],
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
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
