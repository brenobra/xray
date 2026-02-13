CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    results TEXT,
    error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at TEXT,
    duration_ms INTEGER
);

CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);

CREATE TABLE IF NOT EXISTS ai_reports (
    scan_id TEXT PRIMARY KEY,
    report TEXT NOT NULL,
    model TEXT NOT NULL,
    generated_at TEXT NOT NULL DEFAULT (datetime('now')),
    generation_ms INTEGER
);
