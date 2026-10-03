BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS publishes (
    id TEXT PRIMARY KEY,
    build_id TEXT NOT NULL REFERENCES builds(id),
    channel TEXT NOT NULL CHECK(channel IN ('stable', 'beta')),
    status TEXT NOT NULL,
    record TEXT NOT NULL,
    UNIQUE(build_id, channel)
);
CREATE INDEX IF NOT EXISTS publishes_status ON publishes(status);
CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY);
INSERT OR IGNORE INTO schema_migrations VALUES (2);
COMMIT;
