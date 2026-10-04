BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS developers (
 id TEXT PRIMARY KEY, status TEXT NOT NULL CHECK(status IN ('active','disabled')), record TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_tokens (
 id TEXT PRIMARY KEY, developer_id TEXT NOT NULL REFERENCES developers(id),
 hash BLOB NOT NULL CHECK(length(hash)=32), record TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS tokens_owner ON api_tokens(developer_id);
CREATE TABLE IF NOT EXISTS projects (
 id TEXT PRIMARY KEY, owner TEXT NOT NULL REFERENCES developers(id), slug TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('active','disabled','archived')),
 record TEXT NOT NULL, webhook_secret BLOB NOT NULL, UNIQUE(owner,slug)
);
CREATE INDEX IF NOT EXISTS projects_owner ON projects(owner);
CREATE TABLE IF NOT EXISTS source_events (
 id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
 build_id TEXT NOT NULL UNIQUE, status TEXT NOT NULL, record TEXT NOT NULL,
 auto_publish_state TEXT NOT NULL DEFAULT 'pending',
 auto_publish_id TEXT REFERENCES publishes(id)
);
CREATE INDEX IF NOT EXISTS source_events_status ON source_events(status);
CREATE TABLE IF NOT EXISTS webhook_deliveries (
 provider TEXT NOT NULL, project_id TEXT NOT NULL REFERENCES projects(id), delivery_id TEXT NOT NULL,
 event_type TEXT NOT NULL, received_at TEXT NOT NULL, processed_at TEXT, result TEXT NOT NULL,
 source_event_id TEXT REFERENCES source_events(id), PRIMARY KEY(provider,project_id,delivery_id)
);
CREATE TABLE IF NOT EXISTS build_owners (
 build_id TEXT PRIMARY KEY REFERENCES builds(id), developer_id TEXT NOT NULL REFERENCES developers(id),
 project_id TEXT REFERENCES projects(id), source_event_id TEXT UNIQUE REFERENCES source_events(id)
);
CREATE INDEX IF NOT EXISTS build_owners_developer ON build_owners(developer_id);
CREATE TABLE IF NOT EXISTS application_owners (
 app_id TEXT PRIMARY KEY, developer_id TEXT NOT NULL REFERENCES developers(id)
);
CREATE TABLE IF NOT EXISTS audit_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, developer_id TEXT NOT NULL REFERENCES developers(id),
 action TEXT NOT NULL, project_id TEXT REFERENCES projects(id), target_id TEXT NOT NULL,
 timestamp TEXT NOT NULL, result TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_owner ON audit_events(developer_id,id);
INSERT OR IGNORE INTO schema_migrations VALUES(3);
COMMIT;
