-- M7 automation and integrations. Additive; every table is created idempotently.
BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS automation_definitions (
 id TEXT PRIMARY KEY,
 project_id TEXT NOT NULL REFERENCES projects(id),
 owner TEXT NOT NULL REFERENCES developers(id),
 name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 80),
 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
 schedules_enabled INTEGER NOT NULL DEFAULT 1 CHECK(schedules_enabled IN (0,1)),
 current_version INTEGER NOT NULL CHECK(current_version >= 1),
 min_valid_version INTEGER NOT NULL CHECK(min_valid_version >= 1),
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 UNIQUE(project_id, name)
);
CREATE INDEX IF NOT EXISTS automation_definitions_project ON automation_definitions(project_id);

-- Immutable history: a run keeps the exact version it was admitted with.
CREATE TABLE IF NOT EXISTS automation_versions (
 automation_id TEXT NOT NULL REFERENCES automation_definitions(id),
 version INTEGER NOT NULL CHECK(version >= 1),
 spec TEXT NOT NULL, spec_sha256 TEXT NOT NULL CHECK(length(spec_sha256) = 64),
 created_at TEXT NOT NULL, created_by TEXT NOT NULL,
 PRIMARY KEY(automation_id, version)
);
CREATE TRIGGER IF NOT EXISTS automation_versions_no_update BEFORE UPDATE ON automation_versions
BEGIN SELECT RAISE(ABORT, 'automation versions are immutable'); END;
CREATE TRIGGER IF NOT EXISTS automation_versions_no_delete BEFORE DELETE ON automation_versions
BEGIN SELECT RAISE(ABORT, 'automation versions are immutable'); END;

-- Persistent schedule state: next occurrence per schedule trigger of the current version.
CREATE TABLE IF NOT EXISTS automation_triggers (
 automation_id TEXT NOT NULL REFERENCES automation_definitions(id),
 trigger_index INTEGER NOT NULL, version INTEGER NOT NULL,
 next_run_at TEXT NOT NULL, last_occurrence TEXT,
 PRIMARY KEY(automation_id, trigger_index)
);
CREATE INDEX IF NOT EXISTS automation_triggers_due ON automation_triggers(next_run_at);

CREATE TABLE IF NOT EXISTS automation_runs (
 id TEXT PRIMARY KEY,
 automation_id TEXT NOT NULL REFERENCES automation_definitions(id),
 project_id TEXT NOT NULL REFERENCES projects(id),
 owner TEXT NOT NULL REFERENCES developers(id),
 definition_version INTEGER NOT NULL,
 spec TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('queued','running','waiting_for_build','waiting_for_publication','waiting_for_security','waiting_for_approval','completed','failed','cancelled')),
 trigger_kind TEXT NOT NULL CHECK(trigger_kind IN ('manual','push','tag','schedule','ci')),
 trigger_key TEXT NOT NULL, trigger_detail TEXT NOT NULL,
 source_ref TEXT, source_commit TEXT,
 source_event_id TEXT REFERENCES source_events(id),
 build_id TEXT,
 beta_publication_id TEXT REFERENCES publishes(id),
 stable_publication_id TEXT REFERENCES publishes(id),
 current_step TEXT,
 project_policy_version INTEGER NOT NULL,
 chain_depth INTEGER NOT NULL DEFAULT 0 CHECK(chain_depth BETWEEN 0 AND 16),
 correlation_id TEXT NOT NULL,
 fresh_build INTEGER NOT NULL DEFAULT 0,
 cancel_requested INTEGER NOT NULL DEFAULT 0,
 error_code TEXT, error_message TEXT, error_retryable INTEGER,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
 UNIQUE(automation_id, trigger_key)
);
CREATE INDEX IF NOT EXISTS automation_runs_active ON automation_runs(status)
 WHERE status NOT IN ('completed','failed','cancelled');
CREATE INDEX IF NOT EXISTS automation_runs_project ON automation_runs(project_id, created_at);
CREATE INDEX IF NOT EXISTS automation_runs_automation ON automation_runs(automation_id, created_at);
CREATE INDEX IF NOT EXISTS automation_runs_build ON automation_runs(build_id) WHERE build_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS automation_runs_commit ON automation_runs(project_id, source_commit);

CREATE TABLE IF NOT EXISTS automation_steps (
 run_id TEXT NOT NULL REFERENCES automation_runs(id),
 step_id TEXT NOT NULL, kind TEXT NOT NULL, needs TEXT NOT NULL, ordinal INTEGER NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('pending','running','waiting','succeeded','failed','skipped','cancelled')),
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT,
 started_at TEXT, finished_at TEXT,
 output TEXT NOT NULL DEFAULT '{}', error_code TEXT, error_message TEXT,
 PRIMARY KEY(run_id, step_id)
);

CREATE TABLE IF NOT EXISTS automation_approvals (
 id TEXT PRIMARY KEY,
 run_id TEXT NOT NULL REFERENCES automation_runs(id), step_id TEXT NOT NULL,
 project_id TEXT NOT NULL REFERENCES projects(id), owner TEXT NOT NULL REFERENCES developers(id),
 status TEXT NOT NULL CHECK(status IN ('requested','approved','rejected','expired','cancelled')),
 candidate TEXT NOT NULL, candidate_sha256 TEXT NOT NULL CHECK(length(candidate_sha256) = 64),
 definition_version INTEGER NOT NULL, project_policy_version INTEGER NOT NULL,
 requested_by TEXT NOT NULL, requested_at TEXT NOT NULL, expires_at TEXT NOT NULL,
 decided_by TEXT REFERENCES developers(id), decided_role TEXT, decided_at TEXT, reason TEXT,
 consumed_at TEXT,
 UNIQUE(run_id, step_id)
);
CREATE INDEX IF NOT EXISTS automation_approvals_owner ON automation_approvals(owner, status);
CREATE INDEX IF NOT EXISTS automation_approvals_project ON automation_approvals(project_id, status);

CREATE TABLE IF NOT EXISTS automation_run_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 run_id TEXT NOT NULL REFERENCES automation_runs(id),
 at TEXT NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS automation_run_events_run ON automation_run_events(run_id, id);

-- Federated CI identities (deny-by-default policy documents).
CREATE TABLE IF NOT EXISTS integration_connections (
 id TEXT PRIMARY KEY,
 project_id TEXT NOT NULL REFERENCES projects(id),
 owner TEXT NOT NULL REFERENCES developers(id),
 kind TEXT NOT NULL CHECK(kind IN ('github_oidc')),
 name TEXT NOT NULL, policy TEXT NOT NULL,
 repository_id TEXT NOT NULL, repository_owner_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, revoked_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS integration_connections_unique ON integration_connections(project_id, repository_id)
 WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS integration_connections_project ON integration_connections(project_id);

-- Every accepted OIDC token ID is recorded once until it expires: exchange replay defence.
CREATE TABLE IF NOT EXISTS oidc_exchanges (
 issuer TEXT NOT NULL, jti TEXT NOT NULL,
 project_id TEXT NOT NULL REFERENCES projects(id),
 connection_id TEXT NOT NULL REFERENCES integration_connections(id),
 token_id TEXT NOT NULL, claims TEXT NOT NULL DEFAULT '{}', exchanged_at TEXT NOT NULL, expires_at TEXT NOT NULL,
 PRIMARY KEY(issuer, jti)
);
CREATE INDEX IF NOT EXISTS oidc_exchanges_project ON oidc_exchanges(project_id, exchanged_at);
CREATE INDEX IF NOT EXISTS oidc_exchanges_expiry ON oidc_exchanges(expires_at);

CREATE TABLE IF NOT EXISTS webhook_subscriptions (
 id TEXT PRIMARY KEY,
 project_id TEXT NOT NULL REFERENCES projects(id),
 owner TEXT NOT NULL REFERENCES developers(id),
 url TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
 secret BLOB NOT NULL, secret_fingerprint TEXT NOT NULL,
 event_types TEXT NOT NULL, exclude_origins TEXT NOT NULL DEFAULT '[]',
 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)), disabled_reason TEXT,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, secret_rotated_at TEXT,
 UNIQUE(project_id, url)
);
CREATE INDEX IF NOT EXISTS webhook_subscriptions_project ON webhook_subscriptions(project_id);

-- Transactional outbox. Rows are written by the same transaction that changes M1–M6 state.
CREATE TABLE IF NOT EXISTS event_outbox (
 seq INTEGER PRIMARY KEY AUTOINCREMENT,
 event_id TEXT NOT NULL UNIQUE, dedupe_key TEXT NOT NULL UNIQUE,
 project_id TEXT NOT NULL REFERENCES projects(id),
 event_type TEXT NOT NULL, subject_id TEXT NOT NULL, data TEXT NOT NULL,
 origin_kind TEXT, origin_run_id TEXT, correlation_id TEXT, chain_depth INTEGER,
 created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS event_outbox_project ON event_outbox(project_id, seq);
CREATE TABLE IF NOT EXISTS outbox_cursors (consumer TEXT PRIMARY KEY, last_seq INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS integration_deliveries (
 id TEXT PRIMARY KEY,
 webhook_id TEXT NOT NULL REFERENCES webhook_subscriptions(id),
 project_id TEXT NOT NULL REFERENCES projects(id),
 event_id TEXT NOT NULL, event_type TEXT NOT NULL,
 payload BLOB NOT NULL CHECK(length(payload) <= 65536),
 status TEXT NOT NULL CHECK(status IN ('pending','delivering','delivered','retry_wait','failed','dead_letter')),
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT NOT NULL,
 last_http_status INTEGER, last_error TEXT,
 replay_seq INTEGER NOT NULL DEFAULT 0, replay_of TEXT,
 created_at TEXT NOT NULL, delivered_at TEXT, finished_at TEXT,
 UNIQUE(webhook_id, event_id, replay_seq)
);
CREATE INDEX IF NOT EXISTS integration_deliveries_due ON integration_deliveries(next_attempt_at)
 WHERE status IN ('pending','retry_wait','delivering');
CREATE INDEX IF NOT EXISTS integration_deliveries_hook ON integration_deliveries(webhook_id, created_at);
CREATE INDEX IF NOT EXISTS integration_deliveries_project ON integration_deliveries(project_id, created_at);

CREATE TABLE IF NOT EXISTS integration_attempts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 delivery_id TEXT NOT NULL REFERENCES integration_deliveries(id),
 attempt INTEGER NOT NULL, started_at TEXT NOT NULL, duration_ms INTEGER NOT NULL,
 http_status INTEGER, outcome TEXT NOT NULL, error TEXT
);
CREATE INDEX IF NOT EXISTS integration_attempts_delivery ON integration_attempts(delivery_id, id);

CREATE TABLE IF NOT EXISTS integration_audit_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 project_id TEXT REFERENCES projects(id),
 actor TEXT NOT NULL, action TEXT NOT NULL, target_id TEXT NOT NULL,
 timestamp TEXT NOT NULL, result TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS integration_audit_project ON integration_audit_events(project_id, id);

-- source_events.intent_key (canonical build intent) is added by the store, because SQLite
-- cannot make ALTER TABLE ADD COLUMN idempotent.

-- Outbox triggers: the event is committed atomically with the state change itself.
CREATE TRIGGER IF NOT EXISTS m7_outbox_build_status AFTER UPDATE OF status ON builds
WHEN NEW.status<>OLD.status AND NEW.status IN ('building','succeeded','failed')
BEGIN
 INSERT OR IGNORE INTO event_outbox(event_id,dedupe_key,project_id,event_type,subject_id,data,created_at)
 SELECT lower(hex(randomblob(4)))||'-'||lower(hex(randomblob(2)))||'-4'||substr(lower(hex(randomblob(2))),2)||'-a'||substr(lower(hex(randomblob(2))),2)||'-'||lower(hex(randomblob(6))), 'build.'||NEW.status||':'||NEW.id, o.project_id, CASE NEW.status WHEN 'building' THEN 'build.started' WHEN 'succeeded' THEN 'build.succeeded' ELSE 'build.failed' END, NEW.id, json_object('build_id',NEW.id,'status',NEW.status,'app_id',json_extract(NEW.record,'$.manifest.app_id')), strftime('%Y-%m-%dT%H:%M:%fZ','now')
 FROM build_owners o WHERE o.build_id=NEW.id AND o.project_id IS NOT NULL;
END;
CREATE TRIGGER IF NOT EXISTS m7_outbox_publication_status AFTER UPDATE OF status ON publishes
WHEN NEW.status<>OLD.status AND NEW.status IN ('preparing','succeeded','failed')
BEGIN
 INSERT OR IGNORE INTO event_outbox(event_id,dedupe_key,project_id,event_type,subject_id,data,created_at)
 SELECT lower(hex(randomblob(4)))||'-'||lower(hex(randomblob(2)))||'-4'||substr(lower(hex(randomblob(2))),2)||'-a'||substr(lower(hex(randomblob(2))),2)||'-'||lower(hex(randomblob(6))), 'publication.'||NEW.status||':'||NEW.id, o.project_id, CASE NEW.status WHEN 'preparing' THEN 'publication.started' WHEN 'succeeded' THEN 'publication.succeeded' ELSE 'publication.failed' END, NEW.id, json_object('publication_id',NEW.id,'build_id',NEW.build_id,'channel',NEW.channel,'status',NEW.status,'app_id',json_extract(NEW.record,'$.app_id')), strftime('%Y-%m-%dT%H:%M:%fZ','now')
 FROM publishes p JOIN build_owners o ON o.build_id=p.build_id WHERE p.id=NEW.id AND o.project_id IS NOT NULL;
END;
CREATE TRIGGER IF NOT EXISTS m7_outbox_security_upd AFTER UPDATE OF state ON security_jobs
WHEN NEW.state IN ('ready','failed')
BEGIN
 INSERT OR IGNORE INTO event_outbox(event_id,dedupe_key,project_id,event_type,subject_id,data,created_at)
 SELECT lower(hex(randomblob(4)))||'-'||lower(hex(randomblob(2)))||'-4'||substr(lower(hex(randomblob(2))),2)||'-a'||substr(lower(hex(randomblob(2))),2)||'-'||lower(hex(randomblob(6))), 'security.'||NEW.state||':'||NEW.publication_id, o.project_id, CASE NEW.state WHEN 'ready' THEN 'security.analysis_ready' ELSE 'security.analysis_failed' END, NEW.publication_id, json_object('publication_id',NEW.publication_id,'build_id',p.build_id,'state',NEW.state), strftime('%Y-%m-%dT%H:%M:%fZ','now')
 FROM publishes p JOIN build_owners o ON o.build_id=p.build_id WHERE p.id=NEW.publication_id AND o.project_id IS NOT NULL;
END;
CREATE TRIGGER IF NOT EXISTS m7_outbox_security_ins AFTER INSERT ON security_jobs
WHEN NEW.state IN ('ready','failed')
BEGIN
 INSERT OR IGNORE INTO event_outbox(event_id,dedupe_key,project_id,event_type,subject_id,data,created_at)
 SELECT lower(hex(randomblob(4)))||'-'||lower(hex(randomblob(2)))||'-4'||substr(lower(hex(randomblob(2))),2)||'-a'||substr(lower(hex(randomblob(2))),2)||'-'||lower(hex(randomblob(6))), 'security.'||NEW.state||':'||NEW.publication_id, o.project_id, CASE NEW.state WHEN 'ready' THEN 'security.analysis_ready' ELSE 'security.analysis_failed' END, NEW.publication_id, json_object('publication_id',NEW.publication_id,'build_id',p.build_id,'state',NEW.state), strftime('%Y-%m-%dT%H:%M:%fZ','now')
 FROM publishes p JOIN build_owners o ON o.build_id=p.build_id WHERE p.id=NEW.publication_id AND o.project_id IS NOT NULL;
END;
CREATE TRIGGER IF NOT EXISTS m7_outbox_build_attestation AFTER INSERT ON build_attestations
WHEN 1
BEGIN
 INSERT OR IGNORE INTO event_outbox(event_id,dedupe_key,project_id,event_type,subject_id,data,created_at)
 SELECT lower(hex(randomblob(4)))||'-'||lower(hex(randomblob(2)))||'-4'||substr(lower(hex(randomblob(2))),2)||'-a'||substr(lower(hex(randomblob(2))),2)||'-'||lower(hex(randomblob(6))), 'attestation.ready:build:'||NEW.build_id, o.project_id, 'attestation.ready', NEW.build_id, json_object('kind','build','build_id',NEW.build_id,'app_id',NEW.app_id), strftime('%Y-%m-%dT%H:%M:%fZ','now')
 FROM build_owners o WHERE o.build_id=NEW.build_id AND o.project_id IS NOT NULL;
END;
CREATE TRIGGER IF NOT EXISTS m7_outbox_release_attestation AFTER INSERT ON release_attestations
WHEN 1
BEGIN
 INSERT OR IGNORE INTO event_outbox(event_id,dedupe_key,project_id,event_type,subject_id,data,created_at)
 SELECT lower(hex(randomblob(4)))||'-'||lower(hex(randomblob(2)))||'-4'||substr(lower(hex(randomblob(2))),2)||'-a'||substr(lower(hex(randomblob(2))),2)||'-'||lower(hex(randomblob(6))), 'attestation.ready:release:'||NEW.publication_id, o.project_id, 'attestation.ready', NEW.publication_id, json_object('kind','release','publication_id',NEW.publication_id,'build_id',NEW.build_id,'app_id',NEW.app_id), strftime('%Y-%m-%dT%H:%M:%fZ','now')
 FROM build_owners o WHERE o.build_id=NEW.build_id AND o.project_id IS NOT NULL;
END;
CREATE TRIGGER IF NOT EXISTS m7_outbox_attestation_failed AFTER UPDATE OF state ON attestation_jobs
WHEN NEW.state='failed' AND OLD.state<>'failed'
BEGIN
 INSERT OR IGNORE INTO event_outbox(event_id,dedupe_key,project_id,event_type,subject_id,data,created_at)
 SELECT lower(hex(randomblob(4)))||'-'||lower(hex(randomblob(2)))||'-4'||substr(lower(hex(randomblob(2))),2)||'-a'||substr(lower(hex(randomblob(2))),2)||'-'||lower(hex(randomblob(6))), 'attestation.failed:'||NEW.kind||':'||NEW.target_id||':'||NEW.attempts, o.project_id, 'attestation.failed', NEW.target_id, json_object('kind',NEW.kind,'target_id',NEW.target_id,'error_code',NEW.error_code), strftime('%Y-%m-%dT%H:%M:%fZ','now')
 FROM build_owners o WHERE o.project_id IS NOT NULL AND o.build_id=(CASE NEW.kind WHEN 'build' THEN NEW.target_id ELSE (SELECT build_id FROM publishes WHERE id=NEW.target_id) END);
END;
CREATE TRIGGER IF NOT EXISTS m7_outbox_source_completed AFTER UPDATE OF status ON source_events
WHEN NEW.status='completed' AND OLD.status<>'completed'
BEGIN
 INSERT OR IGNORE INTO event_outbox(event_id,dedupe_key,project_id,event_type,subject_id,data,created_at)
 SELECT lower(hex(randomblob(4)))||'-'||lower(hex(randomblob(2)))||'-4'||substr(lower(hex(randomblob(2))),2)||'-a'||substr(lower(hex(randomblob(2))),2)||'-'||lower(hex(randomblob(6))), 'source_event.completed:'||NEW.id, NEW.project_id, 'source_event.completed', NEW.id, json_object('source_event_id',NEW.id,'build_id',NEW.build_id,'commit',json_extract(NEW.record,'$.revision.commit')), strftime('%Y-%m-%dT%H:%M:%fZ','now')
 ;
END;
CREATE TRIGGER IF NOT EXISTS m7_outbox_project_archived AFTER UPDATE OF status ON projects
WHEN NEW.status='archived' AND OLD.status<>'archived'
BEGIN
 INSERT OR IGNORE INTO event_outbox(event_id,dedupe_key,project_id,event_type,subject_id,data,created_at)
 SELECT lower(hex(randomblob(4)))||'-'||lower(hex(randomblob(2)))||'-4'||substr(lower(hex(randomblob(2))),2)||'-a'||substr(lower(hex(randomblob(2))),2)||'-'||lower(hex(randomblob(6))), 'project.archived:'||NEW.id, NEW.id, 'project.archived', NEW.id, json_object('project_id',NEW.id), strftime('%Y-%m-%dT%H:%M:%fZ','now')
 ;
END;

INSERT OR IGNORE INTO schema_migrations VALUES(7);
COMMIT;
