BEGIN IMMEDIATE;

-- Publisher domain verifications (DNS TXT ownership challenge)
CREATE TABLE IF NOT EXISTS publisher_verifications (
    id TEXT PRIMARY KEY,
    developer_id TEXT NOT NULL REFERENCES developers(id),
    domain TEXT NOT NULL,
    method TEXT NOT NULL CHECK(method IN ('dns_txt')),
    challenge_token TEXT,
    challenge_expires_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'verified', 'revoked', 'expired')),
    verified_at TEXT,
    revoked_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS publisher_verifications_dev ON publisher_verifications(developer_id, domain);
CREATE INDEX IF NOT EXISTS publisher_verifications_lookup ON publisher_verifications(domain, status);

-- Security worker queue for successful publications
CREATE TABLE IF NOT EXISTS security_jobs (
    publication_id TEXT PRIMARY KEY REFERENCES publishes(id),
    state TEXT NOT NULL CHECK(state IN ('pending', 'analyzing', 'ready', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0,
    error_code TEXT,
    error_message TEXT,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS security_jobs_state ON security_jobs(state);

-- Release-level security summary records
CREATE TABLE IF NOT EXISTS release_security (
    publication_id TEXT PRIMARY KEY REFERENCES publishes(id),
    app_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'analyzing', 'ready', 'failed', 'unavailable')),
    sbom_format TEXT NOT NULL,
    sbom_path TEXT NOT NULL,
    sbom_component_count INTEGER NOT NULL DEFAULT 0,
    sbom_sha256 TEXT NOT NULL,
    vulnerabilities_status TEXT NOT NULL CHECK(vulnerabilities_status IN ('clean', 'vulnerable', 'unavailable')),
    vulnerabilities_checked_at TEXT,
    permissions_extracted_at TEXT NOT NULL,
    permission_severity TEXT NOT NULL CHECK(permission_severity IN ('none', 'low', 'moderate', 'significant')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS release_security_app ON release_security(app_id, channel, publication_id);

-- Snapshot of permissions extracted at exact published OSTree commit
CREATE TABLE IF NOT EXISTS release_permissions (
    publication_id TEXT PRIMARY KEY REFERENCES publishes(id),
    app_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS release_permissions_app ON release_permissions(app_id, channel);

-- Structured permission differences between consecutive releases
CREATE TABLE IF NOT EXISTS permission_diffs (
    to_publication_id TEXT PRIMARY KEY REFERENCES publishes(id),
    from_publication_id TEXT REFERENCES publishes(id),
    app_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('none', 'low', 'moderate', 'significant')),
    diff_json TEXT NOT NULL,
    generated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS permission_diffs_app ON permission_diffs(app_id, channel);

-- Vulnerability findings matching SBOM components
CREATE TABLE IF NOT EXISTS vulnerability_findings (
    id TEXT PRIMARY KEY,
    publication_id TEXT NOT NULL REFERENCES publishes(id),
    vulnerability_id TEXT NOT NULL,
    component_name TEXT NOT NULL,
    component_version TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('unknown', 'low', 'medium', 'high', 'critical')),
    summary TEXT NOT NULL,
    reference_url TEXT,
    source_provider TEXT NOT NULL,
    checked_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS vulnerability_findings_pub ON vulnerability_findings(publication_id);

-- Current moderation state per application
CREATE TABLE IF NOT EXISTS catalog_moderation (
    app_id TEXT PRIMARY KEY,
    state TEXT NOT NULL CHECK(state IN ('normal', 'under_review', 'restricted', 'removed')),
    reason_code TEXT NOT NULL,
    public_note TEXT,
    internal_note TEXT,
    operator TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Immutable audit log of all moderation transitions
CREATE TABLE IF NOT EXISTS moderation_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('mark_under_review', 'restrict', 'remove', 'restore')),
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    public_note TEXT,
    internal_note TEXT,
    operator TEXT NOT NULL,
    timestamp TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS moderation_events_app ON moderation_events(app_id, timestamp DESC);

-- Public user reports
CREATE TABLE IF NOT EXISTS app_reports (
    id TEXT PRIMARY KEY,
    app_id TEXT NOT NULL,
    reason TEXT NOT NULL CHECK(reason IN ('malware', 'security_vulnerability', 'privacy_violation', 'copyright_infringement', 'impersonation', 'policy_violation', 'broken_build', 'other')),
    message TEXT,
    status TEXT NOT NULL CHECK(status IN ('open', 'resolved', 'dismissed')),
    resolution_note TEXT,
    resolved_by TEXT,
    resolved_at TEXT,
    reporter_hash TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS app_reports_app ON app_reports(app_id, status);
CREATE INDEX IF NOT EXISTS app_reports_status ON app_reports(status, created_at DESC);

INSERT OR IGNORE INTO schema_migrations VALUES(5);
COMMIT;
