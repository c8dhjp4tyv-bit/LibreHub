-- Additive M6 evidence. SQLite transactions are the atomic attestation store.
CREATE TABLE IF NOT EXISTS attestor_keys (
 key_id TEXT PRIMARY KEY, public_key TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('active','retired','revoked')), updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS build_attestations (
 build_id TEXT PRIMARY KEY REFERENCES builds(id), app_id TEXT NOT NULL,
 artifact_sha256 TEXT NOT NULL CHECK(length(artifact_sha256)=64),
 statement_sha256 TEXT NOT NULL CHECK(length(statement_sha256)=64),
 key_id TEXT NOT NULL REFERENCES attestor_keys(key_id),
 envelope TEXT NOT NULL CHECK(length(envelope)<=393216), verified_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS release_attestations (
 publication_id TEXT PRIMARY KEY REFERENCES publishes(id), build_id TEXT NOT NULL REFERENCES build_attestations(build_id),
 app_id TEXT NOT NULL, ostree_checksum TEXT NOT NULL CHECK(length(ostree_checksum)=64),
 sbom_sha256 TEXT NOT NULL CHECK(length(sbom_sha256)=64), statement_sha256 TEXT NOT NULL CHECK(length(statement_sha256)=64),
 key_id TEXT NOT NULL REFERENCES attestor_keys(key_id), envelope TEXT NOT NULL CHECK(length(envelope)<=393216), verified_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attestation_jobs (
 kind TEXT NOT NULL CHECK(kind IN ('build','release')), target_id TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','verified','failed')), attempts INTEGER NOT NULL DEFAULT 0,
 error_code TEXT, updated_at TEXT NOT NULL, PRIMARY KEY(kind,target_id)
);
CREATE TABLE IF NOT EXISTS supply_chain_decisions (
 id INTEGER PRIMARY KEY, build_id TEXT NOT NULL REFERENCES builds(id), mode TEXT NOT NULL,
 allowed INTEGER NOT NULL, violations TEXT NOT NULL, evaluated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS supply_chain_audit (
 id INTEGER PRIMARY KEY, action TEXT NOT NULL, target_id TEXT NOT NULL, result TEXT NOT NULL, timestamp TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reproducibility_attempts (
 id INTEGER PRIMARY KEY, original_build_id TEXT NOT NULL REFERENCES builds(id),
 rebuild_id TEXT REFERENCES builds(id), state TEXT NOT NULL, reason TEXT NOT NULL,
 original_content TEXT, rebuild_content TEXT, checked_at TEXT NOT NULL
);
