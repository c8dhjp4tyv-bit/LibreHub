BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS catalog_jobs (
 publication_id TEXT PRIMARY KEY REFERENCES publishes(id),
 state TEXT NOT NULL CHECK(state IN ('pending','indexing','ready','failed')),
 error_code TEXT, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS catalog_jobs_state ON catalog_jobs(state);
CREATE TABLE IF NOT EXISTS catalog_apps (
 id INTEGER PRIMARY KEY, app_id TEXT NOT NULL, channel TEXT NOT NULL CHECK(channel IN ('stable','beta')),
 name TEXT NOT NULL, publisher_id TEXT, project_id TEXT, published_at TEXT NOT NULL,
 updated_at TEXT NOT NULL, latest_publication TEXT NOT NULL, record TEXT NOT NULL, icon_png BLOB,
 UNIQUE(app_id,channel)
);
CREATE INDEX IF NOT EXISTS catalog_apps_channel ON catalog_apps(channel,updated_at,app_id);
CREATE TABLE IF NOT EXISTS catalog_releases (
 publication_id TEXT PRIMARY KEY REFERENCES publishes(id), app_id TEXT NOT NULL,
 build_id TEXT NOT NULL REFERENCES builds(id), channel TEXT NOT NULL,
 architecture TEXT NOT NULL, published_at TEXT NOT NULL, checksum TEXT NOT NULL, record TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS catalog_release_history ON catalog_releases(app_id,published_at DESC,publication_id);
CREATE INDEX IF NOT EXISTS catalog_release_arch ON catalog_releases(app_id,channel,architecture,published_at DESC);
CREATE TABLE IF NOT EXISTS catalog_categories (
 app_row INTEGER NOT NULL REFERENCES catalog_apps(id), category TEXT NOT NULL, PRIMARY KEY(app_row,category)
);
CREATE VIRTUAL TABLE IF NOT EXISTS catalog_search USING fts5(
 app_id, name, summary, description, developer, keywords, categories, channel UNINDEXED,
 tokenize='unicode61 remove_diacritics 2', prefix='2 3 4'
);
INSERT OR IGNORE INTO schema_migrations VALUES(4);
COMMIT;
