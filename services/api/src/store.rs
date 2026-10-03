//! SQLite repository. All blocking database work runs on Tokio's blocking pool.
use anyhow::{Context, bail};
use chrono::Utc;
use fs2::FileExt;
use librehub_common::*;
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

pub const MAX_LOG_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_LOG_ENTRIES: u64 = 10_000;
pub const MAX_PENDING_BUILDS: usize = 64;

#[derive(Clone)]
pub struct Store {
    db: Arc<Mutex<Connection>>,
    // The lock lasts as long as any repository handle. Two supervisors must never share data.
    _lock: Arc<File>,
    pub data_dir: PathBuf,
}
#[derive(Debug, thiserror::Error)]
#[error("The build queue is full")]
pub struct QueueFull;

impl Store {
    pub fn open(data_dir: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(data_dir).context("Cannot create data directory")?;
        let data_dir = std::fs::canonicalize(data_dir)?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(data_dir.join("supervisor.lock"))?;
        lock.try_lock_exclusive()
            .context("Another LibreHub supervisor owns this data directory")?;
        let db = Connection::open(data_dir.join("builds.sqlite3"))?;
        db.busy_timeout(Duration::from_secs(5))?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS builds (
                id TEXT PRIMARY KEY, status TEXT NOT NULL, record TEXT NOT NULL,
                manifest TEXT NOT NULL, log_bytes INTEGER NOT NULL DEFAULT 0,
                log_count INTEGER NOT NULL DEFAULT 0);
            CREATE INDEX IF NOT EXISTS builds_status ON builds(status);
            CREATE TABLE IF NOT EXISTS logs (
                build_id TEXT NOT NULL REFERENCES builds(id), sequence INTEGER NOT NULL,
                entry TEXT NOT NULL, PRIMARY KEY(build_id, sequence));",
        )?;
        // Migrate existing M1 databases once; preserve the historical error for audit.
        let has_cleanup_pending = db
            .prepare("PRAGMA table_info(builds)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .any(|name| name == "cleanup_pending");
        if !has_cleanup_pending {
            db.execute_batch(
                "BEGIN IMMEDIATE;
                 ALTER TABLE builds ADD COLUMN cleanup_pending INTEGER NOT NULL DEFAULT 0;
                 UPDATE builds SET cleanup_pending=1
                    WHERE json_extract(record, '$.error.code')='container_cleanup_failed';
                 COMMIT;",
            )?;
        }
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            _lock: Arc::new(lock),
            data_dir,
        })
    }
    async fn run<T, F>(&self, f: F) -> anyhow::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> anyhow::Result<T> + Send + 'static,
    {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let mut db = db
                .lock()
                .map_err(|_| anyhow::anyhow!("Database mutex poisoned"))?;
            f(&mut db)
        })
        .await
        .context("Database task failed")?
    }
    pub async fn insert(
        &self,
        manifest: FlatpakManifest,
        architecture: Architecture,
    ) -> anyhow::Result<BuildRecord> {
        self.run(move |db| {
            let tx = db.transaction()?;
            let pending: i64 = tx.query_row(
                "SELECT count(*) FROM builds WHERE status IN ('queued','validating','building')",
                [],
                |r| r.get(0),
            )?;
            if pending >= MAX_PENDING_BUILDS as i64 {
                return Err(QueueFull.into());
            }
            let now = Utc::now();
            let record = BuildRecord {
                id: BuildId::new(),
                status: BuildStatus::Queued,
                architecture,
                created_at: now,
                updated_at: now,
                started_at: None,
                finished_at: None,
                manifest: (&manifest).into(),
                result: None,
                error: None,
                cancellation_requested: false,
                logs_truncated: false,
            };
            tx.execute(
                "INSERT INTO builds(id,status,record,manifest) VALUES(?1,'queued',?2,?3)",
                params![
                    record.id.to_string(),
                    serde_json::to_string(&record)?,
                    serde_json::to_string(&manifest)?
                ],
            )?;
            tx.commit()?;
            Ok(record)
        })
        .await
    }
    pub async fn get(&self, id: BuildId) -> anyhow::Result<Option<BuildRecord>> {
        self.run(move |db| read_record(db, id)).await
    }
    pub async fn manifest(&self, id: BuildId) -> anyhow::Result<FlatpakManifest> {
        self.run(move |db| {
            let value: String = db.query_row(
                "SELECT manifest FROM builds WHERE id=?1",
                [id.to_string()],
                |r| r.get(0),
            )?;
            Ok(serde_json::from_str(&value)?)
        })
        .await
    }
    pub async fn pending(&self) -> anyhow::Result<Vec<BuildId>> {
        self.run(|db| {
            let mut q = db.prepare("SELECT id FROM builds WHERE status='queued' ORDER BY rowid")?;
            let ids = q
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            ids.into_iter()
                .map(|id| id.parse().map_err(Into::into))
                .collect()
        })
        .await
    }
    pub async fn interrupted(&self) -> anyhow::Result<Vec<BuildId>> {
        self.run(|db| {
            let mut q =
                db.prepare("SELECT id FROM builds WHERE status IN ('validating','building') OR cleanup_pending=1")?;
            let ids = q
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            ids.into_iter()
                .map(|id| id.parse().map_err(Into::into))
                .collect()
        })
        .await
    }
    /// Persist confirmed container removal without changing the build's historical error.
    pub async fn clear_cleanup_pending(&self, id: BuildId) -> anyhow::Result<()> {
        self.run(move |db| {
            db.execute(
                "UPDATE builds SET cleanup_pending=0 WHERE id=?1",
                [id.to_string()],
            )?;
            Ok(())
        })
        .await
    }
    /// Reconcile residual output after a crash between terminalization and deletion.
    pub async fn discarded_artifacts(&self) -> anyhow::Result<Vec<BuildId>> {
        self.run(|db| {
            let mut q =
                db.prepare("SELECT id FROM builds WHERE status IN ('failed','cancelled')")?;
            let ids = q
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            ids.into_iter()
                .map(|id| id.parse().map_err(Into::into))
                .collect()
        })
        .await
    }
    pub async fn transition(
        &self,
        id: BuildId,
        status: BuildStatus,
        result: Option<BuildResult>,
        error: Option<BuildError>,
    ) -> anyhow::Result<BuildRecord> {
        self.run(move |db| {
            let tx = db.transaction()?;
            let mut record = read_record(&tx, id)?.context("Build does not exist")?;
            // A queued cancellation can race with the worker claiming it.
            if record.status.is_terminal() {
                if record.status == BuildStatus::Cancelled && status == BuildStatus::Validating {
                    return Ok(record);
                }
                bail!("Cannot transition a terminal build");
            }
            if !record.status.can_transition_to(status) {
                bail!(
                    "Invalid build transition {:?} -> {:?}",
                    record.status,
                    status
                );
            }
            let status = if status == BuildStatus::Succeeded && record.cancellation_requested {
                BuildStatus::Cancelled
            } else {
                status
            };
            record.status = status;
            record.updated_at = Utc::now();
            if status == BuildStatus::Building {
                record.started_at = Some(record.updated_at);
            }
            if status.is_terminal() {
                record.finished_at = Some(record.updated_at);
            }
            record.result = if status == BuildStatus::Cancelled {
                None
            } else {
                result
            };
            record.error = error;
            write_record(&tx, &record)?;
            if record
                .error
                .as_ref()
                .is_some_and(|error| error.code == "container_cleanup_failed")
            {
                tx.execute(
                    "UPDATE builds SET cleanup_pending=1 WHERE id=?1",
                    [id.to_string()],
                )?;
            }
            tx.commit()?;
            Ok(record)
        })
        .await
    }
    pub async fn cancel(&self, id: BuildId) -> anyhow::Result<Option<BuildRecord>> {
        self.run(move |db| {
            let tx = db.transaction()?;
            let Some(mut record) = read_record(&tx, id)? else {
                return Ok(None);
            };
            if !record.status.is_terminal() {
                record.cancellation_requested = true;
                record.updated_at = Utc::now();
                if record.status == BuildStatus::Queued {
                    record.status = BuildStatus::Cancelled;
                    record.finished_at = Some(record.updated_at);
                }
                write_record(&tx, &record)?;
            }
            tx.commit()?;
            Ok(Some(record))
        })
        .await
    }
    pub async fn append(&self, id: BuildId, mut entry: BuildLogEntry) -> anyhow::Result<()> {
        // Executor plugins cannot allocate unbounded storage through the log interface.
        let mut end = entry.message.len().min(8192);
        while !entry.message.is_char_boundary(end) {
            end -= 1;
        }
        entry.message.truncate(end);
        self.run(move |db| {
            let tx = db.transaction()?;
            let (bytes, count): (i64, i64) = tx.query_row(
                "SELECT log_bytes,log_count FROM builds WHERE id=?1",
                [id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            entry.sequence = (count + 1) as u64;
            let encoded = serde_json::to_string(&entry)?;
            if bytes + encoded.len() as i64 > MAX_LOG_BYTES as i64
                || count >= MAX_LOG_ENTRIES as i64
            {
                let mut record = read_record(&tx, id)?.context("Missing build")?;
                if !record.logs_truncated {
                    record.logs_truncated = true;
                    write_record(&tx, &record)?;
                }
            } else {
                tx.execute(
                    "INSERT INTO logs(build_id,sequence,entry) VALUES(?1,?2,?3)",
                    params![id.to_string(), entry.sequence as i64, encoded],
                )?;
                tx.execute(
                    "UPDATE builds SET log_bytes=?2,log_count=?3 WHERE id=?1",
                    params![
                        id.to_string(),
                        bytes + encoded.len() as i64,
                        entry.sequence as i64
                    ],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }
    pub async fn logs(
        &self,
        id: BuildId,
        after: u64,
        limit: usize,
    ) -> anyhow::Result<Vec<BuildLogEntry>> {
        self.run(move |db| {
            let mut q = db.prepare("SELECT entry FROM logs WHERE build_id=?1 AND sequence>?2 ORDER BY sequence LIMIT ?3")?;
            let rows = q.query_map(params![id.to_string(), after.min(i64::MAX as u64) as i64, limit.min(500) as i64], |r| r.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().map(|row| serde_json::from_str(&row).map_err(Into::into)).collect()
        }).await
    }
}
fn read_record(db: &Connection, id: BuildId) -> anyhow::Result<Option<BuildRecord>> {
    let value: Option<String> = db
        .query_row(
            "SELECT record FROM builds WHERE id=?1",
            [id.to_string()],
            |r| r.get(0),
        )
        .optional()?;
    value
        .map(|v| serde_json::from_str(&v).map_err(Into::into))
        .transpose()
}
fn write_record(db: &Connection, record: &BuildRecord) -> anyhow::Result<()> {
    db.execute(
        "UPDATE builds SET status=?2,record=?3 WHERE id=?1",
        params![
            record.id.to_string(),
            serde_json::to_value(record.status)?.as_str(),
            serde_json::to_string(record)?
        ],
    )?;
    Ok(())
}
