use crate::store::Store;
use anyhow::{Context, bail};
use chrono::Utc;
use librehub_common::*;
use rusqlite::{Connection, OptionalExtension, params};

#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    #[error("Build does not exist")]
    Missing,
    #[error("Only successful builds with one bundle can be published")]
    Ineligible,
    #[error("The publication queue is full")]
    Full,
    #[error("Publication has passed the safe cancellation boundary")]
    TooLate,
}
impl Store {
    pub async fn enqueue_publish(
        &self,
        id: BuildId,
        channel: RepositoryChannel,
    ) -> anyhow::Result<PublishRecord> {
        self.run(move |db| {
            let tx = db.transaction()?;
            let existing: Option<String> = tx.query_row("SELECT record FROM publishes WHERE build_id=?1 AND channel=?2", params![id.to_string(), channel.to_string()], |r| r.get(0)).optional()?;
            if let Some(existing) = existing { return Ok(serde_json::from_str(&existing)?); }
            let build: Option<String> = tx.query_row("SELECT record FROM builds WHERE id=?1", [id.to_string()], |r| r.get(0)).optional()?;
            let build: BuildRecord = serde_json::from_str(&build.ok_or(AdmissionError::Missing)?)?;
            if build.status != BuildStatus::Succeeded || build.result.as_ref().is_none_or(|r| r.artifacts.len() != 1 || r.exit_code != Some(0)) { return Err(AdmissionError::Ineligible.into()); }
            let pending: i64 = tx.query_row("SELECT count(*) FROM publishes WHERE status NOT IN ('succeeded','failed','cancelled')", [], |r| r.get(0))?;
            if pending >= 64 { return Err(AdmissionError::Full.into()); }
            let now = Utc::now();
            let record = PublishRecord { id: PublishId::new(), build_id: id, channel, status: PublishStatus::Queued, architecture: build.architecture, app_id: build.manifest.app_id, created_at: now, updated_at: now, flat_manager_build_id: None, create_requested: false, source_commit: None, result: None, error: None, needs_attention: false, attempts: 0 };
            tx.execute("INSERT INTO publishes(id,build_id,channel,status,record) VALUES(?1,?2,?3,'queued',?4)", params![record.id.to_string(), id.to_string(), channel.to_string(), serde_json::to_string(&record)?])?;
            tx.commit()?;
            Ok(record)
        }).await
    }
    pub async fn publish_record(&self, id: PublishId) -> anyhow::Result<Option<PublishRecord>> {
        self.run(move |db| read(db, id)).await
    }
    pub async fn publications(&self, build: BuildId) -> anyhow::Result<Vec<PublishRecord>> {
        self.run(move |db| {
            let mut q =
                db.prepare("SELECT record FROM publishes WHERE build_id=?1 ORDER BY rowid")?;
            let rows = q
                .query_map([build.to_string()], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter()
                .map(|r| serde_json::from_str(&r).map_err(Into::into))
                .collect()
        })
        .await
    }
    pub async fn active_publications(&self) -> anyhow::Result<Vec<PublishRecord>> {
        self.run(|db| {
            let mut q = db.prepare("SELECT record FROM publishes WHERE status NOT IN ('succeeded','failed','cancelled') ORDER BY rowid LIMIT 64")?;
            let rows = q.query_map([], |r| r.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().map(|r| serde_json::from_str(&r).map_err(Into::into)).collect()
        }).await
    }
    /// Transactional compare-and-set prevents cancellation and supervisor races.
    pub async fn save_publication(&self, mut next: PublishRecord) -> anyhow::Result<()> {
        self.run(move |db| {
            let tx = db.transaction()?;
            let old = read(&tx, next.id)?.context("Publication disappeared")?;
            if old.status.is_terminal()
                || (old.status != next.status && !old.status.can_transition_to(next.status))
            {
                bail!("Invalid publication transition");
            }
            if old.build_id != next.build_id
                || old.channel != next.channel
                || old.app_id != next.app_id
                || old.architecture != next.architecture
                || (old.flat_manager_build_id.is_some()
                    && old.flat_manager_build_id != next.flat_manager_build_id)
                || (old.source_commit.is_some() && old.source_commit != next.source_commit)
                || (old.create_requested && !next.create_requested)
            {
                bail!("Publication identity cannot change");
            }
            next.updated_at = Utc::now();
            write(&tx, &next)?;
            tx.commit()?;
            Ok(())
        })
        .await
    }
    pub async fn claim_publication(&self, id: PublishId) -> anyhow::Result<Option<PublishRecord>> {
        self.run(move |db| {
            let tx = db.transaction()?;
            let Some(mut record) = read(&tx, id)? else {
                return Ok(None);
            };
            if record.status != PublishStatus::Queued {
                return Ok(None);
            }
            record.status = PublishStatus::Preparing;
            record.updated_at = Utc::now();
            write(&tx, &record)?;
            tx.commit()?;
            Ok(Some(record))
        })
        .await
    }
    pub async fn cancel_publication(&self, id: PublishId) -> anyhow::Result<Option<PublishRecord>> {
        self.run(move |db| {
            let tx = db.transaction()?;
            let Some(mut record) = read(&tx, id)? else {
                return Ok(None);
            };
            if record.status == PublishStatus::Cancelled {
                return Ok(Some(record));
            }
            if !record.status.can_cancel() {
                return Err(AdmissionError::TooLate.into());
            }
            record.status = PublishStatus::Cancelled;
            record.updated_at = Utc::now();
            write(&tx, &record)?;
            tx.commit()?;
            Ok(Some(record))
        })
        .await
    }
    pub async fn database_ready(&self) -> bool {
        self.run(|db| {
            db.query_row("SELECT 1", [], |_| Ok(()))?;
            Ok(())
        })
        .await
        .is_ok()
    }
}
fn read(db: &Connection, id: PublishId) -> anyhow::Result<Option<PublishRecord>> {
    let value: Option<String> = db
        .query_row(
            "SELECT record FROM publishes WHERE id=?1",
            [id.to_string()],
            |r| r.get(0),
        )
        .optional()?;
    value
        .map(|v| serde_json::from_str(&v).map_err(Into::into))
        .transpose()
}
fn write(db: &Connection, record: &PublishRecord) -> anyhow::Result<()> {
    db.execute(
        "UPDATE publishes SET status=?2,record=?3 WHERE id=?1",
        params![
            record.id.to_string(),
            serde_json::to_value(record.status)?.as_str(),
            serde_json::to_string(record)?
        ],
    )?;
    Ok(())
}
