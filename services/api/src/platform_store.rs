//! All admission, policy snapshots and handoffs are SQLite transactions.
use crate::{
    auth::{Secret, encrypt_secret},
    store::{QueueFull, Store},
};
use chrono::Utc;
use librehub_common::*;
use rusqlite::{Connection, OptionalExtension, params};

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct PlatformError(pub &'static str);
pub const MAX_PROJECTS: usize = 32;
pub const MAX_SOURCE_EVENTS: usize = 64;
pub fn audit(
    db: &Connection,
    developer: DeveloperId,
    action: &str,
    project: Option<ProjectId>,
    target: &str,
    result: &str,
) -> anyhow::Result<()> {
    db.execute("INSERT INTO audit_events(developer_id,action,project_id,target_id,timestamp,result) VALUES(?1,?2,?3,?4,?5,?6)",params![developer.to_string(),action,project.map(|p|p.to_string()),target,Utc::now().to_rfc3339(),result])?;
    db.execute("DELETE FROM audit_events WHERE developer_id=?1 AND id NOT IN (SELECT id FROM audit_events WHERE developer_id=?1 ORDER BY id DESC LIMIT 10000)",[developer.to_string()])?;
    Ok(())
}
fn project(db: &Connection, id: ProjectId) -> anyhow::Result<Option<Project>> {
    let raw: Option<String> = db
        .query_row(
            "SELECT record FROM projects WHERE id=?1",
            [id.to_string()],
            |r| r.get(0),
        )
        .optional()?;
    raw.map(|r| serde_json::from_str(&r).map_err(Into::into))
        .transpose()
}
fn active_project(db: &Connection, id: ProjectId) -> anyhow::Result<Project> {
    let record = project(db, id)?.ok_or(PlatformError("project_not_found"))?;
    if record.status != ProjectStatus::Active {
        return Err(PlatformError("project_disabled").into());
    }
    Ok(record)
}
fn event(db: &Connection, id: SourceEventId) -> anyhow::Result<SourceEvent> {
    let raw: String = db.query_row(
        "SELECT record FROM source_events WHERE id=?1",
        [id.to_string()],
        |r| r.get(0),
    )?;
    Ok(serde_json::from_str(&raw)?)
}
fn save_event(db: &Connection, event: &SourceEvent) -> anyhow::Result<()> {
    db.execute(
        "UPDATE source_events SET status=?2,record=?3 WHERE id=?1",
        params![
            event.id.to_string(),
            serde_json::to_value(event.status)?.as_str(),
            serde_json::to_string(event)?
        ],
    )?;
    if let Some(delivery) = &event.delivery_id {
        db.execute("UPDATE webhook_deliveries SET result=?3,processed_at=?4 WHERE provider='github' AND project_id=?1 AND delivery_id=?2",params![event.project_id.to_string(),delivery,serde_json::to_value(event.status)?.as_str(),event.processed_at.map(|t|t.to_rfc3339())])?;
    }
    Ok(())
}
#[derive(Clone)]
pub struct SourceAdmission {
    pub project_id: ProjectId,
    pub owner: Option<DeveloperId>,
    pub trigger: TriggerType,
    pub source_ref: String,
    pub commit: Option<String>,
    pub webhook: Option<WebhookAdmission>,
}
#[derive(Clone)]
pub struct WebhookAdmission {
    pub delivery_id: String,
    pub event_type: String,
    pub expected_cipher: Vec<u8>,
    pub expected_policy: u64,
}
#[derive(Debug)]
pub enum Admission {
    Created(Box<SourceEvent>),
    Duplicate(Option<SourceEventId>),
    Ignored,
}
impl Store {
    pub async fn create_project(
        &self,
        record: Project,
        key: [u8; 32],
        secret: Secret,
    ) -> anyhow::Result<Project> {
        let cipher = encrypt_secret(&key, record.id, &secret)?;
        self.run(move|db|{let tx=db.transaction()?;let count:i64=tx.query_row("SELECT count(*) FROM projects WHERE owner=?1",[record.owner_developer_id.to_string()],|r|r.get(0))?;if count>=MAX_PROJECTS as i64{return Err(PlatformError("project_limit_exceeded").into())}
            let duplicate:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM projects WHERE owner=?1 AND slug=?2)",params![record.owner_developer_id.to_string(),record.slug],|r|r.get(0))?;if duplicate{return Err(PlatformError("project_slug_taken").into())}
            tx.execute("INSERT INTO projects(id,owner,slug,status,record,webhook_secret) VALUES(?1,?2,?3,'active',?4,?5)",params![record.id.to_string(),record.owner_developer_id.to_string(),record.slug,serde_json::to_string(&record)?,cipher])?;audit(&tx,record.owner_developer_id,"project.created",Some(record.id),&record.id.to_string(),"succeeded")?;tx.commit()?;Ok(record)}).await
    }
    pub async fn project(
        &self,
        id: ProjectId,
        owner: DeveloperId,
    ) -> anyhow::Result<Option<Project>> {
        self.run(move |db| Ok(project(db, id)?.filter(|p| p.owner_developer_id == owner)))
            .await
    }
    pub async fn projects(
        &self,
        owner: DeveloperId,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<Vec<Project>> {
        self.run(move |db| {
            let mut query = db.prepare(
                "SELECT record FROM projects WHERE owner=?1 ORDER BY rowid DESC LIMIT ?2 OFFSET ?3",
            )?;
            let rows = query
                .query_map(
                    params![owner.to_string(), limit as i64, offset as i64],
                    |r| r.get::<_, String>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter()
                .map(|r| serde_json::from_str(&r).map_err(Into::into))
                .collect()
        })
        .await
    }
    pub async fn update_project(
        &self,
        record: Project,
        expected_version: u64,
        action: &'static str,
    ) -> anyhow::Result<Project> {
        self.run(move |db| {
            let tx = db.transaction()?;
            let current = project(&tx, record.id)?.ok_or(PlatformError("project_not_found"))?;
            if current.owner_developer_id != record.owner_developer_id {
                return Err(PlatformError("project_not_found").into());
            }
            if current.policy_version != expected_version {
                return Err(PlatformError("project_update_conflict").into());
            }
            if current.status == ProjectStatus::Archived {
                return Err(PlatformError("project_disabled").into());
            }
            tx.execute(
                "UPDATE projects SET record=?2,status=?3 WHERE id=?1",
                params![
                    record.id.to_string(),
                    serde_json::to_string(&record)?,
                    serde_json::to_value(record.status)?.as_str()
                ],
            )?;
            audit(
                &tx,
                record.owner_developer_id,
                action,
                Some(record.id),
                &record.id.to_string(),
                "succeeded",
            )?;
            tx.commit()?;
            Ok(record)
        })
        .await
    }
    pub async fn rotate_webhook(
        &self,
        id: ProjectId,
        owner: DeveloperId,
        key: [u8; 32],
        secret: Secret,
    ) -> anyhow::Result<()> {
        let cipher = encrypt_secret(&key, id, &secret)?;
        self.run(move |db| {
            let tx = db.transaction()?;
            let current = project(&tx, id)?.ok_or(PlatformError("project_not_found"))?;
            if current.owner_developer_id != owner {
                return Err(PlatformError("project_not_found").into());
            }
            tx.execute(
                "UPDATE projects SET webhook_secret=?2 WHERE id=?1",
                params![id.to_string(), cipher],
            )?;
            audit(
                &tx,
                owner,
                "webhook.secret_rotated",
                Some(id),
                &id.to_string(),
                "succeeded",
            )?;
            tx.commit()?;
            Ok(())
        })
        .await
    }
    pub async fn webhook_connection(
        &self,
        id: ProjectId,
    ) -> anyhow::Result<Option<(Project, Vec<u8>)>> {
        self.run(move |db| {
            let row: Option<(String, Vec<u8>)> = db
                .query_row(
                    "SELECT record,webhook_secret FROM projects WHERE id=?1",
                    [id.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            row.map(|(record, key)| Ok((serde_json::from_str(&record)?, key)))
                .transpose()
        })
        .await
    }
    pub async fn admit_source(
        &self,
        input: SourceAdmission,
        ignored: bool,
    ) -> anyhow::Result<Admission> {
        self.run(move|db|{let tx=db.transaction()?;let policy=project(&tx,input.project_id)?.ok_or(PlatformError("project_not_found"))?;if input.owner.is_some_and(|o|o!=policy.owner_developer_id){return Err(PlatformError("project_not_found").into())}
        if let Some(hook)=&input.webhook {
            let cipher:Vec<u8>=tx.query_row("SELECT webhook_secret FROM projects WHERE id=?1",[policy.id.to_string()],|r|r.get(0))?;if cipher!=hook.expected_cipher{return Err(PlatformError("webhook_signature_invalid").into())}
if policy.policy_version!=hook.expected_policy{return Err(PlatformError("project_update_conflict").into())}
            let duplicate:Option<Option<String>>=tx.query_row("SELECT source_event_id FROM webhook_deliveries WHERE provider='github' AND project_id=?1 AND delivery_id=?2",params![policy.id.to_string(),hook.delivery_id],|r|r.get(0)).optional()?;
            if let Some(id)=duplicate {return Ok(Admission::Duplicate(id.map(|id|id.parse()).transpose()?))}
            let count:i64=tx.query_row("SELECT count(*) FROM webhook_deliveries WHERE project_id=?1",[policy.id.to_string()],|r|r.get(0))?;if count>=10000{return Err(PlatformError("webhook_delivery_limit").into())}
        }
        let ignored=ignored||policy.status!=ProjectStatus::Active;
        if ignored {
            if let Some(hook)=input.webhook {tx.execute("INSERT INTO webhook_deliveries(provider,project_id,delivery_id,event_type,received_at,processed_at,result) VALUES('github',?1,?2,?3,?4,?4,'ignored')",params![policy.id.to_string(),hook.delivery_id,hook.event_type,Utc::now().to_rfc3339()])?;}
            if input.owner.is_some() {return Err(PlatformError("project_disabled").into())}tx.commit()?;return Ok(Admission::Ignored)
        }
        let queued:i64=tx.query_row("SELECT count(*) FROM source_events WHERE status IN ('queued','resolving','fetching','handoff')",[],|r|r.get(0))?;if queued>=MAX_SOURCE_EVENTS as i64{return Err(PlatformError("source_queue_full").into())}
        let total:i64=tx.query_row("SELECT count(*) FROM source_events WHERE project_id=?1",[policy.id.to_string()],|r|r.get(0))?;if total>=10000{return Err(PlatformError("source_history_limit").into())}
        let now=Utc::now();let event=SourceEvent{id:SourceEventId::new(),project_id:policy.id,build_id:BuildId::new(),trigger:input.trigger,delivery_id:input.webhook.as_ref().map(|h|h.delivery_id.clone()),source_ref:input.source_ref.clone(),revision:input.commit.map(|commit|SourceRevision{repository:policy.repository.url.clone(),commit,source_ref:input.source_ref,resolved_at:now}),policy,status:SourceEventStatus::Queued,attempts:0,received_at:now,processed_at:None,error:None};
        tx.execute("INSERT INTO source_events(id,project_id,build_id,status,record) VALUES(?1,?2,?3,'queued',?4)",params![event.id.to_string(),event.project_id.to_string(),event.build_id.to_string(),serde_json::to_string(&event)?])?;
        if let Some(hook)=input.webhook {tx.execute("INSERT INTO webhook_deliveries(provider,project_id,delivery_id,event_type,received_at,result,source_event_id) VALUES('github',?1,?2,?3,?4,'queued',?5)",params![event.project_id.to_string(),hook.delivery_id,hook.event_type,now.to_rfc3339(),event.id.to_string()])?;}
        audit(&tx,event.policy.owner_developer_id,"build.triggered",Some(event.project_id),&event.build_id.to_string(),"queued")?;tx.commit()?;Ok(Admission::Created(Box::new(event)))}).await
    }
    pub async fn pending_source(&self) -> anyhow::Result<Option<SourceEvent>> {
        self.run(|db|{let raw:Option<String>=db.query_row("SELECT record FROM source_events WHERE status IN ('queued','resolving','fetching','handoff') ORDER BY rowid LIMIT 1",[],|r|r.get(0)).optional()?;raw.map(|r|serde_json::from_str(&r).map_err(Into::into)).transpose()}).await
    }
    pub async fn source_event(
        &self,
        id: SourceEventId,
        project_id: ProjectId,
    ) -> anyhow::Result<Option<SourceEvent>> {
        self.run(move |db| {
            let raw: Option<String> = db
                .query_row(
                    "SELECT record FROM source_events WHERE id=?1 AND project_id=?2",
                    params![id.to_string(), project_id.to_string()],
                    |r| r.get(0),
                )
                .optional()?;
            raw.map(|r| serde_json::from_str(&r).map_err(Into::into))
                .transpose()
        })
        .await
    }
    pub async fn save_source(&self, next: SourceEvent) -> anyhow::Result<()> {
        self.run(move |db| {
            let tx = db.transaction()?;
            let old = event(&tx, next.id)?;
            anyhow::ensure!(
                old.build_id == next.build_id
                    && old.project_id == next.project_id
                    && old.source_ref == next.source_ref
                    && old.policy.policy_version == next.policy.policy_version,
                "Source event identity changed"
            );
            if let Some(revision) = old.revision {
                anyhow::ensure!(
                    next.revision.as_ref().is_some_and(
                        |r| r.commit == revision.commit && r.repository == revision.repository
                    ),
                    "Resolved revision cannot change"
                );
            }
            anyhow::ensure!(
                !matches!(
                    old.status,
                    SourceEventStatus::Completed
                        | SourceEventStatus::Failed
                        | SourceEventStatus::Ignored
                ),
                "Source event already terminal"
            );
            save_event(&tx, &next)?;
            tx.commit()?;
            Ok(())
        })
        .await
    }
    /// Single durable transaction: build + owner + provenance + delivery completion.
    pub async fn handoff_source(
        &self,
        id: SourceEventId,
        manifest: FlatpakManifest,
        provenance: BuildProvenance,
        architecture: Architecture,
    ) -> anyhow::Result<BuildRecord> {
        self.run(move|db|{let tx=db.transaction()?;let mut source=event(&tx,id)?;
        let existing:Option<String>=tx.query_row("SELECT record FROM builds WHERE id=?1",[source.build_id.to_string()],|r|r.get(0)).optional()?;if let Some(record)=existing{return Ok(serde_json::from_str(&record)?)}
        active_project(&tx,source.project_id)?;
        let pending:i64=tx.query_row("SELECT count(*) FROM builds WHERE status IN ('queued','validating','building')",[],|r|r.get(0))?;if pending>=crate::store::MAX_PENDING_BUILDS as i64{return Err(QueueFull.into())}
        let revision=source.revision.as_ref().ok_or(PlatformError("source_revision_not_found"))?;anyhow::ensure!(provenance.revision.commit==revision.commit&&provenance.project_id==source.project_id&&provenance.trigger_event_id==source.id,"Invalid source provenance");
        let now=Utc::now();let record=BuildRecord{id:source.build_id,status:BuildStatus::Queued,architecture,created_at:now,updated_at:now,started_at:None,finished_at:None,manifest:(&manifest).into(),result:None,error:None,cancellation_requested:false,logs_truncated:false,provenance:Some(provenance)};
        tx.execute("INSERT INTO builds(id,status,record,manifest) VALUES(?1,'queued',?2,?3)",params![record.id.to_string(),serde_json::to_string(&record)?,serde_json::to_string(&manifest)?])?;
        tx.execute("INSERT INTO build_owners(build_id,developer_id,project_id,source_event_id) VALUES(?1,?2,?3,?4)",params![record.id.to_string(),source.policy.owner_developer_id.to_string(),source.project_id.to_string(),source.id.to_string()])?;
        source.status=SourceEventStatus::Completed;source.processed_at=Some(now);source.error=None;save_event(&tx,&source)?;tx.commit()?;Ok(record)}).await
    }
    pub async fn project_events(
        &self,
        id: ProjectId,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<Vec<SourceEvent>> {
        self.run(move|db|{let mut q=db.prepare("SELECT record FROM source_events WHERE project_id=?1 ORDER BY rowid DESC LIMIT ?2 OFFSET ?3")?;let rows=q.query_map(params![id.to_string(),limit as i64,offset as i64],|r|r.get::<_,String>(0))?.collect::<Result<Vec<_>,_>>()?;rows.into_iter().map(|r|serde_json::from_str(&r).map_err(Into::into)).collect()}).await
    }
    pub async fn audit_events(
        &self,
        owner: DeveloperId,
        project_id: Option<ProjectId>,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<Vec<AuditEvent>> {
        self.run(move|db|{let mut q=db.prepare("SELECT id,action,project_id,target_id,timestamp,result FROM audit_events WHERE developer_id=?1 AND (?2 IS NULL OR project_id=?2) ORDER BY id DESC LIMIT ?3 OFFSET ?4")?;let rows=q.query_map(params![owner.to_string(),project_id.map(|p|p.to_string()),limit as i64,offset as i64],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,Option<String>>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,String>(5)?)))?.collect::<Result<Vec<_>,_>>()?;rows.into_iter().map(|(id,action,project,target,timestamp,result)|Ok(AuditEvent{id,developer_id:owner,action,project_id:project.map(|p|p.parse()).transpose()?,target_id:target,timestamp:timestamp.parse()?,result})).collect()}).await
    }
    pub async fn auto_publish_candidates(&self) -> anyhow::Result<Vec<SourceEvent>> {
        self.run(|db|{let mut q=db.prepare("SELECT e.record FROM source_events e JOIN builds b ON b.id=e.build_id WHERE e.auto_publish_state='pending' AND e.status='completed' AND b.status IN ('succeeded','failed','cancelled') ORDER BY e.rowid LIMIT 64")?;let rows=q.query_map([],|r|r.get::<_,String>(0))?.collect::<Result<Vec<_>,_>>()?;rows.into_iter().map(|r|serde_json::from_str(&r).map_err(Into::into)).collect()}).await
    }
    pub async fn finish_auto_publish(
        &self,
        id: SourceEventId,
        state: &'static str,
    ) -> anyhow::Result<()> {
        self.run(move |db| {
            db.execute(
                "UPDATE source_events SET auto_publish_state=?2 WHERE id=?1",
                params![id.to_string(), state],
            )?;
            Ok(())
        })
        .await
    }
    pub async fn auto_policy_valid(&self, source: SourceEvent) -> anyhow::Result<bool> {
        self.run(move |db| auto_policy_valid(db, &source)).await
    }
}
pub(crate) fn auto_policy_valid(db: &Connection, source: &SourceEvent) -> anyhow::Result<bool> {
    let active: bool = db.query_row(
        "SELECT status='active' FROM developers WHERE id=?1",
        [source.policy.owner_developer_id.to_string()],
        |r| r.get(0),
    )?;
    if !active {
        return Ok(false);
    }
    let current = project(db, source.project_id)?;
    Ok(current.is_some_and(|p| {
        p.status == ProjectStatus::Active
            && p.policy_version == source.policy.policy_version
            && p.settings.auto_publish_channel == source.policy.settings.auto_publish_channel
            && p.settings.auto_publish_channel.is_some()
            && (!p.settings.auto_publish_tags_only || source.trigger == TriggerType::WebhookTag)
    }))
}
pub(crate) fn auto_publish_valid(db: &Connection, build: BuildId) -> anyhow::Result<bool> {
    let raw:Option<String>=db.query_row("SELECT e.record FROM source_events e WHERE e.build_id=?1 AND e.auto_publish_state='queued'",[build.to_string()],|r|r.get(0)).optional()?;
    match raw {
        Some(raw) => auto_policy_valid(db, &serde_json::from_str(&raw)?),
        None => Ok(true),
    }
}
