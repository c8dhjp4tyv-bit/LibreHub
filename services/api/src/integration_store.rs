//! Durable integration state: trusted CI identities, federated credentials, webhook
//! subscriptions, the transactional outbox and the outbound delivery queue.
use crate::{
    auth::Secret,
    platform_store::{PlatformError, audit},
    store::Store,
};
use chrono::{DateTime, Utc};
use librehub_automation::oidc::{self, GithubClaims, GithubIdentityPolicy};
use librehub_common::*;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn now_s() -> String {
    Utc::now().to_rfc3339()
}
fn t(raw: &str) -> anyhow::Result<Timestamp> {
    Ok(raw.parse()?)
}

/// Integration audit rows hold IDs and result codes only; never tokens or secrets.
pub fn integration_audit(
    db: &Connection,
    limit: usize,
    project: Option<ProjectId>,
    actor: &str,
    action: &str,
    target: &str,
    result: &str,
) -> anyhow::Result<()> {
    db.execute(
        "INSERT INTO integration_audit_events(project_id,actor,action,target_id,timestamp,result) VALUES(?1,?2,?3,?4,?5,?6)",
        params![project.map(|p| p.to_string()), actor, action, target, now_s(), result],
    )?;
    if let Some(project) = project {
        db.execute(
            "DELETE FROM integration_audit_events WHERE project_id=?1 AND id NOT IN (SELECT id FROM integration_audit_events WHERE project_id=?1 ORDER BY id DESC LIMIT ?2)",
            params![project.to_string(), limit as i64],
        )?;
    }
    Ok(())
}

pub fn fingerprint(secret: &str) -> String {
    Sha256::digest(secret.as_bytes())
        .iter()
        .take(6)
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[derive(Debug)]
pub struct ExchangeGrant {
    pub token: Secret,
    pub token_id: TokenId,
    pub expires_at: Timestamp,
    pub scopes: Vec<Scope>,
    pub connection_id: IntegrationId,
    pub project_id: ProjectId,
}
/// Why a verified GitHub identity was refused a LibreHub credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeDenied(pub &'static str);
impl std::fmt::Display for ExchangeDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ExchangeDenied {}

fn read_connection(db: &Connection, id: &str) -> anyhow::Result<Option<IntegrationConnection>> {
    type Row = (
        String,
        String,
        String,
        String,
        String,
        String,
        bool,
        String,
        String,
        Option<String>,
    );
    let row: Option<Row> = db
        .query_row(
            "SELECT id,project_id,kind,name,policy,fingerprint,enabled,created_at,updated_at,revoked_at FROM integration_connections WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?)),
        )
        .optional()?;
    row.map(
        |(id, project, kind, name, policy, fp, enabled, created, updated, revoked)| {
            Ok(IntegrationConnection {
                id: id.parse()?,
                project_id: project.parse()?,
                kind,
                name,
                policy: serde_json::from_str(&policy)?,
                fingerprint: fp,
                enabled,
                created_at: t(&created)?,
                updated_at: t(&updated)?,
                revoked_at: revoked.map(|r| t(&r)).transpose()?,
            })
        },
    )
    .transpose()
}

#[derive(Debug, Clone)]
pub struct OutboxEvent {
    pub seq: i64,
    pub event_id: EventId,
    pub project_id: ProjectId,
    pub event_type: String,
    pub subject_id: String,
    pub data: Value,
    pub origin_kind: Option<String>,
    pub origin_run_id: Option<String>,
    pub correlation_id: Option<String>,
    pub chain_depth: Option<u32>,
    pub created_at: Timestamp,
}
#[derive(Debug, Clone)]
pub struct Origin {
    pub kind: String,
    pub run_id: Option<String>,
    pub correlation_id: String,
    pub chain_depth: u32,
}
#[derive(Debug, Clone)]
pub struct NewDelivery {
    pub id: DeliveryId,
    pub webhook_id: WebhookId,
    pub payload: Vec<u8>,
}
#[derive(Debug, Clone)]
pub struct SubscriptionTarget {
    pub id: WebhookId,
    pub event_types: Vec<String>,
    pub exclude_origins: Vec<String>,
}
#[derive(Debug, Clone)]
pub struct DueDelivery {
    pub id: DeliveryId,
    pub webhook_id: WebhookId,
    pub project_id: ProjectId,
    pub event_id: EventId,
    pub event_type: String,
    pub payload: Vec<u8>,
    pub attempt: u32,
    pub url: String,
    pub cipher: Vec<u8>,
}

/// Origin of a build, derived from its M3 source event: automation runs carry their
/// correlation and chain depth; webhooks and API calls are labelled by their trigger.
fn build_origin(db: &Connection, build_id: &str) -> anyhow::Result<Option<Origin>> {
    let row: Option<(String, Option<String>)> = db
        .query_row(
            "SELECT json_extract(record,'$.trigger'),intent_key FROM source_events WHERE build_id=?1",
            [build_id],
            |r| Ok((r.get::<_, Option<String>>(0)?.unwrap_or_default(), r.get(1)?)),
        )
        .optional()?;
    let Some((trigger, intent)) = row else {
        return Ok(None);
    };
    if let Some(run_id) = intent
        .as_deref()
        .and_then(|k| k.strip_prefix("automation-run:"))
    {
        let run: Option<(String, u32)> = db
            .query_row(
                "SELECT correlation_id,chain_depth FROM automation_runs WHERE id=?1",
                [run_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((correlation, depth)) = run {
            return Ok(Some(Origin {
                kind: "automation".into(),
                run_id: Some(run_id.into()),
                correlation_id: correlation,
                chain_depth: depth,
            }));
        }
    }
    let kind = match trigger.as_str() {
        "webhook_push" | "webhook_tag" => "webhook",
        _ => "manual",
    };
    Ok(Some(Origin {
        kind: kind.into(),
        run_id: None,
        correlation_id: build_id.to_owned(),
        chain_depth: 0,
    }))
}
fn resolve_origin(db: &Connection, event: &OutboxEvent) -> anyhow::Result<Origin> {
    if let (Some(kind), Some(correlation), Some(depth)) =
        (&event.origin_kind, &event.correlation_id, event.chain_depth)
    {
        return Ok(Origin {
            kind: kind.clone(),
            run_id: event.origin_run_id.clone(),
            correlation_id: correlation.clone(),
            chain_depth: depth,
        });
    }
    let build: Option<String> = match event.event_type.split('.').next().unwrap_or("") {
        "build" => Some(event.subject_id.clone()),
        "source_event" => db
            .query_row(
                "SELECT build_id FROM source_events WHERE id=?1",
                [&event.subject_id],
                |r| r.get(0),
            )
            .optional()?,
        "publication" | "security" => db
            .query_row(
                "SELECT build_id FROM publishes WHERE id=?1",
                [&event.subject_id],
                |r| r.get(0),
            )
            .optional()?,
        "attestation" => {
            let direct: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM builds WHERE id=?1)",
                [&event.subject_id],
                |r| r.get(0),
            )?;
            if direct {
                Some(event.subject_id.clone())
            } else {
                db.query_row(
                    "SELECT build_id FROM publishes WHERE id=?1",
                    [&event.subject_id],
                    |r| r.get(0),
                )
                .optional()?
            }
        }
        _ => None,
    };
    if let Some(build) = build
        && let Some(origin) = build_origin(db, &build)?
    {
        return Ok(origin);
    }
    Ok(Origin {
        kind: "system".into(),
        run_id: None,
        correlation_id: event.event_id.to_string(),
        chain_depth: 0,
    })
}

impl Store {
    // ------------------------------------------------------------ connections
    pub async fn create_connection(
        &self,
        project: ProjectId,
        owner: DeveloperId,
        name: String,
        policy: GithubIdentityPolicy,
    ) -> anyhow::Result<IntegrationConnection> {
        policy
            .validate()
            .map_err(|_| PlatformError("invalid_request"))?;
        if name.trim().is_empty() || name.len() > 80 || name.chars().any(char::is_control) {
            return Err(PlatformError("invalid_request").into());
        }
        let policy = policy.normalized();
        let limits = self.automation_limits.clone();
        self.run(move |db| {
            let tx = db.transaction()?;
            let (p, _) = project_owned(&tx, project, owner)?;
            if p.status != ProjectStatus::Active {
                return Err(PlatformError("project_not_active").into());
            }
            let count: i64 = tx.query_row(
                "SELECT count(*) FROM integration_connections WHERE project_id=?1 AND revoked_at IS NULL",
                [project.to_string()],
                |r| r.get(0),
            )?;
            if count >= limits.connections_per_project as i64 {
                return Err(PlatformError("integration_limit_exceeded").into());
            }
            let duplicate: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM integration_connections WHERE project_id=?1 AND repository_id=?2 AND revoked_at IS NULL)",
                params![project.to_string(), policy.repository_id],
                |r| r.get(0),
            )?;
            if duplicate {
                return Err(PlatformError("integration_exists").into());
            }
            let id = IntegrationId::new();
            let now = now_s();
            tx.execute(
                "INSERT INTO integration_connections(id,project_id,owner,kind,name,policy,repository_id,repository_owner_id,fingerprint,created_at,updated_at) VALUES(?1,?2,?3,'github_oidc',?4,?5,?6,?7,?8,?9,?9)",
                params![id.to_string(), project.to_string(), owner.to_string(), name, serde_json::to_string(&policy)?, policy.repository_id, policy.repository_owner_id, policy.fingerprint(), now],
            )?;
            audit(&tx, owner, "integration.created", Some(project), &id.to_string(), "succeeded")?;
            integration_audit(&tx, limits.integration_audit_per_project, Some(project), &owner.to_string(), "integration.created", &id.to_string(), "succeeded")?;
            let out = read_connection(&tx, &id.to_string())?.ok_or(PlatformError("integration_not_found"))?;
            tx.commit()?;
            Ok(out)
        })
        .await
    }
    pub async fn connections(
        &self,
        project: ProjectId,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<Vec<IntegrationConnection>> {
        self.run(move |db| {
            let ids: Vec<String> = db
                .prepare("SELECT id FROM integration_connections WHERE project_id=?1 ORDER BY created_at DESC, id LIMIT ?2 OFFSET ?3")?
                .query_map(params![project.to_string(), limit as i64, offset as i64], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            ids.iter().map(|id| read_connection(db, id)?.ok_or_else(|| anyhow::anyhow!("connection vanished"))).collect()
        })
        .await
    }
    pub async fn connection(
        &self,
        project: ProjectId,
        id: IntegrationId,
    ) -> anyhow::Result<Option<IntegrationConnection>> {
        self.run(move |db| {
            Ok(read_connection(db, &id.to_string())?.filter(|c| c.project_id == project))
        })
        .await
    }
    pub async fn update_connection(
        &self,
        project: ProjectId,
        id: IntegrationId,
        owner: DeveloperId,
        policy: Option<GithubIdentityPolicy>,
        enabled: Option<bool>,
    ) -> anyhow::Result<IntegrationConnection> {
        if let Some(policy) = &policy {
            policy
                .validate()
                .map_err(|_| PlatformError("invalid_request"))?;
        }
        let limits = self.automation_limits.clone();
        self.run(move |db| {
            let tx = db.transaction()?;
            project_owned(&tx, project, owner)?;
            let current = read_connection(&tx, &id.to_string())?
                .filter(|c| c.project_id == project && c.revoked_at.is_none())
                .ok_or(PlatformError("integration_not_found"))?;
            let mut revoke_tokens = enabled == Some(false);
            let policy_json = match &policy {
                Some(p) => {
                    let existing: GithubIdentityPolicy =
                        serde_json::from_value(current.policy.clone())?;
                    if existing.repository_id != p.repository_id {
                        // Trusting a different repository is a new connection, not an edit.
                        return Err(PlatformError("invalid_request").into());
                    }
                    let next = p.normalized();
                    // Narrowing any part of the trusted identity (branch, workflow, environment,
                    // event, owner, permission or lifetime) must not leave credentials minted under
                    // the old policy valid. An unchanged policy has no side effects.
                    let mut trusted_existing = existing.normalized();
                    let mut trusted_next = next.clone();
                    // Repository names are display-only; numeric IDs establish trust.
                    trusted_existing.repository = None;
                    trusted_next.repository = None;
                    revoke_tokens |= trusted_existing != trusted_next;
                    serde_json::to_string(&next)?
                }
                None => current.policy.to_string(),
            };
            tx.execute(
                "UPDATE integration_connections SET policy=?2,enabled=?3,updated_at=?4 WHERE id=?1",
                params![
                    id.to_string(),
                    policy_json,
                    enabled.unwrap_or(current.enabled),
                    now_s()
                ],
            )?;
            if revoke_tokens {
                // Only this connection's credentials: the match is on the integration identity.
                let revoked = tx.execute(
                    "UPDATE api_tokens SET record=json_set(record,'$.revoked_at',?2) WHERE json_extract(record,'$.integration_id')=?1 AND json_extract(record,'$.revoked_at') IS NULL",
                    params![id.to_string(), now_s()],
                )?;
                if revoked > 0 {
                    // Counts only: never token identifiers or secrets.
                    integration_audit(
                        &tx,
                        limits.integration_audit_per_project,
                        Some(project),
                        &owner.to_string(),
                        "integration.credentials_revoked",
                        &id.to_string(),
                        &format!("revoked:{revoked}"),
                    )?;
                }
            }
            let action = if enabled == Some(false) {
                "integration.disabled"
            } else {
                "integration.updated"
            };
            audit(
                &tx,
                owner,
                action,
                Some(project),
                &id.to_string(),
                "succeeded",
            )?;
            integration_audit(
                &tx,
                limits.integration_audit_per_project,
                Some(project),
                &owner.to_string(),
                action,
                &id.to_string(),
                "succeeded",
            )?;
            let out = read_connection(&tx, &id.to_string())?
                .ok_or(PlatformError("integration_not_found"))?;
            tx.commit()?;
            Ok(out)
        })
        .await
    }
    /// Revocation also revokes every credential minted through the connection.
    pub async fn revoke_connection(
        &self,
        project: ProjectId,
        id: IntegrationId,
        owner: DeveloperId,
    ) -> anyhow::Result<()> {
        let limits = self.automation_limits.clone();
        self.run(move |db| {
            let tx = db.transaction()?;
            project_owned(&tx, project, owner)?;
            let current = read_connection(&tx, &id.to_string())?
                .filter(|c| c.project_id == project)
                .ok_or(PlatformError("integration_not_found"))?;
            if current.revoked_at.is_some() {
                return Ok(());
            }
            let now = now_s();
            tx.execute("UPDATE integration_connections SET enabled=0,revoked_at=?2,updated_at=?2 WHERE id=?1", params![id.to_string(), now])?;
            tx.execute(
                "UPDATE api_tokens SET record=json_set(record,'$.revoked_at',?2) WHERE json_extract(record,'$.integration_id')=?1 AND json_extract(record,'$.revoked_at') IS NULL",
                params![id.to_string(), now],
            )?;
            audit(&tx, owner, "integration.revoked", Some(project), &id.to_string(), "succeeded")?;
            integration_audit(&tx, limits.integration_audit_per_project, Some(project), &owner.to_string(), "integration.revoked", &id.to_string(), "succeeded")?;
            tx.commit()?;
            Ok(())
        })
        .await
    }

    // ------------------------------------------------------------ OIDC exchange
    /// Authorize a *verified* GitHub identity against the project's deny-by-default policies and
    /// mint a short-lived credential bound to that project. The token's `jti` is single use.
    pub async fn oidc_exchange(
        &self,
        issuer: String,
        project: ProjectId,
        claims: GithubClaims,
    ) -> anyhow::Result<Result<ExchangeGrant, ExchangeDenied>> {
        let limits = self.automation_limits.clone();
        self.run(move |db| {
            let tx = db.transaction()?;
            let actor = format!("github:{}:{}:run-{}", claims.repository_owner_id, claims.repository_id, claims.run_id);
            let raw: Option<String> = tx.query_row("SELECT record FROM projects WHERE id=?1", [project.to_string()], |r| r.get(0)).optional()?;
            let Some(raw) = raw else {
                return Ok(Err(ExchangeDenied("oidc_exchange_denied")));
            };
            let p: Project = serde_json::from_str(&raw)?;
            let deny = |tx: rusqlite::Transaction, reason: &'static str| -> anyhow::Result<Result<ExchangeGrant, ExchangeDenied>> {
                audit(&tx, p.owner_developer_id, "oidc.exchange_denied", Some(project), &claims.run_id, reason)?;
                integration_audit(&tx, limits.integration_audit_per_project, Some(project), &actor, "oidc.exchange_denied", &claims.repository_id, reason)?;
                tx.commit()?;
                Ok(Err(ExchangeDenied("oidc_exchange_denied")))
            };
            let developer_active: bool = tx.query_row("SELECT status='active' FROM developers WHERE id=?1", [p.owner_developer_id.to_string()], |r| r.get(0))?;
            if p.status != ProjectStatus::Active || !developer_active {
                return deny(tx, "project_not_active");
            }
            let hour_ago = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
            let recent: i64 = tx.query_row("SELECT count(*) FROM oidc_exchanges WHERE project_id=?1 AND exchanged_at>?2", params![project.to_string(), hour_ago], |r| r.get(0))?;
            if recent >= limits.oidc_exchanges_per_hour as i64 {
                return deny(tx, "exchange_rate_limited");
            }
            let candidates: Vec<String> = tx
                .prepare("SELECT id FROM integration_connections WHERE project_id=?1 AND repository_id=?2 AND enabled=1 AND revoked_at IS NULL")?
                .query_map(params![project.to_string(), claims.repository_id], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            if candidates.is_empty() {
                return deny(tx, "no_trusted_identity");
            }
            let mut selected = None;
            let mut first_denial = None;
            for candidate in candidates {
                let Some(connection) = read_connection(&tx, &candidate)? else { continue };
                let Ok(policy) = serde_json::from_value::<GithubIdentityPolicy>(connection.policy.clone()) else { continue };
                match oidc::authorize(&claims, &policy) {
                    Ok(scopes) if !scopes.is_empty() => {
                        selected = Some((connection, policy, scopes));
                        break;
                    }
                    Ok(_) => first_denial = first_denial.or(Some("no_permissions")),
                    Err(denial) => first_denial = first_denial.or(Some(denial.code())),
                }
            }
            let Some((connection, policy, scopes)) = selected else {
                return deny(tx, first_denial.unwrap_or("no_trusted_identity"));
            };
            // Single-use token IDs defeat replay of a captured identity token.
            let expires_exchange = DateTime::from_timestamp(claims.expires_at, 0).unwrap_or_else(Utc::now) + chrono::Duration::minutes(5);
            tx.execute("DELETE FROM oidc_exchanges WHERE expires_at<?1 AND exchanged_at<=?2", params![(Utc::now() - chrono::Duration::minutes(5)).to_rfc3339(), hour_ago])?;
            let replay: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM oidc_exchanges WHERE issuer=?1 AND jti=?2)", params![issuer, claims.jti], |r| r.get(0))?;
            if replay {
                return deny(tx, "token_replayed");
            }
            tx.execute("DELETE FROM api_tokens WHERE json_extract(record,'$.expires_at') IS NOT NULL AND json_extract(record,'$.expires_at')<?1", [(Utc::now() - chrono::Duration::days(1)).to_rfc3339()])?;
            let live: i64 = tx.query_row(
                "SELECT count(*) FROM api_tokens WHERE json_extract(record,'$.project_id')=?1 AND json_extract(record,'$.revoked_at') IS NULL AND json_extract(record,'$.expires_at')>?2",
                params![project.to_string(), now_s()],
                |r| r.get(0),
            )?;
            if live >= 64 {
                return deny(tx, "credential_limit");
            }
            let token_id = TokenId::new();
            let secret = crate::auth::random_secret()?;
            let raw = Secret(format!("librehub_{token_id}_{}", secret.0));
            let hash = Sha256::digest(raw.0.as_bytes()).to_vec();
            let now = Utc::now();
            let expires_at = now + chrono::Duration::seconds(policy.token_ttl_seconds as i64);
            let record = ApiToken {
                id: token_id,
                developer_id: p.owner_developer_id,
                name: format!("github-oidc:{}", claims.repository_id),
                scopes: scopes.clone(),
                created_at: now,
                last_used_at: None,
                revoked_at: None,
                expires_at: Some(expires_at),
                project_id: Some(project),
                integration_id: Some(connection.id),
            };
            tx.execute(
                "INSERT INTO api_tokens(id,developer_id,hash,record) VALUES(?1,?2,?3,?4)",
                params![token_id.to_string(), p.owner_developer_id.to_string(), hash, serde_json::to_string(&record)?],
            )?;
            let stored_claims = json!({
                "repository": claims.repository, "repository_id": claims.repository_id,
                "repository_owner_id": claims.repository_owner_id, "ref": claims.git_ref, "sha": claims.sha,
                "event_name": claims.event_name, "workflow_ref": claims.workflow_ref,
                "run_id": claims.run_id, "run_attempt": claims.run_attempt, "actor_id": claims.actor_id,
                "environment": claims.environment,
            });
            tx.execute(
                "INSERT INTO oidc_exchanges(issuer,jti,project_id,connection_id,token_id,claims,exchanged_at,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![issuer, claims.jti, project.to_string(), connection.id.to_string(), token_id.to_string(), stored_claims.to_string(), now.to_rfc3339(), expires_exchange.to_rfc3339()],
            )?;
            audit(&tx, p.owner_developer_id, "oidc.exchange_succeeded", Some(project), &token_id.to_string(), "succeeded")?;
            integration_audit(&tx, limits.integration_audit_per_project, Some(project), &actor, "oidc.exchange_succeeded", &token_id.to_string(), "succeeded")?;
            tx.commit()?;
            Ok(Ok(ExchangeGrant { token: raw, token_id, expires_at, scopes, connection_id: connection.id, project_id: project }))
        })
        .await
    }
    /// The verified claims a federated credential was minted from.
    pub async fn exchange_claims(&self, token: TokenId) -> anyhow::Result<Option<Value>> {
        self.run(move |db| {
            let raw: Option<String> = db
                .query_row(
                    "SELECT claims FROM oidc_exchanges WHERE token_id=?1",
                    [token.to_string()],
                    |r| r.get(0),
                )
                .optional()?;
            raw.map(|r| serde_json::from_str(&r).map_err(Into::into))
                .transpose()
        })
        .await
    }
    pub async fn integration_audit_events(
        &self,
        project: ProjectId,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<Vec<Value>> {
        self.run(move |db| {
            Ok(db
                .prepare("SELECT id,actor,action,target_id,timestamp,result FROM integration_audit_events WHERE project_id=?1 ORDER BY id DESC LIMIT ?2 OFFSET ?3")?
                .query_map(params![project.to_string(), limit as i64, offset as i64], |r| {
                    Ok(json!({"id":r.get::<_,i64>(0)?,"actor":r.get::<_,String>(1)?,"action":r.get::<_,String>(2)?,"target_id":r.get::<_,String>(3)?,"timestamp":r.get::<_,String>(4)?,"result":r.get::<_,String>(5)?}))
                })?
                .collect::<Result<_, _>>()?)
        })
        .await
    }

    // ------------------------------------------------------------ webhook subscriptions
    #[allow(clippy::too_many_arguments)]
    pub async fn create_webhook(
        &self,
        project: ProjectId,
        owner: DeveloperId,
        id: WebhookId,
        url: String,
        description: String,
        event_types: Vec<String>,
        exclude_origins: Vec<String>,
        cipher: Vec<u8>,
        secret_fingerprint: String,
    ) -> anyhow::Result<WebhookView> {
        let limits = self.automation_limits.clone();
        self.run(move |db| {
            let tx = db.transaction()?;
            let (p, _) = project_owned(&tx, project, owner)?;
            if p.status != ProjectStatus::Active {
                return Err(PlatformError("project_not_active").into());
            }
            let count: i64 = tx.query_row("SELECT count(*) FROM webhook_subscriptions WHERE project_id=?1", [project.to_string()], |r| r.get(0))?;
            if count >= limits.webhooks_per_project as i64 {
                return Err(PlatformError("webhook_limit_exceeded").into());
            }
            let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM webhook_subscriptions WHERE project_id=?1 AND url=?2)", params![project.to_string(), url], |r| r.get(0))?;
            if exists {
                return Err(PlatformError("webhook_exists").into());
            }
            let now = now_s();
            tx.execute(
                "INSERT INTO webhook_subscriptions(id,project_id,owner,url,description,secret,secret_fingerprint,event_types,exclude_origins,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10)",
                params![id.to_string(), project.to_string(), owner.to_string(), url, description, cipher, secret_fingerprint, serde_json::to_string(&event_types)?, serde_json::to_string(&exclude_origins)?, now],
            )?;
            audit(&tx, owner, "integration.created", Some(project), &id.to_string(), "webhook")?;
            integration_audit(&tx, limits.integration_audit_per_project, Some(project), &owner.to_string(), "integration.created", &id.to_string(), "webhook")?;
            let out = read_webhook(&tx, &id.to_string())?.ok_or(PlatformError("webhook_not_found"))?;
            tx.commit()?;
            Ok(out)
        })
        .await
    }
    pub async fn webhooks(
        &self,
        project: ProjectId,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<Vec<WebhookView>> {
        self.run(move |db| {
            let ids: Vec<String> = db
                .prepare("SELECT id FROM webhook_subscriptions WHERE project_id=?1 ORDER BY created_at, id LIMIT ?2 OFFSET ?3")?
                .query_map(params![project.to_string(), limit as i64, offset as i64], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            ids.iter().map(|id| read_webhook(db, id)?.ok_or_else(|| anyhow::anyhow!("webhook vanished"))).collect()
        })
        .await
    }
    pub async fn webhook(
        &self,
        project: ProjectId,
        id: WebhookId,
    ) -> anyhow::Result<Option<WebhookView>> {
        self.run(move |db| {
            Ok(read_webhook(db, &id.to_string())?.filter(|w| w.project_id == project))
        })
        .await
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn update_webhook(
        &self,
        project: ProjectId,
        id: WebhookId,
        owner: DeveloperId,
        url: Option<String>,
        description: Option<String>,
        event_types: Option<Vec<String>>,
        exclude_origins: Option<Vec<String>>,
        enabled: Option<bool>,
    ) -> anyhow::Result<WebhookView> {
        let limits = self.automation_limits.clone();
        self.run(move |db| {
            let tx = db.transaction()?;
            project_owned(&tx, project, owner)?;
            let current = read_webhook(&tx, &id.to_string())?.filter(|w| w.project_id == project).ok_or(PlatformError("webhook_not_found"))?;
            let url = url.unwrap_or(current.url.clone());
            if url != current.url {
                let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM webhook_subscriptions WHERE project_id=?1 AND url=?2)", params![project.to_string(), url], |r| r.get(0))?;
                if exists {
                    return Err(PlatformError("webhook_exists").into());
                }
            }
            let enabled = enabled.unwrap_or(current.enabled);
            tx.execute(
                "UPDATE webhook_subscriptions SET url=?2,description=?3,event_types=?4,exclude_origins=?5,enabled=?6,disabled_reason=CASE WHEN ?6=1 THEN NULL ELSE COALESCE(disabled_reason,'disabled_by_owner') END,updated_at=?7 WHERE id=?1",
                params![
                    id.to_string(), url, description.unwrap_or(current.description),
                    serde_json::to_string(&event_types.unwrap_or(current.event_types))?,
                    serde_json::to_string(&exclude_origins.unwrap_or(current.exclude_origins))?,
                    enabled, now_s()
                ],
            )?;
            let action = if enabled { "integration.updated" } else { "integration.disabled" };
            audit(&tx, owner, action, Some(project), &id.to_string(), "webhook")?;
            integration_audit(&tx, limits.integration_audit_per_project, Some(project), &owner.to_string(), action, &id.to_string(), "webhook")?;
            let out = read_webhook(&tx, &id.to_string())?.ok_or(PlatformError("webhook_not_found"))?;
            tx.commit()?;
            Ok(out)
        })
        .await
    }
    pub async fn delete_webhook(
        &self,
        project: ProjectId,
        id: WebhookId,
        owner: DeveloperId,
    ) -> anyhow::Result<()> {
        let limits = self.automation_limits.clone();
        self.run(move |db| {
            let tx = db.transaction()?;
            project_owned(&tx, project, owner)?;
            read_webhook(&tx, &id.to_string())?.filter(|w| w.project_id == project).ok_or(PlatformError("webhook_not_found"))?;
            tx.execute("DELETE FROM integration_attempts WHERE delivery_id IN (SELECT id FROM integration_deliveries WHERE webhook_id=?1)", [id.to_string()])?;
            tx.execute("DELETE FROM integration_deliveries WHERE webhook_id=?1", [id.to_string()])?;
            tx.execute("DELETE FROM webhook_subscriptions WHERE id=?1", [id.to_string()])?;
            audit(&tx, owner, "integration.revoked", Some(project), &id.to_string(), "webhook")?;
            integration_audit(&tx, limits.integration_audit_per_project, Some(project), &owner.to_string(), "integration.revoked", &id.to_string(), "webhook")?;
            tx.commit()?;
            Ok(())
        })
        .await
    }
    pub async fn rotate_webhook_secret(
        &self,
        project: ProjectId,
        id: WebhookId,
        owner: DeveloperId,
        cipher: Vec<u8>,
        fp: String,
    ) -> anyhow::Result<WebhookView> {
        let limits = self.automation_limits.clone();
        self.run(move |db| {
            let tx = db.transaction()?;
            project_owned(&tx, project, owner)?;
            read_webhook(&tx, &id.to_string())?.filter(|w| w.project_id == project).ok_or(PlatformError("webhook_not_found"))?;
            tx.execute("UPDATE webhook_subscriptions SET secret=?2,secret_fingerprint=?3,secret_rotated_at=?4,updated_at=?4 WHERE id=?1", params![id.to_string(), cipher, fp, now_s()])?;
            audit(&tx, owner, "integration.secret_rotated", Some(project), &id.to_string(), "webhook")?;
            integration_audit(&tx, limits.integration_audit_per_project, Some(project), &owner.to_string(), "integration.secret_rotated", &id.to_string(), "webhook")?;
            let out = read_webhook(&tx, &id.to_string())?.ok_or(PlatformError("webhook_not_found"))?;
            tx.commit()?;
            Ok(out)
        })
        .await
    }
    pub async fn webhook_cipher(&self, id: WebhookId) -> anyhow::Result<Option<Vec<u8>>> {
        self.run(move |db| {
            Ok(db
                .query_row(
                    "SELECT secret FROM webhook_subscriptions WHERE id=?1",
                    [id.to_string()],
                    |r| r.get(0),
                )
                .optional()?)
        })
        .await
    }

    // ------------------------------------------------------------ outbox & deliveries
    /// Read events in sequence for one independent consumer. A malformed *stored* event
    /// is quarantined with its original row retained for operator inspection. Advance
    /// only that consumer's cursor, and only when all preceding valid events have
    /// already been handed back for transactional processing. Never skip valid events.
    pub async fn outbox_batch(
        &self,
        consumer: &'static str,
        limit: usize,
    ) -> anyhow::Result<Vec<OutboxEvent>> {
        self.run(move |db| {
            let cursor: i64 = db.query_row(
                "SELECT COALESCE((SELECT last_seq FROM outbox_cursors WHERE consumer=?1),0)",
                [consumer],
                |r| r.get(0),
            )?;
            type Row = (
                i64, String, String, String, String, String,
                Option<String>, Option<String>, Option<String>, Option<u32>, String,
            );
            let rows: Vec<Row> = db
                .prepare("SELECT seq,event_id,project_id,event_type,subject_id,data,origin_kind,origin_run_id,correlation_id,chain_depth,created_at FROM event_outbox WHERE seq>?1 ORDER BY seq LIMIT ?2")?
                .query_map(params![cursor, limit as i64], |r| {
                    Ok((
                        r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?,
                        r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?,
                        r.get(8)?, r.get(9)?, r.get(10)?,
                    ))
                })?
                .collect::<Result<_, _>>()?;

            let mut valid = Vec::with_capacity(rows.len());
            for (seq, event, project, kind, subject, data, ok, orun, corr, depth, at) in rows {
                let decoded = (|| -> anyhow::Result<OutboxEvent> {
                    Ok(OutboxEvent {
                        seq,
                        event_id: event.parse()?,
                        project_id: project.parse()?,
                        event_type: kind,
                        subject_id: subject,
                        data: serde_json::from_str(&data)?,
                        origin_kind: ok,
                        origin_run_id: orun,
                        correlation_id: corr,
                        chain_depth: depth,
                        created_at: t(&at)?,
                    })
                })();
                match decoded {
                    Ok(item) => valid.push(item),
                    Err(error) => {
                        // Previous valid events must be consumed (and individually
                        // acknowledged) before this sequence is quarantined.
                        if !valid.is_empty() {
                            break;
                        }
                        let tx = db.transaction()?;
                        tx.execute(
                            "INSERT OR IGNORE INTO outbox_quarantine(consumer,seq,reason,quarantined_at) VALUES(?1,?2,'invalid_event_encoding',?3)",
                            params![consumer, seq, now_s()],
                        )?;
                        tx.execute(
                            "INSERT INTO outbox_cursors(consumer,last_seq) VALUES(?1,?2) ON CONFLICT(consumer) DO UPDATE SET last_seq=MAX(last_seq,excluded.last_seq)",
                            params![consumer, seq],
                        )?;
                        tx.commit()?;
                        tracing::error!(
                            consumer, seq, error = %error,
                            "Invalid durable outbox event quarantined; original event retained for operator inspection"
                        );
                        return Ok(Vec::new());
                    }
                }
            }
            Ok(valid)
        })
        .await
    }
    pub async fn advance_outbox(&self, consumer: &'static str, seq: i64) -> anyhow::Result<()> {
        self.run(move |db| {
            db.execute(
                "INSERT INTO outbox_cursors(consumer,last_seq) VALUES(?1,?2) ON CONFLICT(consumer) DO UPDATE SET last_seq=MAX(last_seq,excluded.last_seq)",
                params![consumer, seq],
            )?;
            Ok(())
        })
        .await
    }
    /// Resolve origin/subscriptions for an event and create delivery rows *atomically with the
    /// cursor advance*. A crash re-reads the event; `(webhook,event)` uniqueness absorbs it.
    pub async fn fan_out(&self, event: OutboxEvent, max_chain_depth: u32) -> anyhow::Result<usize> {
        self.run(move |db| {
            let tx = db.transaction()?;
            let origin = resolve_origin(&tx, &event)?;
            let mut created = 0;
            if origin.chain_depth < max_chain_depth {
                let targets: Vec<SubscriptionTarget> = tx
                    .prepare("SELECT id,event_types,exclude_origins FROM webhook_subscriptions WHERE project_id=?1 AND enabled=1")?
                    .query_map([event.project_id.to_string()], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))?
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .filter_map(|(id, types, excl)| {
                        Some(SubscriptionTarget { id: id.parse().ok()?, event_types: serde_json::from_str(&types).ok()?, exclude_origins: serde_json::from_str(&excl).ok()? })
                    })
                    .collect();
                for target in targets {
                    if !target.event_types.iter().any(|e| e == &event.event_type) || target.exclude_origins.contains(&origin.kind) {
                        continue;
                    }
                    let delivery = DeliveryId::new();
                    let payload = envelope(&event, &origin, delivery);
                    let inserted = tx.execute(
                        "INSERT OR IGNORE INTO integration_deliveries(id,webhook_id,project_id,event_id,event_type,payload,status,next_attempt_at,created_at) VALUES(?1,?2,?3,?4,?5,?6,'pending',?7,?7)",
                        params![delivery.to_string(), target.id.to_string(), event.project_id.to_string(), event.event_id.to_string(), event.event_type, payload, now_s()],
                    )?;
                    created += inserted;
                }
            } else {
                integration_audit(&tx, 10_000, Some(event.project_id), "system", "webhook.chain_limit", &event.event_id.to_string(), "suppressed")?;
            }
            tx.execute(
                "INSERT INTO outbox_cursors(consumer,last_seq) VALUES('webhooks',?1) ON CONFLICT(consumer) DO UPDATE SET last_seq=MAX(last_seq,excluded.last_seq)",
                [event.seq],
            )?;
            tx.commit()?;
            Ok(created)
        })
        .await
    }
    /// Startup recovery: every `delivering` row belongs to a process that no longer exists.
    pub async fn recover_deliveries(&self, max_attempts: u32) -> anyhow::Result<usize> {
        self.reclaim(
            max_attempts,
            true,
            "process_restarted",
            std::time::Duration::ZERO,
        )
        .await
    }
    /// Lease recovery for attempts abandoned inside a running process: a task that panicked or
    /// was cancelled, or whose result could not be written. Their lease has expired by now.
    pub async fn reclaim_expired_deliveries(
        &self,
        max_attempts: u32,
        backoff_base: std::time::Duration,
    ) -> anyhow::Result<usize> {
        self.reclaim(max_attempts, false, "lease_expired", backoff_base)
            .await
    }
    async fn reclaim(
        &self,
        max_attempts: u32,
        all: bool,
        reason: &'static str,
        backoff_base: std::time::Duration,
    ) -> anyhow::Result<usize> {
        let limits = self.automation_limits.clone();
        self.run(move |db| {
            let tx = db.transaction()?;
            let rows: Vec<(String, u32)> = tx
                .prepare("SELECT id,attempts FROM integration_deliveries WHERE status='delivering' AND (?1 OR lease_expires_at IS NULL OR lease_expires_at<=?2)")?
                .query_map(params![all, now_s()], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?;
            for (id, attempt) in &rows {
                // After a restart the work is due at once. Within a live process the normal retry
                // schedule applies, so a delivery that keeps dying in-process does not spin.
                let delay = if all {
                    std::time::Duration::ZERO
                } else {
                    librehub_automation::retry::backoff_with(backoff_base, *attempt, 0.5)
                };
                interrupt_row(&tx, id, *attempt, reason, max_attempts, delay, &limits)?;
            }
            tx.commit()?;
            for (id, attempt) in &rows {
                record_interruption(db, id, *attempt, reason);
            }
            Ok(rows.len())
        })
        .await
    }
    /// Make an abandoned attempt due again, or terminal once its attempt budget is spent. The
    /// update is fenced on the attempt number, so a stale recovery cannot overwrite a newer one.
    pub async fn interrupt_delivery(
        &self,
        delivery: DeliveryId,
        attempt: u32,
        reason: &'static str,
        max_attempts: u32,
        delay: std::time::Duration,
    ) -> anyhow::Result<Option<DeliveryStatus>> {
        let limits = self.automation_limits.clone();
        self.run(move |db| {
            let id = delivery.to_string();
            let tx = db.transaction()?;
            let status = interrupt_row(&tx, &id, attempt, reason, max_attempts, delay, &limits)?;
            tx.commit()?;
            if status.is_some() {
                record_interruption(db, &id, attempt, reason);
            }
            Ok(status)
        })
        .await
    }
    /// Claim due deliveries for `lease`. A claimed delivery that is not finished when the lease
    /// expires is recovered by [`Self::reclaim_expired_deliveries`]: at-least-once, same identity.
    pub async fn claim_deliveries(
        &self,
        limit: usize,
        lease: std::time::Duration,
    ) -> anyhow::Result<Vec<DueDelivery>> {
        self.run(move |db| {
            let tx = db.transaction()?;
            type Row = (String, String, String, String, String, Vec<u8>, u32, String, Vec<u8>);
            let rows: Vec<Row> = tx
                .prepare("SELECT d.id,d.webhook_id,d.project_id,d.event_id,d.event_type,d.payload,d.attempts,w.url,w.secret FROM integration_deliveries d JOIN webhook_subscriptions w ON w.id=d.webhook_id WHERE d.status IN ('pending','retry_wait') AND d.next_attempt_at<=?1 AND w.enabled=1 ORDER BY d.next_attempt_at LIMIT ?2")?
                .query_map(params![now_s(), limit as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?)))?
                .collect::<Result<_, _>>()?;
            let lease_until = (Utc::now() + chrono::Duration::from_std(lease)?).to_rfc3339();
            let mut out = vec![];
            for (id, hook, project, event, kind, payload, attempts, url, cipher) in rows {
                tx.execute("UPDATE integration_deliveries SET status='delivering',attempts=attempts+1,lease_expires_at=?2 WHERE id=?1", params![&id, lease_until])?;
                out.push(DueDelivery { id: id.parse()?, webhook_id: hook.parse()?, project_id: project.parse()?, event_id: event.parse()?, event_type: kind, payload, attempt: attempts + 1, url, cipher });
            }
            tx.commit()?;
            Ok(out)
        })
        .await
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn finish_delivery(
        &self,
        delivery: DueDelivery,
        started: DateTime<Utc>,
        duration_ms: u64,
        http_status: Option<u16>,
        outcome: DeliveryOutcome,
        max_attempts: u32,
    ) -> anyhow::Result<FinishResult> {
        let limits = self.automation_limits.clone();
        self.run(move |db| {
            let tx = db.transaction()?;
            let (label, error): (&str, Option<String>) = match &outcome {
                DeliveryOutcome::Delivered => ("delivered", None),
                DeliveryOutcome::Retry { reason, .. } => ("retry", Some((*reason).to_owned())),
                DeliveryOutcome::Permanent { reason } => ("permanent", Some((*reason).to_owned())),
            };
            let status = match outcome {
                DeliveryOutcome::Delivered => DeliveryStatus::Delivered,
                DeliveryOutcome::Permanent { .. } => DeliveryStatus::Failed,
                DeliveryOutcome::Retry { .. } if delivery.attempt >= max_attempts => DeliveryStatus::DeadLetter,
                DeliveryOutcome::Retry { .. } => DeliveryStatus::RetryWait,
            };
            let next = match &outcome {
                DeliveryOutcome::Retry { delay, .. } if status == DeliveryStatus::RetryWait => Utc::now() + chrono::Duration::from_std(*delay).unwrap_or(chrono::Duration::minutes(15)),
                _ => Utc::now(),
            };
            let now = now_s();
            // Fenced on the claimed attempt: a lease that expired and was reclaimed (or a newer
            // attempt) must never be overwritten by this result. Nothing is written in that case.
            let fenced = tx.execute(
                "UPDATE integration_deliveries SET status=?2,next_attempt_at=?3,last_http_status=?4,last_error=?5,lease_expires_at=NULL,delivered_at=CASE WHEN ?2='delivered' THEN ?6 ELSE delivered_at END,finished_at=CASE WHEN ?7 THEN ?6 ELSE finished_at END WHERE id=?1 AND status='delivering' AND attempts=?8",
                params![delivery.id.to_string(), status.as_str(), next.to_rfc3339(), http_status, error, now, status.is_terminal(), delivery.attempt],
            )?;
            if fenced == 0 {
                return Ok(FinishResult::Superseded);
            }
            tx.execute(
                "INSERT INTO integration_attempts(delivery_id,attempt,started_at,duration_ms,http_status,outcome,error) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![delivery.id.to_string(), delivery.attempt, started.to_rfc3339(), duration_ms as i64, http_status, label, error],
            )?;
            if matches!(status, DeliveryStatus::Failed | DeliveryStatus::DeadLetter) {
                let owner: String = tx.query_row("SELECT owner FROM webhook_subscriptions WHERE id=?1", [delivery.webhook_id.to_string()], |r| r.get(0))?;
                audit(&tx, owner.parse()?, "webhook.delivery_failed", Some(delivery.project_id), &delivery.id.to_string(), status.as_str())?;
                integration_audit(&tx, limits.integration_audit_per_project, Some(delivery.project_id), "system", "webhook.delivery_failed", &delivery.id.to_string(), status.as_str())?;
            }
            // Bounded history per subscription.
            tx.execute(
                "DELETE FROM integration_attempts WHERE delivery_id IN (SELECT id FROM integration_deliveries WHERE webhook_id=?1 AND status IN ('delivered','failed','dead_letter') AND id NOT IN (SELECT id FROM integration_deliveries WHERE webhook_id=?1 ORDER BY created_at DESC LIMIT 1000))",
                [delivery.webhook_id.to_string()],
            )?;
            tx.execute(
                "DELETE FROM integration_deliveries WHERE webhook_id=?1 AND status IN ('delivered','failed','dead_letter') AND id NOT IN (SELECT id FROM integration_deliveries WHERE webhook_id=?1 ORDER BY created_at DESC LIMIT 1000)",
                [delivery.webhook_id.to_string()],
            )?;
            tx.commit()?;
            Ok(FinishResult::Recorded(status))
        })
        .await
    }
    /// Re-send an event: a new delivery identity with the same event identity and payload fields.
    pub async fn replay_delivery(
        &self,
        project: ProjectId,
        delivery: DeliveryId,
        owner: DeveloperId,
    ) -> anyhow::Result<DeliveryView> {
        let limits = self.automation_limits.clone();
        self.run(move |db| {
            let tx = db.transaction()?;
            project_owned(&tx, project, owner)?;
            let row: Option<(String, String, String, Vec<u8>, String)> = tx
                .query_row(
                    "SELECT webhook_id,event_id,event_type,payload,status FROM integration_deliveries WHERE id=?1 AND project_id=?2",
                    params![delivery.to_string(), project.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .optional()?;
            let (webhook, event, kind, payload, status) = row.ok_or(PlatformError("delivery_not_found"))?;
            let status: DeliveryStatus = status.parse().map_err(|e: &str| anyhow::anyhow!(e.to_owned()))?;
            if !status.is_terminal() {
                return Err(PlatformError("delivery_in_progress").into());
            }
            let seq: i64 = tx.query_row("SELECT COALESCE(MAX(replay_seq),0)+1 FROM integration_deliveries WHERE webhook_id=?1 AND event_id=?2", params![webhook, event], |r| r.get(0))?;
            let id = DeliveryId::new();
            let mut body: Value = serde_json::from_slice(&payload)?;
            body["delivery_id"] = json!(id);
            let payload = serde_json::to_vec(&body)?;
            tx.execute(
                "INSERT INTO integration_deliveries(id,webhook_id,project_id,event_id,event_type,payload,status,next_attempt_at,replay_seq,replay_of,created_at) VALUES(?1,?2,?3,?4,?5,?6,'pending',?7,?8,?9,?7)",
                params![id.to_string(), webhook, project.to_string(), event, kind, payload, now_s(), seq, delivery.to_string()],
            )?;
            audit(&tx, owner, "webhook.replayed", Some(project), &id.to_string(), "queued")?;
            integration_audit(&tx, limits.integration_audit_per_project, Some(project), &owner.to_string(), "webhook.replayed", &id.to_string(), "queued")?;
            let out = read_delivery(&tx, &id.to_string())?.ok_or(PlatformError("delivery_not_found"))?;
            tx.commit()?;
            Ok(out)
        })
        .await
    }
    pub async fn deliveries(
        &self,
        project: ProjectId,
        webhook: Option<WebhookId>,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<Vec<DeliveryView>> {
        self.run(move |db| {
            let ids: Vec<String> = db
                .prepare("SELECT id FROM integration_deliveries WHERE project_id=?1 AND (?2 IS NULL OR webhook_id=?2) ORDER BY created_at DESC, rowid DESC LIMIT ?3 OFFSET ?4")?
                .query_map(params![project.to_string(), webhook.map(|w| w.to_string()), limit as i64, offset as i64], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            ids.iter().map(|id| read_delivery(db, id)?.ok_or_else(|| anyhow::anyhow!("delivery vanished"))).collect()
        })
        .await
    }
    pub async fn delivery(
        &self,
        project: ProjectId,
        id: DeliveryId,
    ) -> anyhow::Result<Option<(DeliveryView, Vec<AttemptView>)>> {
        self.run(move |db| {
            let Some(view) = read_delivery(db, &id.to_string())? else { return Ok(None) };
            let owner: String = db.query_row("SELECT project_id FROM integration_deliveries WHERE id=?1", [id.to_string()], |r| r.get(0))?;
            if owner != project.to_string() {
                return Ok(None);
            }
            let attempts = db
                .prepare("SELECT attempt,started_at,duration_ms,http_status,outcome,error FROM integration_attempts WHERE delivery_id=?1 ORDER BY id")?
                .query_map([id.to_string()], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, Option<u16>>(3)?, r.get::<_, String>(4)?, r.get::<_, Option<String>>(5)?)))?
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .map(|(attempt, started, ms, status, outcome, error)| Ok(AttemptView { attempt, started_at: t(&started)?, duration_ms: ms as u64, http_status: status, outcome, error }))
                .collect::<anyhow::Result<Vec<_>>>()?;
            Ok(Some((view, attempts)))
        })
        .await
    }
    /// Disable a subscription after repeated permanent delivery failure (destination now unsafe).
    pub async fn disable_webhook_for_reason(
        &self,
        id: WebhookId,
        reason: &'static str,
    ) -> anyhow::Result<()> {
        self.run(move |db| {
            db.execute("UPDATE webhook_subscriptions SET enabled=0,disabled_reason=?2,updated_at=?3 WHERE id=?1", params![id.to_string(), reason, now_s()])?;
            Ok(())
        })
        .await
    }
    pub async fn prune_outbox(&self) -> anyhow::Result<usize> {
        self.run(|db| {
            let cutoff = (Utc::now() - chrono::Duration::days(7)).to_rfc3339();
            Ok(db.execute(
                "DELETE FROM event_outbox WHERE created_at<?1 AND seq<=COALESCE((SELECT MIN(last_seq) FROM outbox_cursors),0) AND (SELECT count(*) FROM outbox_cursors)>=2 AND seq NOT IN (SELECT seq FROM outbox_quarantine)",
                [cutoff],
            )?)
        })
        .await
    }
    pub async fn delivery_queue_depth(&self) -> anyhow::Result<(i64, i64)> {
        self.run(|db| {
            let pending: i64 = db.query_row("SELECT count(*) FROM integration_deliveries WHERE status IN ('pending','retry_wait','delivering')", [], |r| r.get(0))?;
            let backlog: i64 = db.query_row("SELECT count(*) FROM event_outbox WHERE seq>COALESCE((SELECT last_seq FROM outbox_cursors WHERE consumer='webhooks'),0)", [], |r| r.get(0))?;
            Ok((pending, backlog))
        })
        .await
    }
}

/// Result of recording a finished attempt. `Superseded` means a recovery or a newer attempt
/// already owns the delivery, so this result was discarded and nothing was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinishResult {
    Recorded(DeliveryStatus),
    Superseded,
}

/// Move one abandoned attempt to `retry_wait`, or to `dead_letter` once its budget is spent.
/// Fenced on the attempt number and on `delivering`, so only the attempt that owns the row moves it.
fn interrupt_row(
    tx: &rusqlite::Transaction,
    id: &str,
    attempt: u32,
    reason: &'static str,
    max_attempts: u32,
    delay: std::time::Duration,
    limits: &crate::automation_store::AutomationLimits,
) -> anyhow::Result<Option<DeliveryStatus>> {
    let row: Option<(String, String)> = tx
        .query_row(
            "SELECT webhook_id,project_id FROM integration_deliveries WHERE id=?1 AND status='delivering' AND attempts=?2",
            params![id, attempt],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((webhook, project)) = row else {
        return Ok(None);
    };
    let status = if attempt >= max_attempts {
        DeliveryStatus::DeadLetter
    } else {
        DeliveryStatus::RetryWait
    };
    let next = Utc::now() + chrono::Duration::from_std(delay)?;
    tx.execute(
        "UPDATE integration_deliveries SET status=?2,next_attempt_at=?3,last_error=?4,lease_expires_at=NULL,finished_at=CASE WHEN ?5 THEN ?6 ELSE finished_at END WHERE id=?1",
        params![id, status.as_str(), next.to_rfc3339(), reason, status.is_terminal(), now_s()],
    )?;
    if status == DeliveryStatus::DeadLetter {
        let owner: String = tx.query_row(
            "SELECT owner FROM webhook_subscriptions WHERE id=?1",
            [&webhook],
            |r| r.get(0),
        )?;
        let project: ProjectId = project.parse()?;
        audit(
            tx,
            owner.parse()?,
            "webhook.delivery_failed",
            Some(project),
            id,
            status.as_str(),
        )?;
        integration_audit(
            tx,
            limits.integration_audit_per_project,
            Some(project),
            "system",
            "webhook.delivery_failed",
            id,
            status.as_str(),
        )?;
    }
    Ok(Some(status))
}

/// Best-effort history row for an interrupted attempt. Diagnostics must never block recovery.
fn record_interruption(db: &Connection, id: &str, attempt: u32, reason: &str) {
    if let Err(error) = db.execute(
        "INSERT INTO integration_attempts(delivery_id,attempt,started_at,duration_ms,http_status,outcome,error) VALUES(?1,?2,?3,0,NULL,'interrupted',?4)",
        params![id, attempt, now_s(), reason],
    ) {
        tracing::warn!(delivery_id = id, %error, "Cannot record an interrupted delivery attempt");
    }
}

#[derive(Debug, Clone)]
pub enum DeliveryOutcome {
    Delivered,
    Retry {
        reason: &'static str,
        delay: std::time::Duration,
    },
    Permanent {
        reason: &'static str,
    },
}

fn envelope(event: &OutboxEvent, origin: &Origin, delivery: DeliveryId) -> Vec<u8> {
    let body = librehub_automation::webhook::EventEnvelope {
        version: librehub_automation::webhook::PAYLOAD_VERSION,
        event_id: event.event_id.to_string(),
        delivery_id: delivery.to_string(),
        event_type: event.event_type.clone(),
        created_at: event.created_at.to_rfc3339(),
        project_id: event.project_id.to_string(),
        origin: librehub_automation::webhook::EventOrigin {
            kind: origin.kind.clone(),
            automation_run_id: origin.run_id.clone(),
        },
        chain_depth: origin.chain_depth,
        correlation_id: origin.correlation_id.clone(),
        data: event.data.clone(),
    };
    serde_json::to_vec(&body).unwrap_or_default()
}

fn project_owned(
    db: &Connection,
    project: ProjectId,
    owner: DeveloperId,
) -> anyhow::Result<(Project, bool)> {
    let raw: Option<String> = db
        .query_row(
            "SELECT record FROM projects WHERE id=?1",
            [project.to_string()],
            |r| r.get(0),
        )
        .optional()?;
    let p: Project = serde_json::from_str(&raw.ok_or(PlatformError("project_not_found"))?)?;
    if p.owner_developer_id != owner {
        return Err(PlatformError("project_not_found").into());
    }
    Ok((p, true))
}

fn read_webhook(db: &Connection, id: &str) -> anyhow::Result<Option<WebhookView>> {
    type Row = (
        String,
        String,
        String,
        String,
        String,
        String,
        bool,
        Option<String>,
        String,
        String,
        String,
        Option<String>,
    );
    let row: Option<Row> = db
        .query_row(
            "SELECT id,project_id,url,description,event_types,exclude_origins,enabled,disabled_reason,secret_fingerprint,created_at,updated_at,secret_rotated_at FROM webhook_subscriptions WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?, r.get(10)?, r.get(11)?)),
        )
        .optional()?;
    let Some((
        wid,
        project,
        url,
        description,
        types,
        excl,
        enabled,
        reason,
        fp,
        created,
        updated,
        rotated,
    )) = row
    else {
        return Ok(None);
    };
    let last: Option<(String, String, Option<u16>, String)> = db
        .query_row(
            "SELECT id,status,last_http_status,COALESCE(finished_at,created_at) FROM integration_deliveries WHERE webhook_id=?1 ORDER BY created_at DESC, rowid DESC LIMIT 1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    Ok(Some(WebhookView {
        id: wid.parse()?,
        project_id: project.parse()?,
        url,
        description,
        event_types: serde_json::from_str(&types)?,
        exclude_origins: serde_json::from_str(&excl)?,
        enabled,
        disabled_reason: reason,
        secret_fingerprint: fp,
        created_at: t(&created)?,
        updated_at: t(&updated)?,
        secret_rotated_at: rotated.map(|r| t(&r)).transpose()?,
        last_delivery: last
            .map(|(did, status, http, at)| {
                Ok::<_, anyhow::Error>(LastDelivery {
                    delivery_id: did.parse()?,
                    status: status
                        .parse()
                        .map_err(|e: &str| anyhow::anyhow!(e.to_owned()))?,
                    http_status: http,
                    at: t(&at)?,
                })
            })
            .transpose()?,
    }))
}
fn read_delivery(db: &Connection, id: &str) -> anyhow::Result<Option<DeliveryView>> {
    type Row = (
        String,
        String,
        String,
        String,
        String,
        u32,
        String,
        Option<u16>,
        Option<String>,
        Option<String>,
        String,
        Option<String>,
    );
    let row: Option<Row> = db
        .query_row(
            "SELECT id,webhook_id,event_id,event_type,status,attempts,next_attempt_at,last_http_status,last_error,replay_of,created_at,delivered_at FROM integration_deliveries WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?, r.get(10)?, r.get(11)?)),
        )
        .optional()?;
    row.map(
        |(
            id,
            hook,
            event,
            kind,
            status,
            attempts,
            next,
            http,
            error,
            replay,
            created,
            delivered,
        )| {
            Ok(DeliveryView {
                id: id.parse()?,
                webhook_id: hook.parse()?,
                event_id: event.parse()?,
                event_type: kind,
                status: status
                    .parse()
                    .map_err(|e: &str| anyhow::anyhow!(e.to_owned()))?,
                attempts,
                next_attempt_at: t(&next)?,
                last_http_status: http,
                last_error: error,
                replay_of: replay.map(|r| r.parse()).transpose()?,
                created_at: t(&created)?,
                delivered_at: delivered.map(|d| t(&d)).transpose()?,
            })
        },
    )
    .transpose()
}
