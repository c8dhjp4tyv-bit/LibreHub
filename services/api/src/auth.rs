//! One bearer parser and reusable ownership checks. Tokens never enter diagnostics.
use crate::{http::ApiError, platform_store::PlatformError, store::Store};
use axum::{
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::Response,
};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use librehub_common::*;
use rusqlite::{OptionalExtension, params};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;
use subtle::ConstantTimeEq;

#[derive(Clone)]
pub struct Secret(pub String);
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}
impl Serialize for Secret {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}
#[derive(Clone, Debug)]
pub struct AuthenticatedDeveloper {
    pub developer_id: DeveloperId,
    pub token_id: TokenId,
    pub scopes: Vec<Scope>,
}
impl AuthenticatedDeveloper {
    pub fn require(&self, scope: Scope) -> Result<(), ApiError> {
        if !self.scopes.contains(&scope) {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "insufficient_scope",
                "The API token lacks the required scope",
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Serialize)]
pub struct IssuedToken {
    #[serde(flatten)]
    pub record: ApiToken,
    pub token: Secret,
}
pub fn random_secret() -> anyhow::Result<Secret> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("Secure randomness unavailable"))?;
    Ok(Secret(bytes.iter().map(|b| format!("{b:02x}")).collect()))
}
/// Operator-owned key file, never exposed to Git/build workers. AEAD binds ciphertext to project ID.
pub fn encryption_key(root: &Path) -> anyhow::Result<[u8; 32]> {
    let path = root.join("webhook.key");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(&path) {
        Ok(mut file) => {
            use std::io::Write;
            let mut key = [0; 32];
            getrandom::fill(&mut key)
                .map_err(|_| anyhow::anyhow!("Secure randomness unavailable"))?;
            file.write_all(&key)?;
            file.sync_all()?;
            std::fs::File::open(root)?.sync_all()?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let meta = std::fs::symlink_metadata(&path)?;
    anyhow::ensure!(meta.is_file(), "Invalid webhook key file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        anyhow::ensure!(
            meta.permissions().mode() & 0o077 == 0,
            "Webhook key file must be private"
        );
    }
    let bytes = std::fs::read(path)?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid webhook key length"))
}
pub fn encrypt_secret(
    key: &[u8; 32],
    project: ProjectId,
    secret: &Secret,
) -> anyhow::Result<Vec<u8>> {
    let mut nonce = [0; 24];
    getrandom::fill(&mut nonce).map_err(|_| anyhow::anyhow!("Secure randomness unavailable"))?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let encrypted = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: secret.0.as_bytes(),
                aad: project.to_string().as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("Cannot encrypt webhook secret"))?;
    Ok([nonce.to_vec(), encrypted].concat())
}
pub fn decrypt_secret(key: &[u8; 32], project: ProjectId, bytes: &[u8]) -> anyhow::Result<Secret> {
    anyhow::ensure!(bytes.len() >= 24, "Invalid webhook secret storage");
    let cipher = XChaCha20Poly1305::new(key.into());
    let raw = cipher
        .decrypt(
            XNonce::from_slice(&bytes[..24]),
            chacha20poly1305::aead::Payload {
                msg: &bytes[24..],
                aad: project.to_string().as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("Cannot decrypt webhook secret"))?;
    Ok(Secret(String::from_utf8(raw)?))
}
impl Store {
    pub async fn platform_key(&self) -> anyhow::Result<[u8; 32]> {
        let has_projects = self
            .run(|db| {
                Ok(
                    db.query_row("SELECT EXISTS(SELECT 1 FROM projects)", [], |r| {
                        r.get::<_, bool>(0)
                    })?,
                )
            })
            .await?;
        anyhow::ensure!(
            !has_projects || self.data_dir.join("webhook.key").exists(),
            "Webhook key is missing; restore the protected key before starting"
        );
        encryption_key(&self.data_dir)
    }

    pub async fn create_developer(&self, name: String) -> anyhow::Result<Developer> {
        anyhow::ensure!(
            !name.trim().is_empty() && name.len() <= 120,
            "Developer name must be 1–120 bytes"
        );
        self.run(move |db| {
            let now = chrono::Utc::now();
            let developer = Developer {
                id: DeveloperId::new(),
                display_name: name,
                created_at: now,
                updated_at: now,
                status: DeveloperStatus::Active,
            };
            db.execute(
                "INSERT INTO developers(id,status,record) VALUES(?1,'active',?2)",
                params![developer.id.to_string(), serde_json::to_string(&developer)?],
            )?;
            Ok(developer)
        })
        .await
    }
    pub async fn issue_token(
        &self,
        developer: DeveloperId,
        name: String,
        scopes: Vec<Scope>,
    ) -> anyhow::Result<IssuedToken> {
        anyhow::ensure!(
            !name.trim().is_empty()
                && name.len() <= 120
                && scopes.len() <= 11
                && !scopes.is_empty(),
            PlatformError("invalid_request")
        );
        let id = TokenId::new();
        let raw = Secret(format!("librehub_{id}_{}", random_secret()?.0));
        let hash = Sha256::digest(raw.0.as_bytes()).to_vec();
        let record=self.run(move|db|{
            let tx=db.transaction()?;
            let active:bool=tx.query_row("SELECT status='active' FROM developers WHERE id=?1",[developer.to_string()],|r|r.get(0))?;anyhow::ensure!(active,PlatformError("developer_disabled"));
            let count:i64=tx.query_row("SELECT count(*) FROM api_tokens WHERE developer_id=?1 AND json_extract(record,'$.revoked_at') IS NULL",[developer.to_string()],|r|r.get(0))?;anyhow::ensure!(count<32,PlatformError("token_limit_exceeded"));
            let record=ApiToken{id,developer_id:developer,name,scopes,created_at:chrono::Utc::now(),last_used_at:None,revoked_at:None};
            tx.execute("INSERT INTO api_tokens(id,developer_id,hash,record) VALUES(?1,?2,?3,?4)",params![id.to_string(),developer.to_string(),hash,serde_json::to_string(&record)?])?;
            crate::platform_store::audit(&tx,developer,"token.created",None,&id.to_string(),"succeeded")?;tx.commit()?;Ok(record)
        }).await?;
        Ok(IssuedToken { record, token: raw })
    }
    pub async fn authenticate(
        &self,
        raw: Secret,
    ) -> anyhow::Result<Option<AuthenticatedDeveloper>> {
        let Some(rest) = raw.0.strip_prefix("librehub_") else {
            return Ok(None);
        };
        let Some((id, random)) = rest.split_once('_') else {
            return Ok(None);
        };
        let Ok(id) = id.parse::<TokenId>() else {
            return Ok(None);
        };
        if random.len() != 64 || !random.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(None);
        }
        let digest = Sha256::digest(raw.0.as_bytes()).to_vec();
        self.run(move|db|{
            let tx=db.transaction()?;
            let row:Option<(Vec<u8>,String,bool)>=tx.query_row("SELECT t.hash,t.record,d.status='active' FROM api_tokens t JOIN developers d ON d.id=t.developer_id WHERE t.id=?1",[id.to_string()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
            let Some((stored,record,active))=row else{return Ok(None)};
            let mut record:ApiToken=serde_json::from_str(&record)?;
            if !bool::from(stored.ct_eq(&digest))||record.revoked_at.is_some()||!active{return Ok(None)}
            record.last_used_at=Some(chrono::Utc::now());tx.execute("UPDATE api_tokens SET record=?2 WHERE id=?1",params![id.to_string(),serde_json::to_string(&record)?])?;tx.commit()?;
            Ok(Some(AuthenticatedDeveloper{developer_id:record.developer_id,token_id:record.id,scopes:record.scopes}))
        }).await
    }
    pub async fn tokens(
        &self,
        developer: DeveloperId,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<Vec<ApiToken>> {
        self.run(move|db|{let mut query=db.prepare("SELECT record FROM api_tokens WHERE developer_id=?1 ORDER BY rowid DESC LIMIT ?2 OFFSET ?3")?;let rows=query.query_map(params![developer.to_string(),limit as i64,offset as i64],|r|r.get::<_,String>(0))?.collect::<Result<Vec<_>,_>>()?;rows.into_iter().map(|r|serde_json::from_str(&r).map_err(Into::into)).collect()}).await
    }
    pub async fn revoke_token(&self, developer: DeveloperId, id: TokenId) -> anyhow::Result<bool> {
        self.run(move |db| {
            let tx = db.transaction()?;
            let record: Option<String> = tx
                .query_row(
                    "SELECT record FROM api_tokens WHERE id=?1 AND developer_id=?2",
                    params![id.to_string(), developer.to_string()],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(record) = record else {
                return Ok(false);
            };
            let mut record: ApiToken = serde_json::from_str(&record)?;
            record.revoked_at = Some(chrono::Utc::now());
            tx.execute(
                "UPDATE api_tokens SET record=?2 WHERE id=?1",
                params![id.to_string(), serde_json::to_string(&record)?],
            )?;
            crate::platform_store::audit(
                &tx,
                developer,
                "token.revoked",
                None,
                &id.to_string(),
                "succeeded",
            )?;
            tx.commit()?;
            Ok(true)
        })
        .await
    }
    pub async fn authorized_build(
        &self,
        auth: &AuthenticatedDeveloper,
        id: BuildId,
    ) -> anyhow::Result<bool> {
        let owner = auth.developer_id.to_string();
        let operator = auth.scopes.contains(&Scope::Operator);
        self.run(move |db| {
            let found: Option<String> = db
                .query_row(
                    "SELECT developer_id FROM build_owners WHERE build_id=?1",
                    [id.to_string()],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(found.map_or(operator, |id| id == owner))
        })
        .await
    }
}
pub async fn middleware(
    State(store): State<Store>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let header = request
        .headers()
        .get(header::AUTHORIZATION)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                "authentication_required",
                "A Bearer API token is required",
            )
        })?;
    let raw = header
        .to_str()
        .ok()
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| v.len() <= 160)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "The API token is invalid",
            )
        })?;
    let auth = store
        .authenticate(Secret(raw.to_owned()))
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "The API token is invalid or revoked",
            )
        })?;
    let write = request.method() != axum::http::Method::GET;
    let segments = request
        .uri()
        .path()
        .trim_matches('/')
        .split('/')
        .collect::<Vec<_>>();
    let resource = segments.get(2).copied().unwrap_or("");
    let scope = match resource {
        "tokens" => {
            if write {
                Scope::TokensWrite
            } else {
                Scope::TokensRead
            }
        }
        "audit" => Scope::AuditRead,
        "builds"
            if segments
                .get(4)
                .is_some_and(|s| ["publish", "publishes"].contains(s)) =>
        {
            if write {
                Scope::PublishesWrite
            } else {
                Scope::PublishesRead
            }
        }
        "builds" => {
            if write {
                Scope::BuildsWrite
            } else {
                Scope::BuildsRead
            }
        }
        "publishes" => {
            if write {
                Scope::PublishesWrite
            } else {
                Scope::PublishesRead
            }
        }
        "projects" if segments.get(4) == Some(&"webhook-secret") => Scope::WebhooksWrite,
        "projects"
            if segments.get(4) == Some(&"builds") || segments.get(4) == Some(&"source-events") =>
        {
            if write {
                Scope::BuildsWrite
            } else {
                Scope::BuildsRead
            }
        }
        "projects" if segments.get(4) == Some(&"audit") => Scope::AuditRead,
        _ => {
            if write {
                Scope::ProjectsWrite
            } else {
                Scope::ProjectsRead
            }
        }
    };
    auth.require(scope)?;
    if resource == "builds"
        && let Some(id) = segments.get(3)
        && let Ok(id) = id.parse::<BuildId>()
        && !store
            .authorized_build(&auth, id)
            .await
            .map_err(ApiError::internal)?
    {
        return Err(ApiError::missing());
    }
    if resource == "publishes"
        && let Some(id) = segments.get(3)
        && let Ok(id) = id.parse::<PublishId>()
        && let Some(record) = store.publish_record(id).await.map_err(ApiError::internal)?
        && !store
            .authorized_build(&auth, record.build_id)
            .await
            .map_err(ApiError::internal)?
    {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "publish_not_found",
            "Publication does not exist",
        ));
    }
    // Remove the bearer header before any downstream handler/trace can inspect it.
    request.headers_mut().remove(header::AUTHORIZATION);
    request.extensions_mut().insert(auth);
    Ok(next.run(request).await)
}
