//! Public read-only evidence, with explicit current trust evaluation and app/release binding.
use crate::{http::ApiError, store::Store};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use librehub_common::*;
use librehub_supply_chain as crypto;
use serde::Serialize;

pub fn router(store: Store) -> Router {
    Router::new()
        .route("/api/v1/supply-chain/keys", get(keys))
        .route(
            "/api/v1/catalog/apps/{app_id}/releases/{release_id}/provenance",
            get(provenance),
        )
        .route(
            "/api/v1/catalog/apps/{app_id}/releases/{release_id}/attestation",
            get(provenance),
        )
        .route(
            "/api/v1/catalog/apps/{app_id}/releases/{release_id}/attestation/download",
            get(download),
        )
        .with_state(store)
}
#[derive(Serialize)]
pub struct PublicEvidence {
    pub status: AttestationStatus,
    pub verification: VerificationResult,
    pub build: Option<ProvenanceStatement>,
    pub release: Option<ProvenanceStatement>,
    pub reproducibility: ReproducibilityState,
    pub bundle: Option<AttestationBundle>,
}
async fn keys(State(store): State<Store>) -> Result<Json<KeyBundle>, ApiError> {
    if store.attestor.is_some() {
        store
            .sync_attestor_keys()
            .await
            .map_err(ApiError::internal)?;
    }
    Ok(Json(store.public_keys().await.map_err(ApiError::internal)?))
}
fn missing() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        "release_not_found",
        "Release was not found",
    )
}
pub async fn evidence(
    store: &Store,
    app: String,
    id: PublishId,
) -> Result<PublicEvidence, ApiError> {
    let publication = store
        .publish_record(id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(missing)?;
    if publication.app_id != app || publication.status != PublishStatus::Succeeded {
        return Err(missing());
    }
    if store
        .get_moderation_state(&app)
        .await
        .map_err(ApiError::internal)?
        .is_some_and(|(s, _, _)| s == ModerationState::Removed)
    {
        return Err(missing());
    }
    let indexed = store
        .run(move |db| {
            Ok(db.query_row(
                "SELECT EXISTS(SELECT 1 FROM catalog_releases WHERE publication_id=?1)",
                [id.to_string()],
                |r| r.get::<_, bool>(0),
            )?)
        })
        .await
        .map_err(ApiError::internal)?;
    if !indexed {
        return Err(missing());
    }
    let mut result = PublicEvidence {
        status: AttestationStatus::Pending,
        verification: VerificationResult {
            verified: false,
            code: "attestation_pending".into(),
            key_id: None,
        },
        build: None,
        release: None,
        reproducibility: store
            .latest_reproducibility(publication.build_id)
            .await
            .map_err(ApiError::internal)?
            .map(|r| r.state)
            .unwrap_or(ReproducibilityState::NotChecked),
        bundle: None,
    };
    let (Some(build), Some(release)) = (
        store
            .envelope("build", publication.build_id.to_string())
            .await
            .map_err(ApiError::internal)?,
        store
            .envelope("release", id.to_string())
            .await
            .map_err(ApiError::internal)?,
    ) else {
        let legacy = store
            .get(publication.build_id)
            .await
            .map_err(ApiError::internal)?
            .is_none_or(|b| b.result.is_none_or(|r| r.environment.is_none()));
        if legacy {
            result.status = AttestationStatus::LegacyUnattested;
            result.verification.code = "legacy_unattested".into();
        } else {
            if store
                .get(publication.build_id)
                .await
                .map_err(ApiError::internal)?
                .is_some_and(|b| b.provenance.is_none())
            {
                result.status = AttestationStatus::Unavailable;
                result.verification.code = "immutable_source_unavailable".into();
                return Ok(result);
            }
            let failed = store.run(move |db|Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM attestation_jobs WHERE target_id=?1 AND state='failed')",[id.to_string()],|r|r.get::<_,bool>(0))?)).await.map_err(ApiError::internal)?;
            if failed {
                result.status = AttestationStatus::Failed;
                result.verification.code = "attestation_failed".into();
            }
        }
        return Ok(result);
    };
    let verification = async {
        let keys = if store.attestor.is_some() {
            store.sync_attestor_keys().await?
        } else {
            store.public_keys().await?
        };
        let (b, hash) = crypto::verify(&build, &keys)?;
        let (r, _) = crypto::verify(&release, &keys)?;
        crypto::verify_link(&r, &b, &hash)?;
        let ProvenancePredicate::Release(p) = &r.predicate else {
            anyhow::bail!("predicate_mismatch")
        };
        anyhow::ensure!(
            p.publication_id == id
                && p.build_id == publication.build_id
                && p.app_id == publication.app_id
                && p.architecture == publication.architecture
                && p.channel == publication.channel.to_string()
                && r.subject[0].digest.get("sha256")
                    == publication.result.as_ref().map(|p| &p.published_ref.commit),
            "publication_mismatch"
        );
        let record = store
            .get(publication.build_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("build_missing"))?;
        let ProvenancePredicate::Build(bp) = &b.predicate else {
            anyhow::bail!("build_predicate_mismatch")
        };
        let invocation = &bp.build_definition.external_parameters;
        let stored_source = record
            .provenance
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("source_missing"))?;
        let stored_result = record
            .result
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("artifact_missing"))?;
        anyhow::ensure!(
            record.status == BuildStatus::Succeeded
                && stored_result.artifacts.len() == 1
                && invocation.build_id == record.id
                && invocation.app_id == record.manifest.app_id
                && invocation.architecture == record.architecture
                && serde_json::to_value(&invocation.source)?
                    == serde_json::to_value(stored_source)?
                && stored_result.environment.as_ref()
                    == Some(&bp.build_definition.internal_parameters)
                && b.subject[0].digest.get("sha256") == Some(&stored_result.artifacts[0].sha256),
            "build_record_mismatch"
        );
        Ok::<_, anyhow::Error>((b, r))
    }
    .await;
    match verification {
        Ok((b, r)) => {
            result.status = AttestationStatus::Verified;
            result.verification = VerificationResult {
                verified: true,
                code: "verified".into(),
                key_id: Some(release.signatures[0].keyid.clone()),
            };
            result.build = Some(b);
            result.release = Some(r);
            result.bundle = Some(AttestationBundle {
                version: 1,
                build,
                release,
            });
        }
        Err(_) => {
            result.status = AttestationStatus::Failed;
            result.verification.code = "signature_or_identity_verification_failed".into();
            store
                .supply_audit("attestation.verification_failed", id.to_string(), "invalid")
                .await
                .map_err(ApiError::internal)?;
        }
    }
    Ok(result)
}
async fn provenance(
    State(store): State<Store>,
    Path((app, id)): Path<(String, String)>,
) -> Result<Json<PublicEvidence>, ApiError> {
    let id = id.parse().map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_release_id",
            "Release ID must be a UUID",
        )
    })?;
    Ok(Json(evidence(&store, app, id).await?))
}
async fn download(
    State(store): State<Store>,
    Path((app, id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let id: PublishId = id.parse().map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_release_id",
            "Release ID must be a UUID",
        )
    })?;
    let evidence = evidence(&store, app, id).await?;
    let bundle = evidence.bundle.ok_or_else(|| {
        ApiError::new(
            StatusCode::CONFLICT,
            "attestation_unavailable",
            "Verified release evidence is unavailable",
        )
    })?;
    Ok((
        [
            ("content-type", "application/json"),
            ("cache-control", "no-store"),
            ("x-content-type-options", "nosniff"),
        ],
        Json(bundle),
    )
        .into_response())
}
