//! Offline DSSE verification and trusted signing primitives. No worker or HTTP mutation signer.
use anyhow::{Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use librehub_common::*;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::{Path, PathBuf},
};

pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
pub const MAX_PAYLOAD: usize = 256 * 1024;
pub const MAX_ENVELOPE: usize = 384 * 1024;
pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn digest(algorithm: &str, value: &str) -> BTreeMap<String, String> {
    BTreeMap::from([(algorithm.into(), value.into())])
}
pub fn key_id(bytes: &[u8]) -> String {
    format!("ed25519:sha256:{}", sha256(bytes))
}
pub fn bounded_file(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path)?;
    ensure!(meta.is_file() && meta.len() <= limit as u64, "invalid_file");
    let mut bytes = Vec::new();
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    ensure!(file.metadata()?.is_file(), "invalid_file");
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "size_limit");
    Ok(bytes)
}
/// DSSE PAE length fields are decimal byte lengths, with literal spaces (no trailing space).
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    )
    .into_bytes();
    bytes.extend_from_slice(payload);
    bytes
}
/// LibreHub canonical profile: sorted object keys, compact UTF-8 JSON, no floats.
/// Verify exactly these bytes; verification never reserializes an altered payload before checking its signature.
pub fn canonical(statement: &ProvenanceStatement) -> Result<Vec<u8>> {
    validate_statement(statement)?;
    let bytes = serde_json::to_vec(&serde_json::to_value(statement)?)?;
    ensure!(bytes.len() <= MAX_PAYLOAD, "size_limit");
    Ok(bytes)
}
pub fn validate_bundle(bundle: &KeyBundle) -> Result<()> {
    ensure!(
        bundle.version == 1 && !bundle.keys.is_empty() && bundle.keys.len() <= 32,
        "invalid_key_bundle"
    );
    let mut ids = BTreeSet::new();
    for key in &bundle.keys {
        let raw = STANDARD.decode(&key.public_key)?;
        ensure!(
            raw.len() == 32 && key.key_id == key_id(&raw) && ids.insert(&key.key_id),
            "invalid_key_identity"
        );
        VerifyingKey::from_bytes(raw.as_slice().try_into()?)?;
    }
    Ok(())
}
pub fn validate_statement(s: &ProvenanceStatement) -> Result<()> {
    ensure!(
        s.statement_type == STATEMENT_V1 && s.subject.len() == 1,
        "invalid_statement"
    );
    let subject = &s.subject[0];
    ensure!(
        !subject.name.is_empty() && subject.name.len() <= 2048 && subject.digest.len() == 1,
        "invalid_subject"
    );
    ensure!(
        subject
            .digest
            .get("sha256")
            .is_some_and(|d| valid_checksum(d)),
        "invalid_subject_digest"
    );
    match (&*s.predicate_type, &s.predicate) {
        (SLSA_V1, ProvenancePredicate::Build(p)) => {
            let d = &p.build_definition;
            let e = &d.external_parameters;
            let env = &d.internal_parameters;
            ensure!(
                d.build_type == BUILD_TYPE_V1 && p.run_details.builder.id == BUILDER_ID,
                "untrusted_builder"
            );
            ensure!(
                p.run_details.builder.version.get("librehub") == Some(&env.builder_version),
                "builder_version_mismatch"
            );
            ensure!(
                p.run_details.metadata.invocation_id == e.build_id.to_string()
                    && p.run_details.metadata.finished_on >= p.run_details.metadata.started_on,
                "invalid_invocation"
            );
            ensure!(
                valid_commit(&e.source.revision.commit)
                    && valid_checksum(&e.source.snapshot.sha256)
                    && !e.source.revision.repository.is_empty(),
                "invalid_source"
            );
            ensure!(
                env.image_config_digest
                    .strip_prefix("sha256:")
                    .is_some_and(valid_checksum)
                    && valid_checksum(&env.runtime_commit)
                    && valid_checksum(&env.sdk_commit),
                "invalid_environment"
            );
            ensure!(
                env.architecture == e.architecture
                    && ["none", "bridge"].contains(&env.network.as_str()),
                "invalid_environment"
            );
            ensure!(
                env.isolation != IsolationPolicy::Hardened
                    || (env.network == "none"
                        && env.container_runtime == "podman"
                        && env.writable_bytes > 0),
                "invalid_isolation"
            );
            ensure!(
                subject.name == format!("app/{}/{}/{}", e.app_id, e.architecture, e.branch),
                "subject_identity_mismatch"
            );
            ensure!(
                d.resolved_dependencies.len() == 6 && e.declared_dependencies.len() <= 4096,
                "invalid_materials"
            );
            let expected = [
                (
                    e.source.revision.repository.as_str(),
                    "gitCommit",
                    e.source.revision.commit.as_str(),
                ),
                (
                    "librehub:source-snapshot",
                    "sha256",
                    e.source.snapshot.sha256.as_str(),
                ),
                ("librehub:manifest", "sha256", ""),
                (
                    "librehub:worker-image-config",
                    "sha256",
                    &env.image_config_digest[7..],
                ),
                (
                    env.runtime_ref.as_str(),
                    "sha256",
                    env.runtime_commit.as_str(),
                ),
                (env.sdk_ref.as_str(), "sha256", env.sdk_commit.as_str()),
            ];
            for (material, (uri, algorithm, value)) in d.resolved_dependencies.iter().zip(expected)
            {
                ensure!(
                    material.uri == uri && material.digest.len() == 1,
                    "material_identity_mismatch"
                );
                let actual = material
                    .digest
                    .get(algorithm)
                    .ok_or_else(|| anyhow::anyhow!("material_digest_missing"))?;
                ensure!(
                    if algorithm == "gitCommit" {
                        valid_commit(actual)
                    } else {
                        valid_checksum(actual)
                    },
                    "invalid_material_digest"
                );
                ensure!(
                    value.is_empty() || actual == value,
                    "material_digest_mismatch"
                );
            }
        }
        (RELEASE_V1, ProvenancePredicate::Release(p)) => {
            ensure!(
                valid_checksum(&p.build_statement_sha256)
                    && valid_checksum(&p.build_artifact_sha256)
                    && valid_checksum(&p.source_ostree_commit)
                    && valid_checksum(&p.sbom_sha256),
                "invalid_release_digest"
            );
            ensure!(
                subject.name == p.flatpak_ref
                    && p.flatpak_ref
                        .starts_with(&format!("app/{}/{}/", p.app_id, p.architecture))
                    && ["stable", "beta"].contains(&p.channel.as_str()),
                "subject_identity_mismatch"
            );
            ensure!(
                p.repository.starts_with("https://") || p.repository.starts_with("http://"),
                "invalid_repository"
            );
        }
        _ => bail!("unsupported_predicate"),
    }
    Ok(())
}
fn valid_commit(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64)
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn verify(
    envelope: &DsseEnvelope,
    bundle: &KeyBundle,
) -> Result<(ProvenanceStatement, String)> {
    validate_bundle(bundle)?;
    ensure!(
        envelope.payload_type == PAYLOAD_TYPE
            && envelope.signatures.len() == 1
            && envelope.payload.len() <= MAX_PAYLOAD.div_ceil(3) * 4,
        "invalid_envelope"
    );
    let payload = STANDARD
        .decode(&envelope.payload)
        .map_err(|_| anyhow::anyhow!("invalid_payload_encoding"))?;
    ensure!(payload.len() <= MAX_PAYLOAD, "size_limit");
    let signature = &envelope.signatures[0];
    let key = bundle
        .keys
        .iter()
        .find(|k| k.key_id == signature.keyid)
        .ok_or_else(|| anyhow::anyhow!("unknown_key"))?;
    ensure!(key.state != KeyState::Revoked, "revoked_key");
    let raw = STANDARD.decode(&key.public_key)?;
    let key = VerifyingKey::from_bytes(raw.as_slice().try_into()?)?;
    ensure!(signature.sig.len() <= 88, "invalid_signature");
    let signature = Signature::from_slice(
        &STANDARD
            .decode(&signature.sig)
            .map_err(|_| anyhow::anyhow!("invalid_signature"))?,
    )?;
    key.verify_strict(&pae(PAYLOAD_TYPE, &payload), &signature)
        .map_err(|_| anyhow::anyhow!("signature_invalid"))?;
    let statement: ProvenanceStatement =
        serde_json::from_slice(&payload).map_err(|_| anyhow::anyhow!("schema_invalid"))?;
    ensure!(canonical(&statement)? == payload, "noncanonical_payload");
    Ok((statement, sha256(&payload)))
}
/// Requires both separately signed envelopes and their exact immutable build/release identities.
pub fn verify_link(
    release: &ProvenanceStatement,
    build: &ProvenanceStatement,
    build_digest: &str,
) -> Result<()> {
    let (ProvenancePredicate::Release(r), ProvenancePredicate::Build(b)) =
        (&release.predicate, &build.predicate)
    else {
        bail!("link_predicate_mismatch")
    };
    let e = &b.build_definition.external_parameters;
    ensure!(
        r.build_statement_sha256 == build_digest
            && r.build_id == e.build_id
            && r.app_id == e.app_id
            && r.architecture == e.architecture
            && r.flatpak_ref == build.subject[0].name
            && build.subject[0].digest.get("sha256") == Some(&r.build_artifact_sha256),
        "build_release_link_mismatch"
    );
    Ok(())
}

pub struct Attestor {
    seed_path: PathBuf,
    bundle_path: PathBuf,
}
impl Attestor {
    pub fn new(seed_path: PathBuf, bundle_path: PathBuf) -> Result<Self> {
        let signer = Self {
            seed_path,
            bundle_path,
        };
        signer.signing_key()?;
        Ok(signer)
    }
    pub fn ready(&self) -> bool {
        self.signing_key().is_ok()
    }
    pub fn bundle(&self) -> Result<KeyBundle> {
        let b = serde_json::from_slice(&bounded_file(&self.bundle_path, 32 * 1024)?)?;
        validate_bundle(&b)?;
        Ok(b)
    }
    fn signing_key(&self) -> Result<(SigningKey, String)> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                std::fs::symlink_metadata(&self.seed_path)?
                    .permissions()
                    .mode()
                    & 0o077
                    == 0,
                "private_key_permissions"
            );
        }
        let raw = bounded_file(&self.seed_path, 32)?;
        let key = SigningKey::from_bytes(raw.as_slice().try_into()?);
        let id = key_id(key.verifying_key().as_bytes());
        ensure!(
            self.bundle()?
                .keys
                .iter()
                .any(|k| k.key_id == id && k.state == KeyState::Active),
            "signing_key_not_active"
        );
        Ok((key, id))
    }
    pub fn sign(&self, statement: &ProvenanceStatement) -> Result<DsseEnvelope> {
        let payload = canonical(statement)?;
        let (key, keyid) = self.signing_key()?;
        let sig = STANDARD.encode(key.sign(&pae(PAYLOAD_TYPE, &payload)).to_bytes());
        Ok(DsseEnvelope {
            payload_type: PAYLOAD_TYPE.into(),
            payload: STANDARD.encode(payload),
            signatures: vec![AttestationSignature { keyid, sig }],
        })
    }
}
/// Explicit provisioning only. Refuses to overwrite existing key files.
pub fn provision(seed_path: &Path, bundle_path: &Path) -> Result<KeyBundle> {
    use std::io::Write;
    ensure!(
        !seed_path.exists() && !bundle_path.exists(),
        "key_already_exists"
    );
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|_| anyhow::anyhow!("entropy_unavailable"))?;
    let key = SigningKey::from_bytes(&seed);
    let public = key.verifying_key().to_bytes();
    let bundle = KeyBundle {
        version: 1,
        keys: vec![AttestorPublicKey {
            key_id: key_id(&public),
            public_key: STANDARD.encode(public),
            state: KeyState::Active,
        }],
    };
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(seed_path)?;
    file.write_all(&seed)?;
    file.sync_all()?;
    let mut file = options.open(bundle_path)?;
    file.write_all(&serde_json::to_vec_pretty(&bundle)?)?;
    file.sync_all()?;
    Ok(bundle)
}

pub fn declared_dependencies(manifest: &FlatpakManifest) -> Vec<DeclaredDependency> {
    fn walk(modules: &[Module], out: &mut Vec<DeclaredDependency>) {
        for m in modules {
            for s in &m.sources {
                let uri = s
                    .options
                    .get("url")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned);
                let pin = s
                    .options
                    .get(if matches!(s.kind, SourceKind::Git) {
                        "commit"
                    } else {
                        "sha256"
                    })
                    .and_then(|v| v.as_str())
                    .map(str::to_owned);
                let immutable = match s.kind {
                    SourceKind::Git => pin.as_deref().is_some_and(valid_commit),
                    SourceKind::Archive | SourceKind::File if uri.is_some() => {
                        pin.as_deref().is_some_and(valid_checksum)
                    }
                    _ => uri.is_none(),
                };
                out.push(DeclaredDependency {
                    kind: serde_json::to_value(s.kind)
                        .expect("enum serializes")
                        .as_str()
                        .expect("enum string")
                        .into(),
                    uri,
                    pin,
                    immutable,
                });
            }
            walk(&m.modules, out);
        }
    }
    let mut out = Vec::new();
    walk(&manifest.modules, &mut out);
    out
}
