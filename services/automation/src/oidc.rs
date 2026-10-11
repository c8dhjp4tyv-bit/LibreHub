//! GitHub Actions OpenID Connect verification and deny-by-default identity policy.
//!
//! Identity is proven only by a JWT whose RS256 signature verifies against a key the
//! trusted issuer published in its JWKS, whose `iss`/`aud` match operator configuration and
//! whose time claims are valid. Policies match GitHub's *immutable numeric* repository and
//! owner IDs; mutable names are informational.
use crate::workflow::{glob_match, valid_pattern};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use librehub_common::Scope;
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";
pub const GITHUB_JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";
pub const MAX_TOKEN_BYTES: usize = 8192;
const MAX_HEADER_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OidcError {
    #[error("token is malformed")]
    Malformed,
    #[error("signing algorithm is not allowed")]
    UnsupportedAlgorithm,
    #[error("token header contains a forbidden field")]
    ForbiddenHeader,
    #[error("signing key is unknown")]
    UnknownKey,
    #[error("signature is invalid")]
    InvalidSignature,
    #[error("issuer is not trusted")]
    WrongIssuer,
    #[error("audience does not match")]
    WrongAudience,
    #[error("token has expired")]
    Expired,
    #[error("token is not valid yet")]
    NotYetValid,
    #[error("token lifetime is too long")]
    LifetimeTooLong,
    #[error("required claim is missing")]
    MissingClaim,
    #[error("subject does not match repository claim")]
    SubjectMismatch,
}
impl OidcError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Malformed => "oidc_token_malformed",
            Self::UnsupportedAlgorithm => "oidc_algorithm_not_allowed",
            Self::ForbiddenHeader => "oidc_header_forbidden",
            Self::UnknownKey => "oidc_key_unknown",
            Self::InvalidSignature => "oidc_signature_invalid",
            Self::WrongIssuer => "oidc_issuer_not_trusted",
            Self::WrongAudience => "oidc_audience_mismatch",
            Self::Expired => "oidc_token_expired",
            Self::NotYetValid => "oidc_token_not_yet_valid",
            Self::LifetimeTooLong => "oidc_lifetime_too_long",
            Self::MissingClaim => "oidc_claim_missing",
            Self::SubjectMismatch => "oidc_subject_mismatch",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default, rename = "use")]
    pub use_: Option<String>,
}
#[derive(Debug, Clone, Default, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}
impl JwkSet {
    pub fn parse(bytes: &[u8]) -> Result<Self, OidcError> {
        if bytes.len() > 256 * 1024 {
            return Err(OidcError::Malformed);
        }
        let set: Self = serde_json::from_slice(bytes).map_err(|_| OidcError::Malformed)?;
        if set.keys.len() > 64 {
            return Err(OidcError::Malformed);
        }
        Ok(set)
    }
    pub fn find(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid.as_deref() == Some(kid))
    }
}

#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub audience: String,
    pub leeway_secs: i64,
    pub max_lifetime_secs: i64,
}
impl OidcConfig {
    pub fn github(audience: impl Into<String>) -> Self {
        Self {
            issuer: GITHUB_ISSUER.into(),
            audience: audience.into(),
            leeway_secs: 30,
            max_lifetime_secs: 3600,
        }
    }
}

/// Verified claims from a GitHub Actions identity token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubClaims {
    pub subject: String,
    pub jti: String,
    pub expires_at: i64,
    pub repository: String,
    pub repository_id: String,
    pub repository_owner: String,
    pub repository_owner_id: String,
    pub git_ref: String,
    pub sha: String,
    pub event_name: String,
    pub workflow_ref: String,
    pub job_workflow_ref: Option<String>,
    pub environment: Option<String>,
    pub run_id: String,
    pub run_attempt: String,
    pub actor_id: Option<String>,
    pub runner_environment: Option<String>,
}

fn decode(part: &str, limit: usize) -> Result<Vec<u8>, OidcError> {
    if part.len() > limit * 2 {
        return Err(OidcError::Malformed);
    }
    URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| OidcError::Malformed)
}
fn text<'a>(claims: &'a Value, key: &str) -> Result<&'a str, OidcError> {
    claims
        .get(key)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.len() <= 512)
        .ok_or(OidcError::MissingClaim)
}
fn optional_text(claims: &Value, key: &str) -> Option<String> {
    claims
        .get(key)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.len() <= 512)
        .map(str::to_owned)
}
fn time(claims: &Value, key: &str) -> Result<i64, OidcError> {
    let value = claims.get(key).ok_or(OidcError::MissingClaim)?;
    value
        .as_i64()
        .or_else(|| value.as_f64().filter(|f| f.is_finite()).map(|f| f as i64))
        .ok_or(OidcError::Malformed)
}

/// Verify `token` against `keys`. `now` is Unix seconds (injected for deterministic tests).
pub fn verify_github_token(
    token: &str,
    keys: &JwkSet,
    config: &OidcConfig,
    now: i64,
) -> Result<GithubClaims, OidcError> {
    if token.len() > MAX_TOKEN_BYTES || token.contains(char::is_whitespace) {
        return Err(OidcError::Malformed);
    }
    let parts: Vec<&str> = token.split('.').collect();
    let [header_b64, payload_b64, signature_b64] = parts[..] else {
        return Err(OidcError::Malformed);
    };
    let header: Value = serde_json::from_slice(&decode(header_b64, MAX_HEADER_BYTES)?)
        .map_err(|_| OidcError::Malformed)?;
    let header = header.as_object().ok_or(OidcError::Malformed)?;
    // The only accepted algorithm is RS256. `none` and HMAC confusion die here.
    if header.get("alg").and_then(Value::as_str) != Some("RS256") {
        return Err(OidcError::UnsupportedAlgorithm);
    }
    // Never let a token name its own key material or processing extensions.
    if ["jku", "jwk", "x5u", "x5c", "crit", "zip", "cty"]
        .iter()
        .any(|forbidden| header.contains_key(*forbidden))
    {
        return Err(OidcError::ForbiddenHeader);
    }
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .filter(|k| !k.is_empty() && k.len() <= 128)
        .ok_or(OidcError::UnknownKey)?;
    let key = keys.find(kid).ok_or(OidcError::UnknownKey)?;
    if key.kty != "RSA"
        || key.alg.as_deref().is_some_and(|a| a != "RS256")
        || key.use_.as_deref().is_some_and(|u| u != "sig")
    {
        return Err(OidcError::UnknownKey);
    }
    let n = decode(key.n.as_deref().ok_or(OidcError::UnknownKey)?, 1024)?;
    let e = decode(key.e.as_deref().ok_or(OidcError::UnknownKey)?, 16)?;
    let n_trimmed: &[u8] = {
        let first = n.iter().position(|b| *b != 0).unwrap_or(n.len());
        &n[first..]
    };
    if n_trimmed.len() < 256 {
        // Reject RSA moduli below 2048 bits regardless of what the key set advertises.
        return Err(OidcError::UnknownKey);
    }
    let signature = decode(signature_b64, 1024)?;
    let signed = format!("{header_b64}.{payload_b64}");
    RsaPublicKeyComponents {
        n: n_trimmed,
        e: &e,
    }
    .verify(&RSA_PKCS1_2048_8192_SHA256, signed.as_bytes(), &signature)
    .map_err(|_| OidcError::InvalidSignature)?;

    let claims: Value = serde_json::from_slice(&decode(payload_b64, MAX_TOKEN_BYTES)?)
        .map_err(|_| OidcError::Malformed)?;
    if !claims.is_object() {
        return Err(OidcError::Malformed);
    }
    if claims.get("iss").and_then(Value::as_str) != Some(config.issuer.as_str()) {
        return Err(OidcError::WrongIssuer);
    }
    match claims.get("aud") {
        Some(Value::String(aud)) if aud == &config.audience => {}
        Some(Value::Array(auds))
            if auds.len() <= 4 && auds.iter().any(|a| a.as_str() == Some(&config.audience)) => {}
        Some(_) => return Err(OidcError::WrongAudience),
        None => return Err(OidcError::MissingClaim),
    }
    let exp = time(&claims, "exp")?;
    let iat = time(&claims, "iat")?;
    if now >= exp.saturating_add(config.leeway_secs) {
        return Err(OidcError::Expired);
    }
    if let Some(nbf) = claims.get("nbf") {
        let nbf = nbf.as_i64().ok_or(OidcError::Malformed)?;
        if nbf > now.saturating_add(config.leeway_secs) {
            return Err(OidcError::NotYetValid);
        }
    }
    if iat > now.saturating_add(config.leeway_secs) {
        return Err(OidcError::NotYetValid);
    }
    if exp.saturating_sub(iat) > config.max_lifetime_secs {
        return Err(OidcError::LifetimeTooLong);
    }
    let out = GithubClaims {
        subject: text(&claims, "sub")?.to_owned(),
        jti: text(&claims, "jti")?.to_owned(),
        expires_at: exp,
        repository: text(&claims, "repository")?.to_owned(),
        repository_id: text(&claims, "repository_id")?.to_owned(),
        repository_owner: text(&claims, "repository_owner")?.to_owned(),
        repository_owner_id: text(&claims, "repository_owner_id")?.to_owned(),
        git_ref: text(&claims, "ref")?.to_owned(),
        sha: text(&claims, "sha")?.to_owned(),
        event_name: text(&claims, "event_name")?.to_owned(),
        workflow_ref: text(&claims, "workflow_ref")?.to_owned(),
        job_workflow_ref: optional_text(&claims, "job_workflow_ref"),
        environment: optional_text(&claims, "environment"),
        run_id: text(&claims, "run_id")?.to_owned(),
        run_attempt: text(&claims, "run_attempt")?.to_owned(),
        actor_id: optional_text(&claims, "actor_id"),
        runner_environment: optional_text(&claims, "runner_environment"),
    };
    // The numeric IDs are what policies trust; make sure they are canonical numbers.
    for id in [
        &out.repository_id,
        &out.repository_owner_id,
        &out.run_id,
        &out.run_attempt,
    ] {
        if id.len() > 20 || !id.bytes().all(|b| b.is_ascii_digit()) {
            return Err(OidcError::Malformed);
        }
    }
    if out.sha.len() != 40
        || !out
            .sha
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(OidcError::Malformed);
    }
    // Default GitHub subjects are `repo:<owner>/<repo>:...`. A subject that names a
    // different repository than the signed `repository` claim is never accepted.
    if !out
        .subject
        .starts_with(&format!("repo:{}:", out.repository))
    {
        return Err(OidcError::SubjectMismatch);
    }
    Ok(out)
}

/// What the default subject says about the workflow run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectKind {
    Ref(String),
    Environment(String),
    PullRequest,
    Other,
}
pub fn subject_kind(claims: &GithubClaims) -> SubjectKind {
    let rest = &claims.subject[format!("repo:{}:", claims.repository).len()..];
    if let Some(r) = rest.strip_prefix("ref:") {
        SubjectKind::Ref(r.to_owned())
    } else if let Some(e) = rest.strip_prefix("environment:") {
        SubjectKind::Environment(e.to_owned())
    } else if rest == "pull_request" {
        SubjectKind::PullRequest
    } else {
        SubjectKind::Other
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubIdentityPolicy {
    #[serde(default = "github")]
    pub provider: String,
    pub repository_id: String,
    pub repository_owner_id: String,
    /// Informational only; never used for authorization.
    #[serde(default)]
    pub repository: Option<String>,
    pub allowed_refs: Vec<String>,
    pub allowed_workflows: Vec<String>,
    #[serde(default)]
    pub allowed_environments: Vec<String>,
    #[serde(default = "default_events")]
    pub allowed_event_types: Vec<String>,
    pub allowed_permissions: Vec<Scope>,
    #[serde(default = "default_ttl")]
    pub token_ttl_seconds: u32,
}
fn github() -> String {
    "github".into()
}
fn default_events() -> Vec<String> {
    vec!["push".into(), "workflow_dispatch".into()]
}
fn default_ttl() -> u32 {
    600
}
pub const READ_ONLY: &[Scope] = &[
    Scope::ProjectsRead,
    Scope::BuildsRead,
    Scope::PublishesRead,
    Scope::AutomationsRead,
];
const KNOWN_EVENTS: &[&str] = &[
    "push",
    "workflow_dispatch",
    "schedule",
    "release",
    "workflow_run",
    "pull_request",
    "pull_request_target",
    "repository_dispatch",
];

fn workflow_pattern(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 200
        && !p.contains("..")
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/*-@:".contains(&b))
}
fn environment_name(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 64
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._- ".contains(&b))
}
fn numeric_id(p: &str) -> bool {
    !p.is_empty() && p.len() <= 20 && p.bytes().all(|b| b.is_ascii_digit())
}

impl GithubIdentityPolicy {
    /// Deny by default: every dimension must be explicitly populated.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.provider != "github" {
            return Err("provider must be github");
        }
        if !numeric_id(&self.repository_id) || !numeric_id(&self.repository_owner_id) {
            return Err("repository_id and repository_owner_id must be numeric GitHub IDs");
        }
        if self
            .repository
            .as_deref()
            .is_some_and(|r| r.len() > 140 || r.contains(char::is_control))
        {
            return Err("repository is invalid");
        }
        let list = |l: &[String], max: usize| !l.is_empty() && l.len() <= max;
        if !list(&self.allowed_refs, 16) || !self.allowed_refs.iter().all(|r| valid_pattern(r)) {
            return Err("allowed_refs must contain 1–16 safe ref patterns");
        }
        if !list(&self.allowed_workflows, 8)
            || !self.allowed_workflows.iter().all(|w| workflow_pattern(w))
        {
            return Err("allowed_workflows must contain 1–8 workflow_ref patterns");
        }
        if self.allowed_environments.len() > 8
            || !self
                .allowed_environments
                .iter()
                .all(|e| environment_name(e))
        {
            return Err("allowed_environments is invalid");
        }
        if !list(&self.allowed_event_types, 8)
            || !self
                .allowed_event_types
                .iter()
                .all(|e| KNOWN_EVENTS.contains(&e.as_str()))
        {
            return Err("allowed_event_types contains an unsupported event");
        }
        if self.allowed_permissions.is_empty()
            || self.allowed_permissions.len() > 8
            || !self
                .allowed_permissions
                .iter()
                .all(|p| Scope::federated_grantable().contains(p))
        {
            return Err("allowed_permissions must be a subset of the federated-grantable scopes");
        }
        if !(60..=900).contains(&self.token_ttl_seconds) {
            return Err("token_ttl_seconds must be 60–900");
        }
        Ok(())
    }
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let id = format!("github:{}:{}", self.repository_owner_id, self.repository_id);
        Sha256::digest(id)
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    Repository,
    Owner,
    Event,
    Ref,
    Workflow,
    Environment,
}
impl Denial {
    pub fn code(self) -> &'static str {
        match self {
            Self::Repository => "oidc_repository_not_trusted",
            Self::Owner => "oidc_owner_not_trusted",
            Self::Event => "oidc_event_not_allowed",
            Self::Ref => "oidc_ref_not_allowed",
            Self::Workflow => "oidc_workflow_not_allowed",
            Self::Environment => "oidc_environment_not_allowed",
        }
    }
}

/// Is this a pull-request-class event, whose code is controlled by whoever opened it?
pub fn untrusted_event(claims: &GithubClaims) -> bool {
    matches!(
        claims.event_name.as_str(),
        "pull_request" | "pull_request_target"
    ) || subject_kind(claims) == SubjectKind::PullRequest
}

/// Return the scopes this identity may hold. Pull-request identities are read-only even
/// when a policy deliberately admits their event type.
pub fn authorize(
    claims: &GithubClaims,
    policy: &GithubIdentityPolicy,
) -> Result<Vec<Scope>, Denial> {
    if claims.repository_id != policy.repository_id {
        return Err(Denial::Repository);
    }
    if claims.repository_owner_id != policy.repository_owner_id {
        return Err(Denial::Owner);
    }
    if !policy
        .allowed_event_types
        .iter()
        .any(|e| e == &claims.event_name)
    {
        return Err(Denial::Event);
    }
    if !policy
        .allowed_refs
        .iter()
        .any(|p| glob_match(p, &claims.git_ref))
    {
        return Err(Denial::Ref);
    }
    if !policy
        .allowed_workflows
        .iter()
        .any(|p| glob_match(p, &claims.workflow_ref))
    {
        return Err(Denial::Workflow);
    }
    match (&claims.environment, policy.allowed_environments.is_empty()) {
        (None, true) => {}
        (Some(env), false)
            if policy
                .allowed_environments
                .iter()
                .any(|p| glob_match(p, env)) => {}
        _ => return Err(Denial::Environment),
    }
    let mut scopes: Vec<Scope> = vec![];
    for scope in &policy.allowed_permissions {
        if !scopes.contains(scope) && (!untrusted_event(claims) || READ_ONLY.contains(scope)) {
            scopes.push(*scope);
        }
    }
    Ok(scopes)
}

#[cfg(any(test, feature = "testing"))]
pub mod testing {
    //! Deterministic signing fixtures for tests and the acceptance harness only.
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{KeyPair, RsaKeyPair},
    };
    use serde_json::json;

    pub fn key_pair(pkcs8_b64: &str) -> RsaKeyPair {
        let der = base64::engine::general_purpose::STANDARD
            .decode(pkcs8_b64.trim())
            .unwrap();
        RsaKeyPair::from_pkcs8(&der).unwrap()
    }
    /// Parse RSAPublicKey DER (SEQUENCE { INTEGER n, INTEGER e }) into JWK members.
    pub fn jwk(pair: &RsaKeyPair, kid: &str) -> Value {
        fn read(der: &[u8]) -> (&[u8], &[u8]) {
            let len = if der[1] & 0x80 == 0 {
                (der[1] as usize, 2)
            } else {
                let n = (der[1] & 0x7f) as usize;
                (
                    der[2..2 + n]
                        .iter()
                        .fold(0usize, |a, b| (a << 8) | *b as usize),
                    2 + n,
                )
            };
            (&der[len.1..len.1 + len.0], &der[len.1 + len.0..])
        }
        let (seq, _) = read(pair.public_key().as_ref());
        let (n, rest) = read(seq);
        let (e, _) = read(rest);
        let trim = |b: &[u8]| {
            b.iter()
                .copied()
                .skip_while(|x| *x == 0)
                .collect::<Vec<u8>>()
        };
        json!({"kty":"RSA","kid":kid,"use":"sig","alg":"RS256",
            "n":URL_SAFE_NO_PAD.encode(trim(n)),"e":URL_SAFE_NO_PAD.encode(trim(e))})
    }
    pub fn sign(pair: &RsaKeyPair, header: Value, claims: Value) -> String {
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let c = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signed = format!("{h}.{c}");
        let mut sig = vec![0; pair.public().modulus_len()];
        pair.sign(
            &ring::signature::RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            signed.as_bytes(),
            &mut sig,
        )
        .unwrap();
        format!("{signed}.{}", URL_SAFE_NO_PAD.encode(sig))
    }
    pub fn github_claims(now: i64, audience: &str) -> Value {
        json!({
            "iss": GITHUB_ISSUER, "aud": audience,
            "sub": "repo:octo/hello:ref:refs/heads/main", "jti": "11111111-2222-3333-4444-555555555555",
            "iat": now, "nbf": now - 5, "exp": now + 300,
            "repository": "octo/hello", "repository_id": "1296269",
            "repository_owner": "octo", "repository_owner_id": "583231",
            "ref": "refs/heads/main", "ref_type": "branch",
            "sha": "0123456789abcdef0123456789abcdef01234567",
            "event_name": "push",
            "workflow_ref": "octo/hello/.github/workflows/release.yml@refs/heads/main",
            "job_workflow_ref": "octo/hello/.github/workflows/release.yml@refs/heads/main",
            "run_id": "42", "run_attempt": "1", "actor_id": "9", "runner_environment": "github-hosted"
        })
    }
    pub fn header(kid: &str) -> Value {
        json!({"alg":"RS256","typ":"JWT","kid":kid})
    }
    pub fn jwks(values: Vec<Value>) -> JwkSet {
        JwkSet::parse(&serde_json::to_vec(&json!({"keys": values})).unwrap()).unwrap()
    }
    pub const SIGNING_KEY: &str = include_str!("../tests/fixtures/oidc_test_rsa_pkcs8.b64");
    pub const OTHER_KEY: &str = include_str!("../tests/fixtures/oidc_other_rsa_pkcs8.b64");
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use serde_json::json;

    const NOW: i64 = 1_800_000_000;
    fn setup() -> (ring::signature::RsaKeyPair, JwkSet, OidcConfig) {
        let pair = key_pair(SIGNING_KEY);
        let set = jwks(vec![jwk(&pair, "k1")]);
        (pair, set, OidcConfig::github("librehub-test"))
    }
    fn policy() -> GithubIdentityPolicy {
        GithubIdentityPolicy {
            provider: "github".into(),
            repository_id: "1296269".into(),
            repository_owner_id: "583231".into(),
            repository: Some("octo/hello".into()),
            allowed_refs: vec!["refs/heads/main".into(), "refs/tags/v*".into()],
            allowed_workflows: vec!["octo/hello/.github/workflows/release.yml@*".into()],
            allowed_environments: vec![],
            allowed_event_types: vec!["push".into(), "workflow_dispatch".into()],
            allowed_permissions: vec![
                Scope::BuildsWrite,
                Scope::AutomationsRun,
                Scope::AutomationsRead,
            ],
            token_ttl_seconds: 600,
        }
    }
    fn token(claims: Value) -> String {
        let (pair, ..) = setup();
        sign(&pair, header("k1"), claims)
    }
    fn claims() -> Value {
        github_claims(NOW, "librehub-test")
    }
    fn modified(f: impl FnOnce(&mut Value)) -> Value {
        let mut c = claims();
        f(&mut c);
        c
    }
    fn verify(t: &str) -> Result<GithubClaims, OidcError> {
        let (_, set, config) = setup();
        verify_github_token(t, &set, &config, NOW)
    }

    #[test]
    fn valid_token_is_accepted() {
        let c = verify(&token(claims())).unwrap();
        assert_eq!(c.repository_id, "1296269");
        assert_eq!(c.sha.len(), 40);
        assert_eq!(subject_kind(&c), SubjectKind::Ref("refs/heads/main".into()));
        assert!(authorize(&c, &policy()).is_ok());
    }
    #[test]
    fn invalid_signature_is_rejected() {
        let other = key_pair(OTHER_KEY);
        let forged = sign(&other, header("k1"), claims());
        assert_eq!(verify(&forged), Err(OidcError::InvalidSignature));
        // Tampered payload with the original signature.
        let good = token(claims());
        let parts: Vec<&str> = good.split('.').collect();
        let evil = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&modified(|c| c["repository_id"] = json!("1"))).unwrap());
        assert_eq!(
            verify(&format!("{}.{}.{}", parts[0], evil, parts[2])),
            Err(OidcError::InvalidSignature)
        );
    }
    #[test]
    fn algorithm_confusion_and_embedded_keys_are_rejected() {
        let pair = key_pair(SIGNING_KEY);
        for alg in ["none", "HS256", "RS512", "ES256"] {
            let t = sign(&pair, json!({"alg":alg,"kid":"k1"}), claims());
            assert_eq!(verify(&t), Err(OidcError::UnsupportedAlgorithm), "{alg}");
        }
        for field in ["jku", "jwk", "x5u", "x5c"] {
            let mut h = header("k1");
            h[field] = json!("https://evil.example/keys");
            assert_eq!(
                verify(&sign(&pair, h, claims())),
                Err(OidcError::ForbiddenHeader),
                "{field}"
            );
        }
        assert_eq!(
            verify(&sign(
                &pair,
                json!({"alg":"RS256","kid":"unknown"}),
                claims()
            )),
            Err(OidcError::UnknownKey)
        );
        assert_eq!(
            verify(&sign(&pair, json!({"alg":"RS256"}), claims())),
            Err(OidcError::UnknownKey)
        );
        assert_eq!(verify("a.b"), Err(OidcError::Malformed));
        assert_eq!(
            verify(&"x".repeat(MAX_TOKEN_BYTES + 1)),
            Err(OidcError::Malformed)
        );
    }
    #[test]
    fn github_style_headers_with_a_thumbprint_hint_are_accepted() {
        // GitHub's real tokens carry `x5t`; only `kid` ever selects a key.
        let pair = key_pair(SIGNING_KEY);
        let t = sign(
            &pair,
            json!({"alg":"RS256","typ":"JWT","kid":"k1","x5t":"abc123"}),
            claims(),
        );
        assert!(verify(&t).is_ok());
    }
    #[test]
    fn kid_substitution_cannot_pick_an_attacker_key() {
        // The attacker signs with their own key but claims the legitimate kid.
        let attacker = key_pair(OTHER_KEY);
        assert_eq!(
            verify(&sign(&attacker, header("k1"), claims())),
            Err(OidcError::InvalidSignature)
        );
        // A kid absent from the issuer's set fails closed even when the attacker publishes it elsewhere.
        assert_eq!(
            verify(&sign(&attacker, header("attacker"), claims())),
            Err(OidcError::UnknownKey)
        );
    }
    #[test]
    fn issuer_and_audience_are_exact() {
        assert_eq!(
            verify(&token(modified(
                |c| c["iss"] = json!("https://evil.example")
            ))),
            Err(OidcError::WrongIssuer)
        );
        assert_eq!(
            verify(&token(modified(
                |c| c["iss"] = json!("https://token.actions.githubusercontent.com/")
            ))),
            Err(OidcError::WrongIssuer)
        );
        assert_eq!(
            verify(&token(modified(
                |c| c["aud"] = json!("https://github.com/octo")
            ))),
            Err(OidcError::WrongAudience)
        );
        assert_eq!(
            verify(&token(modified(|c| c["aud"] = json!(["a", "b"])))),
            Err(OidcError::WrongAudience)
        );
        assert!(
            verify(&token(modified(
                |c| c["aud"] = json!(["a", "librehub-test"])
            )))
            .is_ok()
        );
        assert_eq!(
            verify(&token(modified(|c| {
                c.as_object_mut().unwrap().remove("aud");
            }))),
            Err(OidcError::MissingClaim)
        );
    }
    #[test]
    fn time_claims_are_enforced() {
        assert_eq!(
            verify(&token(modified(|c| c["exp"] = json!(NOW - 600)))),
            Err(OidcError::Expired)
        );
        assert_eq!(
            verify(&token(modified(|c| c["nbf"] = json!(NOW + 600)))),
            Err(OidcError::NotYetValid)
        );
        assert_eq!(
            verify(&token(modified(|c| c["iat"] = json!(NOW + 600)))),
            Err(OidcError::NotYetValid)
        );
        assert_eq!(
            verify(&token(modified(|c| c["exp"] = json!(NOW + 90_000)))),
            Err(OidcError::LifetimeTooLong)
        );
        assert_eq!(
            verify(&token(modified(|c| {
                c.as_object_mut().unwrap().remove("exp");
            }))),
            Err(OidcError::MissingClaim)
        );
    }
    #[test]
    fn subject_must_match_the_signed_repository_claim() {
        let t = token(modified(|c| {
            c["sub"] = json!("repo:evil/other:ref:refs/heads/main")
        }));
        assert_eq!(verify(&t), Err(OidcError::SubjectMismatch));
        let env = verify(&token(modified(|c| {
            c["sub"] = json!("repo:octo/hello:environment:production");
            c["environment"] = json!("production");
        })))
        .unwrap();
        assert_eq!(
            subject_kind(&env),
            SubjectKind::Environment("production".into())
        );
    }
    #[test]
    fn non_numeric_identifiers_and_short_shas_are_rejected() {
        assert_eq!(
            verify(&token(modified(|c| c["repository_id"] = json!("12;DROP")))),
            Err(OidcError::Malformed)
        );
        assert_eq!(
            verify(&token(modified(|c| c["sha"] = json!("abc")))),
            Err(OidcError::Malformed)
        );
    }
    #[test]
    fn policy_is_deny_by_default_on_every_dimension() {
        let c = verify(&token(claims())).unwrap();
        let mut p = policy();
        p.repository_id = "999".into();
        assert_eq!(authorize(&c, &p), Err(Denial::Repository));
        let mut p = policy();
        p.repository_owner_id = "999".into();
        assert_eq!(authorize(&c, &p), Err(Denial::Owner));
        let mut p = policy();
        p.allowed_refs = vec!["refs/heads/release".into()];
        assert_eq!(authorize(&c, &p), Err(Denial::Ref));
        let mut p = policy();
        p.allowed_workflows = vec!["octo/hello/.github/workflows/other.yml@*".into()];
        assert_eq!(authorize(&c, &p), Err(Denial::Workflow));
        let mut p = policy();
        p.allowed_event_types = vec!["workflow_dispatch".into()];
        assert_eq!(authorize(&c, &p), Err(Denial::Event));
        let mut p = policy();
        p.allowed_environments = vec!["production".into()];
        assert_eq!(authorize(&c, &p), Err(Denial::Environment));
        // And a token carrying an environment is refused when the policy lists none.
        let env = verify(&token(modified(|c| c["environment"] = json!("production")))).unwrap();
        assert_eq!(authorize(&env, &policy()), Err(Denial::Environment));
    }
    #[test]
    fn renamed_repository_with_same_ids_is_still_trusted_but_foreign_ids_are_not() {
        let renamed = verify(&token(modified(|c| {
            c["repository"] = json!("octo/renamed");
            c["sub"] = json!("repo:octo/renamed:ref:refs/heads/main");
            c["workflow_ref"] = json!("octo/renamed/.github/workflows/release.yml@refs/heads/main");
        })))
        .unwrap();
        let mut p = policy();
        p.allowed_workflows = vec!["*/.github/workflows/release.yml@*".into()];
        assert!(authorize(&renamed, &p).is_ok());
        // A same-named repository recreated by someone else has a different immutable ID.
        let squatter = verify(&token(modified(|c| c["repository_id"] = json!("777000")))).unwrap();
        assert_eq!(authorize(&squatter, &p), Err(Denial::Repository));
    }
    #[test]
    fn pull_requests_never_receive_write_scopes() {
        let pr = verify(&token(modified(|c| {
            c["event_name"] = json!("pull_request");
            c["ref"] = json!("refs/pull/7/merge");
            c["sub"] = json!("repo:octo/hello:pull_request");
        })))
        .unwrap();
        assert!(untrusted_event(&pr));
        // Default policy does not even admit the event.
        let mut p = policy();
        p.allowed_refs = vec!["refs/pull/*".into()];
        assert_eq!(authorize(&pr, &p), Err(Denial::Event));
        p.allowed_event_types.push("pull_request".into());
        let scopes = authorize(&pr, &p).unwrap();
        assert_eq!(scopes, vec![Scope::AutomationsRead]);
    }
    #[test]
    fn policy_validation_rejects_privileged_scopes_and_empty_lists() {
        assert!(policy().validate().is_ok());
        for scope in [
            Scope::PublishesWrite,
            Scope::ReleasesApprove,
            Scope::AutomationsWrite,
            Scope::TokensWrite,
            Scope::Operator,
            Scope::IntegrationsWrite,
        ] {
            let mut p = policy();
            p.allowed_permissions = vec![scope];
            assert!(p.validate().is_err(), "{scope:?}");
        }
        let mut p = policy();
        p.allowed_refs.clear();
        assert!(p.validate().is_err());
        let mut p = policy();
        p.repository_id = "octo/hello".into();
        assert!(p.validate().is_err());
        let mut p = policy();
        p.token_ttl_seconds = 86_400;
        assert!(p.validate().is_err());
        let mut p = policy();
        p.allowed_event_types = vec!["issue_comment".into()];
        assert!(p.validate().is_err());
    }
}
