//! GitHub Actions identity verification with a safe, rate-limited JWKS cache.
//!
//! Keys come only from the operator-configured issuer. A token cannot name its own key
//! source, an unknown `kid` triggers at most one refresh per interval, and a failed refresh
//! never widens trust (stale keys keep working for a bounded time, otherwise we fail closed).
use async_trait::async_trait;
use librehub_automation::oidc::{self, GithubClaims, JwkSet, OidcConfig, OidcError};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

pub const KEY_TTL: Duration = Duration::from_secs(600);
pub const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
pub const MAX_STALE: Duration = Duration::from_secs(24 * 3600);
const MAX_JWKS_BYTES: usize = 256 * 1024;
const REQUESTS_PER_MINUTE: usize = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    Token(OidcError),
    /// The issuer's keys cannot be fetched and no usable cached copy exists.
    KeysUnavailable,
    RateLimited,
}

#[async_trait]
pub trait JwksFetcher: Send + Sync {
    async fn fetch(&self) -> anyhow::Result<JwkSet>;
}

pub struct HttpJwksFetcher {
    url: String,
    client: reqwest::Client,
}
impl HttpJwksFetcher {
    pub fn new(url: &str, allow_insecure: bool) -> anyhow::Result<Self> {
        let parsed = url::Url::parse(url)?;
        anyhow::ensure!(
            parsed.scheme() == "https" || allow_insecure,
            "The OIDC JWKS URL must use https"
        );
        anyhow::ensure!(
            parsed.username().is_empty() && parsed.password().is_none(),
            "The OIDC JWKS URL must not contain credentials"
        );
        Ok(Self {
            url: url.to_owned(),
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(3))
                .timeout(Duration::from_secs(8))
                .user_agent("LibreHub-OIDC/1")
                .build()?,
        })
    }
}
#[async_trait]
impl JwksFetcher for HttpJwksFetcher {
    async fn fetch(&self) -> anyhow::Result<JwkSet> {
        let mut response = self.client.get(&self.url).send().await?;
        anyhow::ensure!(
            response.status().is_success(),
            "JWKS endpoint returned {}",
            response.status()
        );
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            anyhow::ensure!(
                body.len() + chunk.len() <= MAX_JWKS_BYTES,
                "JWKS response is too large"
            );
            body.extend_from_slice(&chunk);
        }
        JwkSet::parse(&body).map_err(|e| anyhow::anyhow!(e.code()))
    }
}

struct Cache {
    keys: Option<JwkSet>,
    fetched_at: Option<Instant>,
    last_attempt: Option<Instant>,
}
pub struct OidcVerifier {
    pub config: OidcConfig,
    fetcher: Arc<dyn JwksFetcher>,
    cache: Mutex<Cache>,
    window: Mutex<(Instant, usize)>,
}
impl OidcVerifier {
    pub fn new(config: OidcConfig, fetcher: Arc<dyn JwksFetcher>) -> Self {
        Self {
            config,
            fetcher,
            cache: Mutex::new(Cache {
                keys: None,
                fetched_at: None,
                last_attempt: None,
            }),
            window: Mutex::new((Instant::now(), 0)),
        }
    }
    async fn admit(&self) -> bool {
        let mut window = self.window.lock().await;
        if window.0.elapsed() >= Duration::from_secs(60) {
            *window = (Instant::now(), 0);
        }
        window.1 += 1;
        window.1 <= REQUESTS_PER_MINUTE
    }
    /// Return current keys, refreshing when stale or forced (and permitted by the interval).
    async fn keys(&self, force: bool) -> Result<JwkSet, VerifyError> {
        let mut cache = self.cache.lock().await;
        let fresh = cache.fetched_at.is_some_and(|t| t.elapsed() < KEY_TTL);
        let may_refresh = cache
            .last_attempt
            .is_none_or(|t| t.elapsed() >= MIN_REFRESH_INTERVAL);
        if cache.keys.is_none() || (!fresh && may_refresh) || (force && may_refresh) {
            cache.last_attempt = Some(Instant::now());
            match self.fetcher.fetch().await {
                Ok(keys) => {
                    cache.keys = Some(keys);
                    cache.fetched_at = Some(Instant::now());
                }
                Err(error) => {
                    tracing::warn!(error=%error, "Cannot refresh OIDC signing keys");
                    if cache.fetched_at.is_none_or(|t| t.elapsed() > MAX_STALE) {
                        cache.keys = None;
                    }
                }
            }
        }
        cache.keys.clone().ok_or(VerifyError::KeysUnavailable)
    }
    pub async fn verify(&self, token: &str) -> Result<GithubClaims, VerifyError> {
        self.verify_at(token, chrono::Utc::now().timestamp()).await
    }
    pub async fn verify_at(&self, token: &str, now: i64) -> Result<GithubClaims, VerifyError> {
        if !self.admit().await {
            return Err(VerifyError::RateLimited);
        }
        let keys = self.keys(false).await?;
        match oidc::verify_github_token(token, &keys, &self.config, now) {
            Err(OidcError::UnknownKey) => {
                // Key rotation: one forced refresh (rate limited) and a single retry.
                let keys = self.keys(true).await?;
                oidc::verify_github_token(token, &keys, &self.config, now)
                    .map_err(VerifyError::Token)
            }
            other => other.map_err(VerifyError::Token),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use librehub_automation::oidc::testing::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const NOW: i64 = 1_800_000_000;
    struct Fixture {
        sets: std::sync::Mutex<Vec<Option<JwkSet>>>,
        calls: AtomicUsize,
    }
    #[async_trait]
    impl JwksFetcher for Fixture {
        async fn fetch(&self) -> anyhow::Result<JwkSet> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            let sets = self.sets.lock().unwrap();
            sets.get(n.min(sets.len() - 1))
                .cloned()
                .flatten()
                .ok_or_else(|| anyhow::anyhow!("outage"))
        }
    }
    fn verifier(sets: Vec<Option<JwkSet>>) -> (OidcVerifier, Arc<Fixture>) {
        let fixture = Arc::new(Fixture {
            sets: std::sync::Mutex::new(sets),
            calls: AtomicUsize::new(0),
        });
        (
            OidcVerifier::new(OidcConfig::github("librehub-test"), fixture.clone()),
            fixture,
        )
    }
    fn token(kid: &str, key: &str) -> String {
        sign(
            &key_pair(key),
            header(kid),
            github_claims(NOW, "librehub-test"),
        )
    }
    #[tokio::test]
    async fn unknown_kid_refreshes_once_and_never_spams_the_issuer() {
        let old = jwks(vec![jwk(&key_pair(OTHER_KEY), "old")]);
        let new = jwks(vec![jwk(&key_pair(SIGNING_KEY), "new")]);
        let (v, fixture) = verifier(vec![Some(old), Some(new)]);
        // The first fetch lacks "new"; one forced refresh would be rate limited right after the first fetch,
        // so the legitimate rotation is only picked up after the interval. Unknown kids stay rejected.
        assert_eq!(
            v.verify_at(&token("new", SIGNING_KEY), NOW).await,
            Err(VerifyError::Token(OidcError::UnknownKey))
        );
        for _ in 0..20 {
            assert_eq!(
                v.verify_at(&token("spam", SIGNING_KEY), NOW).await,
                Err(VerifyError::Token(OidcError::UnknownKey))
            );
        }
        assert_eq!(
            fixture.calls.load(Ordering::SeqCst),
            1,
            "kid spam must not hammer the issuer"
        );
    }
    #[tokio::test]
    async fn known_key_verifies_from_cache() {
        let set = jwks(vec![jwk(&key_pair(SIGNING_KEY), "k1")]);
        let (v, fixture) = verifier(vec![Some(set)]);
        for _ in 0..5 {
            assert!(v.verify_at(&token("k1", SIGNING_KEY), NOW).await.is_ok());
        }
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn outage_without_cache_fails_closed() {
        let (v, _) = verifier(vec![None]);
        assert_eq!(
            v.verify_at(&token("k1", SIGNING_KEY), NOW).await,
            Err(VerifyError::KeysUnavailable)
        );
    }
    #[tokio::test]
    async fn requests_are_rate_limited() {
        let set = jwks(vec![jwk(&key_pair(SIGNING_KEY), "k1")]);
        let (v, _) = verifier(vec![Some(set)]);
        let mut limited = false;
        for _ in 0..(REQUESTS_PER_MINUTE + 5) {
            if v.verify_at("a.b.c", NOW).await == Err(VerifyError::RateLimited) {
                limited = true;
            }
        }
        assert!(limited);
    }
    #[test]
    fn jwks_url_must_be_https() {
        assert!(HttpJwksFetcher::new("http://issuer.example/jwks", false).is_err());
        assert!(HttpJwksFetcher::new("https://user:pw@issuer.example/jwks", false).is_err());
        assert!(
            HttpJwksFetcher::new(
                "https://token.actions.githubusercontent.com/.well-known/jwks",
                false
            )
            .is_ok()
        );
        assert!(HttpJwksFetcher::new("http://127.0.0.1:1/jwks", true).is_ok());
    }
}
