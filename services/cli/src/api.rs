//! A small HTTP client that never logs, prints or URL-encodes a credential.
use crate::error::CliError;
use reqwest::{Method, header};
use serde_json::Value;
use std::time::Duration;
use url::Url;

const MAX_RESPONSE: usize = 8 * 1024 * 1024;

/// Credential wrapper whose Debug/Display never reveal the value.
#[derive(Clone)]
pub struct Secret(String);
impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    base: Url,
    token: Option<Secret>,
}

/// HTTPS everywhere, except explicit loopback development servers. Credentials never travel
/// in cleartext across a network and are never accepted inside the URL.
pub fn validate_base(raw: &str) -> Result<Url, CliError> {
    let url = Url::parse(raw).map_err(|_| CliError::usage("--api-url is not a valid URL"))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(CliError::usage(
            "--api-url must not contain credentials, a query or a fragment",
        ));
    }
    let loopback = match url.host() {
        Some(url::Host::Domain(d)) => d == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    match url.scheme() {
        "https" => Ok(url),
        "http" if loopback => Ok(url),
        _ => Err(CliError::usage(
            "--api-url must use https (plain http is only allowed for localhost)",
        )),
    }
}

impl Client {
    pub fn new(base: &str, token: Option<Secret>) -> Result<Self, CliError> {
        let base = validate_base(base)?;
        // TLS verification stays on; redirects are never followed so a bearer token cannot be
        // replayed to another host.
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .user_agent(concat!("librehub-cli/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| CliError::Network(e.without_url().to_string()))?;
        Ok(Self { http, base, token })
    }
    pub fn base(&self) -> &Url {
        &self.base
    }
    pub fn with_token(&self, token: Option<Secret>) -> Self {
        Self {
            token,
            ..self.clone()
        }
    }
    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }

    fn url(&self, path: &str, query: &[(&str, String)]) -> Result<Url, CliError> {
        let mut url = self.base.clone();
        let joined = format!(
            "{}/{}",
            url.path().trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        url.set_path(&joined);
        if !query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(query.iter().map(|(k, v)| (*k, v.as_str())));
        }
        Ok(url)
    }
    pub async fn request(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
    ) -> Result<(u16, Value), CliError> {
        self.request_with(method, path, query, body, self.token.as_ref())
            .await
    }
    /// Like `request` but authenticating with a specific bearer value (used for OIDC exchange).
    pub async fn request_with(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
        token: Option<&Secret>,
    ) -> Result<(u16, Value), CliError> {
        let url = self.url(path, query)?;
        let mut request = self.http.request(method, url);
        if let Some(token) = token {
            let mut value = header::HeaderValue::from_str(&format!("Bearer {}", token.expose()))
                .map_err(|_| CliError::usage("The credential contains invalid characters"))?;
            value.set_sensitive(true);
            request = request.header(header::AUTHORIZATION, value);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let mut response = request.send().await.map_err(|e| {
            let e = e.without_url();
            CliError::Network(if e.is_timeout() {
                "The request timed out".into()
            } else if e.is_connect() {
                "Cannot connect to the LibreHub server".into()
            } else {
                format!("Request failed: {}", short(&e.to_string()))
            })
        })?;
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| CliError::Network(short(&e.without_url().to_string())))?
        {
            if bytes.len() + chunk.len() > MAX_RESPONSE {
                return Err(CliError::Network("The response is too large".into()));
            }
            bytes.extend_from_slice(&chunk);
        }
        let value: Value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        if (200..300).contains(&status) {
            return Ok((status, value));
        }
        let code = value["code"]
            .as_str()
            .map(clean)
            .unwrap_or_else(|| format!("http_{status}"));
        let message = value["message"]
            .as_str()
            .map(clean)
            .unwrap_or_else(|| format!("The server returned HTTP {status}"));
        Err(CliError::Api {
            status,
            code,
            message,
        })
    }
    pub async fn get(&self, path: &str, query: &[(&str, String)]) -> Result<Value, CliError> {
        Ok(self.request(Method::GET, path, query, None).await?.1)
    }
    pub async fn post(&self, path: &str, body: Option<&Value>) -> Result<(u16, Value), CliError> {
        self.request(Method::POST, path, &[], body).await
    }
}
/// Server text is displayed, so strip control characters and bound its length.
fn clean(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(300).collect()
}
fn short(text: &str) -> String {
    clean(text).chars().take(120).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn base_urls_are_validated() {
        assert!(validate_base("https://librehub.example").is_ok());
        assert!(validate_base("http://127.0.0.1:8080").is_ok());
        assert!(validate_base("http://localhost:8080/").is_ok());
        assert!(validate_base("http://librehub.example").is_err());
        assert!(validate_base("https://user:token@librehub.example").is_err());
        assert!(validate_base("https://librehub.example/?token=abc").is_err());
        assert!(validate_base("ftp://librehub.example").is_err());
        assert!(validate_base("not a url").is_err());
    }
    #[test]
    fn secrets_are_redacted_in_debug_output() {
        let s = Secret::new("librehub_super_secret");
        assert!(!format!("{s:?}").contains("super_secret"));
        let client = Client::new("https://librehub.example", Some(s)).unwrap();
        assert!(!format!("{:?}", client.token).contains("super_secret"));
    }
    #[test]
    fn urls_never_carry_credentials() {
        let client =
            Client::new("https://librehub.example/base", Some(Secret::new("tok"))).unwrap();
        let url = client
            .url("/api/v1/projects", &[("limit", "5".into())])
            .unwrap();
        assert_eq!(
            url.as_str(),
            "https://librehub.example/base/api/v1/projects?limit=5"
        );
        assert!(!url.as_str().contains("tok"));
    }
}
