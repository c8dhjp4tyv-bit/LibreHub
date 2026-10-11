//! Credential discovery. Static tokens come from the environment or a private file; GitHub
//! Actions identities are exchanged on demand and kept only in memory.
use crate::{
    api::{Client, Secret},
    error::CliError,
};
use reqwest::Method;
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::PathBuf};

pub fn config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("LIBREHUB_CONFIG_DIR") {
        return dir.into();
    }
    if let Ok(dir) = std::env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(dir).join("librehub");
    }
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".config/librehub")
}
fn credentials_path() -> PathBuf {
    config_dir().join("credentials.json")
}
/// Credentials are keyed by the server origin so a token is never sent to another server.
pub fn origin_key(client: &Client) -> String {
    let url = client.base();
    format!("{}://{}", url.scheme(), url.authority())
}

#[cfg(unix)]
fn check_private(path: &std::path::Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .map_err(|e| CliError::usage(format!("Cannot read credentials: {e}")))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(CliError::usage(format!(
            "{} must not be accessible by other users (chmod 600)",
            path.display()
        )));
    }
    Ok(())
}
#[cfg(not(unix))]
fn check_private(_: &std::path::Path) -> Result<(), CliError> {
    Ok(())
}

pub fn load_stored(client: &Client) -> Result<Option<Secret>, CliError> {
    let path = credentials_path();
    if !path.exists() {
        return Ok(None);
    }
    check_private(&path)?;
    let text = std::fs::read_to_string(&path)
        .map_err(|e| CliError::usage(format!("Cannot read credentials: {e}")))?;
    let map: BTreeMap<String, Value> = serde_json::from_str(&text)
        .map_err(|_| CliError::usage("The credentials file is corrupt"))?;
    Ok(map
        .get(&origin_key(client))
        .and_then(|v| v["token"].as_str())
        .map(Secret::new))
}
pub fn store(client: &Client, token: &Secret) -> Result<PathBuf, CliError> {
    let dir = config_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| CliError::usage(format!("Cannot create {}: {e}", dir.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    let path = credentials_path();
    let mut map: BTreeMap<String, Value> = if path.exists() {
        check_private(&path)?;
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_default())
            .unwrap_or_default()
    } else {
        BTreeMap::new()
    };
    map.insert(origin_key(client), json!({"token": token.expose()}));
    let temp = dir.join(format!(".credentials.{}.tmp", std::process::id()));
    {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp)
            .map_err(|e| CliError::usage(format!("Cannot write credentials: {e}")))?;
        file.write_all(serde_json::to_string(&map).unwrap_or_default().as_bytes())
            .map_err(|e| CliError::usage(e.to_string()))?;
        file.sync_all().ok();
    }
    std::fs::rename(&temp, &path)
        .map_err(|e| CliError::usage(format!("Cannot write credentials: {e}")))?;
    Ok(path)
}
pub fn forget(client: &Client) -> Result<bool, CliError> {
    let path = credentials_path();
    if !path.exists() {
        return Ok(false);
    }
    check_private(&path)?;
    let mut map: BTreeMap<String, Value> =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_default())
            .unwrap_or_default();
    let removed = map.remove(&origin_key(client)).is_some();
    std::fs::write(&path, serde_json::to_string(&map).unwrap_or_default())
        .map_err(|e| CliError::usage(e.to_string()))?;
    Ok(removed)
}

pub fn in_github_actions() -> bool {
    std::env::var("GITHUB_ACTIONS").is_ok_and(|v| v == "true")
}
/// Make the runner hide a value in all later log output.
pub fn mask(value: &str) {
    if in_github_actions() && !value.is_empty() && !value.contains(['\n', '\r']) {
        println!("::add-mask::{value}");
    }
}

/// Ask the GitHub Actions runtime for an OIDC identity token with LibreHub's audience.
pub async fn github_identity_token(audience: &str) -> Result<Secret, CliError> {
    let url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").map_err(|_| {
        CliError::usage(
            "ACTIONS_ID_TOKEN_REQUEST_URL is not set; the job needs `permissions: id-token: write`",
        )
    })?;
    let request_token = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        .map_err(|_| CliError::usage("ACTIONS_ID_TOKEN_REQUEST_TOKEN is not set"))?;
    let mut parsed = url::Url::parse(&url)
        .map_err(|_| CliError::usage("ACTIONS_ID_TOKEN_REQUEST_URL is invalid"))?;
    if parsed.scheme() != "https" && !matches!(parsed.host_str(), Some("127.0.0.1" | "localhost")) {
        return Err(CliError::usage(
            "ACTIONS_ID_TOKEN_REQUEST_URL must use https",
        ));
    }
    parsed.query_pairs_mut().append_pair("audience", audience);
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| CliError::Network(e.without_url().to_string()))?;
    let mut bearer = reqwest::header::HeaderValue::from_str(&format!("bearer {request_token}"))
        .map_err(|_| CliError::usage("Invalid runtime token"))?;
    bearer.set_sensitive(true);
    let response = http
        .get(parsed)
        .header(reqwest::header::AUTHORIZATION, bearer)
        .send()
        .await
        .map_err(|e| {
            CliError::Network(format!(
                "Cannot obtain the GitHub identity token: {}",
                e.without_url()
            ))
        })?;
    if !response.status().is_success() {
        return Err(CliError::Network(format!(
            "GitHub refused to issue an identity token (HTTP {})",
            response.status().as_u16()
        )));
    }
    let value: Value = response.json().await.map_err(|_| {
        CliError::Network("GitHub returned an unreadable identity token response".into())
    })?;
    let token = value["value"]
        .as_str()
        .ok_or_else(|| CliError::Network("GitHub returned no identity token".into()))?;
    mask(token);
    Ok(Secret::new(token))
}

pub struct Exchanged {
    pub token: Secret,
    pub expires_in: i64,
    pub scopes: Vec<String>,
}
/// Exchange a verified GitHub identity for a short-lived, project-bound LibreHub credential.
pub async fn exchange(
    client: &Client,
    project: &str,
    identity: &Secret,
) -> Result<Exchanged, CliError> {
    let (_, value) = client
        .request_with(
            Method::POST,
            "/api/v1/integrations/github/oidc/exchange",
            &[],
            Some(&json!({"project_id": project})),
            Some(identity),
        )
        .await?;
    let token = value["token"]
        .as_str()
        .ok_or_else(|| CliError::Network("The exchange response had no token".into()))?;
    mask(token);
    Ok(Exchanged {
        token: Secret::new(token),
        expires_in: value["expires_in"].as_i64().unwrap_or(0),
        scopes: value["scopes"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
    })
}
