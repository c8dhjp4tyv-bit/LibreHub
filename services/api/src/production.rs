//! Production profile. `LIBREHUB_ENVIRONMENT=production` enables the checks here. A production
//! process refuses to start on a test-only switch, an inline secret, a contradictory safety
//! setting, or a public origin that is not HTTPS, and it reports every problem at once by variable
//! name. Values are never printed, because some of them are secrets.
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    path::Path,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Development,
    Production,
}

pub type Vars = BTreeMap<String, String>;

/// `LIBREHUB_ENVIRONMENT`: unset means development, which keeps every existing workflow intact.
pub fn environment(vars: &Vars) -> Result<Environment, String> {
    match vars.get("LIBREHUB_ENVIRONMENT").map(String::as_str) {
        None | Some("development") | Some("test") => Ok(Environment::Development),
        Some("production") => Ok(Environment::Production),
        Some(_) => Err("LIBREHUB_ENVIRONMENT must be production, development or test".into()),
    }
}

/// Validate the process configuration. Development returns immediately; production runs every
/// rule and returns all problems together.
pub fn validate(vars: &Vars) -> Result<Environment, Vec<String>> {
    let environment = environment(vars).map_err(|problem| vec![problem])?;
    if environment == Environment::Development {
        return Ok(environment);
    }
    let mut problems = Vec::new();
    for name in vars.keys() {
        if name.starts_with("LIBREHUB_TEST_") || name.ends_with("_FOR_TESTS") {
            problems.push(format!(
                "{name} is a test-only switch and cannot be set in production"
            ));
        }
    }
    if vars.contains_key("LIBREHUB_FLAT_MANAGER_TOKEN") {
        problems.push("LIBREHUB_FLAT_MANAGER_TOKEN must be supplied as LIBREHUB_FLAT_MANAGER_TOKEN_FILE, never inline".into());
    }
    require_value(
        vars,
        "LIBREHUB_SUPPLY_CHAIN_POLICY",
        "enforce",
        &mut problems,
    );
    require_value(vars, "LIBREHUB_WORKER_ISOLATION", "hardened", &mut problems);
    https_origin(vars, "LIBREHUB_API_PUBLIC_URL", &mut problems);
    https_origin(vars, "LIBREHUB_WEB_PUBLIC_URL", &mut problems);
    https_origin(vars, "LIBREHUB_PUBLIC_BASE_URL", &mut problems);
    match vars.get("LIBREHUB_DATA_DIR") {
        Some(dir) if Path::new(dir).is_absolute() => {}
        _ => problems.push("LIBREHUB_DATA_DIR must be an absolute path".into()),
    }
    match vars.get("LIBREHUB_TRUSTED_PROXIES") {
        Some(list) if !list.trim().is_empty() => {
            if list.split(',').any(|ip| ip.trim().parse::<IpAddr>().is_err()) {
                problems.push("LIBREHUB_TRUSTED_PROXIES must be a comma-separated list of IP addresses".into());
            }
        }
        _ => problems.push("LIBREHUB_TRUSTED_PROXIES must list the reverse proxy address; forwarded headers are otherwise ignored".into()),
    }
    if let Some(bind) = vars.get("LIBREHUB_METRICS_BIND") {
        match bind.parse::<SocketAddr>() {
            Ok(addr) if is_internal(addr.ip()) => {}
            _ => {
                problems.push("LIBREHUB_METRICS_BIND must be a loopback or private address".into())
            }
        }
    }
    if let Some(format) = vars.get("LIBREHUB_LOG_FORMAT")
        && format != "json"
        && format != "text"
    {
        problems.push("LIBREHUB_LOG_FORMAT must be json or text".into());
    }
    if problems.is_empty() {
        Ok(environment)
    } else {
        Err(problems)
    }
}

fn require_value(vars: &Vars, name: &str, expected: &str, problems: &mut Vec<String>) {
    if vars.get(name).map(String::as_str) != Some(expected) {
        problems.push(format!("{name} must be {expected} in production"));
    }
}
fn https_origin(vars: &Vars, name: &str, problems: &mut Vec<String>) {
    let Some(value) = vars.get(name) else {
        problems.push(format!("{name} is required in production"));
        return;
    };
    let secure = value.strip_prefix("https://").is_some_and(|rest| {
        let host = rest.split('/').next().unwrap_or_default();
        !host.is_empty() && !host.contains('@') && !host.contains(' ')
    });
    if !secure {
        problems.push(format!(
            "{name} must be an https:// origin without credentials"
        ));
    }
}
/// Loopback, RFC 1918 and unique-local addresses only: nothing here is reachable from the internet.
pub fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// Public material (repository and attestor public keys, a CA certificate) may be world-readable.
/// Every other `*_FILE` variable names a secret and must be readable by its owner only.
fn is_public_material(name: &str) -> bool {
    name.contains("PUBLIC") || name.ends_with("KEYS_FILE") || name.ends_with("CA_FILE")
}

/// Check every `LIBREHUB_*_FILE` path on the real file system: it must exist and be a regular
/// file, and secrets must not be readable by group or others.
pub fn check_secret_files(vars: &Vars) -> Vec<String> {
    let mut problems = Vec::new();
    for (name, path) in vars
        .iter()
        .filter(|(name, _)| name.starts_with("LIBREHUB_") && name.ends_with("_FILE"))
    {
        match std::fs::metadata(path) {
            Ok(metadata) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if !is_public_material(name) && metadata.permissions().mode() & 0o077 != 0 {
                        problems.push(format!("{name} must not be readable by group or others"));
                    }
                }
                if !metadata.is_file() {
                    problems.push(format!("{name} must name a regular file"));
                }
            }
            Err(_) => problems.push(format!("{name} cannot be read")),
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    fn production() -> Vars {
        [
            ("LIBREHUB_ENVIRONMENT", "production"),
            ("LIBREHUB_SUPPLY_CHAIN_POLICY", "enforce"),
            ("LIBREHUB_WORKER_ISOLATION", "hardened"),
            ("LIBREHUB_API_PUBLIC_URL", "https://api.librehub.example"),
            ("LIBREHUB_WEB_PUBLIC_URL", "https://librehub.example"),
            (
                "LIBREHUB_PUBLIC_BASE_URL",
                "https://repo.librehub.example/repo",
            ),
            ("LIBREHUB_DATA_DIR", "/var/lib/librehub"),
            ("LIBREHUB_TRUSTED_PROXIES", "10.20.0.2"),
            ("LIBREHUB_METRICS_BIND", "127.0.0.1:9464"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
    }
    fn problems(vars: &Vars) -> Vec<String> {
        validate(vars).unwrap_err()
    }

    #[test]
    fn a_complete_production_configuration_is_accepted() {
        assert_eq!(validate(&production()), Ok(Environment::Production));
    }

    #[test]
    fn development_is_the_default_and_is_not_restricted() {
        let vars: Vars = [(
            "LIBREHUB_WEBHOOK_ALLOW_LOOPBACK_FOR_TESTS".to_owned(),
            "1".to_owned(),
        )]
        .into();
        assert_eq!(validate(&vars), Ok(Environment::Development));
        assert_eq!(environment(&Vars::new()), Ok(Environment::Development));
    }

    #[test]
    fn unknown_environments_are_rejected() {
        let vars: Vars = [("LIBREHUB_ENVIRONMENT".to_owned(), "prod".to_owned())].into();
        assert!(validate(&vars).is_err());
    }

    #[test]
    fn test_only_switches_are_rejected_in_production_and_named_not_valued() {
        for flag in [
            "LIBREHUB_WEBHOOK_ALLOW_LOOPBACK_FOR_TESTS",
            "LIBREHUB_OIDC_INSECURE_FOR_TESTS",
            "LIBREHUB_TEST_DNS_TXT",
            "LIBREHUB_TEST_VULNERABILITY_OUTAGE",
        ] {
            let mut vars = production();
            vars.insert(flag.into(), "super-secret-value".into());
            let found = problems(&vars);
            assert!(
                found.iter().any(|p| p.starts_with(flag)),
                "{flag}: {found:?}"
            );
            assert!(found.iter().all(|p| !p.contains("super-secret-value")));
        }
    }

    #[test]
    fn contradictory_safety_settings_are_rejected() {
        let mut vars = production();
        vars.insert("LIBREHUB_SUPPLY_CHAIN_POLICY".into(), "development".into());
        vars.insert("LIBREHUB_WORKER_ISOLATION".into(), "compatibility".into());
        let found = problems(&vars);
        assert!(
            found
                .iter()
                .any(|p| p.contains("LIBREHUB_SUPPLY_CHAIN_POLICY"))
        );
        assert!(
            found
                .iter()
                .any(|p| p.contains("LIBREHUB_WORKER_ISOLATION"))
        );
    }

    #[test]
    fn public_origins_must_be_https_without_credentials() {
        for bad in [
            "http://api.librehub.example",
            "https://user:pw@api.librehub.example",
            "https://",
            "api.librehub.example",
        ] {
            let mut vars = production();
            vars.insert("LIBREHUB_API_PUBLIC_URL".into(), bad.into());
            assert!(
                problems(&vars)
                    .iter()
                    .any(|p| p.starts_with("LIBREHUB_API_PUBLIC_URL")),
                "{bad}"
            );
        }
        let mut vars = production();
        vars.remove("LIBREHUB_WEB_PUBLIC_URL");
        assert!(
            problems(&vars)
                .iter()
                .any(|p| p.contains("LIBREHUB_WEB_PUBLIC_URL is required"))
        );
    }

    #[test]
    fn inline_flat_manager_tokens_are_rejected() {
        let mut vars = production();
        vars.insert("LIBREHUB_FLAT_MANAGER_TOKEN".into(), "x".into());
        assert!(problems(&vars).iter().any(|p| p.contains("_FILE")));
    }

    #[test]
    fn forwarded_headers_need_an_explicit_proxy_and_metrics_stay_internal() {
        let mut vars = production();
        vars.remove("LIBREHUB_TRUSTED_PROXIES");
        assert!(
            problems(&vars)
                .iter()
                .any(|p| p.contains("LIBREHUB_TRUSTED_PROXIES"))
        );
        let mut vars = production();
        vars.insert(
            "LIBREHUB_TRUSTED_PROXIES".into(),
            "10.0.0.1, not-an-ip".into(),
        );
        assert!(
            problems(&vars)
                .iter()
                .any(|p| p.contains("LIBREHUB_TRUSTED_PROXIES"))
        );
        let mut vars = production();
        vars.insert("LIBREHUB_METRICS_BIND".into(), "0.0.0.0:9464".into());
        assert!(
            problems(&vars)
                .iter()
                .any(|p| p.contains("LIBREHUB_METRICS_BIND"))
        );
    }

    #[test]
    fn every_problem_is_reported_together() {
        let found =
            problems(&[("LIBREHUB_ENVIRONMENT".to_owned(), "production".to_owned())].into());
        assert!(found.len() >= 6, "{found:?}");
    }

    #[test]
    fn secret_files_are_private_and_public_material_may_be_shared() {
        let dir =
            std::env::temp_dir().join(format!("librehub-secret-check-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let secret = dir.join("token");
        let public = dir.join("repository.gpg");
        std::fs::write(&secret, b"s").unwrap();
        std::fs::write(&public, b"p").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o400)).unwrap();
            std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let ok: Vars = [
            (
                "LIBREHUB_FLAT_MANAGER_TOKEN_FILE".to_owned(),
                secret.display().to_string(),
            ),
            (
                "LIBREHUB_SIGNING_PUBLIC_KEY_FILE".to_owned(),
                public.display().to_string(),
            ),
        ]
        .into();
        assert!(
            check_secret_files(&ok).is_empty(),
            "{:?}",
            check_secret_files(&ok)
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let loose: Vars = [(
            "LIBREHUB_FLAT_MANAGER_TOKEN_FILE".to_owned(),
            secret.display().to_string(),
        )]
        .into();
        assert_eq!(check_secret_files(&loose).len(), 1);
        let missing: Vars = [(
            "LIBREHUB_ATTESTOR_KEY_FILE".to_owned(),
            dir.join("absent").display().to_string(),
        )]
        .into();
        assert_eq!(check_secret_files(&missing).len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn internal_addresses_are_loopback_or_private() {
        assert!(is_internal("127.0.0.1".parse().unwrap()));
        assert!(is_internal("10.1.2.3".parse().unwrap()));
        assert!(is_internal("172.16.0.9".parse().unwrap()));
        assert!(is_internal("fd00::1".parse().unwrap()));
        assert!(!is_internal("0.0.0.0".parse().unwrap()));
        assert!(!is_internal("203.0.113.7".parse().unwrap()));
    }
}
