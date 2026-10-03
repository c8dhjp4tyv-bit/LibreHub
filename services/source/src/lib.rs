//! Trusted, credential-free HTTPS Git resolution; untrusted content remains data.
use async_trait::async_trait;
use librehub_common::*;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{io::AsyncReadExt, process::Command};
use url::Url;

mod relay;
use relay::{Relay, RelayState, relay_request, uuid_nonce};

pub const MAX_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_FILES: usize = 4096;
pub const MAX_CANDIDATES: usize = 64;
pub const MAX_GIT_BYTES: u64 = 128 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(120);
#[derive(Debug, Clone, thiserror::Error)]
#[error("{code}")]
pub struct SourceError {
    pub code: &'static str,
    pub retryable: bool,
    pub candidates: Vec<String>,
}
impl SourceError {
    pub fn new(code: &'static str) -> Self {
        Self {
            code,
            retryable: false,
            candidates: vec![],
        }
    }
    pub fn transient(code: &'static str) -> Self {
        Self {
            code,
            retryable: true,
            candidates: vec![],
        }
    }
    pub fn failure(&self) -> SourceFailure {
        SourceFailure { code:self.code.into(), message: "Source processing did not complete; inspect the error code and project configuration.".into(), retryable:self.retryable, candidates:self.candidates.clone() }
    }
}
type SnapshotFiles = (
    BTreeMap<String, Vec<u8>>,
    std::collections::BTreeSet<String>,
);
type Result<T> = std::result::Result<T, SourceError>;
fn storage(_: impl std::fmt::Debug) -> SourceError {
    SourceError::new("source_storage_failed")
}

/// Explicit operator-owned test fixture mapping. It does not relax URL admission:
/// only this exact HTTPS identity may connect to one pinned TLS fixture address.
#[derive(Clone, Debug)]
pub struct TestOrigin {
    pub repository: String,
    pub address: Ipv4Addr,
    pub port: u16,
    pub ca_file: PathBuf,
}
#[derive(Clone, Debug, Default)]
pub struct GitSource {
    pub test_origin: Option<TestOrigin>,
}
pub struct FetchedSource {
    pub workspace: tempfile::TempDir,
    pub files: BTreeMap<String, Vec<u8>>,
    pub executable: std::collections::BTreeSet<String>,
}
pub struct PreparedSource {
    pub manifest: FlatpakManifest,
    pub manifest_path: String,
    pub snapshot: SourceSnapshot,
    pub archive: Vec<u8>,
}
#[async_trait]
pub trait SourceProvider: Send + Sync {
    async fn resolve_revision(
        &self,
        repository: &ProjectSource,
        source_ref: &str,
    ) -> Result<String>;
    async fn fetch_source(
        &self,
        repository: &ProjectSource,
        commit: &str,
        staging: &Path,
    ) -> Result<FetchedSource>;
    fn discover_manifest(
        &self,
        fetched: &FetchedSource,
        manifest_path: Option<&str>,
    ) -> Result<PreparedSource>;
}
pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, c, _] = v.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 168 || b == 0 || (b == 88 && c == 99) || (b == 0 && c == 2)))
                || (a == 100 && (64..=127).contains(&b))
                || (a == 198 && (b == 18 || b == 19 || b == 51))
                || (a == 203 && b == 0 && c == 113))
        }
        // Allow only global unicast, excluding documentation, 6to4 and mapped IPv4.
        IpAddr::V6(v) => {
            (v.segments()[0] & 0xe000) == 0x2000
                && v.segments()[0] != 0x2002
                && !(v.segments()[0] == 0x2001 && v.segments()[1] < 0x2000)
        }
    }
}
pub fn normalize_repository(source: &ProjectSource) -> Result<ProjectSource> {
    if source.url.len() > 2048 || source.url.contains(['\\', '\n', '\r', '\0', '%']) {
        return Err(SourceError::new("repository_not_allowed"));
    }
    let mut url =
        Url::parse(&source.url).map_err(|_| SourceError::new("repository_not_allowed"))?;
    let host = url
        .host_str()
        .ok_or_else(|| SourceError::new("repository_not_allowed"))?
        .to_ascii_lowercase();
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port().is_some()
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with('.')
        || host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|ip| !public_ip(ip))
    {
        return Err(SourceError::new("repository_not_allowed"));
    }
    let path = url.path().trim_end_matches('/').trim_end_matches(".git");
    if !safe_path(path.trim_start_matches('/'))
        || path.split('/').skip(1).any(|p| {
            p.starts_with('-')
                || !p
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
    {
        return Err(SourceError::new("repository_not_allowed"));
    }
    if source.provider == RepositoryProvider::Github
        && (host != "github.com" || path.split('/').count() != 3)
    {
        return Err(SourceError::new("repository_not_allowed"));
    }
    let path = if host == "github.com" {
        path.to_ascii_lowercase()
    } else {
        path.to_owned()
    };
    url.set_path(&format!("{path}.git"));
    Ok(ProjectSource {
        provider: source.provider,
        url: url.to_string(),
    })
}
pub fn safe_ref(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.starts_with('-')
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.ends_with('.')
        && !value.contains("..")
        && !value.contains("@{")
        && value != "@"
        && value
            .split('/')
            .all(|part| !part.is_empty() && !part.starts_with('.') && !part.ends_with(".lock"))
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
}
pub fn valid_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
pub fn safe_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.starts_with('/')
        && !value.contains(['\\', ':', '\0'])
        && value.split('/').all(|p| {
            !p.is_empty()
                && p != "."
                && p != ".."
                && p != ".git"
                && !p.chars().any(char::is_control)
        })
}
impl GitSource {
    async fn relay(&self, source: &ProjectSource) -> Result<Relay> {
        let source = normalize_repository(source)?;
        let mut url = Url::parse(&source.url).map_err(storage)?;
        let host = url
            .host_str()
            .ok_or_else(|| SourceError::new("repository_not_allowed"))?
            .to_owned();
        let mut client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(DEADLINE);
        let addresses = if let Some(test) = &self.test_origin
            && test.repository == source.url
        {
            let bytes = std::fs::read(&test.ca_file).map_err(storage)?;
            client = client
                .add_root_certificate(reqwest::Certificate::from_pem(&bytes).map_err(storage)?);
            url.set_port(Some(test.port))
                .map_err(|_| SourceError::new("repository_not_allowed"))?;
            vec![std::net::SocketAddr::new(
                IpAddr::V4(test.address),
                test.port,
            )]
        } else {
            let addresses = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::lookup_host((host.as_str(), 443)),
            )
            .await
            .map_err(|_| SourceError::transient("source_dns_timeout"))?
            .map_err(|_| SourceError::transient("source_dns_failed"))?
            .collect::<Vec<_>>();
            if addresses.is_empty()
                || addresses.len() > 32
                || addresses.iter().any(|ip| !public_ip(ip.ip()))
            {
                return Err(SourceError::new("repository_not_allowed"));
            }
            addresses
        };
        // Pin all allowed destinations for this origin; TLS verifies the original hostname.
        let client = client
            .resolve_to_addrs(&host, &addresses)
            .build()
            .map_err(storage)?;
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(storage)?;
        let port = listener.local_addr().map_err(storage)?.port();
        let nonce = uuid_nonce();
        let path = format!("/{nonce}/repository.git");
        let relay_url = format!("http://127.0.0.1:{port}{path}");
        let failure = std::sync::Arc::new(std::sync::Mutex::new(None));
        let state = RelayState {
            client,
            origin: url.to_string(),
            path,
            failure: failure.clone(),
            admission: std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
        };
        let app = axum::Router::new()
            .fallback(relay_request)
            .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024))
            .with_state(state);
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Relay {
            url: relay_url,
            task,
            failure,
        })
    }
    async fn git(
        &self,
        home: &Path,
        settings: &[String],
        args: &[String],
        cap: u64,
    ) -> Result<Vec<u8>> {
        let mut command = Command::new("git");
        command
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ASKPASS", "/bin/false")
            .env("GIT_ALLOW_PROTOCOL", "http")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_LFS_SKIP_SMUDGE", "1")
            .env("LC_ALL", "C")
            .current_dir(home)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        for setting in [
            "core.hooksPath=/dev/null",
            "credential.helper=",
            "protocol.allow=never",
            "protocol.http.allow=always",
            "protocol.file.allow=never",
            "http.followRedirects=false",
            "http.proxy=",
            "http.sslVerify=true",
            "http.lowSpeedLimit=1024",
            "http.lowSpeedTime=15",
            "fetch.recurseSubmodules=false",
            "submodule.recurse=false",
            "core.fsmonitor=false",
            "gc.auto=0",
            "maintenance.auto=false",
            "fetch.fsckObjects=true",
            "transfer.fsckObjects=true",
            "pack.threads=1",
            "fetch.unpackLimit=0",
            "pack.windowMemory=16m",
            "core.attributesFile=/dev/null",
        ] {
            command.args(["-c", setting]);
        }
        for setting in settings {
            command.args(["-c", setting]);
        }
        command.args(args);
        #[cfg(unix)]
        unsafe {
            command.pre_exec(|| {
                // Each Git child/helper has finite CPU, address space, file size and descriptors.
                for (resource, value) in [
                    (libc::RLIMIT_CPU, 60),
                    (libc::RLIMIT_AS, 512 * 1024 * 1024),
                    (libc::RLIMIT_FSIZE, MAX_GIT_BYTES),
                    (libc::RLIMIT_NOFILE, 128),
                    (libc::RLIMIT_CORE, 0),
                ] {
                    let limit = libc::rlimit {
                        rlim_cur: value,
                        rlim_max: value,
                    };
                    if libc::setrlimit(resource, &limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                libc::setpgid(0, 0);
                Ok(())
            });
        }
        let mut child = command
            .spawn()
            .map_err(|_| SourceError::new("source_subsystem_unavailable"))?;
        let pid = child.id();
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| SourceError::new("source_fetch_failed"))?
            .take(cap + 1);
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| SourceError::new("source_fetch_failed"))?
            .take(8193);
        let operation = async {
            let mut output = Vec::new();
            let mut diagnostic = Vec::new();
            tokio::try_join!(
                stdout.read_to_end(&mut output),
                stderr.read_to_end(&mut diagnostic)
            )
            .map_err(storage)?;
            if output.len() as u64 > cap || diagnostic.len() > 8192 {
                return Err(SourceError::new("source_limit_exceeded"));
            }
            if !child.wait().await.map_err(storage)?.success() {
                let text = String::from_utf8_lossy(&diagnostic);
                let transient = [
                    "Could not resolve host",
                    "Failed to connect",
                    "timed out",
                    "HTTP 500",
                    "HTTP 502",
                    "HTTP 503",
                    "HTTP 504",
                ]
                .iter()
                .any(|needle| text.contains(needle));
                return Err(if transient {
                    SourceError::transient("source_fetch_failed")
                } else {
                    SourceError::new("source_fetch_failed")
                });
            }
            Ok(output)
        };
        let result = tokio::time::timeout(DEADLINE, operation)
            .await
            .unwrap_or_else(|_| Err(SourceError::transient("source_fetch_timeout")));
        #[cfg(unix)]
        if let Some(pid) = pid {
            unsafe {
                libc::kill(-(pid as i32), libc::SIGKILL);
            }
        }
        if result.is_err() {
            let _ = child.kill().await;
        }
        result
    }
}
#[async_trait]
impl SourceProvider for GitSource {
    async fn resolve_revision(&self, source: &ProjectSource, source_ref: &str) -> Result<String> {
        if valid_commit(source_ref) {
            return Ok(source_ref.into());
        }
        if !safe_ref(source_ref) {
            return Err(SourceError::new("source_revision_not_found"));
        }
        let qualified =
            if source_ref.starts_with("refs/heads/") || source_ref.starts_with("refs/tags/") {
                source_ref.to_owned()
            } else {
                format!("refs/heads/{source_ref}")
            };
        let relay = self.relay(source).await?;
        let temp = tempfile::tempdir().map_err(storage)?;
        let output = self
            .git(
                temp.path(),
                &[],
                &[
                    "ls-remote".into(),
                    "--exit-code".into(),
                    "--".into(),
                    relay.url.clone(),
                    qualified.clone(),
                    format!("{qualified}^{{}}"),
                ],
                8192,
            )
            .await?;
        let text = std::str::from_utf8(&output).map_err(storage)?;
        let mut direct = None;
        let mut peeled = None;
        for line in text.lines() {
            if let Some((sha, name)) = line.split_once('\t')
                && valid_commit(sha)
            {
                if name == qualified {
                    direct = Some(sha.to_owned());
                }
                if name == format!("{qualified}^{{}}") {
                    peeled = Some(sha.to_owned());
                }
            }
        }
        peeled
            .or(direct)
            .ok_or_else(|| SourceError::new("source_revision_not_found"))
    }
    async fn fetch_source(
        &self,
        source: &ProjectSource,
        commit: &str,
        staging: &Path,
    ) -> Result<FetchedSource> {
        if !valid_commit(commit) {
            return Err(SourceError::new("source_revision_not_found"));
        }
        std::fs::create_dir_all(staging).map_err(storage)?;
        let workspace = tempfile::Builder::new()
            .prefix("git-")
            .tempdir_in(staging)
            .map_err(storage)?;
        let relay = self.relay(source).await?;
        self.git(
            workspace.path(),
            &[],
            &[
                "init".into(),
                "--bare".into(),
                "--template=".into(),
                "repo".into(),
            ],
            8192,
        )
        .await?;
        let repo = workspace.path().join("repo");
        let prefix = format!("--git-dir={}", repo.display());
        self.git(
            workspace.path(),
            &[],
            &[
                prefix.clone(),
                "fetch".into(),
                "--depth=1".into(),
                "--no-tags".into(),
                "--no-recurse-submodules".into(),
                "--".into(),
                relay.url.clone(),
                commit.into(),
            ],
            8192,
        )
        .await
        .map_err(|error| relay.failure().unwrap_or(error))?;
        // Reject gitlinks even when git archive would silently omit them.
        let tree = self
            .git(
                workspace.path(),
                &[],
                &[
                    prefix.clone(),
                    "ls-tree".into(),
                    "-r".into(),
                    "-z".into(),
                    commit.into(),
                ],
                2 * 1024 * 1024,
            )
            .await?;
        if tree
            .split(|b| *b == 0)
            .any(|line| line.starts_with(b"160000 "))
        {
            return Err(SourceError::new("source_submodules_unsupported"));
        }
        let actual = self
            .git(
                workspace.path(),
                &[],
                &[
                    prefix.clone(),
                    "rev-parse".into(),
                    format!("{commit}^{{commit}}"),
                ],
                128,
            )
            .await?;
        if String::from_utf8_lossy(&actual).trim() != commit {
            return Err(SourceError::new("source_revision_not_found"));
        }
        let archive = self
            .git(
                workspace.path(),
                &[],
                &[
                    prefix,
                    "archive".into(),
                    "--format=tar".into(),
                    commit.into(),
                ],
                MAX_SNAPSHOT_BYTES + 4 * 1024 * 1024,
            )
            .await?;
        let (files, executable) = read_archive(&archive)?;
        Ok(FetchedSource {
            workspace,
            files,
            executable,
        })
    }
    fn discover_manifest(
        &self,
        fetched: &FetchedSource,
        override_path: Option<&str>,
    ) -> Result<PreparedSource> {
        let paths = if let Some(path) = override_path {
            if !safe_path(path) || !fetched.files.contains_key(path) {
                return Err(SourceError::new("manifest_not_found"));
            }
            vec![path.to_owned()]
        } else {
            let paths = fetched
                .files
                .keys()
                .filter(|p| {
                    let parts = p.split('/').collect::<Vec<_>>();
                    (parts.len() == 1
                        || (parts.len() == 2
                            && ["flatpak", "packaging", "build-aux"].contains(&parts[0])))
                        && ["json", "yaml", "yml"].contains(&p.rsplit('.').next().unwrap_or(""))
                })
                .cloned()
                .collect::<Vec<_>>();
            if paths.len() > MAX_CANDIDATES {
                return Err(SourceError::new("manifest_discovery_limit"));
            }
            paths
        };
        let mut manifests = Vec::new();
        for path in &paths {
            let bytes = &fetched.files[path];
            if bytes.len() > librehub_validator::MAX_MANIFEST_BYTES {
                continue;
            }
            let text =
                std::str::from_utf8(bytes).map_err(|_| SourceError::new("manifest_invalid"))?;
            let format = if path.ends_with(".json") {
                ManifestFormat::Json
            } else {
                ManifestFormat::Yaml
            };
            if let Ok(manifest) = librehub_validator::validate_project(text, format) {
                manifests.push((path.clone(), manifest));
            }
        }
        if manifests.len() > 1 {
            return Err(SourceError {
                code: "multiple_manifests_found",
                retryable: false,
                candidates: manifests.into_iter().map(|m| m.0).collect(),
            });
        }
        let (manifest_path, mut manifest) = manifests.pop().ok_or_else(|| {
            SourceError::new(if override_path.is_some() || !paths.is_empty() {
                "manifest_invalid"
            } else {
                "manifest_not_found"
            })
        })?;
        let parent = manifest_path.rsplit_once('/').map(|(p, _)| p);
        normalize_modules(&mut manifest.modules, parent, &fetched.files)?;
        let archive = deterministic_archive(&fetched.files, &fetched.executable)?;
        let snapshot = SourceSnapshot {
            sha256: format!("{:x}", Sha256::digest(&archive)),
            size_bytes: archive.len() as u64,
            file_count: fetched.files.len() as u64,
        };
        Ok(PreparedSource {
            manifest,
            manifest_path,
            snapshot,
            archive,
        })
    }
}
fn normalize_modules(
    modules: &mut [Module],
    parent: Option<&str>,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    for module in modules {
        for source in &mut module.sources {
            if let Some(path) = source
                .options
                .get("path")
                .and_then(serde_json::Value::as_str)
            {
                if !safe_path(path) {
                    return Err(SourceError::new("source_path_unsafe"));
                }
                let resolved = parent.map_or_else(|| path.to_owned(), |p| format!("{p}/{path}"));
                let exists = if matches!(source.kind, SourceKind::Dir) {
                    files.keys().any(|f| f.starts_with(&format!("{resolved}/")))
                } else {
                    files.contains_key(&resolved)
                };
                if !exists {
                    return Err(SourceError::new("source_file_missing"));
                }
                source.options.insert(
                    "path".into(),
                    serde_json::json!(format!("source/{resolved}")),
                );
            }
        }
        normalize_modules(&mut module.modules, parent, files)?;
    }
    Ok(())
}
fn read_archive(bytes: &[u8]) -> Result<SnapshotFiles> {
    let mut archive = tar::Archive::new(bytes);
    let mut files = BTreeMap::new();
    let mut executable = std::collections::BTreeSet::new();
    let mut total = 0_u64;
    let mut entries = 0;
    for entry in archive.entries().map_err(storage)? {
        entries += 1;
        if entries > MAX_FILES * 2 {
            return Err(SourceError::new("source_limit_exceeded"));
        }
        let mut entry = entry.map_err(storage)?;
        let path = entry
            .path()
            .map_err(storage)?
            .to_str()
            .ok_or_else(|| SourceError::new("source_path_unsafe"))?
            .trim_end_matches('/')
            .to_owned();
        if !safe_path(&path) {
            return Err(SourceError::new("source_path_unsafe"));
        }
        if entry.header().entry_type() == tar::EntryType::XGlobalHeader {
            if entry.size() > 65536 {
                return Err(SourceError::new("source_limit_exceeded"));
            }
            continue;
        }
        if entry.header().entry_type().is_dir() {
            continue;
        }
        if !entry.header().entry_type().is_file() {
            return Err(SourceError::new("source_special_file"));
        }
        total = total
            .checked_add(entry.size())
            .ok_or_else(|| SourceError::new("source_limit_exceeded"))?;
        if total > MAX_SNAPSHOT_BYTES || files.len() >= MAX_FILES {
            return Err(SourceError::new("source_limit_exceeded"));
        }
        let mut content = Vec::new();
        entry.read_to_end(&mut content).map_err(storage)?;
        if entry.header().mode().map_err(storage)? & 0o111 != 0 {
            executable.insert(path.clone());
        }
        if files.insert(path, content).is_some() {
            return Err(SourceError::new("source_duplicate_path"));
        }
    }
    Ok((files, executable))
}
fn deterministic_archive(
    files: &BTreeMap<String, Vec<u8>>,
    executable: &std::collections::BTreeSet<String>,
) -> Result<Vec<u8>> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, content) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(if executable.contains(name) {
            0o755
        } else {
            0o644
        });
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        builder
            .append_data(&mut header, name, content.as_slice())
            .map_err(storage)?;
    }
    let archive = builder.into_inner().map_err(storage)?;
    if archive.len() as u64 > MAX_SNAPSHOT_BYTES {
        return Err(SourceError::new("source_limit_exceeded"));
    }
    Ok(archive)
}
/// Rehash/reparse before transfer. Output is rebuilt rather than unpacking untrusted tar paths.
pub fn copy_snapshot(
    root: &Path,
    id: BuildId,
    snapshot: &SourceSnapshot,
    destination: &Path,
    manifest: &FlatpakManifest,
) -> Result<()> {
    let path = root.join("sources").join(format!("{id}.tar"));
    let meta = std::fs::symlink_metadata(&path).map_err(storage)?;
    if !meta.is_file() || meta.len() != snapshot.size_bytes || meta.len() > MAX_SNAPSHOT_BYTES {
        return Err(SourceError::new("source_snapshot_integrity"));
    }
    let bytes = std::fs::read(path).map_err(storage)?;
    if format!("{:x}", Sha256::digest(&bytes)) != snapshot.sha256 {
        return Err(SourceError::new("source_snapshot_integrity"));
    }
    let (files, exec) = read_archive(&bytes)?;
    if files.len() as u64 != snapshot.file_count {
        return Err(SourceError::new("source_snapshot_integrity"));
    }
    check_local_membership(&manifest.modules, &files)?;
    std::fs::create_dir_all(destination).map_err(storage)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o755))
            .map_err(storage)?;
    }

    for (path, content) in files {
        let output = destination.join(&path);
        std::fs::create_dir_all(
            output
                .parent()
                .ok_or_else(|| SourceError::new("source_path_unsafe"))?,
        )
        .map_err(storage)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut parent = destination.to_owned();
            if let Some(parts) = Path::new(&path).parent() {
                for part in parts.components() {
                    parent.push(part);
                    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755))
                        .map_err(storage)?;
                }
            }
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output)
            .map_err(storage)?;
        file.write_all(&content).map_err(storage)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                output,
                std::fs::Permissions::from_mode(if exec.contains(&path) { 0o755 } else { 0o644 }),
            )
            .map_err(storage)?;
        }
    }
    Ok(())
}
fn check_local_membership(modules: &[Module], files: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    for module in modules {
        for source in &module.sources {
            if let Some(path) = source
                .options
                .get("path")
                .and_then(serde_json::Value::as_str)
            {
                let path = path
                    .strip_prefix("source/")
                    .ok_or_else(|| SourceError::new("source_path_unsafe"))?;
                if !safe_path(path)
                    || (!files.contains_key(path)
                        && !(matches!(source.kind, SourceKind::Dir)
                            && files.keys().any(|p| p.starts_with(&format!("{path}/")))))
                {
                    return Err(SourceError::new("source_file_missing"));
                }
            }
        }
        check_local_membership(&module.modules, files)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn repo(url: &str) -> ProjectSource {
        ProjectSource {
            provider: RepositoryProvider::Git,
            url: url.into(),
        }
    }
    #[test]
    fn repository_urls_reject_private_targets_and_transport_abuse() {
        for url in [
            "file:///tmp/repo",
            "ssh://github.com/a/b",
            "https://localhost/a/b",
            "https://127.0.0.1/a/b",
            "https://2130706433/a/b",
            "https://10.0.0.1/a/b",
            "https://169.254.169.254/a/b",
            "https://[::1]/a/b",
            "https://user:secret@github.com/a/b",
            "https://github.com:8443/a/b",
            "https://github.com/a/b?x=1",
            "https://github.com/a/%2e%2e/b",
            "https://github.com/a/b#fragment",
        ] {
            assert!(normalize_repository(&repo(url)).is_err(), "{url}")
        }
        assert_eq!(
            normalize_repository(&repo("https://github.com/Example/Hello/"))
                .unwrap()
                .url,
            "https://github.com/example/hello.git"
        );
    }
    #[test]
    fn addresses_reject_special_ranges_and_mapped_ipv4() {
        for ip in [
            "100.64.0.1",
            "192.168.1.1",
            "172.31.0.1",
            "198.18.0.1",
            "224.1.1.1",
            "0.0.0.0",
            "255.255.255.255",
            "::ffff:127.0.0.1",
            "fe80::1",
            "fc00::1",
            "2001:db8::1",
            "2002:7f00:1::1",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}")
        }
        assert!(public_ip("8.8.8.8".parse().unwrap()));
        assert!(public_ip("2606:4700:4700::1111".parse().unwrap()));
    }
    #[test]
    fn refs_and_paths_reject_argument_and_traversal_injection() {
        for reference in [
            "-upload-pack=x",
            "a..b",
            "refs/heads/../../etc",
            "main\n",
            "a@{0}",
            "a.lock",
            "main^{commit}",
            "a//b",
        ] {
            assert!(!safe_ref(reference));
        }
        for path in [
            "../escape",
            "/etc/passwd",
            "a/../../x",
            ".git/config",
            "a\\b",
            "a/./b",
            "a/",
            "a\0b",
        ] {
            assert!(!safe_path(path));
        }
        assert!(safe_ref("refs/tags/v1.2.3"));
        assert!(safe_path("packaging/hello.json"));
    }
    fn fetched() -> FetchedSource {
        let mut files = BTreeMap::new();
        files.insert(
            "org.librehub.Hello.json".into(),
            include_bytes!("../../../examples/org.librehub.Hello.json").to_vec(),
        );
        FetchedSource {
            workspace: tempfile::tempdir().unwrap(),
            files,
            executable: Default::default(),
        }
    }
    #[test]
    fn multiple_manifest_candidates_require_selection() {
        let mut files = fetched();
        files.files.insert(
            "flatpak/org.librehub.Other.json".into(),
            include_bytes!("../../../examples/org.librehub.Hello.json").to_vec(),
        );
        let error = GitSource::default()
            .discover_manifest(&files, None)
            .err()
            .unwrap();
        assert_eq!(error.code, "multiple_manifests_found");
        assert_eq!(error.candidates.len(), 2);
        assert!(
            GitSource::default()
                .discover_manifest(&files, Some("org.librehub.Hello.json"))
                .is_ok()
        );
    }
    #[test]
    fn local_files_must_exist_and_cannot_traverse() {
        let mut files = fetched();
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&files.files["org.librehub.Hello.json"]).unwrap();
        manifest["modules"][0]["sources"] =
            serde_json::json!([{"type":"file","path":"missing.sh"}]);
        files.files.insert(
            "org.librehub.Hello.json".into(),
            serde_json::to_vec(&manifest).unwrap(),
        );
        assert_eq!(
            GitSource::default()
                .discover_manifest(&files, None)
                .err()
                .unwrap()
                .code,
            "source_file_missing"
        );
        manifest["modules"][0]["sources"][0]["path"] = serde_json::json!("../secret");
        assert!(
            librehub_validator::validate_project(&manifest.to_string(), ManifestFormat::Json)
                .is_err()
        );
    }
    #[test]
    fn snapshot_tampering_and_symlinks_are_rejected() {
        let source = fetched();
        let prepared = GitSource::default()
            .discover_manifest(&source, None)
            .unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("sources")).unwrap();
        let id = BuildId::new();
        let path = root.path().join("sources").join(format!("{id}.tar"));
        std::fs::write(&path, &prepared.archive).unwrap();
        copy_snapshot(
            root.path(),
            id,
            &prepared.snapshot,
            &root.path().join("copy"),
            &prepared.manifest,
        )
        .unwrap();
        std::fs::write(&path, b"changed").unwrap();
        assert_eq!(
            copy_snapshot(
                root.path(),
                id,
                &prepared.snapshot,
                &root.path().join("bad"),
                &prepared.manifest
            )
            .unwrap_err()
            .code,
            "source_snapshot_integrity"
        );
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name("/etc/passwd").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "escape", std::io::empty())
            .unwrap();
        let archive = builder.into_inner().unwrap();
        assert_eq!(
            read_archive(&archive).unwrap_err().code,
            "source_special_file"
        );
    }
    #[test]
    fn manifest_discovery_is_bounded() {
        let mut files = fetched();
        for i in 0..65 {
            files
                .files
                .insert(format!("candidate{i}.json"), b"{}".to_vec());
        }
        assert_eq!(
            GitSource::default()
                .discover_manifest(&files, None)
                .err()
                .unwrap()
                .code,
            "manifest_discovery_limit"
        );
    }
}
