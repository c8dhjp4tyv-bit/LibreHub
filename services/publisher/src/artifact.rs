use crate::PublishError;
use librehub_common::*;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

pub const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;
pub struct PreparedRepository {
    pub workspace: tempfile::TempDir,
    pub path: PathBuf,
    pub ref_name: RepositoryRef,
    pub commit: String,
}
pub fn source_ref(
    build: &BuildRecord,
    manifest: &FlatpakManifest,
    arch: Architecture,
) -> Result<RepositoryRef, PublishError> {
    if build.status != BuildStatus::Succeeded || build.cancellation_requested {
        return Err(PublishError::Ineligible);
    }
    if build.architecture != arch {
        return Err(PublishError::Architecture);
    }
    if build.manifest.app_id != manifest.app_id
        || build.manifest.runtime != manifest.runtime
        || build.manifest.runtime_version != manifest.runtime_version
        || build.manifest.sdk != manifest.sdk
    {
        return Err(PublishError::Metadata);
    }
    librehub_validator::validate(
        &serde_json::to_string(manifest).map_err(|_| PublishError::Metadata)?,
        ManifestFormat::Json,
    )
    .map_err(|_| PublishError::Metadata)?;
    let branch = manifest
        .options
        .get("branch")
        .map(|v| v.as_str().ok_or(PublishError::Metadata))
        .transpose()?
        .unwrap_or("master");
    RepositoryRef::new(&manifest.app_id, build.architecture, branch)
        .map_err(|_| PublishError::Metadata)
}
/// Check every component below the trusted canonical data root, then open without following links.
pub fn controlled_file(root: &Path, relative: &str) -> Result<File, PublishError> {
    let mut path = root.to_owned();
    for part in Path::new(relative).components() {
        let std::path::Component::Normal(part) = part else {
            return Err(PublishError::Storage);
        };
        path.push(part);
        let meta = std::fs::symlink_metadata(&path).map_err(|_| PublishError::Storage)?;
        if meta.file_type().is_symlink() {
            return Err(PublishError::Storage);
        }
    }
    if !path.starts_with(root) {
        return Err(PublishError::Storage);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|_| PublishError::Storage)?;
    if !file
        .metadata()
        .map_err(|_| PublishError::Storage)?
        .is_file()
    {
        return Err(PublishError::Storage);
    }
    Ok(file)
}
pub fn verify_bundle(
    root: &Path,
    build: &BuildRecord,
    mut destination: Option<&mut File>,
) -> Result<(), PublishError> {
    if build.status != BuildStatus::Succeeded {
        return Err(PublishError::Ineligible);
    }
    let result = build.result.as_ref().ok_or(PublishError::Integrity)?;
    if result.exit_code != Some(0) || result.artifacts.len() != 1 {
        return Err(PublishError::Integrity);
    }
    let artifact = &result.artifacts[0];
    let expected = format!("builds/{}/artifacts/application.flatpak", build.id);
    if artifact.path != expected
        || !valid_checksum(&artifact.sha256)
        || artifact.size_bytes == 0
        || artifact.size_bytes > MAX_ARTIFACT_BYTES
    {
        return Err(PublishError::Integrity);
    }
    let mut source = controlled_file(root, &expected)?;
    if source.metadata().map_err(|_| PublishError::Storage)?.len() != artifact.size_bytes {
        return Err(PublishError::Integrity);
    }
    let mut hash = Sha256::new();
    let mut bytes = 0;
    let mut buffer = [0; 65536];
    loop {
        let n = source
            .read(&mut buffer)
            .map_err(|_| PublishError::Storage)?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        if bytes > artifact.size_bytes {
            return Err(PublishError::Integrity);
        }
        hash.update(&buffer[..n]);
        if let Some(out) = destination.as_deref_mut() {
            out.write_all(&buffer[..n])
                .map_err(|_| PublishError::Storage)?;
        }
    }
    if bytes != artifact.size_bytes || format!("{:x}", hash.finalize()) != artifact.sha256 {
        return Err(PublishError::Integrity);
    }
    Ok(())
}

/// Bounded subprocess output, no shell and no inherited publisher credentials.
pub async fn command(
    binary: &str,
    args: &[String],
    timeout: Duration,
) -> Result<String, PublishError> {
    use std::process::Stdio;
    use tokio::{io::AsyncReadExt, process::Command};
    let mut child = Command::new(binary)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| PublishError::Preparation)?;
    let stdout = child.stdout.take().ok_or(PublishError::Preparation)?;
    let work = async {
        let mut output = Vec::new();
        stdout
            .take(1024 * 1024 + 1)
            .read_to_end(&mut output)
            .await
            .map_err(|_| PublishError::Preparation)?;
        if output.len() > 1024 * 1024 {
            return Err(PublishError::Preparation);
        }
        if !child
            .wait()
            .await
            .map_err(|_| PublishError::Preparation)?
            .success()
        {
            return Err(PublishError::Preparation);
        }
        String::from_utf8(output).map_err(|_| PublishError::Preparation)
    };
    tokio::time::timeout(timeout, work)
        .await
        .map_err(|_| PublishError::Timeout)?
}
pub async fn prepare(
    root: PathBuf,
    build: BuildRecord,
    manifest: FlatpakManifest,
    arch: Architecture,
    timeout: Duration,
) -> Result<PreparedRepository, PublishError> {
    let ref_name = source_ref(&build, &manifest, arch)?;
    let workspace = tokio::task::spawn_blocking(move || {
        // Service-owned staging paths; created afresh on recovery to avoid trusting leftovers.
        let staging = root.join("publishes");
        std::fs::create_dir_all(&staging).map_err(|_| PublishError::Storage)?;
        if std::fs::symlink_metadata(&staging)
            .map_err(|_| PublishError::Storage)?
            .file_type()
            .is_symlink()
        {
            return Err(PublishError::Storage);
        }
        let workspace = tempfile::Builder::new()
            .prefix("publish-")
            .tempdir_in(staging)
            .map_err(|_| PublishError::Storage)?;
        let mut file = File::create(workspace.path().join("application.flatpak"))
            .map_err(|_| PublishError::Storage)?;
        verify_bundle(&root, &build, Some(&mut file))?;
        file.sync_all().map_err(|_| PublishError::Storage)?;
        Ok(workspace)
    })
    .await
    .map_err(|_| PublishError::Storage)??;
    let path = workspace.path().join("repo");
    let repo = format!("--repo={}", path.display());
    command(
        "ostree",
        &[repo.clone(), "init".into(), "--mode=archive-z2".into()],
        timeout,
    )
    .await?;
    command(
        "flatpak",
        &[
            "build-import-bundle".into(),
            path.display().to_string(),
            workspace
                .path()
                .join("application.flatpak")
                .display()
                .to_string(),
        ],
        timeout,
    )
    .await?;
    let refs = command("ostree", &[repo.clone(), "refs".into()], timeout).await?;
    if refs.trim() != ref_name.as_str() {
        return Err(PublishError::Metadata);
    }
    let commit = command(
        "ostree",
        &[repo.clone(), "rev-parse".into(), ref_name.to_string()],
        timeout,
    )
    .await?
    .trim()
    .to_owned();
    if !valid_checksum(&commit) {
        return Err(PublishError::Metadata);
    }
    command("ostree", &[repo.clone(), "fsck".into()], timeout).await?;
    let metadata = command(
        "ostree",
        &[
            repo,
            "show".into(),
            "--print-metadata-key=xa.metadata".into(),
            commit.clone(),
        ],
        timeout,
    )
    .await?;
    // OSTree prints a GVariant string with escaped newlines. Compare exact key/value lines.
    let unescaped = metadata.replace("\\n", "\n");
    let expected_runtime = format!(
        "runtime={}/{}/{}",
        manifest.runtime, arch, manifest.runtime_version
    );
    if !unescaped.contains("[Application]\n")
        || !unescaped
            .lines()
            .any(|l| l == format!("name={}", manifest.app_id))
        || !unescaped.lines().any(|l| l == expected_runtime)
    {
        return Err(PublishError::Metadata);
    }
    Ok(PreparedRepository {
        workspace,
        path,
        ref_name,
        commit,
    })
}
