use crate::{BuildExecutor, BuildJob, ExecutorError, LogSink};
use anyhow::{Context, bail};
use async_trait::async_trait;
use chrono::Utc;
use librehub_common::{Architecture, Artifact, BuildId, BuildLogEntry, BuildResult, LogStream};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
pub struct DockerConfig {
    pub binary: PathBuf,
    pub image: String,
    pub timeout: Duration,
    pub max_artifact_bytes: u64,
    /// Only `none` (default) or `bridge`. Bridge allows source downloads.
    pub network: String,
    pub architecture: Architecture,
}
impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            binary: "docker".into(),
            image: "librehub-worker:m1".into(),
            timeout: Duration::from_secs(1800),
            max_artifact_bytes: 1024 * 1024 * 1024,
            network: "none".into(),
            architecture: Architecture::native(),
        }
    }
}
pub struct DockerExecutor {
    config: DockerConfig,
}
impl DockerExecutor {
    pub fn new(config: DockerConfig) -> anyhow::Result<Self> {
        if !["none", "bridge"].contains(&config.network.as_str()) {
            bail!("Worker network must be none or bridge");
        }
        if config.timeout.is_zero() || config.max_artifact_bytes == 0 {
            bail!("Build limits must be positive");
        }
        if config.image.is_empty() || config.image.starts_with('-') {
            bail!("Invalid worker image");
        }
        Ok(Self { config })
    }
    fn command(&self) -> Command {
        let mut cmd = Command::new(&self.config.binary);
        cmd.stdin(Stdio::null()).kill_on_drop(true);
        cmd
    }
    fn name(id: BuildId) -> String {
        format!("librehub-{id}")
    }

    async fn run(
        &self,
        args: &[String],
        logs: Arc<dyn LogSink>,
        cancel: &CancellationToken,
    ) -> Result<(), ExecutorError> {
        let mut child = self
            .command()
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Cannot launch Docker CLI")?;
        let stdout = child.stdout.take().context("Missing stdout pipe")?;
        let stderr = child.stderr.take().context("Missing stderr pipe")?;
        // Scope the readers to this command: dropping this future also drops both pipes.
        let output = async {
            tokio::try_join!(
                pump(stdout, LogStream::Stdout, logs.clone()),
                pump(stderr, LogStream::Stderr, logs)
            )?;
            Ok::<_, anyhow::Error>(())
        };
        let outcome = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(ExecutorError::Cancelled),
            result = async {
                let (status, ()) = tokio::try_join!(async { child.wait().await.context("Cannot wait for Docker CLI") }, output)?;
                if status.success() { Ok(()) } else { Err(ExecutorError::Exit(status.code())) }
            } => result,
        };
        if outcome.is_err() {
            // Terminate the client; the outer execute cleanup stops the actual container.
            if let Err(e) = child.kill().await {
                tracing::debug!(error = %e, "Docker client was already terminated");
            }
        }
        outcome
    }

    async fn build(
        &self,
        job: &BuildJob,
        logs: Arc<dyn LogSink>,
        cancel: &CancellationToken,
    ) -> Result<BuildResult, ExecutorError> {
        if job.architecture != self.config.architecture {
            return Err(
                anyhow::anyhow!("Requested architecture has no configured native worker").into(),
            );
        }
        let scratch_root = job.data_dir.join("tmp");
        tokio::fs::create_dir_all(&scratch_root)
            .await
            .context("Cannot create workspace root")?;
        let scratch = tempfile::Builder::new()
            .prefix(&format!("{}-", job.id))
            .tempdir_in(&scratch_root)
            .context("Cannot create private workspace")?;
        let manifest_path = scratch.path().join("manifest.json");
        tokio::fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&job.manifest).context("Cannot serialize manifest")?,
        )
        .await
        .context("Cannot save manifest")?;
        let name = Self::name(job.id);
        let args: Vec<String> = [
            "create",
            "--name",
            &name,
            "--label",
            "org.librehub.milestone=m1",
            "--network",
            &self.config.network,
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges=true",
            // bubblewrap needs nested unprivileged namespaces. No SYS_ADMIN or privileged mode.
            "--security-opt=seccomp=unconfined",
            "--security-opt=apparmor=unconfined",
            "--pids-limit=512",
            "--memory=4g",
            "--memory-swap=4g",
            "--cpus=2",
            "--ulimit",
            "nofile=4096:4096",
            "--log-driver=none",
            "--user=10001:10001",
            "--workdir=/work",
            "--entrypoint=/usr/local/bin/librehub-build",
            &self.config.image,
            &job.architecture.to_string(),
            &job.manifest.app_id,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        self.run(&args, logs.clone(), cancel).await?;
        self.run(
            &[
                "cp".into(),
                manifest_path.to_string_lossy().into_owned(),
                format!("{name}:/work/manifest.json"),
            ],
            logs.clone(),
            cancel,
        )
        .await?;
        self.run(
            &["start".into(), "--attach".into(), name.clone()],
            logs.clone(),
            cancel,
        )
        .await?;
        // `docker start -a` exit behavior is verified independently by inspecting State.ExitCode.
        let mut inspect = self.command();
        inspect.args(["inspect", "--format={{.State.ExitCode}}", &name]);
        let output = inspect
            .output()
            .await
            .context("Cannot inspect build exit code")?;
        if !output.status.success() {
            bail_executor("Cannot inspect finished container")?;
        }
        let code: i32 = std::str::from_utf8(&output.stdout)
            .context("Invalid Docker exit code")?
            .trim()
            .parse()
            .context("Invalid Docker exit code")?;
        if code != 0 {
            return Err(ExecutorError::Exit(Some(code)));
        }
        if cancel.is_cancelled() {
            return Err(ExecutorError::Cancelled);
        }
        let archive_path = scratch.path().join("bundle.tar");
        self.copy_bundle(&name, &archive_path, logs, cancel).await?;
        let artifacts_dir = job
            .data_dir
            .join("builds")
            .join(job.id.to_string())
            .join("artifacts");
        tokio::fs::create_dir_all(&artifacts_dir)
            .await
            .context("Cannot create artifact directory")?;
        let destination = artifacts_dir.join("application.flatpak");
        let limit = self.config.max_artifact_bytes;
        let relative = format!("builds/{}/artifacts/application.flatpak", job.id);
        let extract_cancel = cancel.clone();
        let artifact = tokio::task::spawn_blocking(move || {
            extract_bundle(
                &archive_path,
                &destination,
                limit,
                relative,
                &extract_cancel,
            )
        })
        .await
        .context("Artifact extraction task failed")??;
        Ok(BuildResult {
            exit_code: Some(0),
            artifacts: vec![artifact],
        })
    }

    async fn copy_bundle(
        &self,
        name: &str,
        archive: &Path,
        logs: Arc<dyn LogSink>,
        cancel: &CancellationToken,
    ) -> Result<(), ExecutorError> {
        let mut child = self
            .command()
            .args([
                "cp",
                &format!("{name}:/work/output/application.flatpak"),
                "-",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Cannot collect artifact")?;
        let mut stdout = child.stdout.take().context("Missing artifact pipe")?;
        let stderr = child.stderr.take().context("Missing artifact stderr")?;
        let mut output = tokio::fs::File::create(archive)
            .await
            .context("Cannot create artifact staging file")?;
        // Bound the archive including headers. Also reject a producer that never closes stdout.
        let limit = self.config.max_artifact_bytes.saturating_add(1024 * 1024);
        let work = async {
            let mut limited = (&mut stdout).take(limit + 1);
            let ((), ()) = tokio::try_join!(
                async {
                    let copied = tokio::io::copy(&mut limited, &mut output)
                        .await
                        .context("Artifact copy failed")?;
                    if copied > limit {
                        bail!("Artifact exceeds configured size limit");
                    }
                    Ok::<_, anyhow::Error>(())
                },
                pump(stderr, LogStream::Stderr, logs)
            )?;
            let status = child
                .wait()
                .await
                .context("Cannot wait for artifact copy")?;
            if !status.success() {
                bail!("Docker artifact copy failed: {status}");
            }
            output
                .sync_all()
                .await
                .context("Cannot flush artifact archive")?;
            Ok::<_, anyhow::Error>(())
        };
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(ExecutorError::Cancelled),
            result = work => result.map_err(ExecutorError::from),
        };
        if result.is_err()
            && let Err(e) = child.kill().await
        {
            tracing::debug!(error = %e, "Artifact copy client was already terminated");
        }
        result
    }
}
fn bail_executor(message: &str) -> Result<(), ExecutorError> {
    Err(anyhow::anyhow!("{message}").into())
}

async fn pump<R: AsyncRead + Unpin>(
    mut reader: R,
    stream: LogStream,
    logs: Arc<dyn LogSink>,
) -> anyhow::Result<()> {
    // Fixed buffers bound memory even when a compiler emits a multi-megabyte line.
    let mut buffer = [0; 8192];
    loop {
        let size = reader
            .read(&mut buffer)
            .await
            .context("Cannot read build output")?;
        if size == 0 {
            return Ok(());
        }
        for line in String::from_utf8_lossy(&buffer[..size]).split_inclusive('\n') {
            logs.append(BuildLogEntry {
                sequence: 0,
                timestamp: Utc::now(),
                stream,
                message: line.trim_end_matches('\n').to_owned(),
            })
            .await?;
        }
    }
}

/// Do not unpack an untrusted directory tree. Accept exactly one regular bundle file.
fn extract_bundle(
    archive: &Path,
    destination: &Path,
    max_bytes: u64,
    relative: String,
    cancel: &CancellationToken,
) -> anyhow::Result<Artifact> {
    let mut tar = tar::Archive::new(std::fs::File::open(archive)?);
    let mut staging =
        tempfile::NamedTempFile::new_in(destination.parent().context("Missing artifact parent")?)?;
    let mut hash = Sha256::new();
    let mut size_bytes = 0;
    let mut found = false;
    for entry in tar.entries()? {
        let mut entry = entry?;
        if found
            || entry.path()?.as_ref() != Path::new("application.flatpak")
            || !entry.header().entry_type().is_file()
        {
            bail!("Artifact archive must contain only the regular file application.flatpak");
        }
        found = true;
        if entry.size() > max_bytes {
            bail!("Artifact exceeds configured size limit");
        }
        let mut buf = [0; 65536];
        loop {
            if cancel.is_cancelled() {
                bail!("Artifact collection cancelled");
            }
            let n = entry.read(&mut buf)?;
            if n == 0 {
                break;
            }
            size_bytes += n as u64;
            if size_bytes > max_bytes {
                bail!("Artifact exceeds configured size limit");
            }
            hash.update(&buf[..n]);
            staging.write_all(&buf[..n])?;
        }
    }
    if !found || size_bytes == 0 {
        bail!("Artifact bundle is empty");
    }
    if cancel.is_cancelled() {
        bail!("Artifact collection cancelled");
    }
    staging.as_file().sync_all()?;
    staging
        .persist_noclobber(destination)
        .context("Cannot preserve build artifact")?;
    Ok(Artifact {
        path: relative,
        size_bytes,
        sha256: format!("{:x}", hash.finalize()),
    })
}

#[async_trait]
impl BuildExecutor for DockerExecutor {
    async fn execute(
        &self,
        job: BuildJob,
        logs: Arc<dyn LogSink>,
        cancel: CancellationToken,
    ) -> Result<BuildResult, ExecutorError> {
        let id = job.id;
        let operation_cancel = cancel.child_token();
        let result = tokio::select! {
            biased;
            _ = operation_cancel.cancelled() => Err(ExecutorError::Cancelled),
            outcome = tokio::time::timeout(self.config.timeout, self.build(&job, logs, &operation_cancel)) => match outcome {
                Ok(result) => result,
                Err(_) => Err(ExecutorError::Timeout),
            }
        };
        // Always remove the container, even if create or a later CLI invocation failed.
        // Stop sends SIGTERM; Docker sends SIGKILL after five seconds. rm -f is a fallback.
        operation_cancel.cancel();
        self.cleanup(id).await.map_err(ExecutorError::Cleanup)?;
        result
    }
    async fn cleanup(&self, id: BuildId) -> anyhow::Result<()> {
        let name = Self::name(id);
        let mut inspect = self.command();
        let output = tokio::time::timeout(
            Duration::from_secs(10),
            inspect
                .args([
                    "container",
                    "ls",
                    "--all",
                    "--filter",
                    &format!("name=^{name}$"),
                    "--format={{.Names}}",
                ])
                .output(),
        )
        .await
        .context("Docker cleanup inspection timed out")??;
        if !output.status.success() {
            bail!(
                "Cannot inspect Docker containers during cleanup: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        if output.stdout.is_empty() {
            return Ok(());
        }
        let mut stop = self.command();
        match tokio::time::timeout(
            Duration::from_secs(10),
            stop.args(["stop", "--time=5", &name]).output(),
        )
        .await
        {
            Ok(Ok(output)) if output.status.success() => {}
            other => tracing::warn!(?other, %id, "Graceful Docker stop failed; forcing removal"),
        }
        let mut remove = self.command();
        let output = tokio::time::timeout(
            Duration::from_secs(10),
            remove.args(["rm", "--force", &name]).output(),
        )
        .await
        .context("Docker removal timed out")??;
        if !output.status.success() {
            bail!(
                "Cannot remove Docker container: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn archive(dir: &Path, name: &str, kind: tar::EntryType) -> PathBuf {
        let file = dir.join("test.tar");
        let mut archive = tar::Builder::new(std::fs::File::create(&file).unwrap());
        let mut header = tar::Header::new_gnu();
        header.set_size(if kind.is_file() { 5 } else { 0 });
        header.set_mode(0o644);
        header.set_entry_type(kind);
        if kind.is_symlink() {
            header.set_link_name("/etc/passwd").unwrap();
        }
        header.set_cksum();
        archive
            .append_data(
                &mut header,
                name,
                if kind.is_file() {
                    &b"hello"[..]
                } else {
                    &b""[..]
                },
            )
            .unwrap();
        archive.finish().unwrap();
        file
    }
    #[test]
    fn accepts_regular_bundle_and_hashes_it() {
        let dir = tempfile::tempdir().unwrap();
        let file = archive(dir.path(), "application.flatpak", tar::EntryType::Regular);
        let out = dir.path().join("result");
        let artifact = extract_bundle(
            &file,
            &out,
            100,
            "builds/id/artifacts/application.flatpak".into(),
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(artifact.size_bytes, 5);
        assert_eq!(artifact.sha256, format!("{:x}", Sha256::digest(b"hello")));
        assert_eq!(std::fs::read(out).unwrap(), b"hello");
    }
    #[test]
    fn rejects_links_unexpected_paths_and_oversize() {
        for (name, kind, limit) in [
            ("application.flatpak", tar::EntryType::Symlink, 100),
            ("application.flatpak", tar::EntryType::Link, 100),
            ("etc/passwd", tar::EntryType::Regular, 100),
            ("application.flatpak", tar::EntryType::Regular, 2),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let file = archive(dir.path(), name, kind);
            let out = dir.path().join("result");
            assert!(
                extract_bundle(
                    &file,
                    &out,
                    limit,
                    "unused".into(),
                    &CancellationToken::new()
                )
                .is_err()
            );
            assert!(!out.exists());
        }
    }
}
