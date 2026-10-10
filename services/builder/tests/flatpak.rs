//! Explicit opt-in: needs Docker, the worker image, and nested user namespaces.
use async_trait::async_trait;
use librehub_builder::*;
use librehub_common::*;
use std::{path::Path, sync::Arc};
use tokio_util::sync::CancellationToken;
struct Console;
#[async_trait]
impl LogSink for Console {
    async fn append(&self, entry: BuildLogEntry) -> anyhow::Result<()> {
        eprintln!("{:?}: {}", entry.stream, entry.message);
        Ok(())
    }
}
#[tokio::test]
#[ignore = "requires Docker and librehub-worker:m1; see README"]
async fn builds_hello_into_a_real_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let id = BuildId::new();
    let manifest = librehub_validator::validate(
        include_str!("../../../examples/org.librehub.Hello.json"),
        ManifestFormat::Json,
    )
    .unwrap();
    let executor = DockerExecutor::new(DockerConfig {
        binary: std::env::var_os("LIBREHUB_DOCKER")
            .map(Into::into)
            .unwrap_or_else(|| "docker".into()),
        ..DockerConfig::default()
    })
    .unwrap();
    let result = executor
        .execute(
            BuildJob {
                source_snapshot: None,
                id,
                manifest,
                architecture: Architecture::native(),
                data_dir: dir.path().into(),
            },
            Arc::new(Console),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.artifacts.len(), 1);
    let artifact = &result.artifacts[0];
    assert!(artifact.size_bytes > 0);
    assert_eq!(artifact.sha256.len(), 64);
    assert!(Path::new(&dir.path().join(&artifact.path)).is_file());
    assert_eq!(
        std::fs::read_dir(dir.path().join("tmp")).unwrap().count(),
        0
    );
    executor.cleanup(id).await.unwrap();
}

#[tokio::test]
#[ignore = "requires rootless Podman/cgroup-v2/seccomp and the worker image; operational hardening acceptance"]
async fn builds_hello_under_hardened_rootless_podman() {
    let dir = tempfile::tempdir().unwrap();
    let id = BuildId::new();
    let manifest = librehub_validator::validate(
        include_str!("../../../examples/org.librehub.Hello.json"),
        ManifestFormat::Json,
    )
    .unwrap();
    let executor = DockerExecutor::new(DockerConfig {
        binary: "podman".into(),
        image: std::env::var("LIBREHUB_WORKER_IMAGE")
            .unwrap_or_else(|_| "librehub-worker:m1".into()),
        isolation: IsolationPolicy::Hardened,
        ..Default::default()
    })
    .unwrap();
    let result = executor
        .execute(
            BuildJob {
                id,
                manifest,
                architecture: Architecture::native(),
                data_dir: dir.path().into(),
                source_snapshot: None,
            },
            Arc::new(Console),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        result.environment.as_ref().unwrap().isolation,
        IsolationPolicy::Hardened
    );
    assert_eq!(result.environment.as_ref().unwrap().network, "none");
    assert!(result.environment.as_ref().unwrap().writable_bytes > 0);
    assert_eq!(result.artifacts.len(), 1);
    executor.cleanup(id).await.unwrap();
}

#[tokio::test]
#[ignore = "requires the supported rootless hardened platform; real cancel/restart cleanup"]
async fn hardened_cancellation_and_abandoned_worker_cleanup() {
    for crash in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let id = BuildId::new();
        let mut manifest = librehub_validator::validate(
            include_str!("../../../examples/org.librehub.Hello.json"),
            ManifestFormat::Json,
        )
        .unwrap();
        manifest.modules[0].options.insert(
            "build-commands".into(),
            serde_json::json!(["touch /app/m6-running && sleep 120"]),
        );
        let executor = Arc::new(
            DockerExecutor::new(DockerConfig {
                binary: "podman".into(),
                image: std::env::var("LIBREHUB_WORKER_IMAGE")
                    .unwrap_or_else(|_| "librehub-worker:m1".into()),
                isolation: IsolationPolicy::Hardened,
                ..Default::default()
            })
            .unwrap(),
        );
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        let exec = executor.clone();
        let task = tokio::spawn(async move {
            exec.execute(
                BuildJob {
                    id,
                    manifest,
                    architecture: Architecture::native(),
                    data_dir: dir.path().into(),
                    source_snapshot: None,
                },
                Arc::new(Console),
                token,
            )
            .await
        });
        let name = format!("librehub-{id}");
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            loop {
                let status = tokio::process::Command::new("podman")
                    .args(["exec", &name, "test", "-f", "/work/build/files/m6-running"])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .await
                    .unwrap();
                if status.success() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();
        if crash {
            task.abort();
            let _ = task.await;
            executor.cleanup(id).await.unwrap();
        } else {
            cancel.cancel();
            assert!(matches!(task.await.unwrap(), Err(ExecutorError::Cancelled)));
        }
        let status = tokio::process::Command::new("podman")
            .args(["container", "inspect", &name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .unwrap();
        assert!(
            !status.success(),
            "A cancelled or abandoned hardened worker survived cleanup"
        );
    }
}
