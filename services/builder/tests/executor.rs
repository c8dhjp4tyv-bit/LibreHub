#![cfg(unix)]
use async_trait::async_trait;
use librehub_builder::*;
use librehub_common::*;
use std::{
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
#[derive(Default)]
struct Captured(Mutex<Vec<BuildLogEntry>>);
#[async_trait]
impl LogSink for Captured {
    async fn append(&self, entry: BuildLogEntry) -> anyhow::Result<()> {
        self.0.lock().unwrap().push(entry);
        Ok(())
    }
}
fn executor(dir: &std::path::Path, mode: &str) -> DockerExecutor {
    let binary = dir.join("docker.py");
    std::fs::write(&binary, include_str!("fixtures/docker.py")).unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(dir.join("mode"), mode).unwrap();
    DockerExecutor::new(DockerConfig {
        binary,
        timeout: Duration::from_secs(if mode == "timeout" { 2 } else { 10 }),
        ..DockerConfig::default()
    })
    .unwrap()
}
fn job(dir: &std::path::Path) -> BuildJob {
    BuildJob {
        source_snapshot: None,
        id: BuildId::new(),
        manifest: librehub_validator::validate(
            include_str!("../../../examples/org.librehub.Hello.json"),
            ManifestFormat::Json,
        )
        .unwrap(),
        architecture: Architecture::native(),
        data_dir: dir.join("data"),
    }
}
#[tokio::test]
async fn executes_cli_captures_streams_and_preserves_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let executor = executor(dir.path(), "success");
    let job = job(dir.path());
    let data_dir = job.data_dir.clone();
    let logs = Arc::new(Captured::default());
    let result = executor
        .execute(job, logs.clone(), CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(result.artifacts.len(), 1);
    assert_eq!(
        std::fs::read(data_dir.join(&result.artifacts[0].path)).unwrap(),
        b"Flatpak bundle"
    );
    let entries = logs.0.lock().unwrap();
    assert!(
        entries
            .iter()
            .any(|e| matches!(e.stream, LogStream::Stdout) && e.message == "compiled")
    );
    assert!(
        entries
            .iter()
            .any(|e| matches!(e.stream, LogStream::Stderr) && e.message == "warning")
    );
    assert!(dir.path().join("removed").exists());
    assert_eq!(std::fs::read_dir(data_dir.join("tmp")).unwrap().count(), 0);
    let calls = std::fs::read_to_string(dir.path().join("calls")).unwrap();
    let create: Vec<String> = calls
        .lines()
        .map(|line| serde_json::from_str::<Vec<String>>(line).unwrap())
        .find(|args| args[0] == "create")
        .unwrap();
    assert!(create.contains(&"--cap-drop=ALL".into()));
    assert!(create.contains(&"--security-opt=systempaths=unconfined".into()));
    assert!(create.contains(&"--user=10001:10001".into()));
    assert!(
        !create
            .iter()
            .any(|arg| arg.starts_with("--volume") || arg == "--privileged")
    );
}
#[tokio::test]
async fn container_exit_failure_is_checked_independently_of_attach() {
    let dir = tempfile::tempdir().unwrap();
    let executor = executor(dir.path(), "failure");
    let job = job(dir.path());
    let artifact_dir = job
        .data_dir
        .join("builds")
        .join(job.id.to_string())
        .join("artifacts");
    let result = executor
        .execute(job, Arc::new(Captured::default()), CancellationToken::new())
        .await;
    assert!(matches!(result, Err(ExecutorError::Exit(Some(23)))));
    assert!(!artifact_dir.exists());
    assert!(dir.path().join("removed").exists());
}
#[tokio::test]
async fn cancellation_and_timeout_stop_and_force_remove_real_process() {
    for mode in ["wait", "timeout"] {
        let dir = tempfile::tempdir().unwrap();
        let executor = executor(dir.path(), mode);
        let job = job(dir.path());
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        let task = tokio::spawn(async move {
            executor
                .execute(job, Arc::new(Captured::default()), token)
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while !dir.path().join("started").exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        if mode == "wait" {
            cancel.cancel();
        }
        let result = tokio::time::timeout(Duration::from_secs(8), task)
            .await
            .unwrap()
            .unwrap();
        assert!(if mode == "wait" {
            matches!(result, Err(ExecutorError::Cancelled))
        } else {
            matches!(result, Err(ExecutorError::Timeout))
        });
        assert!(dir.path().join("removed").exists());
        assert!(!dir.path().join("container").exists());
        let calls = std::fs::read_to_string(dir.path().join("calls")).unwrap();
        assert!(calls.contains("\"stop\""));
        assert!(calls.contains("\"rm\", \"--force\""));
        // On Linux an orphan can briefly be a zombie awaiting init's reap, but cannot run.
        #[cfg(target_os = "linux")]
        {
            let pid = std::fs::read_to_string(dir.path().join("pid")).unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                        Err(_) => break,
                        Ok(stat) if stat.split_whitespace().nth(2) == Some("Z") => break,
                        _ => tokio::time::sleep(Duration::from_millis(10)).await,
                    }
                }
            })
            .await
            .unwrap();
        }
    }
}

#[tokio::test]
async fn oversized_transfer_fails_promptly_without_waiting_for_pipe_eof() {
    let dir = tempfile::tempdir().unwrap();
    let _initial = executor(dir.path(), "oversize");
    // A small cap avoids writing a GiB just to exercise the bounded stream reader.
    let executor = DockerExecutor::new(DockerConfig {
        binary: dir.path().join("docker.py"),
        max_artifact_bytes: 128,
        ..DockerConfig::default()
    })
    .unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        executor.execute(
            job(dir.path()),
            Arc::new(Captured::default()),
            CancellationToken::new(),
        ),
    )
    .await
    .expect("oversized stream deadlocked");
    match result {
        Err(ExecutorError::Infrastructure(error)) => {
            assert!(error.to_string().contains("size limit"))
        }
        other => panic!("Unexpected outcome: {other:?}"),
    }
    assert!(dir.path().join("removed").exists());
}
