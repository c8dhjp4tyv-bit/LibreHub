//! Test the real Docker executor's orchestration without requiring a container daemon.
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
struct Logs(Mutex<Vec<BuildLogEntry>>);
#[async_trait]
impl LogSink for Logs {
    async fn append(&self, entry: BuildLogEntry) -> anyhow::Result<()> {
        self.0.lock().unwrap().push(entry);
        Ok(())
    }
}
const FAKE: &str = r#"#!/usr/bin/env python3
import io, json, os, pathlib, signal, subprocess, sys, tarfile, time
root = pathlib.Path(__file__).parent
args = sys.argv[1:]
with (root / 'calls.jsonl').open('a') as f: f.write(json.dumps(args) + '\n')
mode = (root / 'mode').read_text()
if args[0] == 'create':
    (root / 'exists').touch()
    print('container-id')
elif args[0] == 'cp' and args[-1] == '-':
    if mode == 'oversized':
        sys.stdout.buffer.write(b'x' * (2 * 1024 * 1024))
        sys.stdout.buffer.flush()
        time.sleep(60)
    data = b'flatpak bundle test data'
    with tarfile.open(fileobj=sys.stdout.buffer, mode='w|') as archive:
        entry = tarfile.TarInfo('application.flatpak')
        entry.size = len(data)
        archive.addfile(entry, io.BytesIO(data))
elif args[0] == 'start':
    print('stdout from container', flush=True)
    print('stderr from container', file=sys.stderr, flush=True)
    if mode in ['wait', 'force']:
        # A detached process represents the container; killing the Docker client does not stop it.
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (root / 'pid').write_text(str(child.pid))
        while not (root / 'stopped').exists(): time.sleep(.01)
        child.wait()
    elif mode == 'failure': sys.exit(9)
elif args[0] == 'inspect': print('0')
elif args[:2] == ['container', 'ls']:
    if (root / 'exists').exists(): print('container-name')
elif args[0] == 'stop':
    if mode == 'force': sys.exit(1)
    if (root / 'pid').exists():
        try: os.kill(int((root / 'pid').read_text()), signal.SIGTERM)
        except ProcessLookupError: pass
    (root / 'stopped').touch()
elif args[0] == 'rm':
    if (root / 'pid').exists():
        try: os.kill(int((root / 'pid').read_text()), signal.SIGKILL)
        except ProcessLookupError: pass
    (root / 'stopped').touch()
    (root / 'exists').unlink(missing_ok=True)
"#;
fn setup(mode: &str, timeout: Duration) -> (tempfile::TempDir, DockerExecutor, BuildJob) {
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("fake-docker");
    std::fs::write(&binary, FAKE).unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(dir.path().join("mode"), mode).unwrap();
    let executor = DockerExecutor::new(DockerConfig {
        binary,
        timeout,
        max_artifact_bytes: 1024,
        ..Default::default()
    })
    .unwrap();
    let manifest = librehub_validator::validate(
        include_str!("../../../examples/org.librehub.Hello.json"),
        ManifestFormat::Json,
    )
    .unwrap();
    let job = BuildJob {
        source_snapshot: None,
        id: BuildId::new(),
        manifest,
        architecture: Architecture::native(),
        data_dir: dir.path().join("data"),
    };
    (dir, executor, job)
}
fn calls(dir: &std::path::Path) -> Vec<Vec<String>> {
    std::fs::read_to_string(dir.join("calls.jsonl"))
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect()
}
#[tokio::test]
async fn success_collects_bundle_and_exposes_both_streams_without_host_mounts() {
    let (dir, executor, job) = setup("success", Duration::from_secs(5));
    let logs = Arc::new(Logs::default());
    let result = executor
        .execute(job.clone(), logs.clone(), CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(result.exit_code, Some(0));
    assert_eq!(
        std::fs::read(job.data_dir.join(&result.artifacts[0].path)).unwrap(),
        b"flatpak bundle test data"
    );
    assert!(!dir.path().join("exists").exists());
    assert!(
        logs.0
            .lock()
            .unwrap()
            .iter()
            .any(|l| matches!(l.stream, LogStream::Stderr))
    );
    let calls = calls(dir.path());
    let create = &calls[0];
    assert!(create.contains(&"--cap-drop=ALL".into()));
    assert!(create.contains(&"--security-opt=systempaths=unconfined".into()));
    assert!(create.contains(&"--user=10001:10001".into()));
    assert!(
        create.iter().all(|a| !a.starts_with("--mount")
            && !a.starts_with("--volume")
            && a != "--privileged")
    );
    assert!(calls.iter().any(|a| a[0] == "rm"));
    assert_eq!(
        std::fs::read_dir(job.data_dir.join("tmp")).unwrap().count(),
        0
    );
}
#[tokio::test]
async fn nonzero_exit_fails_and_removes_container() {
    let (dir, executor, job) = setup("failure", Duration::from_secs(5));
    let result = executor
        .execute(job, Arc::new(Logs::default()), CancellationToken::new())
        .await;
    assert!(matches!(result, Err(ExecutorError::Exit(Some(9)))));
    assert!(!dir.path().join("exists").exists());
}
#[tokio::test]
async fn cancellation_stops_the_execution_environment_and_forces_when_needed() {
    for mode in ["wait", "force"] {
        let (dir, executor, job) = setup(mode, Duration::from_secs(5));
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let task = tokio::spawn(async move {
            executor
                .execute(job, Arc::new(Logs::default()), task_cancel)
                .await
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            while !dir.path().join("pid").exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        cancel.cancel();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(3), task)
                .await
                .unwrap()
                .unwrap(),
            Err(ExecutorError::Cancelled)
        ));
        let calls = calls(dir.path());
        assert!(
            calls
                .iter()
                .any(|a| a[0] == "stop" && a.contains(&"--time=5".into()))
        );
        assert!(
            calls
                .iter()
                .any(|a| a[0] == "rm" && a.contains(&"--force".into()))
        );
        assert!(!dir.path().join("exists").exists());
        assert!(dir.path().join("stopped").exists());
    }
}
#[tokio::test]
async fn timeout_removes_the_active_container() {
    let (dir, executor, job) = setup("wait", Duration::from_millis(500));
    let result = executor
        .execute(job, Arc::new(Logs::default()), CancellationToken::new())
        .await;
    assert!(matches!(result, Err(ExecutorError::Timeout)));
    assert!(!dir.path().join("exists").exists());
}

#[tokio::test]
async fn oversized_artifact_is_rejected_before_the_producer_closes_its_pipes() {
    // Allow fixture startup under host load; the assertion still rejects a timeout.
    let (dir, executor, job) = setup("oversized", Duration::from_secs(30));
    let result = executor
        .execute(job, Arc::new(Logs::default()), CancellationToken::new())
        .await;
    match result {
        Err(ExecutorError::Infrastructure(error)) => {
            assert!(error.to_string().contains("Artifact exceeds"))
        }
        other => panic!("Unexpected oversized copy result: {other:?}"),
    }
    assert!(!dir.path().join("exists").exists());
}
