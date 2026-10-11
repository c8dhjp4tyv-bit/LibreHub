//! Crash barriers for the failure-injection acceptance (debug builds only). When
//! `LIBREHUB_TEST_AUTOMATION_FAULT_STAGE` names a stage, the task writes a marker file in the
//! data directory and parks forever so the harness can kill the process at that exact boundary.
use std::path::Path;

pub async fn barrier(data_dir: &Path, stage: &str) {
    #[cfg(debug_assertions)]
    {
        if librehub_common::test_hooks::test_env("LIBREHUB_TEST_AUTOMATION_FAULT_STAGE")
            .ok()
            .as_deref()
            == Some(stage)
        {
            let _ = tokio::fs::write(data_dir.join(format!("automation-fault-{stage}")), b"ready")
                .await;
            std::future::pending::<()>().await;
        }
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = (data_dir, stage);
    }
}
