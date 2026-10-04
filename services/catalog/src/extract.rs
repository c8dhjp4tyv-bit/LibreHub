//! Off-request extraction from the verified bundle and the exact signed published commit.
use crate::{CatalogMetadata, CatalogPermissions, metadata};
use librehub_common::*;
use librehub_publisher::{artifact, repository::RepositoryConfig};
use std::{path::PathBuf, time::Duration};
pub struct Extracted {
    pub metadata: CatalogMetadata,
    pub permissions: CatalogPermissions,
    pub icon_png: Option<Vec<u8>>,
}
async fn command(binary: &str, args: &[String], max: usize) -> anyhow::Result<Vec<u8>> {
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
        .spawn()?;
    let stdout = child.stdout.take().unwrap();
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut bytes = vec![];
        stdout.take(max as u64 + 1).read_to_end(&mut bytes).await?;
        anyhow::ensure!(bytes.len() <= max, "Command output limit");
        anyhow::ensure!(child.wait().await?.success(), "Metadata command failed");
        Ok(bytes)
    })
    .await?
}
async fn cat(repo: &str, commit: &str, path: &str, max: usize) -> anyhow::Result<Vec<u8>> {
    command(
        "ostree",
        &[repo.into(), "cat".into(), commit.into(), path.into()],
        max,
    )
    .await
}
pub fn validate_png(bytes: &[u8]) -> bool {
    // Serve only PNG, never SVG/HTML. IHDR bounds and byte cap avoid arbitrary asset formats.
    bytes.len() >= 33
        && bytes.len() <= 256 * 1024
        && bytes.starts_with(b"\x89PNG\r\n\x1a\n")
        && &bytes[12..16] == b"IHDR"
        && [16, 20].iter().all(|p| {
            let size = u32::from_be_bytes(bytes[*p..*p + 4].try_into().unwrap());
            size > 0 && size <= 1024
        })
}
pub async fn extract(
    root: PathBuf,
    build: BuildRecord,
    manifest: FlatpakManifest,
    publication: PublishRecord,
    repository: RepositoryConfig,
) -> anyhow::Result<Extracted> {
    anyhow::ensure!(
        publication.status == PublishStatus::Succeeded,
        "Only successful publication"
    );
    let result = publication
        .result
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Missing published ref"))?;
    let prepared = artifact::prepare(
        root,
        build,
        manifest,
        publication.architecture,
        Duration::from_secs(60),
    )
    .await?;
    anyhow::ensure!(
        prepared.commit == result.published_ref.source_commit
            && prepared.ref_name == result.published_ref.ref_name,
        "Publication source mismatch"
    );
    let repo = format!("--repo={}", prepared.path.display());
    let app_id = &publication.app_id;
    let mut m = metadata::fallback(app_id);
    // Only canonical app-ID paths, never icon/path strings supplied by metadata.
    for path in [
        format!("/files/share/metainfo/{app_id}.metainfo.xml"),
        format!("/files/share/appdata/{app_id}.appdata.xml"),
    ] {
        if command(
            "ostree",
            &[
                repo.clone(),
                "ls".into(),
                prepared.commit.clone(),
                path.clone(),
            ],
            4096,
        )
        .await
        .is_ok()
        {
            let bytes = cat(&repo, &prepared.commit, &path, metadata::MAX_XML).await?;
            m = metadata::appstream(std::str::from_utf8(&bytes)?, app_id)?;
            break;
        }
    }
    if m.name == *app_id
        && let Ok(bytes) = cat(
            &repo,
            &prepared.commit,
            &format!("/files/share/applications/{app_id}.desktop"),
            65536,
        )
        .await
    {
        m = metadata::desktop(std::str::from_utf8(&bytes)?, app_id)?;
    }
    let mut icon_png = None;
    for size in [128, 64, 256] {
        let path = format!("/files/share/icons/hicolor/{size}x{size}/apps/{app_id}.png");
        if let Ok(bytes) = cat(&repo, &prepared.commit, &path, 256 * 1024).await
            && validate_png(&bytes)
        {
            icon_png = Some(bytes);
            break;
        }
    }
    // M2 rewrites commits. Read permissions from the signed *published* checksum, not its manifest.
    let signed = format!(
        "--repo={}",
        prepared.workspace.path().join("signed").display()
    );
    let key = prepared.workspace.path().join("catalog-public.gpg");
    tokio::fs::write(&key, &repository.public_key).await?;
    for args in [
        vec![signed.clone(), "init".into(), "--mode=archive-z2".into()],
        vec![
            signed.clone(),
            "remote".into(),
            "add".into(),
            "--set=gpg-verify=true".into(),
            "--set=gpg-verify-summary=true".into(),
            format!("--gpg-import={}", key.display()),
            "librehub".into(),
            repository.url(publication.channel),
        ],
        vec![
            signed.clone(),
            "pull".into(),
            "--subpath=/metadata".into(),
            "librehub".into(),
            result.published_ref.commit.clone(),
        ],
    ] {
        command("ostree", &args, 65536).await?;
    }
    let permission_text = cat(&signed, &result.published_ref.commit, "/metadata", 65536).await?;
    let permission_text = std::str::from_utf8(&permission_text)?;
    anyhow::ensure!(
        permission_text
            .lines()
            .any(|line| line == format!("name={app_id}")),
        "Published identity mismatch"
    );
    let permissions = metadata::permissions(permission_text)?;
    metadata::validate_urls(&mut m).await;
    Ok(Extracted {
        metadata: m,
        permissions,
        icon_png,
    })
}
