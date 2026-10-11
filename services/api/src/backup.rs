//! Application-consistent backup, verification and restore.
//!
//! The control-plane database is copied with SQLite's online backup API, which takes a consistent
//! snapshot while the API keeps writing, including content still in the write-ahead log. Evidence
//! directories are copied afterwards. They are immutable once a database row references them, so
//! every reference in the snapshot resolves inside the archive. Signing and encryption keys never
//! enter an archive: they are provisioned separately (see docs/backups.md).
use anyhow::{Context, bail, ensure};
use rusqlite::{Connection, OpenFlags, backup::Backup};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    time::Duration,
};

pub const FORMAT: u32 = 1;
pub const MANIFEST: &str = "manifest.json";
pub const DATABASE: &str = "database.sqlite3";
/// Directories of evidence and records. Their contents are archived.
pub const EVIDENCE: &[&str] = &[
    "sources",
    "builds",
    "artifacts",
    "publishes",
    "security",
    "repo",
];
/// Names that must never enter an archive. Keys are provisioned separately on restore.
const NEVER: &[&str] = &[
    "keys",
    "webhook.key",
    "tmp",
    "source-tmp",
    "supervisor.lock",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    pub created_at: String,
    pub librehub_version: String,
    pub schema_version: i64,
    pub database: FileEntry,
    pub files: Vec<FileEntry>,
    /// Names deliberately left out (keys, locks, temporaries). Never their contents.
    pub excluded: Vec<String>,
}

/// Create an archive of `data_dir` (with its control-plane database at `database`) in the empty
/// directory `destination`. Safe while the API is running.
pub fn create(data_dir: &Path, database: &Path, destination: &Path) -> anyhow::Result<Manifest> {
    prepare_empty(destination)?;
    let snapshot = destination.join(DATABASE);
    snapshot_database(database, &snapshot)?;
    let schema_version = schema_version(&snapshot)?;
    let database_entry = file_entry(DATABASE, &snapshot)?;
    let mut files = Vec::new();
    let mut excluded = Vec::new();
    for name in NEVER {
        if data_dir.join(name).exists() {
            excluded.push((*name).to_owned());
        }
    }
    for directory in EVIDENCE {
        let source = data_dir.join(directory);
        if source.is_dir() {
            copy_tree(
                &source,
                &destination.join("data").join(directory),
                &format!("data/{directory}"),
                &mut files,
                &mut excluded,
            )?;
        }
    }
    let manifest = Manifest {
        format: FORMAT,
        created_at: chrono::Utc::now().to_rfc3339(),
        librehub_version: env!("CARGO_PKG_VERSION").into(),
        schema_version,
        database: database_entry,
        files,
        excluded,
    };
    fs::write(
        destination.join(MANIFEST),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    verify(destination)?;
    Ok(manifest)
}

/// Check an archive against its manifest: every listed file's size and digest, the snapshot's
/// integrity, and that nothing unlisted is present. Restore runs this before writing anything.
pub fn verify(archive: &Path) -> anyhow::Result<Manifest> {
    let raw = fs::read(archive.join(MANIFEST)).context("The archive has no manifest")?;
    let manifest: Manifest = serde_json::from_slice(&raw).context("The manifest is not valid")?;
    ensure!(
        manifest.format == FORMAT,
        "Unsupported archive format {}",
        manifest.format
    );
    let mut listed = std::collections::BTreeSet::new();
    for entry in std::iter::once(&manifest.database).chain(&manifest.files) {
        let relative = safe_relative(&entry.path)?;
        let actual = file_entry(&entry.path, &archive.join(relative))
            .with_context(|| format!("{} is missing from the archive", entry.path))?;
        ensure!(
            actual.bytes == entry.bytes && actual.sha256 == entry.sha256,
            "{} does not match the manifest",
            entry.path
        );
        listed.insert(entry.path.clone());
    }
    ensure!(
        manifest.database.path == DATABASE,
        "The database must be {DATABASE}"
    );
    let present = list_files(archive)?;
    for path in present {
        ensure!(
            path == MANIFEST || listed.contains(&path),
            "{path} is not listed in the manifest"
        );
    }
    let check = integrity_check(&archive.join(DATABASE))?;
    ensure!(
        check == "ok",
        "The database snapshot failed integrity_check: {check}"
    );
    Ok(manifest)
}

/// Restore a verified archive into an empty `data_dir`, with the database at `database`. Keys
/// must be provisioned into `data_dir` afterwards. Opening the store applies this release's
/// migrations and refuses a schema from a newer release.
pub fn restore(archive: &Path, data_dir: &Path, database: &Path) -> anyhow::Result<Manifest> {
    let manifest = verify(archive)?;
    prepare_empty(data_dir)?;
    ensure!(
        !database.exists(),
        "The database path must not exist before a restore"
    );
    if let Some(parent) = database.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(archive.join(DATABASE), database)?;
    for entry in &manifest.files {
        let relative = safe_relative(&entry.path)?;
        let inside = relative
            .strip_prefix("data")
            .context("Evidence must live under data/")?;
        let target = data_dir.join(inside);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(archive.join(relative), &target)?;
        ensure!(
            file_entry(&entry.path, &target)?.sha256 == entry.sha256,
            "{} changed while restoring",
            entry.path
        );
    }
    // Opening the store validates the schema, applies this release's migrations and takes the
    // supervisor lock, so the restored directory is in exactly the state a start would leave it.
    drop(crate::store::Store::open_at(data_dir, Some(database))?);
    Ok(manifest)
}

fn prepare_empty(path: &Path) -> anyhow::Result<()> {
    if path.exists() {
        ensure!(
            path.is_dir() && fs::read_dir(path)?.next().is_none(),
            "{} must be an empty directory",
            path.display()
        );
    } else {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

/// Consistent copy of a live database. The copy is a standalone rollback-journal file.
fn snapshot_database(source: &Path, destination: &Path) -> anyhow::Result<()> {
    let from = Connection::open_with_flags(source, OpenFlags::SQLITE_OPEN_READ_ONLY).with_context(
        || {
            format!(
                "Cannot open the control-plane database {}",
                source.display()
            )
        },
    )?;
    let mut to = Connection::open(destination)?;
    Backup::new(&from, &mut to)?.run_to_completion(256, Duration::from_millis(5), None)?;
    to.pragma_update(None, "journal_mode", "DELETE")?;
    Ok(())
}
fn integrity_check(path: &Path) -> anyhow::Result<String> {
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    Ok(db.query_row("PRAGMA integrity_check", [], |r| r.get(0))?)
}
fn schema_version(path: &Path) -> anyhow::Result<i64> {
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let has_table: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations')",
        [],
        |r| r.get(0),
    )?;
    if !has_table {
        return Ok(0);
    }
    Ok(db.query_row(
        "SELECT COALESCE(MAX(version),0) FROM schema_migrations",
        [],
        |r| r.get(0),
    )?)
}

fn copy_tree(
    source: &Path,
    destination: &Path,
    relative: &str,
    files: &mut Vec<FileEntry>,
    excluded: &mut Vec<String>,
) -> anyhow::Result<()> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        let inside = format!("{relative}/{name}");
        let kind = entry.file_type()?;
        let secret_like = name.ends_with(".key")
            || name.ends_with(".pem")
            || name.ends_with(".env")
            || name.ends_with(".lock");
        if NEVER.contains(&name.as_str()) || secret_like || kind.is_symlink() {
            // Links are never followed: a link could lead out of the data directory.
            excluded.push(inside);
        } else if kind.is_dir() {
            copy_tree(&path, &destination.join(&name), &inside, files, excluded)?;
        } else if kind.is_file() {
            fs::create_dir_all(destination)?;
            let target = destination.join(&name);
            fs::copy(&path, &target)?;
            files.push(file_entry(&inside, &target)?);
        }
    }
    Ok(())
}

fn file_entry(path: &str, file: &Path) -> anyhow::Result<FileEntry> {
    let mut reader = fs::File::open(file)?;
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = vec![0u8; 1 << 16];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes += read as u64;
    }
    Ok(FileEntry {
        path: path.to_owned(),
        bytes,
        sha256: hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    })
}

fn safe_relative(path: &str) -> anyhow::Result<PathBuf> {
    let relative = Path::new(path);
    if relative
        .components()
        .all(|c| matches!(c, Component::Normal(_)))
        && !path.is_empty()
    {
        Ok(relative.to_path_buf())
    } else {
        bail!("The manifest names an unsafe path")
    }
}
fn list_files(root: &Path) -> anyhow::Result<Vec<String>> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) -> anyhow::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            ensure!(!kind.is_symlink(), "The archive contains a link");
            if kind.is_dir() {
                walk(root, &entry.path(), out)?;
            } else {
                let relative = entry
                    .path()
                    .strip_prefix(root)?
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push(relative);
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(root, root, &mut out)?;
    Ok(out)
}
