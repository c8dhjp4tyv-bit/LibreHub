//! Offline independent verification. Trust roots and expected release identity are explicit inputs.
use anyhow::{Context, Result, ensure};
use librehub_common::*;
use librehub_supply_chain as crypto;
use std::path::Path;
fn main() {
    match run() {
        Ok(key_id) => println!(
            "{}",
            serde_json::to_string(&VerificationResult {
                verified: true,
                code: "verified".into(),
                key_id: Some(key_id)
            })
            .expect("JSON")
        ),
        Err(error) => {
            println!(
                "{}",
                serde_json::json!({"verified":false,"code":"verification_failed","reason":error.to_string()})
            );
            std::process::exit(1);
        }
    }
}
fn run() -> Result<String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() >= 3,
        "usage: librehub-verify <bundle.json> <trusted-keys.json> --ref REF --checksum SHA256 --publication-id UUID [--artifact FILE] [--sbom FILE] [--source REPO] [--image SHA256:ID]"
    );
    let bundle: AttestationBundle = serde_json::from_slice(&crypto::bounded_file(
        Path::new(&args[0]),
        crypto::MAX_ENVELOPE * 2,
    )?)?;
    ensure!(bundle.version == 1, "unsupported_bundle_version");
    let keys: KeyBundle =
        serde_json::from_slice(&crypto::bounded_file(Path::new(&args[1]), 32 * 1024)?)?;
    let mut options = std::collections::BTreeMap::new();
    for chunk in args[2..].chunks(2) {
        ensure!(
            chunk.len() == 2
                && [
                    "--ref",
                    "--checksum",
                    "--publication-id",
                    "--artifact",
                    "--sbom",
                    "--source",
                    "--image"
                ]
                .contains(&chunk[0].as_str())
                && options
                    .insert(chunk[0].as_str(), chunk[1].as_str())
                    .is_none(),
            "invalid_option"
        );
    }
    let (b, digest) = crypto::verify(&bundle.build, &keys)?;
    let (r, _) = crypto::verify(&bundle.release, &keys)?;
    crypto::verify_link(&r, &b, &digest)?;
    ensure!(
        r.subject[0].name == *options.get("--ref").context("expected_ref_required")?
            && r.subject[0].digest.get("sha256").map(String::as_str)
                == Some(
                    *options
                        .get("--checksum")
                        .context("expected_checksum_required")?
                ),
        "release_subject_mismatch"
    );
    let ProvenancePredicate::Release(release) = r.predicate else {
        anyhow::bail!("invalid_release")
    };
    let publication: PublishId = options
        .get("--publication-id")
        .context("expected_publication_required")?
        .parse()?;
    ensure!(
        release.publication_id == publication,
        "publication_identity_mismatch"
    );
    if let Some(path) = options.get("--artifact") {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        let mut file = std::fs::File::open(path)?;
        ensure!(
            file.metadata()?.is_file() && file.metadata()?.len() <= 1024 * 1024 * 1024,
            "artifact_size_limit"
        );
        let mut hash = Sha256::new();
        let mut buffer = [0; 65536];
        let mut total = 0u64;
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            total += n as u64;
            ensure!(total <= 1024 * 1024 * 1024, "artifact_size_limit");
            hash.update(&buffer[..n]);
        }
        ensure!(
            format!("{:x}", hash.finalize()) == release.build_artifact_sha256,
            "artifact_digest_mismatch"
        );
    }
    if let Some(path) = options.get("--sbom") {
        ensure!(
            crypto::sha256(&crypto::bounded_file(Path::new(path), 10 * 1024 * 1024)?)
                == release.sbom_sha256,
            "sbom_digest_mismatch"
        );
    }
    let ProvenancePredicate::Build(build) = b.predicate else {
        anyhow::bail!("invalid_build")
    };
    if let Some(repo) = options.get("--source") {
        ensure!(
            build
                .build_definition
                .external_parameters
                .source
                .revision
                .repository
                == *repo,
            "source_policy_mismatch"
        );
    }
    if let Some(image) = options.get("--image") {
        ensure!(
            build
                .build_definition
                .internal_parameters
                .image_config_digest
                == *image,
            "image_policy_mismatch"
        );
    }
    Ok(bundle.release.signatures[0].keyid.clone())
}
