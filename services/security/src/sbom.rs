//! SPDX 2.3 JSON Software Bill of Materials (SBOM) generator.
//! Tied cryptographically to the exact published Flatpak ref, OSTree commit, and source commit.
use chrono::Utc;
use librehub_common::{PublishId, SbomCreationInfo, SbomDocument, SbomPackage, SbomRelationship};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};

pub struct SbomInput<'a> {
    pub publication_id: &'a PublishId,
    pub app_id: &'a str,
    pub version: &'a str,
    pub ostree_checksum: &'a str,
    pub source_commit: Option<&'a str>,
    pub license: Option<&'a str>,
    pub metadata_text: Option<&'a str>,
    pub additional_modules: Vec<SbomPackage>,
}

/// Generates a canonical SPDX 2.3 JSON document from actual publication artifacts and metadata.
pub fn generate_spdx_document(input: SbomInput) -> SbomDocument {
    let now = Utc::now().to_rfc3339();
    let mut packages = Vec::new();
    let mut relationships = Vec::new();

    let root_spdx_id = format!("SPDXRef-Application-{}", sanitize_spdx_id(input.app_id));

    // 1. Primary application package
    let mut app_hashes = BTreeMap::new();
    app_hashes.insert("SHA256".to_string(), input.ostree_checksum.to_string());

    packages.push(SbomPackage {
        spdx_id: root_spdx_id.clone(),
        download_location: "NOASSERTION".into(),
        files_analyzed: false,
        name: input.app_id.to_string(),
        version: Some(input.version.to_string()),
        package_type: "application".to_string(),
        purl: Some(format!("pkg:generic/{}@{}", input.app_id, input.version)),
        license: input.license.map(str::to_string),
        source: input.source_commit.map(str::to_string),
        hashes: app_hashes,
        scope: "direct".to_string(),
    });

    relationships.push(SbomRelationship {
        spdx_element_id: "SPDXRef-DOCUMENT".to_string(),
        related_spdx_element: root_spdx_id.clone(),
        relationship_type: "DESCRIBES".to_string(),
    });

    // 2. Runtime and SDK from /metadata if present
    if let Some(meta) = input.metadata_text {
        let (runtime_name, runtime_ver) = extract_metadata_field(meta, "runtime");
        if let Some(r_name) = runtime_name {
            let r_spdx_id = format!("SPDXRef-Runtime-{}", sanitize_spdx_id(&r_name));
            packages.push(SbomPackage {
                spdx_id: r_spdx_id.clone(),
                download_location: "NOASSERTION".into(),
                files_analyzed: false,
                name: r_name.clone(),
                version: runtime_ver.clone(),
                package_type: "runtime".to_string(),
                purl: Some(format!(
                    "pkg:flatpak/{}@{}",
                    r_name,
                    runtime_ver.as_deref().unwrap_or("unknown")
                )),
                license: Some("NOASSERTION".to_string()),
                source: None,
                hashes: BTreeMap::new(),
                scope: "runtime".to_string(),
            });
            relationships.push(SbomRelationship {
                spdx_element_id: root_spdx_id.clone(),
                related_spdx_element: r_spdx_id,
                relationship_type: "DEPENDS_ON".to_string(),
            });
        }

        let (sdk_name, sdk_ver) = extract_metadata_field(meta, "sdk");
        if let Some(s_name) = sdk_name {
            let s_spdx_id = format!("SPDXRef-Sdk-{}", sanitize_spdx_id(&s_name));
            packages.push(SbomPackage {
                spdx_id: s_spdx_id.clone(),
                download_location: "NOASSERTION".into(),
                files_analyzed: false,
                name: s_name.clone(),
                version: sdk_ver.clone(),
                package_type: "sdk".to_string(),
                purl: Some(format!(
                    "pkg:flatpak/{}@{}",
                    s_name,
                    sdk_ver.as_deref().unwrap_or("unknown")
                )),
                license: Some("NOASSERTION".to_string()),
                source: None,
                hashes: BTreeMap::new(),
                scope: "build-dependency".to_string(),
            });
            relationships.push(SbomRelationship {
                spdx_element_id: root_spdx_id.clone(),
                related_spdx_element: s_spdx_id,
                relationship_type: "DEPENDS_ON".to_string(),
            });
        }
    }

    // 3. Additional modules/components
    for (i, mut module) in input.additional_modules.into_iter().enumerate() {
        let mod_spdx_id = format!("SPDXRef-Package-{}-{}", sanitize_spdx_id(&module.name), i);
        module.spdx_id = mod_spdx_id.clone();
        relationships.push(SbomRelationship {
            spdx_element_id: root_spdx_id.clone(),
            related_spdx_element: mod_spdx_id,
            relationship_type: "DEPENDS_ON".to_string(),
        });
        packages.push(module);
    }

    SbomDocument {
        spdx_version: "SPDX-2.3".to_string(),
        data_license: "CC0-1.0".to_string(),
        spdx_id: "SPDXRef-DOCUMENT".to_string(),
        name: format!("{}-{}", input.app_id, input.version),
        document_namespace: format!(
            "https://librehub.net/spdx/{}/{}",
            input.app_id, input.publication_id
        ),
        creation_info: SbomCreationInfo {
            created: now,
            creators: vec![
                "Tool: LibreHub-Security-0.1.0".to_string(),
                "Organization: LibreHub".to_string(),
            ],
        },
        packages,
        relationships,
    }
}

/// Persist the SBOM document under controlled security artifact directory.
/// Returns (relative_path, sha256_hex, component_count).
pub async fn write_sbom_artifact(
    data_dir: &Path,
    publication_id: &PublishId,
    document: &SbomDocument,
) -> anyhow::Result<(String, String, u32)> {
    let security_dir = data_dir.join("security").join(publication_id.to_string());
    tokio::fs::create_dir_all(&security_dir).await?;

    let file_path = security_dir.join("sbom.spdx.json");
    let json_bytes = serde_json::to_vec_pretty(document)?;

    anyhow::ensure!(
        json_bytes.len() <= 10 * 1024 * 1024,
        "SBOM document exceeds maximum size of 10MB"
    );

    let mut hasher = Sha256::new();
    hasher.update(&json_bytes);
    let sha256 = format!("{:x}", hasher.finalize());

    tokio::fs::write(&file_path, &json_bytes).await?;

    let relative_path = format!("security/{publication_id}/sbom.spdx.json");
    let component_count = document.packages.len() as u32;

    Ok((relative_path, sha256, component_count))
}

fn sanitize_spdx_id(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

fn extract_metadata_field(text: &str, field: &str) -> (Option<String>, Option<String>) {
    let prefix = format!("{field}=");
    for line in text.lines().map(str::trim) {
        if let Some(val) = line.strip_prefix(&prefix) {
            let val = val
                .trim_start_matches("runtime/")
                .trim_start_matches("app/");
            let parts: Vec<&str> = val.split('/').collect();
            if parts.len() >= 3 {
                return (Some(parts[0].to_string()), Some(parts[2].to_string()));
            } else if parts.len() == 2 {
                return (Some(parts[0].to_string()), Some(parts[1].to_string()));
            } else if !val.is_empty() {
                return (Some(val.to_string()), None);
            }
        }
    }
    (None, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_valid_spdx_structure() {
        let pub_id = PublishId::new();
        let metadata = "[Application]\nruntime=runtime/org.freedesktop.Platform/x86_64/25.08\nsdk=runtime/org.freedesktop.Sdk/x86_64/25.08\n";
        let doc = generate_spdx_document(SbomInput {
            publication_id: &pub_id,
            app_id: "org.librehub.Demo",
            version: "1.0.0",
            ostree_checksum: "abcdef1234567890",
            source_commit: Some("commit123"),
            license: Some("MIT"),
            metadata_text: Some(metadata),
            additional_modules: vec![SbomPackage {
                spdx_id: String::new(),
                download_location: "NOASSERTION".into(),
                files_analyzed: false,
                name: "zlib".to_string(),
                version: Some("1.2.13".to_string()),
                package_type: "library".to_string(),
                purl: Some("pkg:generic/zlib@1.2.13".to_string()),
                license: Some("Zlib".to_string()),
                source: None,
                hashes: BTreeMap::new(),
                scope: "dependency".to_string(),
            }],
        });

        assert_eq!(doc.spdx_version, "SPDX-2.3");
        assert_eq!(doc.data_license, "CC0-1.0");
        assert_eq!(doc.packages.len(), 4); // app, runtime, sdk, zlib
        assert_eq!(doc.packages[0].name, "org.librehub.Demo");
        assert_eq!(doc.packages[0].license.as_deref(), Some("MIT"));
        assert_eq!(doc.packages[1].name, "org.freedesktop.Platform");
        assert_eq!(doc.packages[1].version.as_deref(), Some("25.08"));
        let json = serde_json::to_value(&doc).unwrap();
        for (package, serialized) in doc
            .packages
            .iter()
            .zip(json["packages"].as_array().unwrap())
        {
            assert_eq!(serialized["SPDXID"], package.spdx_id);
            assert_eq!(serialized["downloadLocation"], "NOASSERTION");
            assert_eq!(serialized["filesAnalyzed"], false);
            assert!(serialized.get("version").is_none());
            assert!(serialized.get("purl").is_none());
            assert!(
                doc.relationships
                    .iter()
                    .any(|r| r.related_spdx_element == package.spdx_id)
            );
        }
        assert_eq!(json["packages"][0]["versionInfo"], "1.0.0");
        assert_eq!(json["packages"][0]["checksums"][0]["algorithm"], "SHA256");
        assert_eq!(
            json["packages"][0]["externalRefs"][0]["referenceLocator"],
            "pkg:generic/org.librehub.Demo@1.0.0"
        );
        let roundtrip: SbomDocument = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(roundtrip).unwrap(), json);
    }

    #[tokio::test]
    async fn writes_and_hashes_sbom() {
        let tmp = tempfile::tempdir().unwrap();
        let pub_id = PublishId::new();
        let doc = generate_spdx_document(SbomInput {
            publication_id: &pub_id,
            app_id: "org.librehub.Test",
            version: "0.1.0",
            ostree_checksum: "deadbeef",
            source_commit: None,
            license: None,
            metadata_text: None,
            additional_modules: Vec::new(),
        });

        let (rel_path, sha, count) = write_sbom_artifact(tmp.path(), &pub_id, &doc)
            .await
            .unwrap();

        assert_eq!(count, 1);
        assert!(rel_path.starts_with("security/"));
        assert_eq!(sha.len(), 64);
        assert!(tmp.path().join(&rel_path).exists());
    }
}
