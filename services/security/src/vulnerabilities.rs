//! Vulnerability matching against SBOM components.
//! Abstract provider trait with OSV support and deterministic test fixtures.
use chrono::Utc;
use librehub_common::{SbomPackage, VulnerabilityFinding, VulnerabilitySeverity};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};

#[async_trait::async_trait]
pub trait VulnerabilityProvider: Send + Sync {
    async fn check_packages(
        &self,
        packages: &[SbomPackage],
    ) -> anyhow::Result<Vec<VulnerabilityFinding>>;
}

/// Offline / Fixture vulnerability provider for deterministic tests and CI.
#[derive(Debug, Clone, Default)]
pub struct FixtureVulnerabilityProvider {
    pub findings: Vec<VulnerabilityFinding>,
    pub simulate_outage: bool,
}

impl FixtureVulnerabilityProvider {
    pub fn new(findings: Vec<VulnerabilityFinding>) -> Self {
        Self {
            findings,
            simulate_outage: false,
        }
    }

    pub fn with_outage() -> Self {
        Self {
            findings: Vec::new(),
            simulate_outage: true,
        }
    }

    pub fn from_env() -> Option<Self> {
        if std::env::var("LIBREHUB_TEST_VULNERABILITY_OUTAGE").is_ok() {
            return Some(Self::with_outage());
        }
        if let Ok(raw) = std::env::var("LIBREHUB_TEST_VULNERABILITY_FIXTURE")
            && let Ok(findings) = serde_json::from_str::<Vec<VulnerabilityFinding>>(&raw)
        {
            return Some(Self::new(findings));
        }
        None
    }
}

#[async_trait::async_trait]
impl VulnerabilityProvider for FixtureVulnerabilityProvider {
    async fn check_packages(
        &self,
        packages: &[SbomPackage],
    ) -> anyhow::Result<Vec<VulnerabilityFinding>> {
        if self.simulate_outage {
            anyhow::bail!("Vulnerability service temporarily unavailable (simulated outage)");
        }
        let now = Utc::now();
        let mut results = Vec::new();
        for pkg in packages {
            for finding in &self.findings {
                if finding.component_name == pkg.name {
                    let mut matched = finding.clone();
                    matched.checked_at = now;
                    results.push(matched);
                }
            }
        }
        Ok(results)
    }
}

/// Real OSV.dev batch vulnerability scanner with strict timeouts and bounds.
#[derive(Clone)]
pub struct OsvProvider {
    client: reqwest::Client,
    api_url: String,
    timeout: Duration,
}

impl Default for OsvProvider {
    fn default() -> Self {
        Self::new("https://api.osv.dev/v1/querybatch")
    }
}

impl OsvProvider {
    pub fn new(api_url: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self {
            client,
            api_url: api_url.to_string(),
            timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Serialize)]
struct OsvBatchQuery<'a> {
    queries: Vec<OsvPackageQuery<'a>>,
}

#[derive(Serialize)]
struct OsvPackageQuery<'a> {
    package: OsvPackageInfo<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'a str>,
}

#[derive(Serialize)]
struct OsvPackageInfo<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ecosystem: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purl: Option<&'a str>,
}

#[derive(Deserialize)]
struct OsvBatchResponse {
    #[serde(default)]
    results: Vec<OsvQueryResult>,
}

#[derive(Deserialize)]
struct OsvQueryResult {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    database_specific: Option<serde_json::Value>,
    #[serde(default)]
    references: Vec<OsvReference>,
}

#[derive(Deserialize)]
struct OsvReference {
    #[serde(rename = "type")]
    kind: Option<String>,
    url: String,
}

#[async_trait::async_trait]
impl VulnerabilityProvider for OsvProvider {
    async fn check_packages(
        &self,
        packages: &[SbomPackage],
    ) -> anyhow::Result<Vec<VulnerabilityFinding>> {
        if packages.is_empty() {
            return Ok(Vec::new());
        }

        // Bound to at most 100 components per check
        let packages = &packages[..packages.len().min(100)];

        let mut queries = Vec::new();
        let mut package_index_map = Vec::new();

        for pkg in packages {
            if let Some(purl) = &pkg.purl {
                queries.push(OsvPackageQuery {
                    package: OsvPackageInfo {
                        name: &pkg.name,
                        ecosystem: None,
                        purl: Some(purl),
                    },
                    version: if purl.split(['?', '#']).next().unwrap_or(purl).contains('@') {
                        None
                    } else {
                        pkg.version.as_deref()
                    },
                });
                package_index_map.push(pkg);
            }
        }

        if queries.is_empty() {
            return Ok(Vec::new());
        }

        let body = OsvBatchQuery { queries };

        let response = tokio::time::timeout(
            self.timeout,
            self.client
                .post(&self.api_url)
                .header("Content-Type", "application/json")
                .json(&body)
                .send(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("OSV request timed out"))?
        .map_err(|e| anyhow::anyhow!("OSV request failed: {e}"))?;

        if !response.status().is_success() {
            anyhow::bail!("OSV returned HTTP {}", response.status());
        }

        let batch: OsvBatchResponse = response
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to parse OSV response: {e}"))?;

        let now = Utc::now();
        let mut findings = Vec::new();

        for (i, result) in batch.results.into_iter().enumerate() {
            if let Some(pkg) = package_index_map.get(i) {
                for vuln in result.vulns {
                    let severity = parse_osv_severity(&vuln.database_specific);
                    let summary = vuln
                        .summary
                        .or(vuln.details)
                        .unwrap_or_else(|| "Security advisory".to_string());
                    let ref_url = vuln
                        .references
                        .iter()
                        .find(|r| {
                            r.kind.as_deref() == Some("ADVISORY") || r.url.starts_with("https://")
                        })
                        .map(|r| r.url.clone());

                    findings.push(VulnerabilityFinding {
                        vulnerability_id: vuln.id,
                        component_name: pkg.name.clone(),
                        component_version: pkg.version.clone().unwrap_or_else(|| "unknown".into()),
                        severity,
                        summary: sanitize_summary(&summary),
                        reference_url: sanitize_url(ref_url.as_deref()),
                        source_provider: "OSV".to_string(),
                        checked_at: now,
                    });
                }
            }
        }

        Ok(findings)
    }
}

fn parse_osv_severity(specific: &Option<serde_json::Value>) -> VulnerabilitySeverity {
    if let Some(val) = specific
        && let Some(sev) = val.get("severity").and_then(|s| s.as_str())
    {
        match sev.to_ascii_uppercase().as_str() {
            "CRITICAL" => return VulnerabilitySeverity::Critical,
            "HIGH" => return VulnerabilitySeverity::High,
            "MODERATE" | "MEDIUM" => return VulnerabilitySeverity::Medium,
            "LOW" => return VulnerabilitySeverity::Low,
            _ => {}
        }
    }
    VulnerabilitySeverity::Unknown
}

fn sanitize_summary(s: &str) -> String {
    let bounded = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(300)
        .collect::<String>();
    bounded.trim().to_string()
}

fn sanitize_url(url: Option<&str>) -> Option<String> {
    let url = url?;
    if url.len() > 2048 || !url.starts_with("https://") {
        return None;
    }
    Some(url.to_string())
}

/// Create provider from environment: defaults to Fixture if configured, otherwise real OSV.
pub fn default_provider() -> Arc<dyn VulnerabilityProvider> {
    if let Some(fixture) = FixtureVulnerabilityProvider::from_env() {
        Arc::new(fixture)
    } else {
        Arc::new(OsvProvider::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn osv_wire_queries_do_not_duplicate_versions_and_keep_component_mapping() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = OsvProvider::new(&format!("http://{}", listener.local_addr().unwrap()));
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let body = loop {
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buf[..n]);
                if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
                    let length: usize = headers
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    if bytes.len() >= end + 4 + length {
                        break serde_json::from_slice::<serde_json::Value>(
                            &bytes[end + 4..end + 4 + length],
                        )
                        .unwrap();
                    }
                }
            };
            assert_eq!(body["queries"].as_array().unwrap().len(), 2);
            assert_eq!(
                body["queries"][0]["package"]["purl"],
                "pkg:generic/versioned@1.0"
            );
            assert!(body["queries"][0].get("version").is_none());
            assert_eq!(body["queries"][1]["version"], "2.0");
            let body = r#"{"results":[{}, {"vulns":[{"id":"TEST-1"}]}]}"#;
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).as_bytes()).await.unwrap();
        });
        let packages: Vec<_> = [
            ("skipped", None, None),
            ("versioned", Some("pkg:generic/versioned@1.0"), Some("1.0")),
            ("unversioned", Some("pkg:generic/unversioned"), Some("2.0")),
        ]
        .into_iter()
        .map(|(name, purl, version)| SbomPackage {
            spdx_id: String::new(),
            download_location: "NOASSERTION".into(),
            files_analyzed: false,
            name: name.into(),
            version: version.map(str::to_string),
            purl: purl.map(str::to_string),
            package_type: "library".into(),
            license: None,
            source: None,
            hashes: Default::default(),
            scope: "runtime".into(),
        })
        .collect();
        let findings = provider.check_packages(&packages).await.unwrap();
        server.await.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].component_name, "unversioned");
        assert_eq!(findings[0].component_version, "2.0");
    }

    #[tokio::test]
    async fn fixture_provider_matches_components() {
        let finding = VulnerabilityFinding {
            vulnerability_id: "CVE-2026-9999".to_string(),
            component_name: "openssl".to_string(),
            component_version: "1.1.1".to_string(),
            severity: VulnerabilitySeverity::High,
            summary: "Buffer overflow test".to_string(),
            reference_url: Some("https://example.com/cve".to_string()),
            source_provider: "test".to_string(),
            checked_at: Utc::now(),
        };

        let provider = FixtureVulnerabilityProvider::new(vec![finding]);
        let packages = vec![
            SbomPackage {
                spdx_id: String::new(),
                download_location: "NOASSERTION".into(),
                files_analyzed: false,
                name: "openssl".to_string(),
                version: Some("1.1.1".to_string()),
                package_type: "library".to_string(),
                purl: None,
                license: None,
                source: None,
                hashes: Default::default(),
                scope: "runtime".to_string(),
            },
            SbomPackage {
                spdx_id: String::new(),
                download_location: "NOASSERTION".into(),
                files_analyzed: false,
                name: "zlib".to_string(),
                version: Some("1.2.13".to_string()),
                package_type: "library".to_string(),
                purl: None,
                license: None,
                source: None,
                hashes: Default::default(),
                scope: "runtime".to_string(),
            },
        ];

        let results = provider.check_packages(&packages).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vulnerability_id, "CVE-2026-9999");
        assert_eq!(results[0].severity, VulnerabilitySeverity::High);
    }

    #[tokio::test]
    async fn fixture_provider_outage_handling() {
        let provider = FixtureVulnerabilityProvider::with_outage();
        let res = provider.check_packages(&[]).await;
        assert!(res.is_err());
    }
}
