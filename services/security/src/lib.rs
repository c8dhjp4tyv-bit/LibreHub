//! LibreHub Trust, Security & Moderation engine.
//! Provides SBOM generation, permission diffing, vulnerability evaluation, and domain verification.

pub mod permissions;
pub mod sbom;
pub mod verification;
pub mod vulnerabilities;

pub use permissions::{diff_permissions, parse_permission_snapshot};
pub use sbom::{SbomInput, generate_spdx_document, write_sbom_artifact};
pub use verification::{
    CHALLENGE_PREFIX, CHALLENGE_TTL_SECS, DnsResolver, FixtureDnsResolver, SystemUdpDnsResolver,
    default_resolver, format_challenge_txt, generate_challenge_token, validate_domain_syntax,
    verify_domain_txt,
};
pub use vulnerabilities::{
    FixtureVulnerabilityProvider, OsvProvider, VulnerabilityProvider, default_provider,
};
