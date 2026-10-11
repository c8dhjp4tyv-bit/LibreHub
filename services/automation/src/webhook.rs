//! Outbound webhook primitives: signature format, destination (SSRF) validation and
//! delivery-outcome classification. Network I/O lives in the API crate.
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use subtle::ConstantTimeEq;
use url::{Host, Url};

pub const PAYLOAD_VERSION: u32 = 1;
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024;
pub const SIGNATURE_TOLERANCE_SECS: i64 = 300;
pub const SIGNATURE_HEADER: &str = "X-LibreHub-Signature";
pub const TIMESTAMP_HEADER: &str = "X-LibreHub-Timestamp";
pub const DELIVERY_HEADER: &str = "X-LibreHub-Delivery";
pub const EVENT_HEADER: &str = "X-LibreHub-Event";
pub const EVENT_ID_HEADER: &str = "X-LibreHub-Event-Id";

/// Signature input: `"{unix_timestamp}.{delivery_id}.{exact body bytes}"`, HMAC-SHA256 with the
/// subscription secret, hex encoded, prefixed `v1=`. The timestamp and delivery identity are
/// authenticated together with the bytes that are actually transmitted.
pub fn signature(secret: &[u8], timestamp: i64, delivery_id: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(delivery_id.as_bytes());
    mac.update(b".");
    mac.update(body);
    let tag = mac.finalize().into_bytes();
    format!(
        "v1={}",
        tag.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}
/// Reference receiver-side verification, also used by tests and the acceptance receiver.
pub fn verify_signature(
    secret: &[u8],
    header: &str,
    timestamp: i64,
    delivery_id: &str,
    body: &[u8],
    now: i64,
) -> bool {
    if (now - timestamp).abs() > SIGNATURE_TOLERANCE_SECS {
        return false;
    }
    let expected = signature(secret, timestamp, delivery_id, body);
    bool::from(expected.as_bytes().ct_eq(header.as_bytes()))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventOrigin {
    /// automation | manual | webhook | schedule | ci | system
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub automation_run_id: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub version: u32,
    pub event_id: String,
    pub delivery_id: String,
    pub event_type: String,
    pub created_at: String,
    pub project_id: String,
    pub origin: EventOrigin,
    /// Number of automation hops that led to this event. Receivers must pass it back when
    /// they trigger LibreHub, which refuses chains deeper than the configured maximum.
    pub chain_depth: u32,
    pub correlation_id: String,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DestinationError {
    #[error("destination URL is invalid")]
    Invalid,
    #[error("destination must use https")]
    NotHttps,
    #[error("destination must not contain credentials")]
    Credentials,
    #[error("destination port is not allowed")]
    Port,
    #[error("destination host is not allowed")]
    Host,
    #[error("destination resolves to a non-public address")]
    NonPublicAddress,
    #[error("destination cannot be resolved")]
    Unresolvable,
}
impl DestinationError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Invalid => "webhook_url_invalid",
            Self::NotHttps => "webhook_url_not_https",
            Self::Credentials => "webhook_url_credentials",
            Self::Port => "webhook_url_port",
            Self::Host => "webhook_url_host",
            Self::NonPublicAddress => "webhook_destination_not_public",
            Self::Unresolvable => "webhook_destination_unresolvable",
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DestinationPolicy {
    /// Test-only operator switch: permits loopback destinations, never link-local/private ranges.
    pub allow_loopback: bool,
}

#[derive(Debug, Clone)]
pub struct Destination {
    pub url: Url,
    pub host: String,
    pub port: u16,
    pub literal: Option<IpAddr>,
}

pub fn is_public_ip(ip: IpAddr, policy: DestinationPolicy) -> bool {
    match ip {
        IpAddr::V4(v) => public_v4(v, policy),
        IpAddr::V6(v) => {
            if let Some(mapped) = v.to_ipv4_mapped() {
                return public_v4(mapped, policy);
            }
            if v == Ipv6Addr::LOCALHOST {
                return policy.allow_loopback;
            }
            // Global unicast only: excludes ULA, link-local, multicast, NAT64, documentation and 6to4.
            let s = v.segments();
            (s[0] & 0xe000) == 0x2000
                && s[0] != 0x2002
                && !(s[0] == 0x2001 && s[1] < 0x0200)
                && !(s[0] == 0x2001 && s[1] == 0x0db8)
        }
    }
}
fn public_v4(v: Ipv4Addr, policy: DestinationPolicy) -> bool {
    let [a, b, c, _] = v.octets();
    if a == 127 {
        return policy.allow_loopback;
    }
    !(a == 0
        || a == 10
        || a >= 224
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && (b == 168 || (b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99)))
        || (a == 100 && (64..=127).contains(&b))
        || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113))
}

const BLOCKED_SUFFIXES: &[&str] = &[
    ".local",
    ".localhost",
    ".internal",
    ".lan",
    ".home",
    ".corp",
    ".intranet",
    ".localdomain",
    ".home.arpa",
    ".svc",
    ".cluster.local",
];

/// Syntax and literal checks that need no network. DNS results are checked separately.
pub fn parse_destination(
    raw: &str,
    policy: DestinationPolicy,
) -> Result<Destination, DestinationError> {
    if raw.is_empty()
        || raw.len() > 2048
        || raw.contains(|c: char| c.is_control() || c.is_whitespace())
    {
        return Err(DestinationError::Invalid);
    }
    let url = Url::parse(raw).map_err(|_| DestinationError::Invalid)?;
    if url.scheme() != "https" {
        return Err(DestinationError::NotHttps);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(DestinationError::Credentials);
    }
    if url.fragment().is_some() {
        return Err(DestinationError::Invalid);
    }
    let port = url.port_or_known_default().ok_or(DestinationError::Port)?;
    if port != 443 && port != 8443 && !(1024..=65535).contains(&port) {
        return Err(DestinationError::Port);
    }
    let (host, literal) = match url.host().ok_or(DestinationError::Host)? {
        Host::Domain(domain) => {
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            let loopback_name = domain == "localhost";
            if loopback_name && policy.allow_loopback {
                (domain, None)
            } else {
                if !domain.contains('.')
                    || domain.len() > 253
                    || BLOCKED_SUFFIXES.iter().any(|s| domain.ends_with(s))
                    || domain.bytes().all(|b| b.is_ascii_digit() || b == b'.')
                    || !domain.is_ascii()
                {
                    return Err(DestinationError::Host);
                }
                (domain, None)
            }
        }
        Host::Ipv4(ip) => (ip.to_string(), Some(IpAddr::V4(ip))),
        Host::Ipv6(ip) => (ip.to_string(), Some(IpAddr::V6(ip))),
    };
    if let Some(ip) = literal
        && !is_public_ip(ip, policy)
    {
        return Err(DestinationError::NonPublicAddress);
    }
    Ok(Destination {
        url,
        host,
        port,
        literal,
    })
}

/// Resolve and require *every* answer to be public, then return the addresses the connection
/// must be pinned to. Resolving once and connecting to those addresses defeats DNS rebinding
/// between validation and connection.
pub async fn resolve_destination(
    destination: &Destination,
    policy: DestinationPolicy,
    deadline: Duration,
) -> Result<Vec<SocketAddr>, DestinationError> {
    let addresses: Vec<SocketAddr> = if let Some(ip) = destination.literal {
        vec![SocketAddr::new(ip, destination.port)]
    } else {
        let lookup = tokio::net::lookup_host((destination.host.as_str(), destination.port));
        tokio::time::timeout(deadline, lookup)
            .await
            .map_err(|_| DestinationError::Unresolvable)?
            .map_err(|_| DestinationError::Unresolvable)?
            .take(16)
            .collect()
    };
    if addresses.is_empty() {
        return Err(DestinationError::Unresolvable);
    }
    if addresses.iter().any(|a| !is_public_ip(a.ip(), policy)) {
        return Err(DestinationError::NonPublicAddress);
    }
    Ok(addresses)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Delivered,
    /// Retry later; `retry_after` is the receiver's hint, already capped.
    Retry {
        reason: &'static str,
        retry_after: Option<Duration>,
    },
    /// The receiver rejected the delivery in a way retrying cannot fix.
    Permanent {
        reason: &'static str,
    },
}
pub fn classify_status(status: u16, retry_after_secs: Option<u64>) -> Outcome {
    let hint = retry_after_secs.map(|s| Duration::from_secs(s.min(3600)));
    match status {
        200..=299 => Outcome::Delivered,
        300..=399 => Outcome::Permanent {
            reason: "redirect_rejected",
        },
        408 | 425 => Outcome::Retry {
            reason: "http_timeout_status",
            retry_after: hint,
        },
        429 => Outcome::Retry {
            reason: "http_429",
            retry_after: hint,
        },
        410 => Outcome::Permanent {
            reason: "http_410_gone",
        },
        400..=499 => Outcome::Permanent {
            reason: "http_client_error",
        },
        _ => Outcome::Retry {
            reason: "http_server_error",
            retry_after: hint,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: i64 = 1_800_000_000;
    #[test]
    fn signature_covers_timestamp_delivery_and_bytes() {
        let sig = signature(b"secret", NOW, "d-1", b"{\"a\":1}");
        assert!(sig.starts_with("v1="));
        assert_eq!(sig.len(), 3 + 64);
        assert!(verify_signature(
            b"secret",
            &sig,
            NOW,
            "d-1",
            b"{\"a\":1}",
            NOW + 10
        ));
        assert!(
            !verify_signature(b"secret", &sig, NOW, "d-1", b"{\"a\":2}", NOW),
            "body tampering"
        );
        assert!(
            !verify_signature(b"secret", &sig, NOW, "d-2", b"{\"a\":1}", NOW),
            "delivery identity"
        );
        assert!(
            !verify_signature(b"secret", &sig, NOW + 1, "d-1", b"{\"a\":1}", NOW),
            "timestamp"
        );
        assert!(
            !verify_signature(b"other", &sig, NOW, "d-1", b"{\"a\":1}", NOW),
            "wrong secret"
        );
        assert!(
            !verify_signature(b"secret", &sig, NOW, "d-1", b"{\"a\":1}", NOW + 10_000),
            "replay window"
        );
        assert!(!verify_signature(
            b"secret",
            "v1=00",
            NOW,
            "d-1",
            b"{\"a\":1}",
            NOW
        ));
    }
    #[test]
    fn ipv4_special_ranges_do_not_block_public_192_0_addresses() {
        let policy = DestinationPolicy::default();
        for ip in ["192.0.0.1", "192.0.2.1", "192.168.1.1", "192.88.99.1"] {
            assert!(!is_public_ip(ip.parse().unwrap(), policy), "{ip}");
        }
        for ip in ["192.0.1.1", "192.0.3.1", "192.0.255.1"] {
            assert!(is_public_ip(ip.parse().unwrap(), policy), "{ip}");
        }
    }
    #[test]
    fn destinations_must_be_public_https() {
        let p = DestinationPolicy::default();
        assert!(parse_destination("https://hooks.example.com/librehub", p).is_ok());
        assert!(parse_destination("https://hooks.example.com:8443/x", p).is_ok());
        let cases = [
            ("http://hooks.example.com/x", DestinationError::NotHttps),
            (
                "https://user:pw@hooks.example.com/x",
                DestinationError::Credentials,
            ),
            (
                "https://user@hooks.example.com/x",
                DestinationError::Credentials,
            ),
            ("https://localhost/x", DestinationError::Host),
            ("https://intranet/x", DestinationError::Host),
            ("https://db.internal/x", DestinationError::Host),
            ("https://thing.local/x", DestinationError::Host),
            ("https://127.0.0.1/x", DestinationError::NonPublicAddress),
            ("https://[::1]/x", DestinationError::NonPublicAddress),
            ("https://10.0.0.5/x", DestinationError::NonPublicAddress),
            ("https://172.16.0.1/x", DestinationError::NonPublicAddress),
            ("https://192.168.1.1/x", DestinationError::NonPublicAddress),
            (
                "https://169.254.169.254/latest/meta-data",
                DestinationError::NonPublicAddress,
            ),
            ("https://[fd00::1]/x", DestinationError::NonPublicAddress),
            ("https://[fe80::1]/x", DestinationError::NonPublicAddress),
            (
                "https://[::ffff:127.0.0.1]/x",
                DestinationError::NonPublicAddress,
            ),
            (
                "https://[::ffff:169.254.169.254]/x",
                DestinationError::NonPublicAddress,
            ),
            (
                "https://[64:ff9b::7f00:1]/x",
                DestinationError::NonPublicAddress,
            ),
            ("https://2130706433/x", DestinationError::NonPublicAddress),
            ("https://0x7f.1/x", DestinationError::NonPublicAddress),
            ("https://hooks.example.com:80/x", DestinationError::Port),
            ("https://hooks.example.com:22/x", DestinationError::Port),
            (
                "https://hooks.example.com/x#frag",
                DestinationError::Invalid,
            ),
            ("ftp://hooks.example.com/x", DestinationError::NotHttps),
            ("", DestinationError::Invalid),
            ("https://exa mple.com/", DestinationError::Invalid),
        ];
        for (url, expected) in cases {
            assert_eq!(parse_destination(url, p).unwrap_err(), expected, "{url}");
        }
    }
    #[test]
    fn loopback_allowance_never_covers_metadata_or_private_ranges() {
        let p = DestinationPolicy {
            allow_loopback: true,
        };
        assert!(parse_destination("https://127.0.0.1:8443/x", p).is_ok());
        assert!(parse_destination("https://localhost:9443/x", p).is_ok());
        assert!(parse_destination("https://169.254.169.254/x", p).is_err());
        assert!(parse_destination("https://10.1.1.1/x", p).is_err());
        assert!(parse_destination("https://[::ffff:10.0.0.1]/x", p).is_err());
    }
    #[tokio::test]
    async fn resolution_requires_every_address_to_be_public() {
        let p = DestinationPolicy::default();
        // A literal public address is accepted without DNS; a hostname resolving to loopback is not.
        let literal = parse_destination("https://8.8.8.8/x", p).unwrap();
        assert!(
            resolve_destination(&literal, p, Duration::from_secs(1))
                .await
                .is_ok()
        );
        let local = Destination {
            url: Url::parse("https://rebind.example.com/").unwrap(),
            host: "localhost".into(),
            port: 443,
            literal: None,
        };
        assert_eq!(
            resolve_destination(&local, p, Duration::from_secs(2))
                .await
                .unwrap_err(),
            DestinationError::NonPublicAddress
        );
    }
    #[test]
    fn statuses_classify_into_retry_or_permanent() {
        assert_eq!(classify_status(204, None), Outcome::Delivered);
        assert!(matches!(classify_status(500, None), Outcome::Retry { .. }));
        assert!(
            matches!(classify_status(503, Some(2)), Outcome::Retry { retry_after: Some(d), .. } if d == Duration::from_secs(2))
        );
        assert!(
            matches!(classify_status(429, Some(999_999)), Outcome::Retry { retry_after: Some(d), .. } if d == Duration::from_secs(3600))
        );
        assert!(matches!(
            classify_status(404, None),
            Outcome::Permanent { .. }
        ));
        assert!(matches!(
            classify_status(302, None),
            Outcome::Permanent {
                reason: "redirect_rejected"
            }
        ));
        assert!(matches!(classify_status(408, None), Outcome::Retry { .. }));
    }
}
