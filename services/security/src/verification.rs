//! Publisher domain ownership verification via DNS TXT challenge.
//! Defends against malformed records, huge responses, timeouts, and private DNS assumptions.
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::UdpSocket;

pub const CHALLENGE_PREFIX: &str = "librehub-verification=";
pub const CHALLENGE_TTL_SECS: i64 = 86400; // 24 hours

/// Validate domain syntax: valid labels, no IP addresses, no localhost, bounded length.
pub fn validate_domain_syntax(domain: &str) -> anyhow::Result<String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();

    anyhow::ensure!(!domain.is_empty(), "Domain cannot be empty");
    anyhow::ensure!(
        domain.len() <= 253,
        "Domain exceeds maximum length of 253 characters"
    );
    anyhow::ensure!(
        !domain.contains('/') && !domain.contains(':') && !domain.contains('@'),
        "Domain cannot contain paths, ports or credentials"
    );

    // Reject IP addresses (IPv4 or IPv6)
    if domain.parse::<std::net::IpAddr>().is_ok() {
        anyhow::bail!("Domain cannot be an IP address");
    }

    let labels: Vec<&str> = domain.split('.').collect();
    anyhow::ensure!(
        labels.len() >= 2,
        "Domain must have at least two labels (e.g. example.org)"
    );

    for label in &labels {
        anyhow::ensure!(
            !label.is_empty() && label.len() <= 63,
            "Domain label must be between 1 and 63 characters"
        );
        anyhow::ensure!(
            !label.starts_with('-') && !label.ends_with('-'),
            "Domain label cannot start or end with a hyphen"
        );
        anyhow::ensure!(
            label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "Domain label contains invalid characters"
        );
    }

    // Disallow reserved/local domains
    let last = labels.last().unwrap();
    if [
        "local",
        "localhost",
        "internal",
        "test",
        "example",
        "invalid",
    ]
    .contains(last)
    {
        anyhow::bail!("Domain uses a reserved top-level domain");
    }

    Ok(domain)
}

/// Generate cryptographically secure random token (32 bytes hex = 64 chars).
pub fn generate_challenge_token() -> String {
    use sha2::{Digest, Sha256};
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).unwrap_or_else(|_| {
        let fallback = format!("{}-{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let hash = Sha256::digest(fallback.as_bytes());
        bytes.copy_from_slice(&hash);
    });
    hex_encode(&bytes)
}

pub fn format_challenge_txt(token: &str) -> String {
    format!("{CHALLENGE_PREFIX}{token}")
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[async_trait::async_trait]
pub trait DnsResolver: Send + Sync {
    async fn lookup_txt(&self, domain: &str) -> anyhow::Result<Vec<String>>;
}

/// In-memory / fixture resolver for deterministic tests and CI.
#[derive(Debug, Clone, Default)]
pub struct FixtureDnsResolver {
    records: HashMap<String, Vec<String>>,
}

impl FixtureDnsResolver {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    pub fn with_record(mut self, domain: &str, txt: &str) -> Self {
        self.records
            .entry(domain.to_ascii_lowercase())
            .or_default()
            .push(txt.to_string());
        self
    }

    pub fn from_env() -> Option<Self> {
        if let Ok(raw) = std::env::var("LIBREHUB_TEST_DNS_TXT") {
            let mut resolver = Self::new();
            // Format: "domain1=txt1;domain2=txt2"
            for item in raw.split(';') {
                if let Some((d, t)) = item.split_once('=') {
                    resolver = resolver.with_record(d.trim(), t.trim());
                }
            }
            return Some(resolver);
        }
        None
    }
}

#[async_trait::async_trait]
impl DnsResolver for FixtureDnsResolver {
    async fn lookup_txt(&self, domain: &str) -> anyhow::Result<Vec<String>> {
        let key = domain.trim_end_matches('.').to_ascii_lowercase();
        Ok(self.records.get(&key).cloned().unwrap_or_default())
    }
}

/// RFC 1035 UDP DNS TXT resolver with bounded buffers, deadlines, and parsing protections.
#[derive(Clone)]
pub struct SystemUdpDnsResolver {
    nameserver: SocketAddr,
    timeout: Duration,
}

impl Default for SystemUdpDnsResolver {
    fn default() -> Self {
        let ns = parse_system_nameserver().unwrap_or_else(|| "1.1.1.1:53".parse().unwrap());
        Self {
            nameserver: ns,
            timeout: Duration::from_secs(4),
        }
    }
}

impl SystemUdpDnsResolver {
    pub fn new(nameserver: SocketAddr) -> Self {
        Self {
            nameserver,
            timeout: Duration::from_secs(4),
        }
    }
}

fn parse_system_nameserver() -> Option<SocketAddr> {
    if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            let line = line.trim();
            if let Some(ip_str) = line.strip_prefix("nameserver ") {
                let ip_str = ip_str.trim();
                if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                    return Some(SocketAddr::new(ip, 53));
                }
            }
        }
    }
    None
}

#[async_trait::async_trait]
impl DnsResolver for SystemUdpDnsResolver {
    async fn lookup_txt(&self, domain: &str) -> anyhow::Result<Vec<String>> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        let query = build_dns_txt_query(&domain)?;

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(self.nameserver).await?;

        tokio::time::timeout(self.timeout, socket.send(&query))
            .await
            .map_err(|_| anyhow::anyhow!("DNS lookup timed out"))??;

        let mut buf = [0u8; 4096];
        let len = tokio::time::timeout(self.timeout, socket.recv(&mut buf))
            .await
            .map_err(|_| anyhow::anyhow!("DNS response timed out"))??;

        parse_dns_txt_response(&buf[..len])
    }
}

/// Builds a 12-byte header + QNAME + QTYPE(16) + QCLASS(1) query packet.
fn build_dns_txt_query(domain: &str) -> anyhow::Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(512);

    // Header
    let id: u16 = 0x4242;
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD = 1
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    // QNAME
    for label in domain.split('.') {
        anyhow::ensure!(label.len() <= 63, "Label too long for DNS packet");
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0); // Root label

    // QTYPE = 16 (TXT)
    packet.extend_from_slice(&16u16.to_be_bytes());
    // QCLASS = 1 (IN)
    packet.extend_from_slice(&1u16.to_be_bytes());

    Ok(packet)
}

/// Parse answers from DNS response buffer, strictly extracting TXT character-strings.
fn parse_dns_txt_response(buf: &[u8]) -> anyhow::Result<Vec<String>> {
    anyhow::ensure!(buf.len() >= 12, "DNS response buffer too short");

    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Ok(Vec::new()); // Non-zero RCODE (e.g. NXDOMAIN, SERVFAIL) -> no records
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut offset = 12;

    // Skip question section
    for _ in 0..qdcount {
        offset = skip_name(buf, offset)?;
        anyhow::ensure!(buf.len() >= offset + 4, "Truncated question section");
        offset += 4; // QTYPE + QCLASS
    }

    let mut results = Vec::new();
    let max_records = ancount.min(16);

    for _ in 0..max_records {
        if offset >= buf.len() {
            break;
        }
        offset = skip_name(buf, offset)?;
        anyhow::ensure!(buf.len() >= offset + 10, "Truncated answer header");

        let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let _rclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
        let _ttl = u32::from_be_bytes([
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        offset += 10;

        anyhow::ensure!(buf.len() >= offset + rdlength, "Truncated RDATA");

        if rtype == 16 {
            // TXT RDATA is a sequence of length-prefixed strings
            let rdata = &buf[offset..offset + rdlength];
            let mut rdata_offset = 0;
            let mut full_txt = String::new();

            while rdata_offset < rdata.len() {
                let str_len = rdata[rdata_offset] as usize;
                rdata_offset += 1;
                if rdata_offset + str_len <= rdata.len() {
                    if let Ok(s) = std::str::from_utf8(&rdata[rdata_offset..rdata_offset + str_len])
                    {
                        full_txt.push_str(s);
                    }
                    rdata_offset += str_len;
                } else {
                    break;
                }
            }

            if !full_txt.is_empty() && full_txt.len() <= 512 {
                results.push(full_txt);
            }
        }

        offset += rdlength;
    }

    Ok(results)
}

fn skip_name(buf: &[u8], mut offset: usize) -> anyhow::Result<usize> {
    let mut jumps = 0;
    while offset < buf.len() {
        let len = buf[offset];
        if len == 0 {
            return Ok(offset + 1);
        }
        if (len & 0xC0) == 0xC0 {
            // Pointer
            anyhow::ensure!(buf.len() >= offset + 2, "Truncated pointer");
            return Ok(offset + 2);
        }
        let step = (len as usize) + 1;
        offset += step;
        jumps += 1;
        anyhow::ensure!(jumps < 64, "DNS pointer loop detected");
    }
    anyhow::bail!("Unterminated DNS name");
}

/// Verify domain ownership by checking TXT records on `_librehub-challenge.<domain>` and `<domain>`.
pub async fn verify_domain_txt(
    resolver: &dyn DnsResolver,
    domain: &str,
    expected_token: &str,
) -> anyhow::Result<bool> {
    let expected_txt = format_challenge_txt(expected_token);

    // Try `_librehub-challenge.<domain>` first
    let challenge_subdomain = format!("_librehub-challenge.{domain}");
    if let Ok(records) = resolver.lookup_txt(&challenge_subdomain).await {
        for record in records {
            if record.trim() == expected_txt {
                return Ok(true);
            }
        }
    }

    // Fallback: check apex / direct `<domain>`
    if let Ok(records) = resolver.lookup_txt(domain).await {
        for record in records {
            if record.trim() == expected_txt {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Get default resolver: fixture if configured in env, else system UDP resolver.
pub fn default_resolver() -> Arc<dyn DnsResolver> {
    if let Some(fixture) = FixtureDnsResolver::from_env() {
        Arc::new(fixture)
    } else {
        Arc::new(SystemUdpDnsResolver::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_domain_syntax() {
        assert_eq!(
            validate_domain_syntax("example.org").unwrap(),
            "example.org"
        );
        assert_eq!(
            validate_domain_syntax("sub.domain.co.uk.").unwrap(),
            "sub.domain.co.uk"
        );
        assert!(validate_domain_syntax("localhost").is_err());
        assert!(validate_domain_syntax("192.168.1.1").is_err());
        assert!(validate_domain_syntax("http://example.org").is_err());
        assert!(validate_domain_syntax("example.org:8080").is_err());
        assert!(validate_domain_syntax("-bad.org").is_err());
    }

    #[tokio::test]
    async fn fixture_resolver_verifies_challenge() {
        let token = "fedcba9876543210fedcba9876543210";
        let resolver = FixtureDnsResolver::new().with_record(
            "_librehub-challenge.example.org",
            &format_challenge_txt(token),
        );

        let verified = verify_domain_txt(&resolver, "example.org", token)
            .await
            .unwrap();
        assert!(verified);

        let wrong = verify_domain_txt(&resolver, "example.org", "wrongtoken")
            .await
            .unwrap();
        assert!(!wrong);
    }
}
