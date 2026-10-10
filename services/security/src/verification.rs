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
        let mut id = [0; 2];
        getrandom::fill(&mut id)
            .map_err(|e| anyhow::anyhow!("DNS query randomness unavailable: {e}"))?;
        let id = u16::from_be_bytes(id);
        let query = build_dns_txt_query(&domain, id)?;

        let bind = if self.nameserver.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(self.nameserver).await?;

        tokio::time::timeout(self.timeout, socket.send(&query))
            .await
            .map_err(|_| anyhow::anyhow!("DNS lookup timed out"))??;

        let mut buf = [0u8; 4096];
        let len = tokio::time::timeout(self.timeout, socket.recv(&mut buf))
            .await
            .map_err(|_| anyhow::anyhow!("DNS response timed out"))??;

        parse_dns_txt_response(&buf[..len], id, &domain)
    }
}

/// Builds a 12-byte header + QNAME + QTYPE(16) + QCLASS(1) query packet.
fn build_dns_txt_query(domain: &str, id: u16) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(domain.len() <= 253, "DNS name too long");
    let mut packet = Vec::with_capacity(512);

    // Header
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD = 1
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    // QNAME
    for label in domain.split('.') {
        anyhow::ensure!(
            !label.is_empty() && label.len() <= 63,
            "Invalid DNS label length"
        );
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
fn parse_dns_txt_response(buf: &[u8], id: u16, domain: &str) -> anyhow::Result<Vec<String>> {
    anyhow::ensure!(buf.len() >= 12, "DNS response buffer too short");

    anyhow::ensure!(
        u16::from_be_bytes([buf[0], buf[1]]) == id,
        "DNS response ID mismatch"
    );
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    anyhow::ensure!(flags & 0x8000 != 0, "DNS QR flag unset");
    anyhow::ensure!(flags & 0x0200 == 0, "Truncated DNS response");
    anyhow::ensure!(flags & 0x7800 == 0, "Unexpected DNS opcode");
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    anyhow::ensure!(qdcount == 1, "Unexpected DNS question count");
    let (question, mut offset) = read_name(buf, 12)?;
    anyhow::ensure!(
        question.eq_ignore_ascii_case(domain),
        "DNS question name mismatch"
    );
    anyhow::ensure!(
        buf.get(offset..offset + 4) == Some(&[0, 16, 0, 1]),
        "DNS question type/class mismatch"
    );
    offset += 4;
    if flags & 0x000f != 0 {
        return Ok(Vec::new());
    }

    let mut results = Vec::new();
    anyhow::ensure!(ancount <= 64, "Too many DNS answers");
    for _ in 0..ancount {
        let (owner, next) = read_name(buf, offset)?;
        anyhow::ensure!(
            owner.eq_ignore_ascii_case(domain),
            "DNS answer owner mismatch"
        );
        offset = next;
        anyhow::ensure!(buf.len() >= offset + 10, "Truncated answer header");

        let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let rclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
        let _ttl = u32::from_be_bytes([
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        offset += 10;

        anyhow::ensure!(buf.len() >= offset + rdlength, "Truncated RDATA");

        if rtype == 16 && rclass == 1 {
            // TXT RDATA is a sequence of length-prefixed strings
            let rdata = &buf[offset..offset + rdlength];
            let mut rdata_offset = 0;
            let mut full_txt = String::new();

            while rdata_offset < rdata.len() {
                let str_len = rdata[rdata_offset] as usize;
                rdata_offset += 1;
                anyhow::ensure!(
                    rdata_offset + str_len <= rdata.len(),
                    "Truncated TXT string"
                );
                full_txt.push_str(std::str::from_utf8(
                    &rdata[rdata_offset..rdata_offset + str_len],
                )?);
                rdata_offset += str_len;
            }

            if !full_txt.is_empty() && full_txt.len() <= 512 {
                results.push(full_txt);
            }
        }

        offset += rdlength;
    }

    Ok(results)
}

fn read_name(buf: &[u8], mut offset: usize) -> anyhow::Result<(String, usize)> {
    let mut end = None;
    let mut labels = Vec::new();
    let mut length = 0;
    for _ in 0..128 {
        let len = *buf
            .get(offset)
            .ok_or_else(|| anyhow::anyhow!("Truncated DNS name"))?;
        if len == 0 {
            return Ok((labels.join("."), end.unwrap_or(offset + 1)));
        }
        if len & 0xc0 == 0xc0 {
            let low = *buf
                .get(offset + 1)
                .ok_or_else(|| anyhow::anyhow!("Truncated DNS pointer"))?;
            end.get_or_insert(offset + 2);
            offset = (((len & 0x3f) as usize) << 8) | low as usize;
            continue;
        }
        anyhow::ensure!(len & 0xc0 == 0, "Invalid DNS label");
        let next = offset + 1 + len as usize;
        let label = buf
            .get(offset + 1..next)
            .ok_or_else(|| anyhow::anyhow!("Truncated DNS label"))?;
        anyhow::ensure!(!label.contains(&b'.'), "Invalid DNS label separator");
        labels.push(std::str::from_utf8(label)?.to_string());
        length += len as usize + 1;
        anyhow::ensure!(length <= 254, "DNS name too long");
        offset = next;
    }
    anyhow::bail!("DNS name pointer loop or excessive indirection");
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

    fn txt_response(id: u16) -> Vec<u8> {
        let mut packet = build_dns_txt_query("example.org", id).unwrap();
        packet[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        packet[6..8].copy_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&[0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 60, 0, 3, 2, b'o', b'k']);
        packet
    }

    #[test]
    fn dns_response_is_bound_to_query() {
        let packet = txt_response(1234);
        assert_eq!(
            parse_dns_txt_response(&packet, 1234, "example.org").unwrap(),
            vec!["ok"]
        );
        assert!(parse_dns_txt_response(&packet, 1235, "example.org").is_err());
        assert!(parse_dns_txt_response(&packet, 1234, "another.org").is_err());
        for flags in [0x0180u16, 0x8380] {
            let mut bad = packet.clone();
            bad[2..4].copy_from_slice(&flags.to_be_bytes());
            assert!(parse_dns_txt_response(&bad, 1234, "example.org").is_err());
        }
        let answer = build_dns_txt_query("example.org", 1234).unwrap().len();
        let mut wrong_owner = packet.clone();
        wrong_owner.splice(answer..answer + 2, [3, b'b', b'a', b'd', 0]);
        assert!(parse_dns_txt_response(&wrong_owner, 1234, "example.org").is_err());
        let mut looped = packet.clone();
        looped[answer + 1] = answer as u8;
        assert!(parse_dns_txt_response(&looped, 1234, "example.org").is_err());
        let mut wrong_type = packet.clone();
        wrong_type[answer - 3] = 1;
        assert!(parse_dns_txt_response(&wrong_type, 1234, "example.org").is_err());
        for len in 0..packet.len() {
            assert!(parse_dns_txt_response(&packet[..len], 1234, "example.org").is_err());
        }
    }

    #[tokio::test]
    async fn dns_resolver_uses_ipv6_nameserver() {
        let server = UdpSocket::bind("[::1]:0").await.unwrap();
        let resolver = SystemUdpDnsResolver::new(server.local_addr().unwrap());
        let reply = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_, peer) = server.recv_from(&mut buf).await.unwrap();
            server
                .send_to(&txt_response(u16::from_be_bytes([buf[0], buf[1]])), peer)
                .await
                .unwrap();
        });
        assert_eq!(
            resolver.lookup_txt("example.org").await.unwrap(),
            vec!["ok"]
        );
        reply.await.unwrap();
    }

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
