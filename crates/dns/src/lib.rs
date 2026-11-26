//! DNS lookup contract used by checks for DNSBL, PTR and HELO lookups.
//!
//! Names are validated and normalized here, before any implementation sees them, so every
//! resolver refuses the same names in the same way.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;

mod address;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use address::is_listable;

/// Why a lookup gave no records.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    /// The name is not a valid DNS name; nothing was queried.
    #[error("invalid DNS name")]
    InvalidName,
    /// The name does not exist, or has no records of this type (`NXDOMAIN` or NODATA).
    #[error("no records")]
    NotFound,
    /// No answer before the deadline.
    #[error("DNS timeout")]
    Timeout,
    /// The resolver failed (`SERVFAIL`, refused, network error); the name may still exist.
    #[error("DNS failure: {0}")]
    Failed(String),
}

impl DnsError {
    /// Whether the answer says something about the name (`NotFound`, `InvalidName`) rather than
    /// about the resolver (`Timeout`, `Failed`).
    pub fn is_definite(&self) -> bool {
        matches!(self, DnsError::NotFound | DnsError::InvalidName)
    }
}

/// DNS lookups for checks.
///
/// Guarantees an implementation must keep:
/// - Names go through [`normalize`] first; an invalid name is [`DnsError::InvalidName`] and is
///   never sent anywhere.
/// - Names under `.invalid` (RFC 6761) are [`DnsError::NotFound`] without a query.
/// - `Ok` always holds at least one record; an empty answer is [`DnsError::NotFound`].
/// - Returned host names are lowercase without the trailing dot.
/// - Every call finishes within the implementation's deadline, as [`DnsError::Timeout`] at worst.
#[async_trait]
pub trait Resolver: Send + Sync {
    /// A records.
    async fn ipv4(&self, name: &str) -> Result<Vec<Ipv4Addr>, DnsError>;
    /// AAAA records.
    async fn ipv6(&self, name: &str) -> Result<Vec<Ipv6Addr>, DnsError>;
    /// TXT records, each with its character strings joined.
    async fn txt(&self, name: &str) -> Result<Vec<Vec<u8>>, DnsError>;
    /// MX records as preference and exchange.
    async fn mx(&self, name: &str) -> Result<Vec<(u16, String)>, DnsError>;
    /// PTR records for an address.
    async fn ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsError>;
}

/// Validates a DNS name and returns it lowercase without a trailing dot.
///
/// A valid name has 1 to 253 bytes, labels of 1 to 63 bytes, and only letters, digits, `-` and
/// `_` (underscores appear in DKIM and DMARC names), with no label starting or ending in `-`.
pub fn normalize(name: &str) -> Result<String, DnsError> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > 253 {
        return Err(DnsError::InvalidName);
    }
    for label in name.split('.') {
        let valid = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !valid {
            return Err(DnsError::InvalidName);
        }
    }
    Ok(name.to_ascii_lowercase())
}

/// Whether a normalized name is under the reserved `.invalid` top-level domain.
pub fn is_reserved_invalid(name: &str) -> bool {
    name == "invalid" || name.ends_with(".invalid")
}

/// The name to query in a DNS list zone for an address: reversed octets for IPv4
/// (`7.2.0.192.zone`), reversed nibbles for IPv6.
pub fn list_query(ip: IpAddr, zone: &str) -> String {
    let zone = zone.trim_end_matches('.');
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.{zone}")
        }
        IpAddr::V6(v6) => {
            let mut name = String::with_capacity(64 + zone.len());
            for byte in v6.octets().iter().rev() {
                name.push(char::from_digit(u32::from(byte & 0x0f), 16).expect("nibble"));
                name.push('.');
                name.push(char::from_digit(u32::from(byte >> 4), 16).expect("nibble"));
                name.push('.');
            }
            name.push_str(zone);
            name
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_valid_names() {
        assert_eq!(normalize("Mail.Example.COM.").unwrap(), "mail.example.com");
        assert_eq!(
            normalize("sel._domainkey.example.org").unwrap(),
            "sel._domainkey.example.org"
        );
        assert_eq!(normalize("localhost").unwrap(), "localhost");
        assert!(normalize(&format!("{}.example", "a".repeat(63))).is_ok());
    }

    #[test]
    fn refuses_invalid_names() {
        for bad in [
            "",
            ".",
            "a..b",
            "-lead.example",
            "trail-.example",
            "has space.example",
            "ünï.example",
            "semi;colon.example",
        ] {
            assert_eq!(normalize(bad), Err(DnsError::InvalidName), "{bad:?}");
        }
        assert!(normalize(&format!("{}.example", "a".repeat(64))).is_err());
        let long = vec!["abcdefghi"; 26].join(".");
        assert!(long.len() > 253);
        assert!(normalize(&long).is_err());
    }

    #[test]
    fn reserved_invalid() {
        assert!(is_reserved_invalid("host.invalid"));
        assert!(is_reserved_invalid("invalid"));
        assert!(!is_reserved_invalid("notinvalid"));
        assert!(!is_reserved_invalid("example.org"));
    }

    #[test]
    fn list_queries() {
        assert_eq!(
            list_query("192.0.2.7".parse().unwrap(), "zen.example.org."),
            "7.2.0.192.zen.example.org"
        );
        let v6 = list_query("2001:db8::1".parse().unwrap(), "zone.example");
        assert_eq!(
            v6,
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.zone.example"
        );
    }

    #[test]
    fn definite_errors() {
        assert!(DnsError::NotFound.is_definite());
        assert!(!DnsError::Timeout.is_definite());
        assert!(!DnsError::Failed("x".into()).is_definite());
    }
}
