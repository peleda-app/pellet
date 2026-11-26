use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whether an address can appear in a public DNS list or have meaningful public reverse DNS.
///
/// False for unspecified, loopback, private (RFC 1918), shared (RFC 6598), link-local,
/// multicast and broadcast IPv4, and for unspecified, loopback, unique local, link-local and
/// multicast IPv6. IPv4-mapped IPv6 addresses are judged as IPv4.
pub fn is_listable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => listable_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => listable_v4(v4),
            None => listable_v6(v6),
        },
    }
}

fn listable_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    let shared = a == 100 && (64..128).contains(&b);
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || shared)
}

fn listable_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    let unique_local = first & 0xfe00 == 0xfc00;
    let link_local = first & 0xffc0 == 0xfe80;
    !(ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || unique_local || link_local)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listable(ip: &str) -> bool {
        is_listable(ip.parse().unwrap())
    }

    #[test]
    fn public_and_documentation_addresses_are_listable() {
        for ip in [
            "192.0.2.7",
            "198.51.100.1",
            "203.0.113.9",
            "2001:db8::1",
            "8.8.8.8",
        ] {
            assert!(listable(ip), "{ip}");
        }
    }

    #[test]
    fn local_addresses_are_not() {
        for ip in [
            "0.0.0.0",
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fd00::1",
            "fe80::1",
            "ff02::1",
            "::ffff:192.168.1.1",
        ] {
            assert!(!listable(ip), "{ip}");
        }
        assert!(listable("::ffff:192.0.2.7"));
    }
}
