use std::net::{IpAddr, Ipv4Addr};

/// A parsed absolute URL.
///
/// The host is lowercased; everything else is kept as written. Parsing is lenient about the
/// path and strict about the authority: a URL without a host, or whose host holds spaces or
/// characters no host name may have, does not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    /// The text as found, trimmed.
    pub raw: String,
    /// The scheme in lowercase: `http`, `https`, `ftp`, ...
    pub scheme: String,
    /// The part before `@` in the authority, when present.
    pub userinfo: Option<String>,
    /// The host in lowercase, without brackets for IPv6.
    pub host: String,
    /// The port, when given.
    pub port: Option<u16>,
    /// The path, `/` when empty.
    pub path: String,
    /// The query without `?`, empty when absent.
    pub query: String,
}

impl Url {
    /// Parses `scheme://authority/path?query#fragment`; a leading `www.` without a scheme is
    /// read as `http://www.`.
    pub fn parse(text: &str) -> Option<Url> {
        let raw = text.trim();
        let lower = raw.to_ascii_lowercase();
        let (scheme, rest) = if lower.starts_with("www.") {
            ("http".to_string(), raw)
        } else {
            let (scheme, rest) = raw.split_once("://")?;
            if scheme.is_empty()
                || !scheme.starts_with(|c: char| c.is_ascii_alphabetic())
                || !scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
            {
                return None;
            }
            (scheme.to_ascii_lowercase(), rest)
        };
        let rest = rest.split('#').next().unwrap_or_default();
        let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(authority_end);
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((user, host)) => (Some(user.to_string()), host),
            None => (None, authority),
        };
        let (host, port) = if let Some(inner) = hostport.strip_prefix('[') {
            let (host, after) = inner.split_once(']')?;
            let port = after.strip_prefix(':').and_then(|p| p.parse().ok());
            (host.to_string(), port)
        } else {
            match hostport.rsplit_once(':') {
                Some((host, port))
                    if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() =>
                {
                    (host.to_string(), port.parse().ok())
                }
                _ => (hostport.to_string(), None),
            }
        };
        let host = host.trim_end_matches('.').to_lowercase();
        if host.is_empty()
            || host
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || "<>\"'`{}|\\^%,;".contains(c))
        {
            return None;
        }
        let (path, query) = match tail.split_once('?') {
            Some((path, query)) => (path, query),
            None => (tail, ""),
        };
        Some(Url {
            raw: raw.to_string(),
            scheme,
            userinfo,
            host,
            port,
            path: if path.is_empty() {
                "/".into()
            } else {
                path.to_string()
            },
            query: query.to_string(),
        })
    }

    /// The host as an address: dotted, bracketed IPv6, or a single decimal or hexadecimal
    /// number standing for an IPv4 address (`http://3221225985/`).
    pub fn host_ip(&self) -> Option<IpAddr> {
        if let Ok(ip) = self.host.parse() {
            return Some(ip);
        }
        let number = if let Some(hex) = self.host.strip_prefix("0x") {
            u32::from_str_radix(hex, 16).ok()?
        } else if self.host.chars().all(|c| c.is_ascii_digit()) {
            self.host.parse().ok()?
        } else {
            return None;
        };
        Some(IpAddr::V4(Ipv4Addr::from(number)))
    }

    /// Whether the host is written as a plain number rather than a dotted address.
    pub fn host_is_numeric(&self) -> bool {
        self.host.parse::<IpAddr>().is_err() && self.host_ip().is_some()
    }

    /// The path with `?query` when there is one.
    pub fn path_query(&self) -> String {
        if self.query.is_empty() {
            self.path.clone()
        } else {
            format!("{}?{}", self.path, self.query)
        }
    }

    /// The registrable domain of the host (`example.co.uk` for `www.example.co.uk`), or the
    /// host itself for addresses and names without a public suffix.
    pub fn registrable(&self) -> &str {
        if self.host_ip().is_some() {
            return &self.host;
        }
        psl::domain_str(&self.host).unwrap_or(&self.host)
    }

    /// Whether the host ends in a suffix of the public suffix list (`com`, `co.uk`, `lt`), so
    /// it can be a real domain; false for addresses, single labels and names such as
    /// `yarn.lock` or `94.75`.
    pub fn has_known_suffix(&self) -> bool {
        self.host_ip().is_none()
            && self.host.contains('.')
            && psl::suffix(self.host.as_bytes()).is_some_and(|s| s.is_known())
    }

    /// The first absolute URL found in a query parameter value, percent-decoded: where a
    /// redirector sends the reader.
    pub fn redirect_target(&self) -> Option<Url> {
        self.query
            .split('&')
            .filter_map(|pair| pair.split_once('=').map(|(_, v)| percent_decode(v)))
            .find_map(|value| {
                let lower = value.to_ascii_lowercase();
                (lower.starts_with("http://") || lower.starts_with("https://"))
                    .then(|| Url::parse(&value))
                    .flatten()
            })
    }
}

/// Decodes `%XX` escapes and `+` as space; invalid escapes stay as written, invalid UTF-8 is
/// replaced.
pub fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = |b: u8| (b as char).to_digit(16);
                match (
                    bytes.get(i + 1).and_then(|b| hex(*b)),
                    bytes.get(i + 2).and_then(|b| hex(*b)),
                ) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                        continue;
                    }
                    _ => out.push(b'%'),
                }
            }
            b'+' => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_parts() {
        let url = Url::parse("HTTPS://User:pw@WWW.Example.COM:8443/a/b?x=1&y=2#frag").unwrap();
        assert_eq!(url.scheme, "https");
        assert_eq!(url.userinfo.as_deref(), Some("User:pw"));
        assert_eq!(url.host, "www.example.com");
        assert_eq!(url.port, Some(8443));
        assert_eq!(url.path, "/a/b");
        assert_eq!(url.query, "x=1&y=2");
        assert_eq!(url.path_query(), "/a/b?x=1&y=2");
        assert_eq!(url.registrable(), "example.com");
    }

    #[test]
    fn defaults_and_www() {
        let url = Url::parse("www.example.org").unwrap();
        assert_eq!(
            (url.scheme.as_str(), url.host.as_str(), url.path.as_str()),
            ("http", "www.example.org", "/")
        );
        assert_eq!(
            Url::parse("http://[2001:db8::1]:80/x").unwrap().host,
            "2001:db8::1"
        );
    }

    #[test]
    fn refuses_garbage() {
        for bad in [
            "example.com",
            "http://",
            "http:// spaced.example/",
            "http://a<b>/",
            "://x",
            "1http://x/",
        ] {
            assert!(Url::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn numeric_hosts() {
        let decimal = Url::parse("http://3221225985/").unwrap();
        assert_eq!(decimal.host_ip(), Some("192.0.2.1".parse().unwrap()));
        assert!(decimal.host_is_numeric());
        assert_eq!(
            Url::parse("http://0xC0000201/").unwrap().host_ip(),
            Some("192.0.2.1".parse().unwrap())
        );
        let dotted = Url::parse("http://192.0.2.1/").unwrap();
        assert!(dotted.host_ip().is_some() && !dotted.host_is_numeric());
        assert_eq!(dotted.registrable(), "192.0.2.1");
        assert!(
            Url::parse("http://example.com/")
                .unwrap()
                .host_ip()
                .is_none()
        );
    }

    #[test]
    fn known_suffixes() {
        for real in [
            "http://www.example.com/",
            "http://shop.example.co.uk/",
            "http://example.lt/",
        ] {
            assert!(Url::parse(real).unwrap().has_known_suffix(), "{real}");
        }
        for fake in [
            "http://yarn.lock/",
            "http://package.json/",
            "http://94.75/",
            "http://9.0.5/",
            "http://d.u.k/",
            "http://192.0.2.1/",
            "http://localhost/",
        ] {
            assert!(!Url::parse(fake).unwrap().has_known_suffix(), "{fake}");
        }
    }

    #[test]
    fn redirect_targets() {
        let url = Url::parse(
            "https://redirect.example.net/r?id=7&u=https%3A%2F%2Fevil.example.org%2Flogin",
        )
        .unwrap();
        assert_eq!(url.redirect_target().unwrap().host, "evil.example.org");
        assert!(
            Url::parse("https://example.com/?q=hello")
                .unwrap()
                .redirect_target()
                .is_none()
        );
    }

    #[test]
    fn decoding() {
        assert_eq!(percent_decode("a%20b+c%2"), "a b c%2");
        assert_eq!(percent_decode("%zz"), "%zz");
    }
}
