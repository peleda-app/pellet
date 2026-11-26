use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// What the SMTP conversation has revealed about a message so far.
///
/// Fields fill in as stages pass; a field that is `None` was not known at that stage or the host
/// does not know it. `mail_from` is `Some("")` for the null reverse path (`MAIL FROM:<>`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Envelope {
    /// The connecting client's address, after any PROXY protocol header.
    pub client_ip: Option<IpAddr>,
    /// The client's reverse DNS name, as the host resolved and confirmed it.
    pub client_ptr: Option<String>,
    /// The `HELO`/`EHLO` argument.
    pub helo: Option<String>,
    /// The `MAIL FROM` address without angle brackets.
    pub mail_from: Option<String>,
    /// Every `RCPT TO` address accepted so far, in order.
    pub recipients: Vec<String>,
    /// Whether the session runs over TLS.
    pub tls: bool,
    /// Whether the client authenticated (submission rather than inbound mail).
    pub authenticated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_fields_deserialize_to_defaults() {
        let envelope: Envelope =
            serde_json::from_str(r#"{"client_ip":"192.0.2.7","mail_from":""}"#).unwrap();
        assert_eq!(envelope.client_ip, Some("192.0.2.7".parse().unwrap()));
        assert_eq!(envelope.mail_from.as_deref(), Some(""));
        assert!(envelope.recipients.is_empty());
        assert!(!envelope.tls);
    }
}
