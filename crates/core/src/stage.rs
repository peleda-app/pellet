use std::fmt;

use serde::{Deserialize, Serialize};

/// A point in the SMTP conversation at which checks run.
///
/// Stages are ordered as they happen: `Connect < Helo < Mail < Rcpt < Data`. A host that only has
/// the finished message runs every stage, in this order, on one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stage {
    /// The client connected; its IP address and reverse DNS are known.
    Connect,
    /// The client sent `HELO` or `EHLO`.
    Helo,
    /// The client sent `MAIL FROM`.
    Mail,
    /// The client sent a `RCPT TO`; the envelope holds every recipient accepted so far.
    Rcpt,
    /// The client sent the message.
    Data,
}

impl Stage {
    /// Every stage in conversation order.
    pub const ALL: [Stage; 5] = [
        Stage::Connect,
        Stage::Helo,
        Stage::Mail,
        Stage::Rcpt,
        Stage::Data,
    ];

    /// The lowercase name used in configuration and output.
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Connect => "connect",
            Stage::Helo => "helo",
            Stage::Mail => "mail",
            Stage::Rcpt => "rcpt",
            Stage::Data => "data",
        }
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_is_in_conversation_order() {
        let mut sorted = Stage::ALL;
        sorted.sort();
        assert_eq!(sorted, Stage::ALL);
    }

    #[test]
    fn serializes_lowercase() {
        assert_eq!(serde_json::to_string(&Stage::Rcpt).unwrap(), "\"rcpt\"");
        assert_eq!(Stage::Data.to_string(), "data");
    }
}
