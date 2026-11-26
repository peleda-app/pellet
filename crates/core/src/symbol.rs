use std::{fmt, str::FromStr, sync::Arc};

use serde::{Deserialize, Serialize};

use crate::CoreError;

/// Longest accepted symbol name, in bytes.
pub const MAX_SYMBOL_LEN: usize = 64;
/// Most options a symbol keeps; later ones are dropped.
pub const MAX_OPTIONS: usize = 8;
/// Longest option kept, in bytes; longer options are cut at a character boundary.
pub const MAX_OPTION_LEN: usize = 128;

/// The name of a symbol, such as `DMARC_POLICY_REJECT`.
///
/// Guaranteed to be 1 to [`MAX_SYMBOL_LEN`] bytes of `A-Z`, `0-9` and `_`, starting with a letter.
/// Cheap to clone.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SymbolName(Arc<str>);

impl SymbolName {
    /// Validates a name.
    pub fn new(name: &str) -> Result<Self, CoreError> {
        let valid = !name.is_empty()
            && name.len() <= MAX_SYMBOL_LEN
            && name.starts_with(|c: char| c.is_ascii_uppercase())
            && name
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
        if valid {
            Ok(SymbolName(name.into()))
        } else {
            Err(CoreError::InvalidSymbolName(
                name.chars().take(80).collect(),
            ))
        }
    }

    /// The name as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SymbolName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SymbolName {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SymbolName::new(s)
    }
}

impl TryFrom<String> for SymbolName {
    type Error = CoreError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        SymbolName::new(&value)
    }
}

impl From<SymbolName> for String {
    fn from(value: SymbolName) -> Self {
        value.0.to_string()
    }
}

/// A symbol a check emitted: a name and optional short options, without a score.
///
/// Options name what triggered the symbol (a domain, a list zone), never message content.
/// At most [`MAX_OPTIONS`] options of at most [`MAX_OPTION_LEN`] bytes are kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Symbol {
    /// The symbol's name.
    pub name: SymbolName,
    /// What triggered it, in the order the check added them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
}

impl Symbol {
    /// A symbol without options.
    pub fn new(name: SymbolName) -> Self {
        Symbol {
            name,
            options: Vec::new(),
        }
    }

    /// Adds an option, cut to [`MAX_OPTION_LEN`] bytes; ignored once [`MAX_OPTIONS`] are present.
    pub fn with_option(mut self, option: impl Into<String>) -> Self {
        self.push_option(option);
        self
    }

    /// Same as [`Symbol::with_option`] on a borrowed symbol.
    pub fn push_option(&mut self, option: impl Into<String>) {
        if self.options.len() >= MAX_OPTIONS {
            return;
        }
        let mut option = option.into();
        if option.len() > MAX_OPTION_LEN {
            let mut end = MAX_OPTION_LEN;
            while !option.is_char_boundary(end) {
                end -= 1;
            }
            option.truncate(end);
        }
        self.options.push(option);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> SymbolName {
        SymbolName::new(s).unwrap()
    }

    #[test]
    fn accepts_upper_snake_case() {
        assert_eq!(name("DMARC_POLICY_REJECT").as_str(), "DMARC_POLICY_REJECT");
        assert_eq!(name("R2").as_str(), "R2");
    }

    #[test]
    fn refuses_bad_names() {
        for bad in [
            "",
            "lower",
            "_LEADING",
            "9START",
            "HAS SPACE",
            "DASH-ED",
            "ÜBER",
        ] {
            assert!(SymbolName::new(bad).is_err(), "{bad:?}");
        }
        assert!(SymbolName::new(&"A".repeat(MAX_SYMBOL_LEN)).is_ok());
        assert!(SymbolName::new(&"A".repeat(MAX_SYMBOL_LEN + 1)).is_err());
    }

    #[test]
    fn deserialization_validates() {
        assert!(serde_json::from_str::<SymbolName>("\"OK_NAME\"").is_ok());
        assert!(serde_json::from_str::<SymbolName>("\"bad\"").is_err());
    }

    #[test]
    fn options_are_capped() {
        let mut symbol = Symbol::new(name("X"));
        for i in 0..MAX_OPTIONS + 3 {
            symbol.push_option(format!("o{i}"));
        }
        assert_eq!(symbol.options.len(), MAX_OPTIONS);
        assert_eq!(symbol.options[0], "o0");
    }

    #[test]
    fn long_options_are_cut_on_a_char_boundary() {
        let symbol = Symbol::new(name("X")).with_option("é".repeat(MAX_OPTION_LEN));
        let option = &symbol.options[0];
        assert!(option.len() <= MAX_OPTION_LEN);
        assert!(option.chars().all(|c| c == 'é'));
    }
}
