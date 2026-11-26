use async_trait::async_trait;
use pellet_check::{Check, CheckError, Context};
use pellet_core::{Stage, Symbol, SymbolName};

/// `X_HDR_<NAME>` when a header field is present, at [`Stage::Data`], for a fixed set of
/// field names.
///
/// The symbol for `List-Unsubscribe` is `X_HDR_LIST_UNSUBSCRIBE`: the name uppercased with `-`
/// turned into `_`. Built from field names, or from the `X_HDR_*` symbols the rules reference.
pub struct HeaderPresenceCheck {
    fields: Vec<(String, SymbolName)>,
    declared: Vec<SymbolName>,
}

impl HeaderPresenceCheck {
    /// Watches these field names; names that cannot form a symbol are skipped.
    pub fn new<S: AsRef<str>>(fields: impl IntoIterator<Item = S>) -> Self {
        let mut pairs: Vec<(String, SymbolName)> = fields
            .into_iter()
            .filter_map(|field| {
                let field = field.as_ref().trim().to_ascii_lowercase();
                let symbol = format!("X_HDR_{}", field.to_ascii_uppercase().replace('-', "_"));
                Some((field, SymbolName::new(&symbol).ok()?))
            })
            .collect();
        pairs.sort_by(|a, b| a.1.cmp(&b.1));
        pairs.dedup_by(|a, b| a.1 == b.1);
        let declared = pairs.iter().map(|(_, s)| s.clone()).collect();
        HeaderPresenceCheck {
            fields: pairs,
            declared,
        }
    }

    /// Watches the field behind every `X_HDR_*` symbol given; other symbols are ignored.
    pub fn from_symbols<S: AsRef<str>>(symbols: impl IntoIterator<Item = S>) -> Self {
        Self::new(symbols.into_iter().filter_map(|s| {
            s.as_ref()
                .strip_prefix("X_HDR_")
                .filter(|rest| !rest.is_empty())
                .map(|rest| rest.replace('_', "-"))
        }))
    }
}

#[async_trait]
impl Check for HeaderPresenceCheck {
    fn name(&self) -> &str {
        "content.presence"
    }

    fn stage(&self) -> Stage {
        Stage::Data
    }

    fn symbols(&self) -> &[SymbolName] {
        &self.declared
    }

    async fn run(&self, ctx: &Context<'_>) -> Result<Vec<Symbol>, CheckError> {
        let message = ctx
            .message
            .ok_or_else(|| CheckError::Failed("no message at the data stage".into()))?;
        Ok(self
            .fields
            .iter()
            .filter(|(field, _)| message.header(field).is_some())
            .map(|(_, symbol)| Symbol::new(symbol.clone()))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use pellet_check::testing::{Fixture, conformance};

    use super::*;

    #[tokio::test]
    async fn emits_one_symbol_per_present_field() {
        let check = HeaderPresenceCheck::from_symbols([
            "X_HDR_LIST_UNSUBSCRIBE",
            "X_HDR_X_MAILER",
            "OTHER",
            "X_HDR_",
        ]);
        assert_eq!(check.symbols().len(), 2);
        let fixture =
            Fixture::message("List-Unsubscribe: <mailto:u@example.com>\r\nSubject: x\r\n\r\n");
        let names: Vec<String> = check
            .run(&fixture.context(Stage::Data))
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.name.to_string())
            .collect();
        assert_eq!(names, ["X_HDR_LIST_UNSUBSCRIBE"]);
    }

    #[test]
    fn field_names_map_to_symbols() {
        let check = HeaderPresenceCheck::new(["X-PHP-Script", "x-php-script", "bad name!"]);
        let names: Vec<&str> = check.symbols().iter().map(|s| s.as_str()).collect();
        assert_eq!(names, ["X_HDR_X_PHP_SCRIPT"]);
    }

    #[tokio::test]
    async fn passes_conformance() {
        conformance(
            &HeaderPresenceCheck::new(["List-Unsubscribe", "X-Mailer"]),
            &[
                Fixture::message("X-Mailer: a\r\nList-Unsubscribe: b\r\n\r\n"),
                Fixture::message(""),
            ],
        )
        .await;
    }
}
