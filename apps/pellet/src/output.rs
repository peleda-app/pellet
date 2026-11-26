use std::fmt::Write;

use pellet_core::{FailureReason, Verdict};

/// A verdict for people: the action and score, then one line per symbol, then failures.
pub fn text(verdict: &Verdict, with_headers: bool) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "action: {}  score: {:.2}  stage: {}",
        verdict.action, verdict.score, verdict.stage
    );
    let width = verdict
        .symbols
        .iter()
        .map(|s| s.name.as_str().len())
        .max()
        .unwrap_or(0);
    for symbol in &verdict.symbols {
        let _ = write!(
            out,
            "  {:<width$}  {:>7.2}  {}",
            symbol.name.as_str(),
            symbol.score,
            symbol.stage
        );
        if !symbol.options.is_empty() {
            let _ = write!(out, "  [{}]", symbol.options.join(", "));
        }
        out.push('\n');
    }
    if !verdict.failures.is_empty() {
        out.push_str("failures:\n");
        for failure in &verdict.failures {
            let reason = match &failure.reason {
                FailureReason::Deadline => "missed the deadline".to_string(),
                FailureReason::Error(e) => e.clone(),
                FailureReason::Undeclared(name) => format!("emitted undeclared {name}"),
            };
            let _ = writeln!(out, "  {} ({}): {reason}", failure.check, failure.stage);
        }
    }
    if with_headers {
        for (name, value) in pellet_engine::headers(verdict) {
            let _ = writeln!(out, "{name}: {value}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use pellet_core::{Action, Failure, ScoredSymbol, Stage, SymbolName};

    use super::*;

    #[test]
    fn lists_symbols_failures_and_headers() {
        let verdict = Verdict {
            stage: Stage::Data,
            score: 3.5,
            action: Action::Accept,
            symbols: vec![
                ScoredSymbol {
                    name: SymbolName::new("MISSING_MID").unwrap(),
                    score: 2.5,
                    stage: Stage::Data,
                    options: vec![],
                },
                ScoredSymbol {
                    name: SymbolName::new("RBL").unwrap(),
                    score: 1.0,
                    stage: Stage::Connect,
                    options: vec!["zone.example".into()],
                },
            ],
            failures: vec![Failure {
                check: "slow".into(),
                stage: Stage::Data,
                reason: FailureReason::Deadline,
            }],
        };
        assert_eq!(
            text(&verdict, true),
            "action: accept  score: 3.50  stage: data\n\
             \x20 MISSING_MID     2.50  data\n\
             \x20 RBL             1.00  connect  [zone.example]\n\
             failures:\n\
             \x20 slow (data): missed the deadline\n\
             X-Spam-Score: 3.50\n\
             X-Spam-Action: accept\n\
             X-Spam-Symbols: MISSING_MID(2.50), RBL(1.00)[zone.example]\n"
        );
    }
}
