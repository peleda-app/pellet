use std::fmt::Write;

use pellet_core::Verdict;

/// `X-Spam-Score`, `X-Spam-Action` and `X-Spam-Symbols` header fields for a verdict.
///
/// Values are single-line printable ASCII; anything else in symbol options becomes `?`. Symbols
/// keep the verdict's order: `NAME(score)` with options in brackets.
pub fn headers(verdict: &Verdict) -> Vec<(&'static str, String)> {
    let mut symbols = String::new();
    for (i, symbol) in verdict.symbols.iter().enumerate() {
        if i > 0 {
            symbols.push_str(", ");
        }
        let _ = write!(symbols, "{}({:.2})", symbol.name, symbol.score);
        if !symbol.options.is_empty() {
            symbols.push('[');
            for (j, option) in symbol.options.iter().enumerate() {
                if j > 0 {
                    symbols.push(',');
                }
                symbols.extend(option.chars().map(|c| match c {
                    ' '..='~' if !matches!(c, ',' | '[' | ']') => c,
                    _ => '?',
                }));
            }
            symbols.push(']');
        }
    }
    vec![
        ("X-Spam-Score", format!("{:.2}", verdict.score)),
        ("X-Spam-Action", verdict.action.to_string()),
        ("X-Spam-Symbols", symbols),
    ]
}
