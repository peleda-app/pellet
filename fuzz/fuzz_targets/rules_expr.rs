#![no_main]

use libfuzzer_sys::fuzz_target;
use pellet_rules::Expr;

fuzz_target!(|data: &[u8]| {
    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(expr) = Expr::parse(source) {
        let _ = expr.variables();
        let _ = expr.symbols();
        let _ = expr.string_literals();
        let _ = expr.lists();
    }
});
