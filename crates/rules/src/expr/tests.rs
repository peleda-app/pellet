use std::collections::{BTreeMap, HashMap, HashSet};

use super::*;

#[derive(Default)]
struct TestEnv {
    vars: HashMap<String, Value>,
    symbols: HashSet<String>,
    lists: HashMap<String, HashSet<String>>,
}

impl TestEnv {
    fn new() -> Self {
        let mut from = BTreeMap::new();
        from.insert("local".to_string(), Value::from("ana"));
        from.insert("domain".to_string(), Value::from("example.com"));
        from.insert("name".to_string(), Value::from("Dr. Ana  Lind"));
        let mut env = TestEnv::default();
        env.vars.insert("from".into(), Value::Map(from));
        env.vars
            .insert("subject".into(), Value::from("Re: Lunch today?"));
        env.vars
            .insert("octets".into(), Value::from(vec![127i64, 0, 0, 18]));
        env.vars.insert("location".into(), Value::from("tcp"));
        env.symbols.insert("DMARC_POLICY_ALLOW".into());
        env.lists.insert(
            "trusted-domains".into(),
            ["example.com".to_string()].into_iter().collect(),
        );
        env
    }
}

impl Env for TestEnv {
    fn var(&self, name: &str) -> Value {
        self.vars.get(name).cloned().unwrap_or_default()
    }

    fn symbol(&self, name: &str) -> bool {
        self.symbols.contains(name)
    }

    fn list_contains(&self, list: &str, key: &str) -> bool {
        self.lists.get(list).is_some_and(|l| l.contains(key))
    }
}

fn eval(source: &str) -> Value {
    Expr::parse(source)
        .unwrap_or_else(|e| panic!("{source}: {e}"))
        .eval(&TestEnv::new())
}

#[test]
fn literals_and_arithmetic() {
    assert_eq!(eval("'a\\'b'"), Value::from("a'b"));
    assert_eq!(eval("1 + 2 * 3"), Value::Int(7));
    assert_eq!(eval("(1 + 2) * 3"), Value::Int(9));
    assert_eq!(eval("7 / 2"), Value::Float(3.5));
    assert_eq!(eval("1 / 0"), Value::Null);
    assert_eq!(eval("-3 + 1"), Value::Int(-2));
    assert_eq!(eval("1.5 + 1"), Value::Float(2.5));
    assert_eq!(eval("'FREEMAIL_' + 'FROM'"), Value::from("FREEMAIL_FROM"));
    assert_eq!(eval("'n' + 5"), Value::from("n5"));
    assert_eq!(eval("[1, 2] + [3]"), Value::from(vec![1i64, 2, 3]));
}

#[test]
fn comparisons_and_logic() {
    assert_eq!(
        eval("2 >= 2 && 3 > 2 && 1 < 2 && 2 <= 3"),
        Value::Bool(true)
    );
    assert_eq!(eval("1 == 1.0"), Value::Bool(true));
    assert_eq!(eval("'1' == 1"), Value::Bool(false));
    assert_eq!(eval("'a' != 'b'"), Value::Bool(true));
    assert_eq!(eval("'a' < 'b'"), Value::Bool(true));
    assert_eq!(eval("'a' < 1"), Value::Bool(false));
    assert_eq!(eval("!false || missing"), Value::Bool(true));
    assert_eq!(eval("false && missing"), Value::Bool(false));
    assert_eq!(
        eval("1 == 1 || 2 == 3 && false"),
        Value::Bool(true),
        "&& binds tighter"
    );
}

#[test]
fn variables_fields_indexes_and_symbols() {
    assert_eq!(eval("from.local"), Value::from("ana"));
    assert_eq!(eval("from.missing"), Value::Null);
    assert_eq!(eval("unknown.field"), Value::Null);
    assert_eq!(eval("octets[3]"), Value::Int(18));
    assert_eq!(eval("octets[9]"), Value::Null);
    assert_eq!(eval("octets[-1]"), Value::Null);
    assert_eq!(eval("$DMARC_POLICY_ALLOW && !$SPF_FAIL"), Value::Bool(true));
    assert_eq!(eval("contains(subject.words, 'Lunch')"), Value::Bool(true));
}

#[test]
fn functions() {
    let truthy = [
        "contains(subject, 'Lunch')",
        "contains(['to', 'cc'], 'cc')",
        "contains_ignore_case(subject, 'LUNCH')",
        "contains_ignore_case(['RE', 'AW'], 're')",
        "starts_with(from.domain, 'example')",
        "ends_with(subject, '?')",
        "is_empty('')",
        "is_empty([])",
        "is_empty(missing)",
        "key_exists('trusted-domains', 'EXAMPLE.com')",
        "is_intersect(['dr.', 'mr.'], split(to_lowercase(from.name), ' '))",
        "trim('  x  ') == 'x'",
        "to_uppercase('to') == 'TO'",
        "split_once(subject, ':')[0] == 'Re'",
        "split_once('none', ':')[0] == 'none'",
        "len(subject) == 16",
        "len(['a']) == 1",
        "has_digits('v2')",
        "bit_and(octets[3], 16) != 0",
        "if_then(location == 'tcp', 'RBL_X', 'RECEIVED_X') == 'RBL_X'",
        "contains(from.name, '  ')",
    ];
    for source in truthy {
        assert!(eval(source).truthy(), "{source}");
    }
    let falsy = [
        "contains(missing, 'x')",
        "contains(subject, 1)",
        "starts_with(1, 'x')",
        "key_exists('trusted-domains', '')",
        "key_exists('no-such-list', 'example.com')",
        "is_empty('x')",
        "has_digits('none')",
        "is_intersect('a', ['a'])",
    ];
    for source in falsy {
        assert!(!eval(source).truthy(), "{source}");
    }
    assert_eq!(eval("trim(1)"), Value::Null);
    assert_eq!(
        eval("hash('abc', 'md5')"),
        Value::from("900150983cd24fb0d6963f7d28e17f72")
    );
    assert_eq!(
        eval("hash('abc', 'sha1')"),
        Value::from("a9993e364706816aba3e25717850c26c9cd0d89d")
    );
    assert_eq!(eval("hash('abc', 'crc32')"), Value::Null);
    assert_eq!(eval("hash(1, 'md5')"), Value::Null);
}

#[test]
fn syntax_errors_name_the_place() {
    for (source, message) in [
        ("contains(subject", "expected `,`"),
        ("(1 + 2", "expected `)`"),
        ("1 +", "unexpected end"),
        ("'open", "unterminated string"),
        ("nope(1)", "unknown function `nope`"),
        ("trim(1, 2)", "`trim` takes 1 arguments, got 2"),
        ("a b", "unexpected"),
        ("$", "`$` without a symbol name"),
        ("from.", "expected a field name"),
        ("#", "unexpected character"),
    ] {
        let error = Expr::parse(source).unwrap_err();
        assert!(error.message.contains(message), "{source}: {error}");
    }
}

#[test]
fn analysis() {
    let expr = Expr::parse(
        "key_exists('trusted-domains', from.domain) && $DMARC_POLICY_ALLOW && contains(subject, 'x') && !$X",
    )
    .unwrap();
    assert_eq!(
        expr.variables(),
        ["from", "subject"].map(String::from).into()
    );
    assert_eq!(
        expr.symbols(),
        ["DMARC_POLICY_ALLOW", "X"].map(String::from).into()
    );
    assert_eq!(expr.lists(), ["trusted-domains"].map(String::from).into());
    assert_eq!(expr.string_literals(), ["trusted-domains", "x"]);
}

#[test]
fn backslash_before_a_multibyte_char_does_not_panic() {
    assert_eq!(eval("'a\\ܡb'"), Value::from("aܡb"));
    assert_eq!(eval("'\\é'"), Value::from("é"));
    let crash = "'T\\\\\\-t>=-0-0*2-0_\\\\\\ܡ*2\n";
    assert!(Expr::parse(crash).is_err());
}
