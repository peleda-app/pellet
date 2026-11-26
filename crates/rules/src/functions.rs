use md5::Digest;

use crate::{expr::Env, value::Value};

/// Every function the language knows, with its number of arguments.
pub const FUNCTIONS: [(&str, usize); 17] = [
    ("contains", 2),
    ("contains_ignore_case", 2),
    ("starts_with", 2),
    ("ends_with", 2),
    ("is_empty", 1),
    ("key_exists", 2),
    ("if_then", 3),
    ("is_intersect", 2),
    ("trim", 1),
    ("to_lowercase", 1),
    ("to_uppercase", 1),
    ("split", 2),
    ("split_once", 2),
    ("len", 1),
    ("has_digits", 1),
    ("bit_and", 2),
    ("hash", 2),
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn arity(name: &str) -> Option<usize> {
    FUNCTIONS.iter().find(|(n, _)| *n == name).map(|(_, a)| *a)
}

fn text(value: &Value) -> Option<&str> {
    value.as_str()
}

fn strings_equal_ignore_case(a: &Value, b: &Value) -> bool {
    match (a.as_str(), b.as_str()) {
        (Some(x), Some(y)) => x.eq_ignore_ascii_case(y),
        _ => a.loose_eq(b),
    }
}

pub(crate) fn call(name: &str, args: &[Value], env: &dyn Env) -> Value {
    match (name, args) {
        ("contains", [haystack, needle]) => Value::Bool(match haystack {
            Value::Str(s) => needle.as_str().is_some_and(|n| s.contains(n)),
            Value::List(items) => items.iter().any(|i| i.loose_eq(needle)),
            _ => false,
        }),
        ("contains_ignore_case", [haystack, needle]) => Value::Bool(match haystack {
            Value::Str(s) => needle
                .as_str()
                .is_some_and(|n| s.to_lowercase().contains(&n.to_lowercase())),
            Value::List(items) => items.iter().any(|i| strings_equal_ignore_case(i, needle)),
            _ => false,
        }),
        ("starts_with", [s, p]) => Value::Bool(match (text(s), text(p)) {
            (Some(s), Some(p)) => s.starts_with(p),
            _ => false,
        }),
        ("ends_with", [s, p]) => Value::Bool(match (text(s), text(p)) {
            (Some(s), Some(p)) => s.ends_with(p),
            _ => false,
        }),
        ("is_empty", [v]) => Value::Bool(
            !v.truthy() && !matches!(v, Value::Bool(_) | Value::Int(_) | Value::Float(_)),
        ),
        ("key_exists", [list, key]) => Value::Bool(match list.as_str() {
            Some(list) => {
                let key = key.to_string();
                !key.is_empty() && env.list_contains(list, &key.to_lowercase())
            }
            None => false,
        }),
        ("is_intersect", [Value::List(a), Value::List(b)]) => {
            Value::Bool(a.iter().any(|x| b.iter().any(|y| x.loose_eq(y))))
        }
        ("trim", [Value::Str(s)]) => Value::Str(s.trim().to_string()),
        ("to_lowercase", [Value::Str(s)]) => Value::Str(s.to_lowercase()),
        ("to_uppercase", [Value::Str(s)]) => Value::Str(s.to_uppercase()),
        ("split", [Value::Str(s), Value::Str(sep)]) if !sep.is_empty() => {
            Value::List(s.split(sep.as_str()).map(Value::from).collect())
        }
        ("split_once", [Value::Str(s), Value::Str(sep)]) if !sep.is_empty() => {
            match s.split_once(sep.as_str()) {
                Some((a, b)) => Value::from(vec![a, b]),
                None => Value::from(vec![s.as_str()]),
            }
        }
        ("len", [Value::Str(s)]) => Value::Int(s.chars().count() as i64),
        ("len", [Value::List(items)]) => Value::Int(items.len() as i64),
        ("len", [_]) => Value::Int(0),
        ("has_digits", [Value::Str(s)]) => Value::Bool(s.chars().any(|c| c.is_ascii_digit())),
        ("hash", [Value::Str(s), Value::Str(algorithm)]) => match algorithm.as_str() {
            "md5" => Value::Str(hex(&md5::Md5::digest(s.as_bytes()))),
            "sha1" => Value::Str(hex(&sha1::Sha1::digest(s.as_bytes()))),
            _ => Value::Null,
        },
        ("bit_and", [a, b]) => match (a.as_i64(), b.as_i64()) {
            (Some(a), Some(b)) => Value::Int(a & b),
            _ => Value::Null,
        },
        _ => Value::Null,
    }
}
