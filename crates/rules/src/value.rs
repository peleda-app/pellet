use std::{cmp::Ordering, collections::BTreeMap, fmt};

/// A value in the expression language.
///
/// Evaluation never fails: an operation on the wrong kind of value yields [`Value::Null`], which
/// is falsy.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum Value {
    /// Nothing; also the result of every type mismatch.
    #[default]
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A whole number.
    Int(i64),
    /// A floating point number.
    Float(f64),
    /// Text.
    Str(String),
    /// An ordered list.
    List(Vec<Value>),
    /// Named fields, such as an address with `name`, `local` and `domain`.
    Map(BTreeMap<String, Value>),
}

impl Value {
    /// Truthiness: `null`, `false`, `0`, `0.0`, `""`, `[]` and an empty map are false.
    pub fn truthy(&self) -> bool {
        match self {
            Value::Null => false,
            Value::Bool(b) => *b,
            Value::Int(i) => *i != 0,
            Value::Float(f) => *f != 0.0,
            Value::Str(s) => !s.is_empty(),
            Value::List(l) => !l.is_empty(),
            Value::Map(m) => !m.is_empty(),
        }
    }

    /// The text of a string, `None` for anything else.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Int(i) => Some(*i as f64),
            Value::Float(f) => Some(*f),
            _ => None,
        }
    }

    pub(crate) fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            Value::Float(f) if f.fract() == 0.0 => Some(*f as i64),
            _ => None,
        }
    }

    /// Equality across kinds: numbers compare by value, everything else only with its own kind.
    pub(crate) fn loose_eq(&self, other: &Value) -> bool {
        match (self.as_f64(), other.as_f64()) {
            (Some(a), Some(b)) => a == b,
            _ => self == other,
        }
    }

    pub(crate) fn compare(&self, other: &Value) -> Option<Ordering> {
        match (self, other) {
            (Value::Str(a), Value::Str(b)) => Some(a.cmp(b)),
            _ => self.as_f64()?.partial_cmp(&other.as_f64()?),
        }
    }

    /// A string from a map field, a string, or nothing.
    pub fn field(&self, name: &str) -> Value {
        match self {
            Value::Map(fields) => fields.get(name).cloned().unwrap_or_default(),
            Value::Str(s) if name == "words" => Value::List(
                s.split(|c: char| !c.is_alphanumeric())
                    .filter(|w| !w.is_empty())
                    .map(|w| Value::Str(w.to_string()))
                    .collect(),
            ),
            _ => Value::Null,
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Null => Ok(()),
            Value::Bool(b) => write!(f, "{b}"),
            Value::Int(i) => write!(f, "{i}"),
            Value::Float(x) => write!(f, "{x}"),
            Value::Str(s) => f.write_str(s),
            Value::List(items) => {
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    write!(f, "{item}")?;
                }
                Ok(())
            }
            Value::Map(_) => Ok(()),
        }
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::Str(s.to_string())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::Str(s)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

impl From<i64> for Value {
    fn from(i: i64) -> Self {
        Value::Int(i)
    }
}

impl<T: Into<Value>> From<Vec<T>> for Value {
    fn from(items: Vec<T>) -> Self {
        Value::List(items.into_iter().map(Into::into).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truthiness() {
        for falsy in [
            Value::Null,
            Value::Bool(false),
            Value::Int(0),
            Value::Float(0.0),
            Value::from(""),
            Value::List(vec![]),
            Value::Map(BTreeMap::new()),
        ] {
            assert!(!falsy.truthy(), "{falsy:?}");
        }
        assert!(Value::from("x").truthy());
        assert!(Value::Int(-1).truthy());
    }

    #[test]
    fn numbers_compare_across_kinds() {
        assert!(Value::Int(2).loose_eq(&Value::Float(2.0)));
        assert!(!Value::Int(2).loose_eq(&Value::from("2")));
        assert_eq!(
            Value::Int(1).compare(&Value::Float(1.5)),
            Some(Ordering::Less)
        );
        assert_eq!(
            Value::from("a").compare(&Value::from("b")),
            Some(Ordering::Less)
        );
        assert_eq!(Value::from("a").compare(&Value::Int(1)), None);
    }

    #[test]
    fn fields_and_words() {
        let mut fields = BTreeMap::new();
        fields.insert("local".to_string(), Value::from("ana"));
        let map = Value::Map(fields);
        assert_eq!(map.field("local"), Value::from("ana"));
        assert_eq!(map.field("missing"), Value::Null);
        assert_eq!(
            Value::from("Buy SEO, now!").field("words"),
            Value::from(vec!["Buy", "SEO", "now"])
        );
        assert_eq!(Value::Int(1).field("x"), Value::Null);
    }
}
