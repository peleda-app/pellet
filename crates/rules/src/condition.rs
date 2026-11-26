use crate::{
    expr::{Env, Expr, ParseError},
    value::Value,
};

/// An ordered list of `if`/`then` clauses with an optional `else`, as written in rule data:
///
/// ```toml
/// condition = [ { if = "contains(subject, '!')", then = "'SUBJECT_HAS_EXCLAIM'" },
///               { else = false } ]
/// ```
///
/// The first clause whose `if` is truthy decides; its `then` is the result. Without a match the
/// `else` value is the result, or `null`. A plain string or boolean is a condition with only an
/// `else`.
#[derive(Debug, Clone, PartialEq)]
pub struct Condition {
    clauses: Vec<(Expr, Expr)>,
    otherwise: Expr,
}

/// A condition in rule data could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConditionError {
    /// An expression does not parse.
    #[error("{part}: {source}")]
    Parse {
        /// Which part: `if #1`, `then #2`, `else`.
        part: String,
        /// The syntax error.
        source: ParseError,
    },
    /// The TOML value is not a string, boolean or list of clause tables.
    #[error("{0}")]
    Shape(String),
}

fn expr_from(value: &toml::Value, part: &str) -> Result<Expr, ConditionError> {
    match value {
        toml::Value::String(s) => Expr::parse(s).map_err(|source| ConditionError::Parse {
            part: part.to_string(),
            source,
        }),
        toml::Value::Boolean(b) => Ok(Expr::constant(Value::Bool(*b))),
        toml::Value::Integer(i) => Ok(Expr::constant(Value::Int(*i))),
        other => Err(ConditionError::Shape(format!(
            "{part} must be an expression string or a boolean, not {}",
            other.type_str()
        ))),
    }
}

impl Condition {
    /// Reads a condition from its TOML value.
    pub fn from_toml(value: &toml::Value) -> Result<Self, ConditionError> {
        let toml::Value::Array(entries) = value else {
            return Ok(Condition {
                clauses: Vec::new(),
                otherwise: expr_from(value, "else")?,
            });
        };
        let mut clauses = Vec::new();
        let mut otherwise = None;
        for (i, entry) in entries.iter().enumerate() {
            let toml::Value::Table(table) = entry else {
                return Err(ConditionError::Shape(format!(
                    "clause {} is not a table",
                    i + 1
                )));
            };
            if otherwise.is_some() {
                return Err(ConditionError::Shape("a clause follows `else`".into()));
            }
            match (table.get("if"), table.get("then"), table.get("else")) {
                (Some(cond), Some(then), None) if table.len() == 2 => clauses.push((
                    expr_from(cond, &format!("if #{}", i + 1))?,
                    expr_from(then, &format!("then #{}", i + 1))?,
                )),
                (None, None, Some(value)) if table.len() == 1 => {
                    otherwise = Some(expr_from(value, "else")?)
                }
                _ => {
                    return Err(ConditionError::Shape(format!(
                        "clause {} needs `if` and `then`, or only `else`",
                        i + 1
                    )));
                }
            }
        }
        Ok(Condition {
            clauses,
            otherwise: otherwise.unwrap_or_else(|| Expr::constant(Value::Null)),
        })
    }

    /// The result of the first matching clause, or of `else`.
    pub fn eval(&self, env: &dyn Env) -> Value {
        self.clauses
            .iter()
            .find(|(cond, _)| cond.eval(env).truthy())
            .map_or_else(|| self.otherwise.eval(env), |(_, then)| then.eval(env))
    }

    /// Every expression, `if` and `then` alike, for static checks.
    pub fn exprs(&self) -> impl Iterator<Item = &Expr> {
        self.clauses
            .iter()
            .flat_map(|(a, b)| [a, b])
            .chain(std::iter::once(&self.otherwise))
    }

    /// The `then` and `else` expressions: the ones whose result is used.
    pub fn results(&self) -> impl Iterator<Item = &Expr> {
        self.clauses
            .iter()
            .map(|(_, then)| then)
            .chain(std::iter::once(&self.otherwise))
    }
}
