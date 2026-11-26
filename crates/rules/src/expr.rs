use std::collections::BTreeSet;

use crate::{functions, value::Value};

/// What an expression can read while it is evaluated.
pub trait Env {
    /// A variable such as `subject` or `name_lower`; unknown names are [`Value::Null`].
    fn var(&self, name: &str) -> Value;
    /// Whether a symbol (`$NAME`) has fired so far.
    fn symbol(&self, name: &str) -> bool;
    /// Whether a named list holds a key; `key_exists('trusted-domains', domain)`.
    fn list_contains(&self, list: &str, key: &str) -> bool;
}

/// A syntax error, with the byte offset where it was found.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message} at byte {position}")]
pub struct ParseError {
    /// What is wrong.
    pub message: String,
    /// Byte offset into the expression.
    pub position: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Or,
    And,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Add,
    Sub,
    Mul,
    Div,
    Not,
    Neg,
}

#[derive(Debug, Clone, PartialEq)]
enum Node {
    Lit(Value),
    Var(String),
    Symbol(String),
    List(Vec<Node>),
    Field(Box<Node>, String),
    Index(Box<Node>, Box<Node>),
    Call(String, Vec<Node>),
    Unary(Op, Box<Node>),
    Binary(Op, Box<Node>, Box<Node>),
}

/// A parsed expression.
///
/// Evaluation never fails and never loops: it only reads the [`Env`], and mismatched kinds give
/// [`Value::Null`]. `&&` and `||` short-circuit and return booleans.
#[derive(Debug, Clone, PartialEq)]
pub struct Expr {
    node: Node,
}

impl Expr {
    /// Parses an expression; function names and arities are checked here.
    pub fn parse(source: &str) -> Result<Expr, ParseError> {
        let tokens = lex(source)?;
        let mut parser = Parser {
            tokens,
            pos: 0,
            end: source.len(),
        };
        let node = parser.expr(0)?;
        if let Some((token, at)) = parser.tokens.get(parser.pos) {
            return Err(ParseError {
                message: format!("unexpected {token:?}"),
                position: *at,
            });
        }
        Ok(Expr { node })
    }

    /// An expression that always gives `value`.
    pub fn constant(value: Value) -> Expr {
        Expr {
            node: Node::Lit(value),
        }
    }

    /// Evaluates against an environment.
    pub fn eval(&self, env: &dyn Env) -> Value {
        eval(&self.node, env)
    }

    /// The variables read, without fields: `from.local` reads `from`.
    pub fn variables(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        walk(&self.node, &mut |node| {
            if let Node::Var(name) = node {
                out.insert(name.clone());
            }
        });
        out
    }

    /// The symbols referenced with `$NAME`.
    pub fn symbols(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        walk(&self.node, &mut |node| {
            if let Node::Symbol(name) = node {
                out.insert(name.clone());
            }
        });
        out
    }

    /// Every string literal, in order of appearance.
    pub fn string_literals(&self) -> Vec<String> {
        let mut out = Vec::new();
        walk(&self.node, &mut |node| {
            if let Node::Lit(Value::Str(s)) = node {
                out.push(s.clone());
            }
        });
        out
    }

    /// The names passed as the first argument of `key_exists`, when they are literals.
    pub fn lists(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        walk(&self.node, &mut |node| {
            if let Node::Call(name, args) = node
                && name == "key_exists"
                && let Some(Node::Lit(Value::Str(list))) = args.first()
            {
                out.insert(list.clone());
            }
        });
        out
    }
}

fn walk(node: &Node, f: &mut impl FnMut(&Node)) {
    f(node);
    match node {
        Node::Lit(_) | Node::Var(_) | Node::Symbol(_) => {}
        Node::List(items) | Node::Call(_, items) => items.iter().for_each(|n| walk(n, f)),
        Node::Field(inner, _) | Node::Unary(_, inner) => walk(inner, f),
        Node::Index(a, b) | Node::Binary(_, a, b) => {
            walk(a, f);
            walk(b, f);
        }
    }
}

fn eval(node: &Node, env: &dyn Env) -> Value {
    match node {
        Node::Lit(v) => v.clone(),
        Node::Var(name) => env.var(name),
        Node::Symbol(name) => Value::Bool(env.symbol(name)),
        Node::List(items) => Value::List(items.iter().map(|n| eval(n, env)).collect()),
        Node::Field(inner, name) => eval(inner, env).field(name),
        Node::Index(inner, index) => match (eval(inner, env), eval(index, env).as_i64()) {
            (Value::List(items), Some(i)) if i >= 0 => {
                items.into_iter().nth(i as usize).unwrap_or_default()
            }
            _ => Value::Null,
        },
        Node::Call(name, args) => {
            if name == "if_then" {
                return if eval(&args[0], env).truthy() {
                    eval(&args[1], env)
                } else {
                    eval(&args[2], env)
                };
            }
            let args: Vec<Value> = args.iter().map(|n| eval(n, env)).collect();
            functions::call(name, &args, env)
        }
        Node::Unary(Op::Not, inner) => Value::Bool(!eval(inner, env).truthy()),
        Node::Unary(_, inner) => match eval(inner, env) {
            Value::Int(i) => Value::Int(i.wrapping_neg()),
            Value::Float(f) => Value::Float(-f),
            _ => Value::Null,
        },
        Node::Binary(Op::And, a, b) => Value::Bool(eval(a, env).truthy() && eval(b, env).truthy()),
        Node::Binary(Op::Or, a, b) => Value::Bool(eval(a, env).truthy() || eval(b, env).truthy()),
        Node::Binary(op, a, b) => binary(*op, eval(a, env), eval(b, env)),
    }
}

fn binary(op: Op, a: Value, b: Value) -> Value {
    use std::cmp::Ordering::*;
    match op {
        Op::Eq => Value::Bool(a.loose_eq(&b)),
        Op::Ne => Value::Bool(!a.loose_eq(&b)),
        Op::Lt | Op::Le | Op::Gt | Op::Ge => match a.compare(&b) {
            Some(order) => Value::Bool(match op {
                Op::Lt => order == Less,
                Op::Le => order != Greater,
                Op::Gt => order == Greater,
                _ => order != Less,
            }),
            None => Value::Bool(false),
        },
        Op::Add => match (&a, &b) {
            (Value::Int(x), Value::Int(y)) => Value::Int(x.wrapping_add(*y)),
            (Value::List(x), Value::List(y)) => Value::List(x.iter().chain(y).cloned().collect()),
            (Value::Str(_), _) | (_, Value::Str(_)) => Value::Str(format!("{a}{b}")),
            _ => arithmetic(&a, &b, |x, y| x + y),
        },
        Op::Sub => match (&a, &b) {
            (Value::Int(x), Value::Int(y)) => Value::Int(x.wrapping_sub(*y)),
            _ => arithmetic(&a, &b, |x, y| x - y),
        },
        Op::Mul => match (&a, &b) {
            (Value::Int(x), Value::Int(y)) => Value::Int(x.wrapping_mul(*y)),
            _ => arithmetic(&a, &b, |x, y| x * y),
        },
        Op::Div => match (a.as_f64(), b.as_f64()) {
            (Some(_), Some(0.0)) => Value::Null,
            (Some(x), Some(y)) => Value::Float(x / y),
            _ => Value::Null,
        },
        Op::Or | Op::And | Op::Not | Op::Neg => unreachable!("handled before"),
    }
}

fn arithmetic(a: &Value, b: &Value, f: impl Fn(f64, f64) -> f64) -> Value {
    match (a.as_f64(), b.as_f64()) {
        (Some(x), Some(y)) => Value::Float(f(x, y)),
        _ => Value::Null,
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    Symbol(String),
    Str(String),
    Int(i64),
    Float(f64),
    Punct(&'static str),
}

const PUNCT: [&str; 20] = [
    "&&", "||", "==", "!=", "<=", ">=", "<", ">", "!", "+", "-", "*", "/", "(", ")", "[", "]", ",",
    ".", "$",
];

fn lex(source: &str) -> Result<Vec<(Token, usize)>, ParseError> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    let error = |message: &str, position| ParseError {
        message: message.to_string(),
        position,
    };
    while i < bytes.len() {
        let c = bytes[i];
        let start = i;
        if c.is_ascii_whitespace() {
            i += 1;
        } else if c == b'\'' {
            let mut text = String::new();
            i += 1;
            loop {
                let Some(&b) = bytes.get(i) else {
                    return Err(error("unterminated string", start));
                };
                match b {
                    b'\'' => {
                        i += 1;
                        break;
                    }
                    b'\\' => {
                        let next = source[i + 1..]
                            .chars()
                            .next()
                            .ok_or_else(|| error("unterminated string", start))?;
                        text.push(match next {
                            'n' => '\n',
                            't' => '\t',
                            other => other,
                        });
                        i += 1 + next.len_utf8();
                    }
                    _ => {
                        let ch = source[i..].chars().next().expect("char boundary");
                        text.push(ch);
                        i += ch.len_utf8();
                    }
                }
            }
            tokens.push((Token::Str(text), start));
        } else if c.is_ascii_digit() {
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
            let text = &source[start..i];
            let token = if text.contains('.') {
                Token::Float(text.parse().map_err(|_| error("invalid number", start))?)
            } else {
                Token::Int(text.parse().map_err(|_| error("invalid number", start))?)
            };
            tokens.push((token, start));
        } else if c.is_ascii_alphabetic() || c == b'_' {
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            tokens.push((Token::Ident(source[start..i].to_string()), start));
        } else if c == b'$' {
            i += 1;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            if i == start + 1 {
                return Err(error("`$` without a symbol name", start));
            }
            tokens.push((Token::Symbol(source[start + 1..i].to_string()), start));
        } else if let Some(p) = PUNCT.iter().find(|p| source[i..].starts_with(**p)) {
            i += p.len();
            tokens.push((Token::Punct(p), start));
        } else {
            return Err(error("unexpected character", start));
        }
    }
    Ok(tokens)
}

struct Parser {
    tokens: Vec<(Token, usize)>,
    pos: usize,
    end: usize,
}

fn binary_op(token: &Token) -> Option<(Op, u8)> {
    let Token::Punct(p) = token else { return None };
    Some(match *p {
        "||" => (Op::Or, 1),
        "&&" => (Op::And, 2),
        "==" => (Op::Eq, 3),
        "!=" => (Op::Ne, 3),
        "<" => (Op::Lt, 4),
        "<=" => (Op::Le, 4),
        ">" => (Op::Gt, 4),
        ">=" => (Op::Ge, 4),
        "+" => (Op::Add, 5),
        "-" => (Op::Sub, 5),
        "*" => (Op::Mul, 6),
        "/" => (Op::Div, 6),
        _ => return None,
    })
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos).map(|(t, _)| t)
    }

    fn at(&self) -> usize {
        self.tokens.get(self.pos).map_or(self.end, |(_, at)| *at)
    }

    fn error<T>(&self, message: impl Into<String>) -> Result<T, ParseError> {
        Err(ParseError {
            message: message.into(),
            position: self.at(),
        })
    }

    fn eat(&mut self, punct: &str) -> bool {
        if matches!(self.peek(), Some(Token::Punct(p)) if *p == punct) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, punct: &str) -> Result<(), ParseError> {
        if self.eat(punct) {
            Ok(())
        } else {
            self.error(format!("expected `{punct}`"))
        }
    }

    fn expr(&mut self, min: u8) -> Result<Node, ParseError> {
        let mut left = self.unary()?;
        while let Some((op, precedence)) = self.peek().and_then(binary_op) {
            if precedence <= min {
                break;
            }
            self.pos += 1;
            let right = self.expr(precedence)?;
            left = Node::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Node, ParseError> {
        if self.eat("!") {
            return Ok(Node::Unary(Op::Not, Box::new(self.unary()?)));
        }
        if self.eat("-") {
            return Ok(Node::Unary(Op::Neg, Box::new(self.unary()?)));
        }
        let mut node = self.primary()?;
        loop {
            if self.eat(".") {
                match self.peek().cloned() {
                    Some(Token::Ident(name)) => {
                        self.pos += 1;
                        node = Node::Field(Box::new(node), name);
                    }
                    _ => return self.error("expected a field name"),
                }
            } else if self.eat("[") {
                let index = self.expr(0)?;
                self.expect("]")?;
                node = Node::Index(Box::new(node), Box::new(index));
            } else {
                return Ok(node);
            }
        }
    }

    fn primary(&mut self) -> Result<Node, ParseError> {
        let Some(token) = self.peek().cloned() else {
            return self.error("unexpected end");
        };
        let start = self.at();
        self.pos += 1;
        match token {
            Token::Str(s) => Ok(Node::Lit(Value::Str(s))),
            Token::Int(i) => Ok(Node::Lit(Value::Int(i))),
            Token::Float(f) => Ok(Node::Lit(Value::Float(f))),
            Token::Symbol(name) => Ok(Node::Symbol(name)),
            Token::Ident(name) if name == "true" => Ok(Node::Lit(Value::Bool(true))),
            Token::Ident(name) if name == "false" => Ok(Node::Lit(Value::Bool(false))),
            Token::Ident(name) => {
                if !self.eat("(") {
                    return Ok(Node::Var(name));
                }
                let args = self.items(")")?;
                match functions::arity(&name) {
                    None => Err(ParseError {
                        message: format!("unknown function `{name}`"),
                        position: start,
                    }),
                    Some(n) if n != args.len() => Err(ParseError {
                        message: format!("`{name}` takes {n} arguments, got {}", args.len()),
                        position: start,
                    }),
                    Some(_) => Ok(Node::Call(name, args)),
                }
            }
            Token::Punct("(") => {
                let inner = self.expr(0)?;
                self.expect(")")?;
                Ok(inner)
            }
            Token::Punct("[") => Ok(Node::List(self.items("]")?)),
            other => {
                self.pos -= 1;
                self.error(format!("unexpected {other:?}"))
            }
        }
    }

    fn items(&mut self, close: &str) -> Result<Vec<Node>, ParseError> {
        let mut items = Vec::new();
        if self.eat(close) {
            return Ok(items);
        }
        loop {
            items.push(self.expr(0)?);
            if self.eat(close) {
                return Ok(items);
            }
            self.expect(",")?;
        }
    }
}

#[cfg(test)]
mod tests;
