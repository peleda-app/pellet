//! HTTP API: check a message, report feedback, record sent mail, health; and the rspamd protocol
//! for mail servers that already speak it.
//!
//! `router` builds an axum router to serve on its own or mount in another application.

mod rspamd;

use std::{net::IpAddr, sync::Arc};

use async_trait::async_trait;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, RawQuery, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use pellet_core::{Envelope, Message, Symbol, Verdict};
use pellet_engine::{Engine, headers};
use pellet_urls::percent_decode;
use serde::Serialize;

/// Default largest message accepted, in bytes.
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// How the API is protected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    /// When set, every request but `/health` needs `Authorization: Bearer <token>`.
    pub token: Option<String>,
    /// Largest request body; bigger ones get `413`.
    pub max_message_size: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            token: None,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
        }
    }
}

/// Something that learns from a message a person marked: the classifier, reputation.
#[async_trait]
pub trait Learner: Send + Sync {
    /// A short name reported back to the caller.
    fn name(&self) -> &str;

    /// Learns one message with the symbols the checks gave it (classifier symbols left out).
    async fn learn(&self, message: &Message, envelope: &Envelope, symbols: &[Symbol], spam: bool);
}

/// Something that remembers mail the host sent, so replies to it are recognized.
#[async_trait]
pub trait SentLog: Send + Sync {
    /// Remembers one sent message; `false` when there was nothing to remember (no Message-ID or
    /// no recipient) or it could not be stored.
    async fn record(&self, message: &Message, envelope: &Envelope) -> bool;
}

/// What the API hands feedback and sent mail to; the default has neither.
#[derive(Default, Clone)]
pub struct Hooks {
    /// Learners for `/v1/learn`, `/learnspam` and `/learnham`.
    pub learners: Vec<Arc<dyn Learner>>,
    /// Where `/v1/sent` records sent mail.
    pub sent: Option<Arc<dyn SentLog>>,
}

#[derive(Clone)]
struct AppState {
    engine: Engine,
    learners: Arc<[Arc<dyn Learner>]>,
    sent: Option<Arc<dyn SentLog>>,
    token: Option<Arc<str>>,
}

/// The verdict and the `X-Spam-*` fields to add to the message.
#[derive(Debug, Serialize)]
struct CheckResponse {
    #[serde(flatten)]
    verdict: Verdict,
    headers: Vec<(&'static str, String)>,
}

/// Who learned the message.
#[derive(Debug, Serialize)]
struct LearnResponse {
    learned: Vec<String>,
}

/// Whether a sent message was remembered.
#[derive(Debug, Serialize)]
struct SentResponse {
    recorded: bool,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

fn error(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorBody {
            error: message.into(),
        }),
    )
        .into_response()
}

/// The API.
///
/// | Route | Request | Response |
/// | --- | --- | --- |
/// | `POST /v1/check` | the message as the body; envelope in the query: `ip`, `ptr`, `helo`, `from` (empty for the null sender), `rcpt` (repeat), `tls`, `authenticated` | the verdict as JSON plus `headers`, the `X-Spam-*` fields |
/// | `POST /v1/learn` | the message as the body; `label=spam` or `label=ham` and the same envelope fields | `{"learned": [names]}`, the learners that took it; `404` without learners |
/// | `POST /v1/sent` | a message the host sent as the body; `rcpt` (repeat) for its envelope recipients, else its `To` and `Cc` count | `{"recorded": true or false}`; `404` without a sent log |
/// | `POST /checkv2`, `POST /learnspam`, `POST /learnham`, `GET /ping` | the rspamd protocol, see below | rspamd's JSON |
/// | `GET /health` | | `ok` |
///
/// Unknown query keys and malformed values get `400`, bodies over the limit `413`, a missing or
/// wrong token `401`; `/health` and `/ping` need no token. Responses never hold message content beyond the symbols' options.
///
/// The rspamd routes take the envelope from request headers as rspamd clients send it: `IP`,
/// `Helo`, `From`, `Rcpt` (repeat), `Hostname` (`unknown` means none), `User` (any value means
/// an authenticated client) and `TLS-Version` or `TLS-Cipher`; other headers are ignored. The
/// token may come as `Authorization: Bearer` or as rspamd's `Password` header. `/checkv2`
/// answers with `score`, `required_score` (the reject threshold, else the tag threshold),
/// `action` (`no action`, `add header`, `greylist` or `reject`), `symbols` with their scores and
/// options, and `milter.add_headers` with the `X-Spam-*` fields; compressed bodies get `415`.
pub fn router(engine: Engine, hooks: Hooks, config: ServerConfig) -> Router {
    let state = AppState {
        engine,
        learners: hooks.learners.into(),
        sent: hooks.sent,
        token: config.token.map(Arc::from),
    };
    let api = Router::new()
        .route("/v1/check", post(check))
        .route("/v1/learn", post(learn))
        .route("/v1/sent", post(sent))
        .route("/checkv2", post(rspamd::check))
        .route("/learnspam", post(rspamd::learn_spam))
        .route("/learnham", post(rspamd::learn_ham))
        .route_layer(middleware::from_fn_with_state(state.clone(), authorize))
        .layer(DefaultBodyLimit::max(config.max_message_size));
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/ping", get(|| async { "pong\r\n" }))
        .merge(api)
        .with_state(state)
}

fn equal_in_constant_time(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn authorize(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if let Some(token) = &state.token {
        let headers = request.headers();
        let given = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .or_else(|| headers.get("password").and_then(|v| v.to_str().ok()))
            .unwrap_or_default();
        if !equal_in_constant_time(given.as_bytes(), token.as_bytes()) {
            return error(StatusCode::UNAUTHORIZED, "missing or wrong token");
        }
    }
    next.run(request).await
}

struct Query {
    envelope: Envelope,
    label: Option<String>,
}

fn flag(key: &str, value: &str) -> Result<bool, String> {
    match value {
        "" | "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => Err(format!("{key} must be true or false")),
    }
}

fn parse_query(query: Option<&str>, allow_label: bool) -> Result<Query, String> {
    let mut parsed = Query {
        envelope: Envelope::default(),
        label: None,
    };
    for pair in query
        .unwrap_or_default()
        .split('&')
        .filter(|p| !p.is_empty())
    {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = percent_decode(value);
        let envelope = &mut parsed.envelope;
        match percent_decode(key).as_str() {
            "ip" => {
                envelope.client_ip = Some(
                    value
                        .parse::<IpAddr>()
                        .map_err(|_| "ip must be an IP address".to_string())?,
                )
            }
            "ptr" => envelope.client_ptr = Some(value),
            "helo" => envelope.helo = Some(value),
            "from" => envelope.mail_from = Some(value),
            "rcpt" => envelope.recipients.push(value),
            "tls" => envelope.tls = flag("tls", &value)?,
            "authenticated" => envelope.authenticated = flag("authenticated", &value)?,
            "label" if allow_label => parsed.label = Some(value),
            other => return Err(format!("unknown query parameter {other:?}")),
        }
    }
    Ok(parsed)
}

async fn check(State(state): State<AppState>, RawQuery(query): RawQuery, body: Bytes) -> Response {
    let query = match parse_query(query.as_deref(), false) {
        Ok(query) => query,
        Err(message) => return error(StatusCode::BAD_REQUEST, message),
    };
    let verdict = state
        .engine
        .check_message(query.envelope, Message::new(Vec::from(body)))
        .await;
    tracing::debug!(score = verdict.score, action = %verdict.action, symbols = verdict.symbols.len(), "checked");
    let headers = headers(&verdict);
    Json(CheckResponse { verdict, headers }).into_response()
}

async fn learn(State(state): State<AppState>, RawQuery(query): RawQuery, body: Bytes) -> Response {
    let query = match parse_query(query.as_deref(), true) {
        Ok(query) => query,
        Err(message) => return error(StatusCode::BAD_REQUEST, message),
    };
    let spam = match query.label.as_deref() {
        Some("spam") => true,
        Some("ham") => false,
        _ => return error(StatusCode::BAD_REQUEST, "label must be spam or ham"),
    };
    match learn_message(&state, query.envelope, body, spam).await {
        Ok(learned) => Json(LearnResponse { learned }).into_response(),
        Err((status, message)) => error(status, message),
    }
}

async fn learn_message(
    state: &AppState,
    envelope: Envelope,
    body: Bytes,
    spam: bool,
) -> Result<Vec<String>, (StatusCode, &'static str)> {
    if state.learners.is_empty() {
        return Err((StatusCode::NOT_FOUND, "nothing is configured to learn"));
    }
    let message = Message::new(Vec::from(body));
    let verdict = state
        .engine
        .check_message(envelope.clone(), message.clone())
        .await;
    let symbols: Vec<Symbol> = verdict
        .symbols
        .into_iter()
        .filter(|s| !s.name.as_str().starts_with("PROB_"))
        .map(|s| Symbol::new(s.name))
        .collect();
    let mut learned = Vec::new();
    for learner in state.learners.iter() {
        learner.learn(&message, &envelope, &symbols, spam).await;
        learned.push(learner.name().to_string());
    }
    tracing::debug!(learners = learned.len(), spam, "learned");
    Ok(learned)
}

async fn sent(State(state): State<AppState>, RawQuery(query): RawQuery, body: Bytes) -> Response {
    let query = match parse_query(query.as_deref(), false) {
        Ok(query) => query,
        Err(message) => return error(StatusCode::BAD_REQUEST, message),
    };
    let Some(log) = &state.sent else {
        return error(
            StatusCode::NOT_FOUND,
            "nothing is configured to record sent mail",
        );
    };
    let recorded = log
        .record(&Message::new(Vec::from(body)), &query.envelope)
        .await;
    tracing::debug!(recorded, "sent");
    Json(SentResponse { recorded }).into_response()
}

#[cfg(test)]
mod tests;
