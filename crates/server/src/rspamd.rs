use std::{collections::BTreeMap, net::IpAddr, time::Instant};

use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use pellet_core::{Action, Envelope, Message};
use pellet_engine::headers as spam_headers;
use serde::Serialize;

use crate::{AppState, error, learn_message};

#[derive(Debug, Serialize)]
struct Symbol {
    name: String,
    score: f64,
    metric_score: f64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    options: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Header {
    value: String,
    order: u32,
}

#[derive(Debug, Serialize)]
struct Milter {
    add_headers: BTreeMap<&'static str, Header>,
}

#[derive(Debug, Serialize)]
struct CheckResponse {
    is_skipped: bool,
    score: f64,
    required_score: f64,
    action: &'static str,
    symbols: BTreeMap<String, Symbol>,
    messages: BTreeMap<String, String>,
    #[serde(rename = "message-id", skip_serializing_if = "Option::is_none")]
    message_id: Option<String>,
    milter: Milter,
    time_real: f64,
}

#[derive(Debug, Serialize)]
struct LearnResponse {
    success: bool,
}

fn action(action: Action) -> &'static str {
    match action {
        Action::Accept => "no action",
        Action::Tag => "add header",
        Action::Greylist => "greylist",
        Action::Reject => "reject",
    }
}

fn text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

fn address(value: &str) -> String {
    value
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_string()
}

pub(crate) fn envelope(headers: &HeaderMap) -> Result<Envelope, (StatusCode, &'static str)> {
    if headers.contains_key("compression") {
        return Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "compressed bodies are not supported",
        ));
    }
    let client_ip = match text(headers, "ip") {
        Some(ip) => Some(
            ip.parse::<IpAddr>()
                .map_err(|_| (StatusCode::BAD_REQUEST, "IP must be an IP address"))?,
        ),
        None => None,
    };
    Ok(Envelope {
        client_ip,
        client_ptr: text(headers, "hostname")
            .filter(|h| !h.eq_ignore_ascii_case("unknown"))
            .map(str::to_string),
        helo: text(headers, "helo").map(str::to_string),
        mail_from: headers
            .get("from")
            .and_then(|v| v.to_str().ok())
            .map(address),
        recipients: headers
            .get_all("rcpt")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(address)
            .filter(|r| !r.is_empty())
            .collect(),
        tls: headers.contains_key("tls-version") || headers.contains_key("tls-cipher"),
        authenticated: text(headers, "user").is_some(),
    })
}

pub(crate) async fn check(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();
    let envelope = match envelope(&headers) {
        Ok(envelope) => envelope,
        Err((status, message)) => return error(status, message),
    };
    let message = Message::new(Vec::from(body));
    let message_id = message.header("Message-ID").map(|h| {
        h.value_str()
            .trim()
            .trim_start_matches('<')
            .trim_end_matches('>')
            .to_string()
    });
    let verdict = state.engine.check_message(envelope, message).await;
    let thresholds = state.engine.thresholds();
    let add_headers = spam_headers(&verdict)
        .into_iter()
        .map(|(name, value)| (name, Header { value, order: 0 }))
        .collect();
    let symbols = verdict
        .symbols
        .iter()
        .map(|s| {
            (
                s.name.to_string(),
                Symbol {
                    name: s.name.to_string(),
                    score: s.score,
                    metric_score: s.score,
                    options: s.options.clone(),
                },
            )
        })
        .collect();
    tracing::debug!(score = verdict.score, action = %verdict.action, "checked (rspamd)");
    Json(CheckResponse {
        is_skipped: false,
        score: verdict.score,
        required_score: thresholds.reject.or(thresholds.tag).unwrap_or(0.0),
        action: action(verdict.action),
        symbols,
        messages: BTreeMap::new(),
        message_id,
        milter: Milter { add_headers },
        time_real: started.elapsed().as_secs_f64(),
    })
    .into_response()
}

async fn learn(state: AppState, headers: HeaderMap, body: Bytes, spam: bool) -> Response {
    let envelope = match envelope(&headers) {
        Ok(envelope) => envelope,
        Err((status, message)) => return error(status, message),
    };
    match learn_message(&state, envelope, body, spam).await {
        Ok(_) => Json(LearnResponse { success: true }).into_response(),
        Err((status, message)) => error(status, message),
    }
}

pub(crate) async fn learn_spam(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    learn(state, headers, body, true).await
}

pub(crate) async fn learn_ham(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    learn(state, headers, body, false).await
}
