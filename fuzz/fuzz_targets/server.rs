#![no_main]

mod common;

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use axum::{Router, body::Body, http::Request};
use libfuzzer_sys::fuzz_target;
use pellet_check::testing::FixedCheck;
use pellet_core::{Envelope, Message, ScoreTable, Stage, Symbol};
use pellet_engine::Engine;
use pellet_server::{Hooks, Learner, SentLog, ServerConfig, router};
use tower::ServiceExt;

struct Sink;

#[async_trait]
impl Learner for Sink {
    fn name(&self) -> &str {
        "sink"
    }

    async fn learn(&self, _: &Message, _: &Envelope, _: &[Symbol], _: bool) {}
}

#[async_trait]
impl SentLog for Sink {
    async fn record(&self, message: &Message, _: &Envelope) -> bool {
        message.header("Message-ID").is_some()
    }
}

const PATHS: [&str; 8] = [
    "/v1/check",
    "/v1/learn",
    "/v1/sent",
    "/checkv2",
    "/learnspam",
    "/learnham",
    "/health",
    "/ping",
];

fn app(token: Option<&str>) -> Router {
    static OPEN: OnceLock<Router> = OnceLock::new();
    static PROTECTED: OnceLock<Router> = OnceLock::new();
    let cell = if token.is_some() { &PROTECTED } else { &OPEN };
    cell.get_or_init(|| {
        let engine = Engine::builder()
            .check(Arc::new(FixedCheck::new("fixed", Stage::Data, &["FUZZ"])))
            .scores(ScoreTable::from_pairs([("FUZZ", 1.0)]).expect("scores"))
            .build()
            .expect("engine");
        router(
            engine,
            Hooks {
                learners: vec![Arc::new(Sink)],
                sent: Some(Arc::new(Sink)),
            },
            ServerConfig {
                token: token.map(str::to_owned),
                max_message_size: 1 << 20,
            },
        )
    })
    .clone()
}

// The input's first byte picks the path, the method and whether a token is required; then
// come lines up to an empty one: the first is the query string, the rest are `name: value`
// headers; what follows is the body.
fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    let (head, body) = match rest.windows(2).position(|w| w == b"\n\n") {
        Some(at) => (&rest[..at], &rest[at + 2..]),
        None => (rest, &[][..]),
    };
    let head = String::from_utf8_lossy(head);
    let mut lines = head.split('\n');
    let query = lines.next().unwrap_or_default();
    let path = PATHS[pick as usize % PATHS.len()];
    let method = if pick & 0x80 != 0 { "GET" } else { "POST" };
    let uri = if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    };
    let mut request = Request::builder().method(method).uri(uri);
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            request = request.header(name.trim(), value.trim());
        }
    }
    let Ok(request) = request.body(Body::from(body.to_vec())) else {
        return;
    };
    let token = (pick & 0x40 != 0).then_some("fuzz-token");
    let response = common::runtime().block_on(app(token).oneshot(request));
    let status = response.expect("infallible").status();
    assert!(!status.is_server_error(), "{status}");
});
