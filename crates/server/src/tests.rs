use async_trait::async_trait;
use axum::{body::Body, http::Request};
use pellet_check::testing::FixedCheck;
use pellet_check_classifier::{ClassifierCheck, ClassifierConfig};
use pellet_classifier::{Model, Params};
use pellet_core::{ScoreTable, Stage, Thresholds};
use tower::ServiceExt;

use super::*;

fn engine(classifier: Option<Arc<ClassifierCheck>>) -> Engine {
    let mut builder = Engine::builder()
        .check(Arc::new(FixedCheck::new(
            "fixed",
            Stage::Data,
            &["RBL_EXAMPLE"],
        )))
        .scores(ScoreTable::from_pairs([("RBL_EXAMPLE", 7.0)]).unwrap())
        .thresholds(Thresholds {
            tag: Some(5.0),
            ..Thresholds::NONE
        });
    if let Some(classifier) = classifier {
        builder = builder.check(classifier);
    }
    builder.build().unwrap()
}

fn classifier() -> Arc<ClassifierCheck> {
    Arc::new(ClassifierCheck::new(
        Model::new(Params {
            bits: 16,
            ..Params::default()
        })
        .unwrap(),
        ClassifierConfig {
            auto_learn: false,
            ..ClassifierConfig::default()
        },
    ))
}

struct ClassifierLearner(Arc<ClassifierCheck>);

#[async_trait]
impl Learner for ClassifierLearner {
    fn name(&self) -> &str {
        "classifier"
    }

    async fn learn(&self, message: &Message, envelope: &Envelope, symbols: &[Symbol], spam: bool) {
        self.0.learn(message, envelope, symbols, spam);
    }
}

#[derive(Default)]
struct Recorder(std::sync::Mutex<Vec<Vec<String>>>);

#[async_trait]
impl SentLog for Recorder {
    async fn record(&self, message: &Message, envelope: &Envelope) -> bool {
        self.0.lock().unwrap().push(envelope.recipients.clone());
        message.header("Message-ID").is_some()
    }
}

fn app(config: ServerConfig) -> (Router, Arc<ClassifierCheck>) {
    let classifier = classifier();
    let learners: Vec<Arc<dyn Learner>> = vec![Arc::new(ClassifierLearner(classifier.clone()))];
    (
        router(
            engine(Some(classifier.clone())),
            Hooks {
                learners,
                sent: Some(Arc::new(Recorder::default())),
            },
            config,
        ),
        classifier,
    )
}

const MESSAGE: &str = "From: ana@example.com\r\nSubject: hi\r\n\r\nhello\r\n";

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, serde_json::Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::String(
        String::from_utf8_lossy(&bytes).into_owned(),
    ));
    (status, value)
}

fn post(uri: &str, body: &str) -> Request<Body> {
    Request::post(uri)
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn health() {
    let (app, _) = app(ServerConfig::default());
    let (status, body) = send(&app, Request::get("/health").body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn check_returns_verdict_and_headers() {
    let (app, _) = app(ServerConfig::default());
    let (status, body) = send(
        &app,
        post("/v1/check?ip=192.0.2.7&helo=mx.example.org&from=ana%40example.com&rcpt=bo%40example.org&rcpt=cy%40example.org&tls=true", MESSAGE),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["action"], "tag");
    assert_eq!(body["score"], 7.0);
    assert_eq!(body["symbols"][0]["name"], "RBL_EXAMPLE");
    assert_eq!(
        body["headers"][1],
        serde_json::json!(["X-Spam-Action", "tag"])
    );
}

#[test]
fn query_parsing() {
    let q = parse_query(
        Some("ip=2001%3Adb8%3A%3A1&from=&rcpt=a%40example.org&rcpt=b%40example.org&authenticated"),
        false,
    )
    .unwrap();
    assert_eq!(q.envelope.client_ip, Some("2001:db8::1".parse().unwrap()));
    assert_eq!(q.envelope.mail_from.as_deref(), Some(""));
    assert_eq!(q.envelope.recipients, ["a@example.org", "b@example.org"]);
    assert!(q.envelope.authenticated && !q.envelope.tls);
    assert!(parse_query(Some("ip=nope"), false).is_err());
    assert!(parse_query(Some("tls=maybe"), false).is_err());
    assert!(parse_query(Some("colour=red"), false).is_err());
    assert!(
        parse_query(Some("label=spam"), false).is_err(),
        "label only on learn"
    );
    assert_eq!(
        parse_query(Some("label=spam"), true)
            .unwrap()
            .label
            .as_deref(),
        Some("spam")
    );
}

#[tokio::test]
async fn bad_queries_are_refused() {
    let (app, _) = app(ServerConfig::default());
    let (status, body) = send(&app, post("/v1/check?ip=nope", MESSAGE)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "ip must be an IP address");
}

#[tokio::test]
async fn learn_trains_the_classifier() {
    let (app, classifier) = app(ServerConfig::default());
    let (status, body) = send(&app, post("/v1/learn?label=spam", MESSAGE)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, serde_json::json!({"learned": ["classifier"]}));
    send(&app, post("/v1/learn?label=ham", MESSAGE)).await;
    assert_eq!(classifier.samples(), (1, 1));
    let (status, _) = send(&app, post("/v1/learn?label=maybe", MESSAGE)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn learn_without_learners_is_not_found() {
    let app = router(engine(None), Hooks::default(), ServerConfig::default());
    let (status, body) = send(&app, post("/v1/learn?label=spam", MESSAGE)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "nothing is configured to learn");
}

#[tokio::test]
async fn token_protects_the_api_but_not_health() {
    let (app, _) = app(ServerConfig {
        token: Some("s3cret".into()),
        ..ServerConfig::default()
    });
    let (status, _) = send(&app, post("/v1/check", MESSAGE)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let wrong = Request::post("/v1/check")
        .header("authorization", "Bearer nope")
        .body(Body::from(MESSAGE))
        .unwrap();
    assert_eq!(send(&app, wrong).await.0, StatusCode::UNAUTHORIZED);
    let right = Request::post("/v1/check")
        .header("authorization", "Bearer s3cret")
        .body(Body::from(MESSAGE))
        .unwrap();
    assert_eq!(send(&app, right).await.0, StatusCode::OK);
    let health = Request::get("/health").body(Body::empty()).unwrap();
    assert_eq!(send(&app, health).await.0, StatusCode::OK);
}

#[tokio::test]
async fn oversized_messages_are_refused() {
    let (app, _) = app(ServerConfig {
        max_message_size: 64,
        ..ServerConfig::default()
    });
    let (status, _) = send(&app, post("/v1/check", &"x".repeat(1000))).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[test]
fn constant_time_comparison() {
    assert!(equal_in_constant_time(b"abc", b"abc"));
    assert!(!equal_in_constant_time(b"abc", b"abd"));
    assert!(!equal_in_constant_time(b"abc", b"ab"));
}

#[tokio::test]
async fn sent_mail_is_recorded() {
    let (app, _) = app(ServerConfig::default());
    let sent = "Message-ID: <a@example.com>\r\nTo: bo@example.org\r\n\r\nhi\r\n";
    let (status, body) = send(&app, post("/v1/sent?rcpt=bo%40example.org", sent)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, serde_json::json!({"recorded": true}));
    let (_, body) = send(&app, post("/v1/sent", MESSAGE)).await;
    assert_eq!(body, serde_json::json!({"recorded": false}));

    let none = router(engine(None), Hooks::default(), ServerConfig::default());
    assert_eq!(
        send(&none, post("/v1/sent", sent)).await.0,
        StatusCode::NOT_FOUND
    );
}

fn rspamd(uri: &str) -> axum::http::request::Builder {
    Request::post(uri)
        .header("IP", "192.0.2.7")
        .header("Helo", "mx.example.org")
        .header("From", "<ana@example.com>")
        .header("Rcpt", "<bo@example.org>")
        .header("Rcpt", "cy@example.org")
        .header("Hostname", "unknown")
}

#[tokio::test]
async fn rspamd_checkv2_speaks_the_rspamd_format() {
    let (app, _) = app(ServerConfig::default());
    let request = rspamd("/checkv2")
        .body(Body::from(format!(
            "Message-ID: <m1@example.com>\r\n{MESSAGE}"
        )))
        .unwrap();
    let (status, body) = send(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["action"], "add header");
    assert_eq!(body["score"], 7.0);
    assert_eq!(body["required_score"], 5.0);
    assert_eq!(body["is_skipped"], false);
    assert_eq!(body["message-id"], "m1@example.com");
    assert_eq!(body["symbols"]["RBL_EXAMPLE"]["score"], 7.0);
    assert_eq!(body["symbols"]["RBL_EXAMPLE"]["metric_score"], 7.0);
    assert_eq!(
        body["milter"]["add_headers"]["X-Spam-Action"]["value"],
        "tag"
    );

    let bad = Request::post("/checkv2")
        .header("IP", "nope")
        .body(Body::from(MESSAGE))
        .unwrap();
    assert_eq!(send(&app, bad).await.0, StatusCode::BAD_REQUEST);
    let zstd = rspamd("/checkv2")
        .header("Compression", "zstd")
        .body(Body::from(MESSAGE))
        .unwrap();
    assert_eq!(send(&app, zstd).await.0, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[test]
fn rspamd_headers_become_the_envelope() {
    let request = rspamd("/checkv2")
        .header("User", "ana")
        .header("TLS-Version", "TLSv1.3")
        .body(())
        .unwrap();
    let envelope = rspamd::envelope(request.headers()).unwrap();
    assert_eq!(envelope.client_ip, Some("192.0.2.7".parse().unwrap()));
    assert_eq!(envelope.client_ptr, None, "unknown means no PTR");
    assert_eq!(envelope.mail_from.as_deref(), Some("ana@example.com"));
    assert_eq!(envelope.recipients, ["bo@example.org", "cy@example.org"]);
    assert!(envelope.tls && envelope.authenticated);
}

#[tokio::test]
async fn rspamd_learning_and_ping() {
    let (app, classifier) = app(ServerConfig {
        token: Some("s3cret".into()),
        ..ServerConfig::default()
    });
    let spam = rspamd("/learnspam")
        .header("Password", "s3cret")
        .body(Body::from(MESSAGE))
        .unwrap();
    let (status, body) = send(&app, spam).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, serde_json::json!({"success": true}));
    let ham = rspamd("/learnham")
        .header("Password", "s3cret")
        .body(Body::from(MESSAGE))
        .unwrap();
    send(&app, ham).await;
    assert_eq!(classifier.samples(), (1, 1));
    let no_token = rspamd("/learnham").body(Body::from(MESSAGE)).unwrap();
    assert_eq!(send(&app, no_token).await.0, StatusCode::UNAUTHORIZED);
    let (status, body) = send(&app, Request::get("/ping").body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "pong\r\n");
}
