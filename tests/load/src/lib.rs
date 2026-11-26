//! Load tests: generated messages through the engine and the HTTP API, with time and memory
//! budgets.
//!
//! The engine has every check but `auth`, whose `mail-auth` resolver would make a load run
//! measure network waits instead of work; DNS goes to an in-process fake that answers at once.

pub mod generate;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use futures::{StreamExt, stream};
use pellet_check_classifier::{ClassifierCheck, ClassifierConfig};
use pellet_check_content::{
    AddressCheck, DateCheck, EncodingCheck, HeaderFlagsCheck, HeaderPresenceCheck, HeadersCheck,
    HtmlCheck, MessageIdCheck, MimeCheck, ReceivedCheck, SubjectCheck,
};
use pellet_check_ip::{
    DnsblCheck, DnsblResult, DnsblZone, FromHostCheck, HeloCheck, ReverseDnsCheck,
};
use pellet_check_reputation::{ReputationCheck, ReputationConfig};
use pellet_check_rules::{DnsListCheck, RulesCheck};
use pellet_check_url::UrlCheck;
use pellet_classifier::{Model, Params};
use pellet_core::{Envelope, Message, Symbol, SymbolName};
use pellet_dns::testing::FakeResolver;
use pellet_engine::Engine;
use pellet_rules::RuleSet;
use pellet_server::{Hooks, Learner, ServerConfig};
use pellet_state_memory::MemoryState;

pub use generate::{Kind, message};

/// The pieces a load run checks with.
pub struct Setup {
    /// The engine.
    pub engine: Engine,
    /// Its classifier, to learn through the API.
    pub classifier: Arc<ClassifierCheck>,
    /// Its reputation, to learn through the API.
    pub reputation: Arc<ReputationCheck>,
}

/// Every check but `auth`, over bundled rules, a fake resolver, an untrained 2^18 classifier that
/// still predicts, and in-memory reputation.
pub fn setup() -> Setup {
    let rules = Arc::new(RuleSet::bundled().expect("bundled rules"));
    let resolver: Arc<dyn pellet_dns::Resolver> = Arc::new(FakeResolver::new());
    let classifier = Arc::new(ClassifierCheck::new(
        Model::new(Params::default()).expect("model"),
        ClassifierConfig {
            min_ham: 0,
            min_spam: 0,
            auto_learn: false,
            ..ClassifierConfig::default()
        },
    ));
    let reputation = Arc::new(ReputationCheck::new(
        Arc::new(MemoryState::new(100_000)),
        ReputationConfig::default(),
    ));
    let zone = DnsblZone {
        zone: "dnsbl.example.net".into(),
        ipv6: true,
        results: vec![DnsblResult {
            codes: 2..=2,
            symbol: SymbolName::new("RBL_EXAMPLE").expect("name"),
        }],
    };
    let engine = Engine::builder()
        .check(Arc::new(DnsblCheck::new(resolver.clone(), vec![zone])))
        .check(Arc::new(ReverseDnsCheck::new(resolver.clone())))
        .check(Arc::new(HeloCheck::new(resolver.clone())))
        .check(Arc::new(FromHostCheck::new(resolver.clone())))
        .check(Arc::new(HeadersCheck::new()))
        .check(Arc::new(HeaderPresenceCheck::from_symbols(
            rules.referenced_symbols(),
        )))
        .check(Arc::new(HeaderFlagsCheck::new()))
        .check(Arc::new(AddressCheck::new()))
        .check(Arc::new(EncodingCheck::new()))
        .check(Arc::new(MessageIdCheck::new()))
        .check(Arc::new(DateCheck::new()))
        .check(Arc::new(ReceivedCheck::new()))
        .check(Arc::new(SubjectCheck::new()))
        .check(Arc::new(MimeCheck::new(
            rules.lists().entries("file-extensions"),
        )))
        .check(Arc::new(HtmlCheck::new()))
        .check(Arc::new(UrlCheck::new(
            rules
                .lists()
                .entries("url-redirectors")
                .map(|(host, _)| host),
        )))
        .check(Arc::new(RulesCheck::new(rules.clone())))
        .check(Arc::new(DnsListCheck::new(rules.clone(), resolver)))
        .check(classifier.clone())
        .check(reputation.clone())
        .scores(rules.scores().clone())
        .build()
        .expect("engine");
    Setup {
        engine,
        classifier,
        reputation,
    }
}

/// An envelope as an inbound connection would give it.
pub fn envelope(n: usize) -> Envelope {
    Envelope {
        client_ip: Some(format!("192.0.2.{}", n % 250 + 1).parse().expect("address")),
        client_ptr: None,
        helo: Some("mail.example.com".into()),
        mail_from: Some(format!("sender{n}@example.com")),
        recipients: vec!["reader@example.org".into()],
        tls: true,
        authenticated: false,
    }
}

/// Times for one kind of message.
#[derive(Debug, Clone)]
pub struct Stats {
    /// The kind's label.
    pub label: String,
    /// Bytes per message.
    pub bytes: usize,
    /// Messages checked.
    pub count: usize,
    /// Median time per message.
    pub p50: Duration,
    /// 99th percentile time per message.
    pub p99: Duration,
    /// Slowest message.
    pub max: Duration,
    /// Messages per second over the whole run of this kind.
    pub per_second: f64,
}

impl Stats {
    fn from(label: String, bytes: usize, mut times: Vec<Duration>, wall: Duration) -> Stats {
        times.sort();
        let pick = |q: f64| times[((times.len() as f64 - 1.0) * q).round() as usize];
        Stats {
            label,
            bytes,
            count: times.len(),
            p50: pick(0.5),
            p99: pick(0.99),
            max: *times.last().expect("at least one"),
            per_second: times.len() as f64 / wall.as_secs_f64().max(1e-9),
        }
    }
}

/// Checks `count` messages of a kind, `concurrency` at a time, and times each. Messages are made
/// as they are checked, so only those in flight are in memory; making them is not timed.
pub async fn run_engine(engine: &Engine, kind: Kind, count: usize, concurrency: usize) -> Stats {
    let bytes = message(kind, 0).len();
    let started = Instant::now();
    let times: Vec<Duration> = stream::iter(0..count)
        .map(|n| async move {
            let m = Message::new(message(kind, n));
            let t = Instant::now();
            let verdict = engine.check_message(envelope(n), m).await;
            assert!(verdict.failures.is_empty(), "{:?}", verdict.failures);
            t.elapsed()
        })
        .buffer_unordered(concurrency.max(1))
        .collect()
        .await;
    Stats::from(kind.label(), bytes, times, started.elapsed())
}

/// The process's peak resident memory in bytes where the system reports it (Linux), else the
/// current resident memory (from `ps`), else `None`.
pub fn resident_memory() -> Option<u64> {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        let kb = status
            .lines()
            .find_map(|l| l.strip_prefix("VmHWM:"))?
            .trim()
            .trim_end_matches("kB")
            .trim()
            .parse::<u64>()
            .ok()?;
        return Some(kb * 1024);
    }
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()?;
    let kb = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u64>()
        .ok()?;
    Some(kb * 1024)
}

/// The kinds a default run covers: everyday mail, big attachments and inputs built to find
/// quadratic paths.
pub fn default_kinds() -> Vec<Kind> {
    vec![
        Kind::Plain,
        Kind::Newsletter(400),
        Kind::Attachment(1 << 20),
        Kind::Attachment(8 << 20),
        Kind::LongText(1 << 20),
        Kind::NoSpaces(1 << 20),
        Kind::ManyHeaders(2000),
        Kind::DeepMime(60),
        Kind::GrowingUnicode(256 << 10),
    ]
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

struct ReputationLearner(Arc<ReputationCheck>);

#[async_trait]
impl Learner for ReputationLearner {
    fn name(&self) -> &str {
        "reputation"
    }

    async fn learn(&self, _message: &Message, envelope: &Envelope, symbols: &[Symbol], spam: bool) {
        self.0.learn(envelope, symbols, spam).await;
    }
}

/// Times of an HTTP run.
#[derive(Debug, Clone)]
pub struct ServeStats {
    /// Requests sent, checks and learns together.
    pub requests: usize,
    /// Of them, learn requests.
    pub learns: usize,
    /// Median time per request, client side.
    pub p50: Duration,
    /// 99th percentile.
    pub p99: Duration,
    /// Requests per second.
    pub per_second: f64,
}

/// Serves the API on a loopback port in this process and sends `requests` requests, `concurrency`
/// at a time: newsletters, plain messages and 1 MB attachments, every tenth a learn.
pub async fn run_serve(requests: usize, concurrency: usize) -> ServeStats {
    let setup = setup();
    let learners: Vec<Arc<dyn Learner>> = vec![
        Arc::new(ClassifierLearner(setup.classifier.clone())),
        Arc::new(ReputationLearner(setup.reputation.clone())),
    ];
    let app = pellet_server::router(
        setup.engine,
        Hooks {
            learners,
            sent: None,
        },
        ServerConfig::default(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("address");
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let client = reqwest::Client::new();
    let kinds = [
        Kind::Newsletter(100),
        Kind::Plain,
        Kind::Attachment(1 << 20),
    ];
    let bodies: Vec<Vec<u8>> = kinds.iter().map(|k| message(*k, 0)).collect();
    let started = Instant::now();
    let times: Vec<Duration> = stream::iter(0..requests)
        .map(|i| {
            let client = client.clone();
            let body = bodies[i % bodies.len()].clone();
            async move {
                let path = if i % 10 == 9 {
                    format!("v1/learn?label={}&ip=192.0.2.{}", if i % 20 == 19 { "spam" } else { "ham" }, i % 250 + 1)
                } else {
                    format!("v1/check?ip=192.0.2.{}&from=sender%40example.com&rcpt=reader%40example.org", i % 250 + 1)
                };
                let t = Instant::now();
                let response = client
                    .post(format!("http://{addr}/{path}"))
                    .body(body)
                    .send()
                    .await
                    .expect("request");
                assert!(response.status().is_success(), "{}", response.status());
                response.bytes().await.expect("body");
                t.elapsed()
            }
        })
        .buffer_unordered(concurrency.max(1))
        .collect()
        .await;
    let wall = started.elapsed();
    server.abort();
    let mut sorted = times;
    sorted.sort();
    let pick = |q: f64| sorted[((sorted.len() as f64 - 1.0) * q).round() as usize];
    ServeStats {
        requests,
        learns: requests / 10,
        p50: pick(0.5),
        p99: pick(0.99),
        per_second: requests as f64 / wall.as_secs_f64().max(1e-9),
    }
}
