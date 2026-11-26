use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use pellet_check::{
    Check, CheckError, Context, symbol_names,
    testing::{FailingCheck, FixedCheck, SlowCheck},
};
use pellet_core::{
    Action, Envelope, FailureReason, Message, ScoreTable, Stage, Symbol, SymbolName, Thresholds,
};

use super::*;

fn scores() -> ScoreTable {
    ScoreTable::from_pairs([("HIGH", 5.0), ("MID", 2.0), ("LOW", -1.0), ("RBL", 3.0)]).unwrap()
}

fn message() -> Message {
    Message::new(&b"From: a@example.com\r\n\r\nhello\r\n"[..])
}

struct SeesContext {
    declared: Vec<SymbolName>,
}

impl SeesContext {
    fn new() -> Self {
        SeesContext {
            declared: symbol_names(&["SAW_RBL", "HAS_MESSAGE", "HAS_HELO"]),
        }
    }
}

#[async_trait]
impl Check for SeesContext {
    fn name(&self) -> &str {
        "sees"
    }

    fn stage(&self) -> Stage {
        Stage::Data
    }

    fn symbols(&self) -> &[SymbolName] {
        &self.declared
    }

    async fn run(&self, ctx: &Context<'_>) -> Result<Vec<Symbol>, CheckError> {
        let mut out = Vec::new();
        if ctx.earlier_has("RBL") {
            out.push(Symbol::new(self.declared[0].clone()));
        }
        if ctx.message.is_some() {
            out.push(Symbol::new(self.declared[1].clone()));
        }
        if ctx.envelope.helo.is_some() {
            out.push(Symbol::new(self.declared[2].clone()));
        }
        Ok(out)
    }
}

struct WithOption(Vec<SymbolName>, &'static str, &'static str);

#[async_trait]
impl Check for WithOption {
    fn name(&self) -> &str {
        self.1
    }

    fn stage(&self) -> Stage {
        Stage::Data
    }

    fn symbols(&self) -> &[SymbolName] {
        &self.0
    }

    async fn run(&self, _ctx: &Context<'_>) -> Result<Vec<Symbol>, CheckError> {
        Ok(vec![Symbol::new(self.0[0].clone()).with_option(self.2)])
    }
}

#[tokio::test]
async fn sums_scores_sorts_symbols_and_picks_the_action() {
    let engine = Engine::builder()
        .check(Arc::new(FixedCheck::new(
            "a",
            Stage::Data,
            &["MID", "LOW", "UNSCORED"],
        )))
        .check(Arc::new(FixedCheck::new("b", Stage::Data, &["HIGH"])))
        .scores(scores())
        .thresholds(Thresholds {
            tag: Some(5.0),
            ..Thresholds::NONE
        })
        .build()
        .unwrap();
    let verdict = engine.check_message(Envelope::default(), message()).await;
    assert_eq!(verdict.score, 6.0);
    assert_eq!(verdict.action, Action::Tag);
    let names: Vec<_> = verdict.symbols.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["HIGH", "MID", "UNSCORED", "LOW"]);
    assert_eq!(verdict.symbol("UNSCORED").unwrap().score, 0.0);
    assert!(verdict.failures.is_empty());
    assert_eq!(verdict.stage, Stage::Data);
}

#[tokio::test]
async fn stages_accumulate_and_later_checks_see_earlier_symbols() {
    let engine = Engine::builder()
        .check(Arc::new(FixedCheck::new("rbl", Stage::Connect, &["RBL"])))
        .check(Arc::new(SeesContext::new()))
        .scores(scores())
        .build()
        .unwrap();
    let mut session = engine.session(Envelope::default());

    let connect = session.run(Stage::Connect).await.unwrap();
    assert_eq!(connect.score, 3.0);
    assert_eq!(connect.symbol("RBL").unwrap().stage, Stage::Connect);

    session.envelope_mut().helo = Some("mx.example.org".into());
    let data = session.data(message()).await.unwrap();
    assert!(data.has("RBL"));
    assert!(data.has("SAW_RBL"));
    assert!(data.has("HAS_MESSAGE"));
    assert!(
        data.has("HAS_HELO"),
        "envelope changes are visible to later stages"
    );
    assert_eq!(data.symbol("SAW_RBL").unwrap().stage, Stage::Data);
}

#[tokio::test]
async fn stages_cannot_repeat_or_go_back() {
    let engine = Engine::builder().build().unwrap();
    let mut session = engine.session(Envelope::default());
    session.run(Stage::Mail).await.unwrap();
    assert_eq!(
        session.run(Stage::Helo).await,
        Err(SessionError::OutOfOrder {
            stage: Stage::Helo,
            last: Stage::Mail
        })
    );
    assert!(session.run(Stage::Mail).await.is_err());
    assert_eq!(
        session.run(Stage::Data).await,
        Err(SessionError::NeedsMessage)
    );
    session.data(message()).await.unwrap();
    assert!(session.data(message()).await.is_err());
}

#[tokio::test]
async fn undeclared_symbols_are_dropped_and_reported() {
    let engine = Engine::builder()
        .check(Arc::new(FixedCheck::lying(
            "liar",
            Stage::Data,
            &["MID"],
            &["MID", "HIGH"],
        )))
        .scores(scores())
        .build()
        .unwrap();
    let verdict = engine.check_message(Envelope::default(), message()).await;
    assert!(verdict.has("MID"));
    assert!(!verdict.has("HIGH"));
    assert_eq!(verdict.failures.len(), 1);
    assert_eq!(verdict.failures[0].check, "liar");
    assert_eq!(
        verdict.failures[0].reason,
        FailureReason::Undeclared(SymbolName::new("HIGH").unwrap())
    );
}

#[tokio::test]
async fn failing_checks_are_reported_and_others_still_count() {
    let engine = Engine::builder()
        .check(Arc::new(FailingCheck::new("broken", Stage::Data)))
        .check(Arc::new(FixedCheck::new("ok", Stage::Data, &["MID"])))
        .scores(scores())
        .build()
        .unwrap();
    let verdict = engine.check_message(Envelope::default(), message()).await;
    assert_eq!(verdict.score, 2.0);
    assert_eq!(verdict.failures[0].check, "broken");
    assert!(matches!(
        verdict.failures[0].reason,
        FailureReason::Error(_)
    ));
}

#[tokio::test(start_paused = true)]
async fn slow_checks_miss_the_deadline_without_blocking_the_verdict() {
    let engine = Engine::builder()
        .check(Arc::new(SlowCheck::new(
            "slow",
            Stage::Data,
            &["HIGH"],
            Duration::from_secs(60),
        )))
        .check(Arc::new(SlowCheck::new(
            "quick",
            Stage::Data,
            &["MID"],
            Duration::from_millis(10),
        )))
        .scores(scores())
        .deadline(Duration::from_secs(1))
        .build()
        .unwrap();
    let started = tokio::time::Instant::now();
    let verdict = engine.check_message(Envelope::default(), message()).await;
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(verdict.has("MID"));
    assert!(!verdict.has("HIGH"));
    assert_eq!(verdict.failures[0].check, "slow");
    assert_eq!(verdict.failures[0].reason, FailureReason::Deadline);
}

#[tokio::test(start_paused = true)]
async fn checks_of_one_stage_run_concurrently() {
    let mut builder = Engine::builder().deadline(Duration::from_secs(2));
    for i in 0..5 {
        builder = builder.check(Arc::new(SlowCheck::new(
            &format!("c{i}"),
            Stage::Data,
            &[["A", "B", "C", "D", "E"][i]],
            Duration::from_secs(1),
        )));
    }
    let verdict = builder
        .build()
        .unwrap()
        .check_message(Envelope::default(), message())
        .await;
    assert_eq!(verdict.symbols.len(), 5, "{:?}", verdict.failures);
}

#[tokio::test]
async fn same_symbol_from_two_checks_merges_options() {
    let name = symbol_names(&["RBL"]);
    let engine = Engine::builder()
        .check(Arc::new(WithOption(name.clone(), "one", "zone-a.example")))
        .check(Arc::new(WithOption(name.clone(), "two", "zone-b.example")))
        .check(Arc::new(WithOption(name, "three", "zone-a.example")))
        .scores(scores())
        .build()
        .unwrap();
    let verdict = engine.check_message(Envelope::default(), message()).await;
    assert_eq!(verdict.symbols.len(), 1);
    assert_eq!(verdict.score, 3.0, "a symbol counts once");
    assert_eq!(
        verdict.symbols[0].options,
        ["zone-a.example", "zone-b.example"]
    );
}

#[tokio::test]
async fn checks_only_run_at_their_stage() {
    let engine = Engine::builder()
        .check(Arc::new(FixedCheck::new("helo", Stage::Helo, &["MID"])))
        .build()
        .unwrap();
    let mut session = engine.session(Envelope::default());
    assert!(
        session
            .run(Stage::Connect)
            .await
            .unwrap()
            .symbols
            .is_empty()
    );
    let verdict = session.data(message()).await.unwrap();
    assert!(
        verdict.symbols.is_empty(),
        "skipped stage does not run later"
    );
}

#[test]
fn refuses_duplicate_check_names_and_bad_thresholds() {
    let duplicate = Engine::builder()
        .check(Arc::new(FixedCheck::new("same", Stage::Data, &["A"])))
        .check(Arc::new(FixedCheck::new("same", Stage::Connect, &["B"])))
        .build();
    assert!(matches!(duplicate, Err(EngineError::DuplicateCheck(name)) if name == "same"));

    let nan = Engine::builder()
        .thresholds(Thresholds {
            reject: Some(f64::NAN),
            ..Thresholds::NONE
        })
        .build();
    assert!(matches!(nan, Err(EngineError::Thresholds(_))));
}

#[tokio::test]
async fn renders_headers() {
    let name = symbol_names(&["RBL"]);
    let engine = Engine::builder()
        .check(Arc::new(WithOption(name, "opt", "bad,option\n[x]")))
        .check(Arc::new(FixedCheck::new("b", Stage::Data, &["MID"])))
        .scores(scores())
        .build()
        .unwrap();
    let verdict = engine.check_message(Envelope::default(), message()).await;
    let headers = headers(&verdict);
    assert_eq!(headers[0], ("X-Spam-Score", "5.00".to_string()));
    assert_eq!(headers[1], ("X-Spam-Action", "accept".to_string()));
    assert_eq!(
        headers[2],
        (
            "X-Spam-Symbols",
            "RBL(3.00)[bad?option??x?], MID(2.00)".to_string()
        )
    );
}

#[test]
fn declared_symbols_cover_every_check() {
    let engine = Engine::builder()
        .check(Arc::new(FixedCheck::new("a", Stage::Data, &["A", "B"])))
        .check(Arc::new(FixedCheck::new("b", Stage::Connect, &["B", "C"])))
        .build()
        .unwrap();
    let names: Vec<String> = engine
        .declared_symbols()
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(names, ["A", "B", "C"]);
}

#[test]
fn sessions_are_send() {
    fn assert_send<T: Send>(_: T) {}
    let engine = Engine::builder().build().unwrap();
    let mut session = engine.session(Envelope::default());
    assert_send(async move { session.run(Stage::Connect).await });
}

#[tokio::test]
async fn forced_actions_override_a_low_score() {
    let mut scores = scores();
    scores.force(SymbolName::new("BLOCKED").unwrap(), Action::Reject);
    let engine = Engine::builder()
        .check(Arc::new(FixedCheck::new(
            "blocked",
            Stage::Data,
            &["BLOCKED", "LOW"],
        )))
        .scores(scores)
        .build()
        .unwrap();
    let verdict = engine.check_message(Envelope::default(), message()).await;
    assert_eq!(verdict.score, -1.0);
    assert_eq!(verdict.action, Action::Reject);
}

struct LateEcho {
    declared: Vec<SymbolName>,
}

#[async_trait]
impl Check for LateEcho {
    fn name(&self) -> &str {
        "late"
    }

    fn stage(&self) -> Stage {
        Stage::Data
    }

    fn symbols(&self) -> &[SymbolName] {
        &self.declared
    }

    fn late(&self) -> bool {
        true
    }

    async fn run(&self, ctx: &Context<'_>) -> Result<Vec<Symbol>, CheckError> {
        Ok(if ctx.earlier_has("MID") && ctx.earlier_has("RBL") {
            vec![Symbol::new(self.declared[0].clone())]
        } else {
            vec![]
        })
    }
}

#[tokio::test]
async fn late_checks_see_symbols_of_their_own_stage() {
    let engine = Engine::builder()
        .check(Arc::new(LateEcho {
            declared: symbol_names(&["COMPOSITE"]),
        }))
        .check(Arc::new(FixedCheck::new("rbl", Stage::Connect, &["RBL"])))
        .check(Arc::new(FixedCheck::new("mid", Stage::Data, &["MID"])))
        .build()
        .unwrap();
    let verdict = engine.check_message(Envelope::default(), message()).await;
    assert!(verdict.has("COMPOSITE"), "{:?}", verdict.symbols);
}

#[tokio::test(start_paused = true)]
async fn late_checks_share_the_stage_deadline() {
    struct SlowLate(SlowCheck);
    #[async_trait]
    impl Check for SlowLate {
        fn name(&self) -> &str {
            self.0.name()
        }
        fn stage(&self) -> Stage {
            self.0.stage()
        }
        fn symbols(&self) -> &[SymbolName] {
            self.0.symbols()
        }
        fn late(&self) -> bool {
            true
        }
        async fn run(&self, ctx: &Context<'_>) -> Result<Vec<Symbol>, CheckError> {
            self.0.run(ctx).await
        }
    }
    let engine = Engine::builder()
        .check(Arc::new(SlowCheck::new(
            "first",
            Stage::Data,
            &["A"],
            Duration::from_millis(800),
        )))
        .check(Arc::new(SlowLate(SlowCheck::new(
            "late",
            Stage::Data,
            &["B"],
            Duration::from_millis(800),
        ))))
        .deadline(Duration::from_secs(1))
        .build()
        .unwrap();
    let verdict = engine.check_message(Envelope::default(), message()).await;
    assert!(verdict.has("A"));
    assert!(!verdict.has("B"));
    assert_eq!(verdict.failures[0].check, "late");
    assert_eq!(verdict.failures[0].reason, FailureReason::Deadline);
}
