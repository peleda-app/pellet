//! Time and memory budgets. They only mean something in a release build: run them with
//! `cargo test --release -p pellet-load`; a debug build skips them.

use std::time::Duration;

use pellet_load::{Kind, resident_memory, run_engine, run_serve, setup};

fn release() -> bool {
    if cfg!(debug_assertions) {
        eprintln!("load budgets need a release build; skipped");
        return false;
    }
    true
}

/// Each kind's slowest message stays under a ceiling about ten times what a laptop measures, so
/// a slower machine passes and a regression of that order does not.
#[tokio::test(flavor = "current_thread")]
async fn time_and_memory_budgets() {
    if !release() {
        return;
    }
    let setup = setup();
    let ceilings = [
        (Kind::Plain, 20, 30),
        (Kind::Newsletter(400), 20, 60),
        (Kind::Attachment(1 << 20), 20, 30),
        (Kind::Attachment(8 << 20), 8, 100),
        (Kind::LongText(1 << 20), 10, 120),
        (Kind::NoSpaces(1 << 20), 10, 60),
        (Kind::ManyHeaders(2000), 10, 100),
        (Kind::DeepMime(60), 20, 30),
        (Kind::GrowingUnicode(256 << 10), 10, 80),
    ];
    let mut over = Vec::new();
    for (kind, count, ceiling_ms) in ceilings {
        let stats = run_engine(&setup.engine, kind, count, 1).await;
        eprintln!(
            "{}: p50 {:.2?}, max {:.2?}",
            stats.label, stats.p50, stats.max
        );
        if stats.max > Duration::from_millis(ceiling_ms) {
            over.push(format!(
                "{} took {:.2?}, over {ceiling_ms} ms",
                stats.label, stats.max
            ));
        }
    }
    assert!(over.is_empty(), "{over:#?}");
    if let Some(peak) = resident_memory() {
        eprintln!("resident memory: {:.1} MB", peak as f64 / 1_048_576.0);
        assert!(
            peak < 96 << 20,
            "memory {} MB with 11 MB messages in flight",
            peak >> 20
        );
    }
}

/// Eight times the input takes at most twenty times as long: linear work passes with room to
/// spare, quadratic work (sixty-four times) does not.
#[tokio::test(flavor = "current_thread")]
async fn work_grows_linearly_with_input() {
    if !release() {
        return;
    }
    let setup = setup();
    let pairs = [
        (Kind::LongText(128 << 10), Kind::LongText(1 << 20)),
        (Kind::NoSpaces(128 << 10), Kind::NoSpaces(1 << 20)),
        (
            Kind::GrowingUnicode(32 << 10),
            Kind::GrowingUnicode(256 << 10),
        ),
        (Kind::ManyHeaders(100), Kind::ManyHeaders(800)),
        (Kind::Attachment(1 << 20), Kind::Attachment(8 << 20)),
    ];
    let mut worse = Vec::new();
    for (small, large) in pairs {
        let small_time = run_engine(&setup.engine, small, 9, 1).await.p50;
        let large_time = run_engine(&setup.engine, large, 9, 1).await.p50;
        let ratio = large_time.as_secs_f64() / small_time.as_secs_f64().max(1e-6);
        eprintln!("{} -> {}: {ratio:.1}x", small.label(), large.label());
        if ratio > 20.0 {
            worse.push(format!(
                "{} -> {} grew {ratio:.1}x for 8x the input",
                small.label(),
                large.label()
            ));
        }
    }
    assert!(worse.is_empty(), "{worse:#?}");
}

/// The API answers 500 requests, a tenth of them learning, eight at a time, each within 250 ms.
#[tokio::test(flavor = "current_thread")]
async fn serve_budget() {
    if !release() {
        return;
    }
    let stats = run_serve(500, 8).await;
    eprintln!(
        "serve: p50 {:.2?}, p99 {:.2?}, {:.0}/s",
        stats.p50, stats.p99, stats.per_second
    );
    assert!(
        stats.p99 < Duration::from_millis(250),
        "p99 {:.2?}",
        stats.p99
    );
}
