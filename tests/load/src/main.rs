//! `pellet-load`: run the load scenarios and print a Markdown report.

use clap::{Parser, ValueEnum};
use pellet_load::{default_kinds, resident_memory, run_engine, run_serve, setup};

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Scenario {
    /// Every default kind of message through the engine.
    Engine,
    /// Requests over HTTP to the API served in this process.
    Serve,
    /// Both.
    All,
}

#[derive(Parser)]
#[command(about = "Load test of Pellet with generated messages")]
struct Args {
    /// Which scenario to run.
    #[arg(long, value_enum, default_value_t = Scenario::All)]
    scenario: Scenario,
    /// Messages per kind (engine).
    #[arg(long, default_value_t = 50)]
    messages: usize,
    /// Messages or requests in flight at once.
    #[arg(long, default_value_t = 1)]
    concurrency: usize,
    /// Requests (serve).
    #[arg(long, default_value_t = 500)]
    requests: usize,
}

fn mb(bytes: u64) -> String {
    if bytes < 1 << 20 {
        return format!("{:.1} KB", bytes as f64 / 1024.0);
    }
    format!("{:.1} MB", bytes as f64 / 1_048_576.0)
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Args::parse();
    let before = resident_memory();
    if matches!(args.scenario, Scenario::Engine | Scenario::All) {
        let setup = setup();
        let ready = resident_memory();
        println!("| message | size | count | p50 | p99 | max | per second | memory after |");
        println!("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
        for kind in default_kinds() {
            let count = if matches!(kind, pellet_load::Kind::Attachment(b) if b >= 4 << 20) {
                args.messages.min(10)
            } else {
                args.messages
            };
            let s = run_engine(&setup.engine, kind, count, args.concurrency).await;
            println!(
                "| {} | {} | {} | {:.2?} | {:.2?} | {:.2?} | {:.0} | {} |",
                s.label,
                mb(s.bytes as u64),
                s.count,
                s.p50,
                s.p99,
                s.max,
                s.per_second,
                resident_memory().map_or("?".into(), mb)
            );
        }
        if let (Some(before), Some(ready), Some(after)) = (before, ready, resident_memory()) {
            println!();
            println!(
                "Memory (peak on Linux, current elsewhere): {} at start, {} with the engine built, {} after the run.",
                mb(before),
                mb(ready),
                mb(after)
            );
        }
    }
    if matches!(args.scenario, Scenario::Serve | Scenario::All) {
        let s = run_serve(args.requests, args.concurrency.max(8)).await;
        println!();
        println!("| HTTP requests | of them learns | p50 | p99 | per second |");
        println!("| ---: | ---: | ---: | ---: | ---: |");
        println!(
            "| {} | {} | {:.2?} | {:.2?} | {:.0} |",
            s.requests, s.learns, s.p50, s.p99, s.per_second
        );
    }
}
