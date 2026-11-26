//! `pellet-eval`: real spam and ham through the offline checks, then through a classifier
//! trained on half of them, with a Markdown report. The corpora stay outside the repository;
//! `scripts/fetch-eval-corpora.sh` downloads them.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::Parser;
use pellet_check_classifier::{ClassifierCheck, ClassifierConfig, document};
use pellet_check_content::{
    AddressCheck, EncodingCheck, HeaderFlagsCheck, HeaderPresenceCheck, HeadersCheck, HtmlCheck,
    MessageIdCheck, MimeCheck, ReceivedCheck, SubjectCheck,
};
use pellet_check_rules::RulesCheck;
use pellet_check_url::UrlCheck;
use pellet_classifier::{Model, Params};
use pellet_core::{Envelope, Message, Symbol, Verdict};
use pellet_engine::{Engine, EngineBuilder};
use pellet_rules::RuleSet;

#[derive(Parser)]
#[command(about = "Evaluate Pellet over spam and ham corpora")]
struct Args {
    /// A directory of spam messages, one per file, searched recursively; repeat for several.
    #[arg(long, required = true)]
    spam: Vec<PathBuf>,
    /// A directory of ham messages; repeat for several.
    #[arg(long, required = true)]
    ham: Vec<PathBuf>,
    /// Most messages read from each directory.
    #[arg(long, default_value_t = usize::MAX)]
    limit: usize,
    /// Symbols listed in each table.
    #[arg(long, default_value_t = 15)]
    top: usize,
}

struct Sample {
    source: String,
    file: String,
    message: Message,
    spam: bool,
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files(&path, out);
        } else if path
            .file_name()
            .is_some_and(|n| n != "cmds" && !n.to_string_lossy().starts_with('.'))
        {
            out.push(path);
        }
    }
}

/// Reads a message, dropping an mbox `From ` line in front of the headers.
fn read(path: &Path) -> Option<Message> {
    let raw = std::fs::read(path).ok()?;
    let start = if raw.starts_with(b"From ") {
        raw.iter()
            .position(|&b| b == b'\n')
            .map_or(raw.len(), |i| i + 1)
    } else {
        0
    };
    Some(Message::new(raw[start..].to_vec()))
}

fn load(dirs: &[PathBuf], spam: bool, limit: usize) -> Vec<Sample> {
    let mut out = Vec::new();
    for dir in dirs {
        let mut paths = Vec::new();
        files(dir, &mut paths);
        paths.sort();
        out.extend(paths.iter().take(limit).filter_map(|p| {
            Some(Sample {
                source: dir.display().to_string(),
                file: p.strip_prefix(dir).unwrap_or(p).display().to_string(),
                message: read(p)?,
                spam,
            })
        }));
    }
    out
}

/// The checks that judge content alone: no DNS, no state, no clock, so messages from any year
/// and any server are judged alike.
fn offline(rules: &Arc<RuleSet>) -> EngineBuilder {
    Engine::builder()
        .check(Arc::new(HeadersCheck::new()))
        .check(Arc::new(HeaderPresenceCheck::from_symbols(
            rules.referenced_symbols(),
        )))
        .check(Arc::new(HeaderFlagsCheck::new()))
        .check(Arc::new(AddressCheck::new()))
        .check(Arc::new(EncodingCheck::new()))
        .check(Arc::new(MessageIdCheck::new()))
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
        .scores(rules.scores().clone())
}

async fn judge(engine: &Engine, samples: &[&Sample]) -> Vec<Verdict> {
    let mut out = Vec::with_capacity(samples.len());
    for sample in samples {
        out.push(
            engine
                .check_message(Envelope::default(), sample.message.clone())
                .await,
        );
    }
    out
}

struct Tally {
    count: usize,
    tagged: usize,
    rejected: usize,
    scores: Vec<f64>,
}

fn tally(verdicts: &[&Verdict], tag: f64, reject: f64) -> Tally {
    let mut scores: Vec<f64> = verdicts.iter().map(|v| v.score).collect();
    scores.sort_by(f64::total_cmp);
    Tally {
        count: verdicts.len(),
        tagged: scores.iter().filter(|s| **s >= tag).count(),
        rejected: scores.iter().filter(|s| **s >= reject).count(),
        scores,
    }
}

fn percent(part: usize, whole: usize) -> String {
    format!("{:.1}%", 100.0 * part as f64 / whole.max(1) as f64)
}

fn print_summary(title: &str, samples: &[&Sample], verdicts: &[Verdict], tag: f64, reject: f64) {
    println!("### {title}\n");
    println!("| corpus | messages | score ≥ {tag} | score ≥ {reject} | median score |");
    println!("| --- | ---: | ---: | ---: | ---: |");
    let mut sources: Vec<(String, bool)> = Vec::new();
    for sample in samples {
        let key = (sample.source.clone(), sample.spam);
        if !sources.contains(&key) {
            sources.push(key);
        }
    }
    let row = |name: String, keep: &dyn Fn(&Sample) -> bool| {
        let picked: Vec<&Verdict> = samples
            .iter()
            .zip(verdicts)
            .filter(|(s, _)| keep(s))
            .map(|(_, v)| v)
            .collect();
        let t = tally(&picked, tag, reject);
        let median = t.scores.get(t.count / 2).copied().unwrap_or(0.0);
        println!(
            "| {name} | {} | {} | {} | {median:.1} |",
            t.count,
            percent(t.tagged, t.count),
            percent(t.rejected, t.count)
        );
    };
    for (spam, label) in [(true, "spam"), (false, "ham")] {
        row(format!("**all {label}**"), &|s: &Sample| s.spam == spam);
        for (source, _) in sources.iter().filter(|(_, s)| *s == spam) {
            let short = Path::new(source)
                .components()
                .rev()
                .take(2)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            row(format!("{label}: {short}"), &|s: &Sample| {
                s.spam == spam && &s.source == source
            });
        }
    }
    println!();
}

fn print_symbols(samples: &[&Sample], verdicts: &[Verdict], tag: f64, top: usize) {
    let mut seen: BTreeMap<String, (usize, usize, f64)> = BTreeMap::new();
    let (mut spam_total, mut ham_total) = (0, 0);
    for (sample, verdict) in samples.iter().zip(verdicts) {
        if sample.spam {
            spam_total += 1;
        } else {
            ham_total += 1;
        }
        for symbol in &verdict.symbols {
            let entry = seen.entry(symbol.name.to_string()).or_default();
            entry.2 = symbol.score;
            if sample.spam {
                entry.0 += 1;
            } else {
                entry.1 += 1;
            }
        }
    }
    let table = |title: &str, rows: Vec<(&String, &(usize, usize, f64))>| {
        println!("#### {title}\n");
        println!("| symbol | score | in spam | in ham |");
        println!("| --- | ---: | ---: | ---: |");
        for (name, (spam, ham, score)) in rows {
            println!(
                "| `{name}` | {score:.1} | {} | {} |",
                percent(*spam, spam_total),
                percent(*ham, ham_total)
            );
        }
        println!();
    };
    let mut by_spam: Vec<_> = seen.iter().filter(|(_, v)| v.2 > 0.0).collect();
    by_spam.sort_by_key(|(_, v)| std::cmp::Reverse(v.0));
    table(
        "Most frequent scoring symbols in spam",
        by_spam.into_iter().take(top).collect(),
    );

    let mut weight: BTreeMap<String, f64> = BTreeMap::new();
    for (sample, verdict) in samples.iter().zip(verdicts) {
        if sample.spam || verdict.score < tag {
            continue;
        }
        for symbol in verdict.symbols.iter().filter(|s| s.score > 0.0) {
            *weight.entry(symbol.name.to_string()).or_default() += symbol.score;
        }
    }
    let mut blame: Vec<_> = weight.into_iter().collect();
    blame.sort_by(|a, b| b.1.total_cmp(&a.1));
    let rows = blame
        .iter()
        .take(top)
        .filter_map(|(name, _)| seen.get_key_value(name))
        .collect();
    table(
        "Symbols that push flagged ham over the threshold (by total score)",
        rows,
    );
}

fn print_flagged_ham(samples: &[&Sample], verdicts: &[Verdict], tag: f64, top: usize) {
    let mut flagged: Vec<(&str, f64)> = samples
        .iter()
        .zip(verdicts)
        .filter(|(s, v)| !s.spam && v.score >= tag)
        .map(|(s, v)| (s.file.as_str(), v.score))
        .collect();
    flagged.sort_by(|a, b| b.1.total_cmp(&a.1));
    if flagged.is_empty() {
        return;
    }
    let shown: Vec<String> = flagged
        .iter()
        .take(top)
        .map(|(file, score)| format!("`{file}` ({score:.1})"))
        .collect();
    println!("Highest-scoring ham files: {}\n", shown.join(", "));
}

fn untrained() -> Model {
    Model::new(Params::default()).expect("model")
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Args::parse();
    let mut samples = load(&args.spam, true, args.limit);
    samples.extend(load(&args.ham, false, args.limit));
    assert!(
        samples.iter().any(|s| s.spam) && samples.iter().any(|s| !s.spam),
        "need both spam and ham"
    );
    let rules = Arc::new(RuleSet::bundled().expect("bundled rules"));
    let base = offline(&rules).build().expect("engine");
    let thresholds = base.thresholds();
    let tag = thresholds.tag.unwrap_or(6.0);
    let reject = thresholds.reject.unwrap_or(15.0);

    let all: Vec<&Sample> = samples.iter().collect();
    let verdicts = judge(&base, &all).await;
    println!("## Pellet evaluation\n");
    println!(
        "Offline checks only (headers, addresses, encoding, Message-ID, Received, subject, MIME, HTML, URLs, rules); no DNS, authentication, dates or reputation. Thresholds: tag {tag}, reject {reject} (bundled scores).\n"
    );
    print_summary("Rules and heuristics", &all, &verdicts, tag, reject);
    print_symbols(&all, &verdicts, tag, args.top);
    print_flagged_ham(&all, &verdicts, tag, args.top);

    type Indexed<'a> = Vec<(usize, &'a Sample)>;
    let (mut train, test): (Indexed, Indexed) =
        samples.iter().enumerate().partition(|(i, _)| i % 2 == 0);
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for i in (1..train.len()).rev() {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        train.swap(i, (seed % (i as u64 + 1)) as usize);
    }
    let mut model = untrained();
    for (i, sample) in &train {
        let symbols: Vec<Symbol> = verdicts[*i]
            .symbols
            .iter()
            .map(|s| Symbol::new(s.name.clone()))
            .collect();
        model.train(
            &document(&sample.message, &Envelope::default(), &symbols),
            sample.spam,
        );
    }
    let mut right = [0usize; 2];
    let mut total = [0usize; 2];
    for (i, sample) in &test {
        let symbols: Vec<Symbol> = verdicts[*i]
            .symbols
            .iter()
            .map(|s| Symbol::new(s.name.clone()))
            .collect();
        let p = model.predict(&document(&sample.message, &Envelope::default(), &symbols));
        let k = usize::from(sample.spam);
        total[k] += 1;
        right[k] += usize::from((p > 0.5) == sample.spam);
    }
    let classifier = Arc::new(ClassifierCheck::new(
        model,
        ClassifierConfig {
            min_ham: 0,
            min_spam: 0,
            auto_learn: false,
            ..ClassifierConfig::default()
        },
    ));
    let with_classifier = offline(&rules).check(classifier).build().expect("engine");
    let test_samples: Vec<&Sample> = test.iter().map(|(_, s)| *s).collect();
    println!(
        "Classifier alone on the test half (p > 0.5): spam {} right, ham {} right.\n",
        percent(right[1], total[1]),
        percent(right[0], total[0])
    );
    let test_verdicts = judge(&with_classifier, &test_samples).await;
    print_summary(
        &format!(
            "With the classifier, trained on the other half ({} messages in random order, one pass)",
            train.len()
        ),
        &test_samples,
        &test_verdicts,
        tag,
        reject,
    );
    print_symbols(&test_samples, &test_verdicts, tag, args.top);
}
