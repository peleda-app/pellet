//! The Pellet binary: `check` today; `serve` and `learn` come with the server and classifier.

mod config;
mod output;
mod snapshot;

use std::{
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::Context as _;
use async_trait::async_trait;
use clap::{Parser, Subcommand};
use pellet_check_auth::{AuthCheck, AuthConfig};
use pellet_check_classifier::ClassifierCheck;
use pellet_check_content::{
    AddressCheck, DateCheck, EncodingCheck, HeaderFlagsCheck, HeaderPresenceCheck, HeadersCheck,
    HtmlCheck, MessageIdCheck, MimeCheck, ReceivedCheck, SubjectCheck,
};
use pellet_check_ip::{DnsblCheck, FromHostCheck, HeloCheck, ReverseDnsCheck};
use pellet_check_pyzor::PyzorCheck;
use pellet_check_reputation::{ReplyCheck, ReputationCheck, ReputationConfig, TrapCheck};
use pellet_check_rules::{DnsListCheck, RulesCheck};
use pellet_check_url::UrlCheck;
use pellet_classifier::{Model, Params};
use pellet_core::{Envelope, Message, Symbol};
use pellet_dns::Resolver;
use pellet_dns_hickory::{HickoryConfig, HickoryResolver};
use pellet_engine::Engine;
use pellet_fetch::Fetch;
use pellet_fetch_http::HttpFetch;
use pellet_rules::RemoteLists;
use pellet_server::{Hooks, Learner, SentLog, ServerConfig};
use pellet_state_memory::MemoryState;

use crate::config::Config;

#[derive(Parser)]
#[command(name = "pellet", version, about = "Spam filter for weak hardware")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the verdict for a message file (`-` reads standard input).
    Check(CheckArgs),
    /// Train the classifier model file on messages marked as spam or ham.
    Learn(LearnArgs),
    /// Serve the HTTP API.
    Serve(ServeArgs),
}

#[derive(clap::Args)]
struct ServeArgs {
    /// Configuration; `[server]` and `[classifier] model` matter most here.
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(clap::Args)]
struct LearnArgs {
    /// The model file; created when missing.
    #[arg(long)]
    model: PathBuf,
    /// Spam message files.
    #[arg(long, num_args = 1.., required_unless_present = "ham")]
    spam: Vec<PathBuf>,
    /// Ham message files.
    #[arg(long, num_args = 1..)]
    ham: Vec<PathBuf>,
    /// Configuration, for the checks whose symbols become features and `[classifier] bits`.
    #[arg(long)]
    config: Option<PathBuf>,
}

/// The files with their labels in a fixed shuffled order: the classifier follows its latest
/// samples, so all spam followed by all ham would leave it calling everything ham.
fn interleaved(spam: &[PathBuf], ham: &[PathBuf]) -> Vec<(PathBuf, bool)> {
    let mut all: Vec<(PathBuf, bool)> = spam
        .iter()
        .map(|p| (p.clone(), true))
        .chain(ham.iter().map(|p| (p.clone(), false)))
        .collect();
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for i in (1..all.len()).rev() {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        all.swap(i, (seed % (i as u64 + 1)) as usize);
    }
    all
}

#[derive(clap::Args)]
struct CheckArgs {
    /// The message as an RFC 5322 file, or `-` for standard input.
    file: PathBuf,
    /// Configuration with `[scores]` and `[thresholds]`.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Client IP address.
    #[arg(long)]
    ip: Option<IpAddr>,
    /// Client reverse DNS name.
    #[arg(long)]
    ptr: Option<String>,
    /// HELO/EHLO name.
    #[arg(long)]
    helo: Option<String>,
    /// MAIL FROM address; an empty value is the null reverse path.
    #[arg(long)]
    from: Option<String>,
    /// RCPT TO address; repeat for several.
    #[arg(long = "rcpt")]
    recipients: Vec<String>,
    /// The session ran over TLS.
    #[arg(long)]
    tls: bool,
    /// The client authenticated.
    #[arg(long)]
    authenticated: bool,
    /// Print the verdict as JSON.
    #[arg(long)]
    json: bool,
    /// Also print the X-Spam-* header fields.
    #[arg(long)]
    headers: bool,
    /// A classifier model file to add the `PROB_*` symbols; it is read, never written.
    #[arg(long)]
    model: Option<PathBuf>,
}

fn engine(
    config: &Config,
    classifier: Option<Arc<ClassifierCheck>>,
    reputation: Option<Arc<ReputationCheck>>,
    replies: Option<Arc<ReplyCheck>>,
) -> anyhow::Result<(Engine, RemoteLists)> {
    let timeout = Duration::from_millis(config.dns.timeout_ms);
    let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::new(&HickoryConfig {
        nameservers: config.dns.nameservers.clone(),
        deadline: timeout,
        cache_size: config.dns.cache_size,
    })?);
    let auth = AuthCheck::new(&AuthConfig {
        nameservers: config.dns.nameservers.clone(),
        hostname: config.dns.hostname.clone(),
        cache_entries: usize::try_from(config.dns.cache_size).unwrap_or(usize::MAX),
        dns_timeout: timeout,
    })?;
    let rules = Arc::new(config.rule_set()?);
    let remote = rules.lists().remote();
    if let Some(dir) = &config.feeds.dir {
        for list in config.feeds(&rules)? {
            pellet_feeds::restore(&list, &rules.lists().remote(), dir);
        }
    }
    let scores = config.scores(rules.scores())?;
    let mut builder = Engine::builder()
        .check(Arc::new(ReverseDnsCheck::new(resolver.clone())))
        .check(Arc::new(HeloCheck::new(resolver.clone())))
        .check(Arc::new(FromHostCheck::new(resolver.clone())))
        .check(Arc::new(HeadersCheck::new()))
        .check(Arc::new(HeaderPresenceCheck::from_symbols(
            rules.referenced_symbols(),
        )))
        .check(Arc::new(HeaderFlagsCheck::new()))
        .check(Arc::new(AddressCheck::new().alias_domains(
            rules.lists().entries("alias-relays").map(|(d, _)| d),
        )))
        .check(Arc::new(EncodingCheck::new()))
        .check(Arc::new(MessageIdCheck::new()))
        .check(Arc::new(DateCheck::new()))
        .check(Arc::new(ReceivedCheck::new()))
        .check(Arc::new(SubjectCheck::new()))
        .check(Arc::new(MimeCheck::new(
            rules.lists().entries("file-extensions"),
        )))
        .check(Arc::new(HtmlCheck::new()))
        .check(Arc::new(
            UrlCheck::new(
                rules
                    .lists()
                    .entries("url-redirectors")
                    .map(|(host, _)| host),
            )
            .click_trackers(rules.lists().entries("click-trackers").map(|(h, _)| h)),
        ))
        .check(Arc::new(auth))
        .check(Arc::new(RulesCheck::new(rules.clone())));
    if let Some(classifier) = classifier {
        builder = builder.check(classifier);
    }
    if let Some(reputation) = reputation {
        builder = builder.check(reputation);
    }
    if let Some(replies) = replies {
        builder = builder.check(replies);
    }
    if !config.traps.addresses.is_empty() {
        builder = builder.check(Arc::new(TrapCheck::new(&config.traps.addresses)));
    }
    if let Some(pyzor) = config.pyzor_config() {
        builder = builder.check(Arc::new(PyzorCheck::new(pyzor)));
    }
    if config.rules.dns_lists {
        builder = builder.check(Arc::new(DnsListCheck::new(rules, resolver.clone())));
    }
    let zones = config.dnsbl_zones()?;
    if !zones.is_empty() {
        builder = builder.check(Arc::new(DnsblCheck::new(resolver, zones)));
    }
    let engine = builder
        .scores(scores)
        .thresholds(config.thresholds)
        .deadline(config.deadline())
        .build()?;
    Ok((engine, remote))
}

fn read_message(path: &Path) -> anyhow::Result<Message> {
    let mut raw = Vec::new();
    if path == Path::new("-") {
        std::io::stdin()
            .read_to_end(&mut raw)
            .context("reading standard input")?;
    } else {
        raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    }
    Ok(Message::new(raw))
}

async fn check(args: CheckArgs) -> anyhow::Result<()> {
    let config = match &args.config {
        Some(path) => Config::load(path)?,
        None => Config::default(),
    };
    let classifier = match args.model.as_deref() {
        Some(path) => Some(Arc::new(ClassifierCheck::new(
            load_model(path)?,
            config.classifier_config(),
        ))),
        None => None,
    };
    let state = open_state(&config)?;
    let reputation = Arc::new(ReputationCheck::new(
        state.clone(),
        ReputationConfig::default(),
    ));
    let replies = config
        .replies
        .enabled
        .then(|| Arc::new(ReplyCheck::new(state, config.reply_config())));
    let (engine, _) = engine(&config, classifier, Some(reputation), replies)?;
    let message = read_message(&args.file)?;
    let envelope = Envelope {
        client_ip: args.ip,
        client_ptr: args.ptr,
        helo: args.helo,
        mail_from: args.from,
        recipients: args.recipients,
        tls: args.tls,
        authenticated: args.authenticated,
    };
    let verdict = engine.check_message(envelope, message).await;
    let text = if args.json {
        serde_json::to_string_pretty(&verdict)? + "\n"
    } else {
        output::text(&verdict, args.headers)
    };
    print!("{text}");
    Ok(())
}

fn load_model(path: &Path) -> anyhow::Result<Model> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Model::from_bytes(&bytes).with_context(|| format!("loading {}", path.display()))
}

fn save_model(path: &Path, model: &Model) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, model.to_bytes()).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
}

async fn learn(args: LearnArgs) -> anyhow::Result<()> {
    let config = match &args.config {
        Some(path) => Config::load(path)?,
        None => Config::default(),
    };
    let model = if args.model.exists() {
        load_model(&args.model)?
    } else {
        Model::new(Params {
            bits: config.classifier.bits,
            ..Params::default()
        })?
    };
    let (engine, _) = engine(&config, None, None, None)?;
    let classifier = ClassifierCheck::new(model, config.classifier_config());
    let files = interleaved(&args.spam, &args.ham);
    for (file, spam) in &files {
        let message = read_message(file)?;
        let verdict = engine
            .check_message(Envelope::default(), message.clone())
            .await;
        let symbols: Vec<Symbol> = verdict
            .symbols
            .into_iter()
            .map(|s| Symbol::new(s.name))
            .collect();
        classifier.learn(&message, &Envelope::default(), &symbols, *spam);
    }
    let model = classifier.snapshot();
    save_model(&args.model, &model)?;
    let (ham, spam) = model.samples();
    println!(
        "learned {} spam and {} ham message(s); the model now has {ham} ham and {spam} spam",
        args.spam.len(),
        args.ham.len()
    );
    Ok(())
}

/// The in-memory state, filled from the snapshot file when there is one.
fn open_state(config: &Config) -> anyhow::Result<Arc<MemoryState>> {
    let state = Arc::new(MemoryState::new(config.state.entries));
    if let Some(path) = &config.state.path
        && path.exists()
    {
        state.import(snapshot::load(path)?);
    }
    Ok(state)
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

struct ReplyLog(Arc<ReplyCheck>);

#[async_trait]
impl SentLog for ReplyLog {
    async fn record(&self, message: &Message, envelope: &Envelope) -> bool {
        self.0.record_sent(message, envelope).await.unwrap_or(false)
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

async fn shutdown_signal() {
    let interrupt = tokio::signal::ctrl_c();
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = interrupt => {}
        _ = terminate => {}
    }
}

/// Saves the model when it learned something since the last save.
fn save_if_changed(
    path: &Path,
    classifier: &ClassifierCheck,
    saved: &mut u64,
) -> anyhow::Result<()> {
    let updates = classifier.updates();
    if updates != *saved {
        save_model(path, &classifier.snapshot())?;
        *saved = updates;
        tracing::info!(updates, "model saved");
    }
    Ok(())
}

async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    let config = match &args.config {
        Some(path) => Config::load(path)?,
        None => Config::default(),
    };
    let persisted = match &config.classifier.model {
        Some(path) => {
            let model = if path.exists() {
                load_model(path)?
            } else {
                Model::new(Params {
                    bits: config.classifier.bits,
                    ..Params::default()
                })?
            };
            Some((
                path.clone(),
                Arc::new(ClassifierCheck::new(model, config.classifier_config())),
            ))
        }
        None => None,
    };
    let classifier = persisted.as_ref().map(|(_, c)| c.clone());
    let state = open_state(&config)?;
    let reputation = Arc::new(ReputationCheck::new(
        state.clone(),
        ReputationConfig::default(),
    ));
    let replies = config
        .replies
        .enabled
        .then(|| Arc::new(ReplyCheck::new(state.clone(), config.reply_config())));
    let (engine, remote) = engine(
        &config,
        classifier.clone(),
        Some(reputation.clone()),
        replies.clone(),
    )?;
    let mut learners: Vec<Arc<dyn Learner>> = Vec::new();
    if let Some(classifier) = &classifier {
        learners.push(Arc::new(ClassifierLearner(classifier.clone())));
    }
    learners.push(Arc::new(ReputationLearner(reputation)));
    let app = pellet_server::router(
        engine,
        Hooks {
            learners,
            sent: replies.map(|r| Arc::new(ReplyLog(r)) as Arc<dyn SentLog>),
        },
        ServerConfig {
            token: config.server.token.clone(),
            max_message_size: config.server.max_message_size,
        },
    );
    let feeds = config.feeds(&config.rule_set()?)?;
    if let Some(dir) = config.feeds.dir.clone()
        && !feeds.is_empty()
    {
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let fetch: Arc<dyn Fetch> = Arc::new(HttpFetch::new()?);
        for list in feeds {
            tokio::spawn(pellet_feeds::keep_fresh(
                list,
                fetch.clone(),
                remote.clone(),
                dir.clone(),
                config.feeds.max_entries,
            ));
        }
    }
    let listener = tokio::net::TcpListener::bind(config.server.listen)
        .await
        .with_context(|| format!("binding {}", config.server.listen))?;
    println!("listening on {}", listener.local_addr()?);

    let saver = persisted.clone().map(|(path, classifier)| {
        let interval = Duration::from_secs(config.classifier.save_interval_secs.max(1));
        tokio::spawn(async move {
            let mut saved = classifier.updates();
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if let Err(error) = save_if_changed(&path, &classifier, &mut saved) {
                    tracing::warn!(%error, "saving the model failed");
                }
            }
        })
    });

    let state_saver = config.state.path.clone().map(|path| {
        let state = state.clone();
        let interval = Duration::from_secs(config.state.save_interval_secs.max(1));
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if let Err(error) = snapshot::save(&path, &state.export()) {
                    tracing::warn!(%error, "saving the state failed");
                }
            }
        })
    });

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    if let Some(saver) = state_saver {
        saver.abort();
    }
    if let Some(path) = &config.state.path {
        snapshot::save(path, &state.export())?;
        tracing::info!("state saved at shutdown");
    }
    if let Some(saver) = saver {
        saver.abort();
    }
    if let Some((path, classifier)) = persisted {
        save_model(&path, &classifier.snapshot())?;
        tracing::info!("model saved at shutdown");
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("PELLET_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();
    match Cli::parse().command {
        Command::Check(args) => check(args).await,
        Command::Learn(args) => learn(args).await,
        Command::Serve(args) => serve(args).await,
    }
}
