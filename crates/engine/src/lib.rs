//! The pipeline: runs checks per stage, sums scores and picks an action.
//!
//! An [`Engine`] is built once from checks, a score table and thresholds, and is cheap to clone.
//! Each SMTP conversation gets a [`Session`] that walks the stages in order and accumulates
//! symbols; [`Engine::check_message`] runs every stage at once for a finished message.

mod headers;

use std::{collections::HashSet, sync::Arc, time::Duration};

use futures::future::join_all;
use pellet_check::{Check, Context};
use pellet_core::{
    CoreError, Envelope, Failure, FailureReason, Message, ScoreTable, ScoredSymbol, Stage, Symbol,
    SymbolName, Thresholds, Verdict,
};

pub use headers::headers;

/// Default time every check of one stage has to finish.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(5);

/// A configuration the engine refuses.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum EngineError {
    /// Two checks share a name.
    #[error("two checks are named {0:?}")]
    DuplicateCheck(String),
    /// A threshold is not a finite number.
    #[error(transparent)]
    Thresholds(#[from] CoreError),
}

/// Misuse of a [`Session`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// The stage already ran, or a later one did.
    #[error("stage {stage} cannot run after {last}")]
    OutOfOrder {
        /// The stage asked for.
        stage: Stage,
        /// The last stage that ran.
        last: Stage,
    },
    /// [`Stage::Data`] needs the message; use [`Session::data`].
    #[error("the data stage needs the message")]
    NeedsMessage,
}

/// Collects checks and settings for an [`Engine`].
pub struct EngineBuilder {
    checks: Vec<Arc<dyn Check>>,
    scores: ScoreTable,
    thresholds: Thresholds,
    deadline: Duration,
}

impl EngineBuilder {
    /// Adds a check; checks of one stage run concurrently, and their results are merged in the
    /// order they were added.
    pub fn check(mut self, check: Arc<dyn Check>) -> Self {
        self.checks.push(check);
        self
    }

    /// Sets the score table. Without one every symbol scores `0.0`.
    pub fn scores(mut self, scores: ScoreTable) -> Self {
        self.scores = scores;
        self
    }

    /// Sets the action thresholds. The default only tags, at `6.0`.
    pub fn thresholds(mut self, thresholds: Thresholds) -> Self {
        self.thresholds = thresholds;
        self
    }

    /// Sets how long the checks of one stage may take together. Default [`DEFAULT_DEADLINE`].
    pub fn deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// Validates the configuration.
    pub fn build(self) -> Result<Engine, EngineError> {
        self.thresholds.validate()?;
        let mut names = HashSet::new();
        let mut checks = Vec::with_capacity(self.checks.len());
        for check in self.checks {
            if !names.insert(check.name().to_string()) {
                return Err(EngineError::DuplicateCheck(check.name().to_string()));
            }
            let declared = check.symbols().iter().cloned().collect();
            checks.push(Registered { check, declared });
        }
        Ok(Engine {
            inner: Arc::new(Inner {
                checks,
                scores: self.scores,
                thresholds: self.thresholds,
                deadline: self.deadline,
            }),
        })
    }
}

struct Registered {
    check: Arc<dyn Check>,
    declared: HashSet<SymbolName>,
}

struct Inner {
    checks: Vec<Registered>,
    scores: ScoreTable,
    thresholds: Thresholds,
    deadline: Duration,
}

/// The configured pipeline. Cheap to clone; shared by every session.
#[derive(Clone)]
pub struct Engine {
    inner: Arc<Inner>,
}

impl Engine {
    /// Starts configuring an engine.
    pub fn builder() -> EngineBuilder {
        EngineBuilder {
            checks: Vec::new(),
            scores: ScoreTable::new(),
            thresholds: Thresholds::default(),
            deadline: DEFAULT_DEADLINE,
        }
    }

    /// Starts a conversation with what is known when the client connects.
    pub fn session(&self, envelope: Envelope) -> Session {
        Session {
            engine: self.clone(),
            envelope,
            message: None,
            symbols: Vec::new(),
            failures: Vec::new(),
            last: None,
        }
    }

    /// Runs every stage, in order, on a finished message and returns the final verdict.
    pub async fn check_message(&self, envelope: Envelope, message: Message) -> Verdict {
        let mut session = self.session(envelope);
        for stage in [Stage::Connect, Stage::Helo, Stage::Mail, Stage::Rcpt] {
            let _ = session.run(stage).await;
        }
        session.data(message).await.expect("data follows rcpt")
    }

    /// Every symbol any registered check may emit.
    pub fn declared_symbols(&self) -> std::collections::BTreeSet<SymbolName> {
        self.inner
            .checks
            .iter()
            .flat_map(|r| r.declared.iter().cloned())
            .collect()
    }

    /// The action thresholds it was built with.
    pub fn thresholds(&self) -> Thresholds {
        self.inner.thresholds
    }

    /// Names of the registered checks, in order.
    pub fn check_names(&self) -> Vec<&str> {
        self.inner.checks.iter().map(|r| r.check.name()).collect()
    }
}

/// One SMTP conversation: stages in order, symbols accumulated across them.
///
/// Stages may be skipped but never repeated or run backwards. Each stage's checks get the
/// envelope as it is when the stage runs and the symbols of earlier stages; late checks run after
/// the others of their stage, under the same deadline, and also see their symbols.
pub struct Session {
    engine: Engine,
    envelope: Envelope,
    message: Option<Message>,
    symbols: Vec<(Stage, Symbol)>,
    failures: Vec<Failure>,
    last: Option<Stage>,
}

impl Session {
    /// The envelope, to fill in as the conversation goes on (`helo`, `mail_from`, `recipients`).
    pub fn envelope_mut(&mut self) -> &mut Envelope {
        &mut self.envelope
    }

    /// The envelope as it stands.
    pub fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    /// Runs a stage before [`Stage::Data`] and returns the verdict so far.
    pub async fn run(&mut self, stage: Stage) -> Result<Verdict, SessionError> {
        if stage == Stage::Data {
            return Err(SessionError::NeedsMessage);
        }
        self.advance(stage).await
    }

    /// Runs [`Stage::Data`] on the message and returns the final verdict.
    pub async fn data(&mut self, message: Message) -> Result<Verdict, SessionError> {
        self.ensure_after(Stage::Data)?;
        self.message = Some(message);
        self.advance(Stage::Data).await
    }

    fn ensure_after(&self, stage: Stage) -> Result<(), SessionError> {
        match self.last {
            Some(last) if last >= stage => Err(SessionError::OutOfOrder { stage, last }),
            _ => Ok(()),
        }
    }

    async fn advance(&mut self, stage: Stage) -> Result<Verdict, SessionError> {
        self.ensure_after(stage)?;
        self.last = Some(stage);
        let inner = self.engine.inner.clone();
        let deadline = tokio::time::Instant::now() + inner.deadline;
        for late in [false, true] {
            let running: Vec<&Registered> = inner
                .checks
                .iter()
                .filter(|r| r.check.stage() == stage && r.check.late() == late)
                .collect();
            if running.is_empty() {
                continue;
            }
            let earlier: Vec<Symbol> = self.symbols.iter().map(|(_, s)| s.clone()).collect();
            let ctx = Context {
                stage,
                envelope: &self.envelope,
                message: self.message.as_ref().filter(|_| stage == Stage::Data),
                earlier: &earlier,
            };
            let results = join_all(
                running
                    .iter()
                    .map(|r| tokio::time::timeout_at(deadline, r.check.run(&ctx))),
            )
            .await;
            self.collect(stage, running, results);
        }

        let verdict = self.verdict(stage);
        tracing::debug!(
            stage = %stage,
            score = verdict.score,
            action = %verdict.action,
            symbols = verdict.symbols.len(),
            failures = verdict.failures.len(),
            "stage done"
        );
        Ok(verdict)
    }

    fn collect(
        &mut self,
        stage: Stage,
        running: Vec<&Registered>,
        results: Vec<
            Result<Result<Vec<Symbol>, pellet_check::CheckError>, tokio::time::error::Elapsed>,
        >,
    ) {
        for (registered, result) in running.into_iter().zip(results) {
            let name = registered.check.name();
            match result {
                Err(_) => self.fail(name, stage, FailureReason::Deadline),
                Ok(Err(error)) => self.fail(name, stage, FailureReason::Error(error.to_string())),
                Ok(Ok(symbols)) => {
                    for symbol in symbols {
                        if registered.declared.contains(&symbol.name) {
                            self.add(stage, symbol);
                        } else {
                            self.fail(name, stage, FailureReason::Undeclared(symbol.name));
                        }
                    }
                }
            }
        }
    }

    fn fail(&mut self, check: &str, stage: Stage, reason: FailureReason) {
        tracing::debug!(check, stage = %stage, ?reason, "check failed");
        self.failures.push(Failure {
            check: check.to_string(),
            stage,
            reason,
        });
    }

    fn add(&mut self, stage: Stage, symbol: Symbol) {
        match self.symbols.iter_mut().find(|(_, s)| s.name == symbol.name) {
            Some((_, existing)) => {
                for option in symbol.options {
                    if !existing.options.contains(&option) {
                        existing.push_option(option);
                    }
                }
            }
            None => self.symbols.push((stage, symbol)),
        }
    }

    fn verdict(&self, stage: Stage) -> Verdict {
        let inner = &self.engine.inner;
        let mut symbols: Vec<ScoredSymbol> = self
            .symbols
            .iter()
            .map(|(stage, symbol)| ScoredSymbol {
                score: inner.scores.score(&symbol.name),
                name: symbol.name.clone(),
                stage: *stage,
                options: symbol.options.clone(),
            })
            .collect();
        symbols.sort_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then_with(|| a.name.cmp(&b.name))
        });
        let score = symbols.iter().map(|s| s.score).sum::<f64>();
        let action = symbols
            .iter()
            .filter_map(|s| inner.scores.forced(&s.name))
            .fold(inner.thresholds.action(score), Ord::max);
        Verdict {
            stage,
            score,
            action,
            symbols,
            failures: self.failures.clone(),
        }
    }
}

#[cfg(test)]
mod tests;
