use std::{collections::HashMap, fmt};

use serde::{Deserialize, Serialize};

use crate::{CoreError, SymbolName};

/// The weight of every known symbol, and actions some symbols force.
///
/// A symbol missing from the table scores `0.0` and is still reported. Every score is finite.
/// A forced action applies whenever its symbol fires, whatever the total score; it can only make
/// the verdict stricter.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScoreTable {
    scores: HashMap<SymbolName, f64>,
    forced: HashMap<SymbolName, Action>,
}

impl ScoreTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets a symbol's score, replacing any earlier one.
    pub fn insert(&mut self, name: SymbolName, score: f64) -> Result<(), CoreError> {
        if !score.is_finite() {
            return Err(CoreError::NonFiniteScore(name.to_string()));
        }
        self.scores.insert(name, score);
        Ok(())
    }

    /// Makes a symbol force `action` (`tag`, `greylist` or `reject`) when it fires.
    pub fn force(&mut self, name: SymbolName, action: Action) {
        self.forced.insert(name, action);
    }

    /// The action a symbol forces, if any.
    pub fn forced(&self, name: &SymbolName) -> Option<Action> {
        self.forced.get(name).copied()
    }

    /// Builds a table from name–score pairs; later pairs win.
    pub fn from_pairs<I, S>(pairs: I) -> Result<Self, CoreError>
    where
        I: IntoIterator<Item = (S, f64)>,
        S: AsRef<str>,
    {
        let mut table = Self::new();
        for (name, score) in pairs {
            table.insert(SymbolName::new(name.as_ref())?, score)?;
        }
        Ok(table)
    }

    /// The symbol's score, `0.0` when unknown.
    pub fn score(&self, name: &SymbolName) -> f64 {
        self.scores.get(name).copied().unwrap_or(0.0)
    }

    /// Whether the table has a score or a forced action for the symbol.
    pub fn contains(&self, name: &SymbolName) -> bool {
        self.scores.contains_key(name) || self.forced.contains_key(name)
    }

    /// Every symbol with a score, in no particular order.
    pub fn names(&self) -> impl Iterator<Item = &SymbolName> {
        self.scores.keys().chain(self.forced.keys())
    }

    /// Number of symbols with a numeric score.
    pub fn len(&self) -> usize {
        self.scores.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.scores.is_empty() && self.forced.is_empty()
    }
}

/// What the host should do with a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Deliver normally.
    Accept,
    /// Deliver, marked as spam (headers, junk folder).
    Tag,
    /// Refuse temporarily (`451`); a legitimate sender retries.
    Greylist,
    /// Refuse permanently (`550` or `554`).
    Reject,
}

impl Action {
    /// Reads `accept`, `tag`, `greylist` or `reject`.
    pub fn parse(name: &str) -> Option<Action> {
        Some(match name {
            "accept" => Action::Accept,
            "tag" => Action::Tag,
            "greylist" => Action::Greylist,
            "reject" => Action::Reject,
            _ => return None,
        })
    }

    /// The lowercase name used in configuration and output.
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Accept => "accept",
            Action::Tag => "tag",
            Action::Greylist => "greylist",
            Action::Reject => "reject",
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Score thresholds for each action; an action without a threshold never happens.
///
/// The action for a score is the one whose threshold is the highest that the score reaches; on
/// equal thresholds the more severe action wins. The default only tags, at `6.0`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Thresholds {
    /// Score at which a message is tagged.
    pub tag: Option<f64>,
    /// Score at which a message is greylisted.
    pub greylist: Option<f64>,
    /// Score at which a message is rejected.
    pub reject: Option<f64>,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            tag: Some(6.0),
            greylist: None,
            reject: None,
        }
    }
}

impl Thresholds {
    /// No action ever fires: everything is accepted.
    pub const NONE: Thresholds = Thresholds {
        tag: None,
        greylist: None,
        reject: None,
    };

    /// Checks that every threshold is finite.
    pub fn validate(&self) -> Result<(), CoreError> {
        for (name, value) in self.entries() {
            if !value.is_finite() {
                return Err(CoreError::NonFiniteScore(format!("threshold {name}")));
            }
        }
        Ok(())
    }

    /// The action for a score.
    pub fn action(&self, score: f64) -> Action {
        [
            (Action::Tag, self.tag),
            (Action::Greylist, self.greylist),
            (Action::Reject, self.reject),
        ]
        .into_iter()
        .filter_map(|(action, threshold)| threshold.map(|t| (action, t)))
        .filter(|&(_, threshold)| score >= threshold)
        .max_by(|a, b| a.1.total_cmp(&b.1).then(a.0.cmp(&b.0)))
        .map_or(Action::Accept, |(action, _)| action)
    }

    fn entries(&self) -> impl Iterator<Item = (&'static str, f64)> {
        [
            ("tag", self.tag),
            ("greylist", self.greylist),
            ("reject", self.reject),
        ]
        .into_iter()
        .filter_map(|(n, v)| v.map(|v| (n, v)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> SymbolName {
        SymbolName::new(s).unwrap()
    }

    #[test]
    fn unknown_symbols_score_zero() {
        let table = ScoreTable::from_pairs([("KNOWN", 2.5)]).unwrap();
        assert_eq!(table.score(&name("KNOWN")), 2.5);
        assert_eq!(table.score(&name("UNKNOWN")), 0.0);
        assert!(!table.contains(&name("UNKNOWN")));
    }

    #[test]
    fn refuses_non_finite_scores_and_bad_names() {
        assert!(ScoreTable::from_pairs([("A", f64::NAN)]).is_err());
        assert!(ScoreTable::from_pairs([("A", f64::INFINITY)]).is_err());
        assert!(ScoreTable::from_pairs([("bad", 1.0)]).is_err());
    }

    #[test]
    fn later_pairs_win() {
        let table = ScoreTable::from_pairs([("A", 1.0), ("A", 3.0)]).unwrap();
        assert_eq!(table.score(&name("A")), 3.0);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn forced_actions() {
        let mut table = ScoreTable::new();
        table.force(name("BLOCKED"), Action::Reject);
        assert_eq!(table.forced(&name("BLOCKED")), Some(Action::Reject));
        assert_eq!(table.forced(&name("OTHER")), None);
        assert!(table.contains(&name("BLOCKED")));
        assert_eq!(table.score(&name("BLOCKED")), 0.0);
        assert_eq!(table.len(), 0);
        assert!(!table.is_empty());
    }

    #[test]
    fn highest_reached_threshold_decides() {
        let t = Thresholds {
            tag: Some(6.0),
            greylist: Some(4.0),
            reject: Some(15.0),
        };
        assert_eq!(t.action(-1.0), Action::Accept);
        assert_eq!(t.action(3.99), Action::Accept);
        assert_eq!(t.action(4.0), Action::Greylist);
        assert_eq!(t.action(6.0), Action::Tag);
        assert_eq!(t.action(14.0), Action::Tag);
        assert_eq!(t.action(15.0), Action::Reject);
    }

    #[test]
    fn equal_thresholds_pick_the_more_severe() {
        let t = Thresholds {
            tag: Some(5.0),
            greylist: None,
            reject: Some(5.0),
        };
        assert_eq!(t.action(5.0), Action::Reject);
    }

    #[test]
    fn defaults_only_tag() {
        assert_eq!(Thresholds::default().action(100.0), Action::Tag);
        assert_eq!(Thresholds::NONE.action(100.0), Action::Accept);
    }

    #[test]
    fn validate_refuses_nan() {
        let t = Thresholds {
            tag: Some(f64::NAN),
            ..Thresholds::NONE
        };
        assert!(t.validate().is_err());
        assert!(Thresholds::default().validate().is_ok());
    }
}
