//! Pyzor: asks a Pyzor server how often others reported a message's digest as spam.
//!
//! Written from the documented Pyzor protocol; no Pyzor code is used.

mod digest;

use std::{
    sync::atomic::{AtomicU16, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use pellet_check::{Check, CheckError, Context, symbol_names};
use pellet_core::{Stage, Symbol, SymbolName};
use tokio::net::UdpSocket;

pub use digest::digest;

/// Where to ask and when a digest counts as bulk spam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyzorConfig {
    /// Servers as `host:port`, asked in order until one answers.
    pub servers: Vec<String>,
    /// Reports a digest needs before `PYZOR` fires; it must also be whitelisted fewer times.
    pub min_count: u64,
    /// Longest wait for one server.
    pub timeout: Duration,
}

impl Default for PyzorConfig {
    fn default() -> Self {
        PyzorConfig {
            servers: vec!["public.pyzor.org:24441".into()],
            min_count: 5,
            timeout: Duration::from_secs(2),
        }
    }
}

/// The Pyzor lookup at [`Stage::Data`].
///
/// | Symbol | When |
/// | --- | --- |
/// | `PYZOR` | the server counts at least `min_count` spam reports of the message's digest and fewer than `min_count` whitelist entries; the option is the report count |
///
/// Only the digest leaves the process: a SHA-1 over normalized lines of the text parts (see
/// [`digest`]), sent as an anonymous `check` over UDP. Messages with no qualifying text line and messages from authenticated clients are not
/// looked up. Server names resolve through the system resolver. When no server answers within
/// its `timeout` the check fails with [`CheckError::Temporary`], which the engine records
/// without a symbol.
pub struct PyzorCheck {
    config: PyzorConfig,
    declared: Vec<SymbolName>,
    thread: AtomicU16,
}

/// What a server said about a digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Counts {
    spam: u64,
    whitelist: u64,
}

const USER: &str = "anonymous";

fn sign(request: &str, time: u64) -> String {
    let key = digest::sha1_hex(format!("{USER}:").as_bytes());
    let mut signed = digest::sha1_raw(request.trim().as_bytes()).to_vec();
    signed.extend_from_slice(format!(":{time}:{key}").as_bytes());
    digest::sha1_hex(&signed)
}

fn request(digest: &str, thread: u16, time: u64) -> String {
    let unsigned = format!(
        "Op: check\nOp-Digest: {digest}\nThread: {thread}\nPV: 2.1\nUser: {USER}\nTime: {time}"
    );
    let sig = sign(&unsigned, time);
    format!("{unsigned}\nSig: {sig}\n\n")
}

fn parse(response: &str, thread: u16) -> Option<Counts> {
    let field = |name: &str| {
        response.lines().find_map(|l| {
            let (key, value) = l.split_once(':')?;
            key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
        })
    };
    if field("Code")? != "200" || field("Thread")?.parse::<u16>().ok()? != thread {
        return None;
    }
    Some(Counts {
        spam: field("Count")?.parse().ok()?,
        whitelist: field("WL-Count").map_or(Some(0), |v| v.parse().ok())?,
    })
}

impl PyzorCheck {
    /// Builds the check.
    pub fn new(config: PyzorConfig) -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        PyzorCheck {
            config,
            declared: symbol_names(&["PYZOR"]),
            thread: AtomicU16::new((seed % 64_512) as u16),
        }
    }

    fn next_thread(&self) -> u16 {
        1024 + self.thread.fetch_add(1, Ordering::Relaxed) % 64_512
    }

    async fn ask(&self, server: &str, digest: &str) -> Option<Counts> {
        let target = tokio::net::lookup_host(server).await.ok()?.next()?;
        let bind = if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind).await.ok()?;
        let thread = self.next_thread();
        let time = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        socket
            .send_to(request(digest, thread, time).as_bytes(), target)
            .await
            .ok()?;
        let wait = async {
            let mut buf = [0u8; 2048];
            loop {
                let (len, from) = socket.recv_from(&mut buf).await.ok()?;
                if from != target {
                    continue;
                }
                if let Some(counts) = parse(&String::from_utf8_lossy(&buf[..len]), thread) {
                    return Some(counts);
                }
            }
        };
        tokio::time::timeout(self.config.timeout, wait).await.ok()?
    }
}

#[async_trait]
impl Check for PyzorCheck {
    fn name(&self) -> &str {
        "pyzor"
    }

    fn stage(&self) -> Stage {
        Stage::Data
    }

    fn symbols(&self) -> &[SymbolName] {
        &self.declared
    }

    async fn run(&self, ctx: &Context<'_>) -> Result<Vec<Symbol>, CheckError> {
        if ctx.envelope.authenticated {
            return Ok(Vec::new());
        }
        let Some(digest) = ctx.message.and_then(digest) else {
            return Ok(Vec::new());
        };
        for server in &self.config.servers {
            if let Some(counts) = self.ask(server, &digest).await {
                let min = self.config.min_count;
                let hit = counts.spam >= min && counts.whitelist < min;
                return Ok(hit
                    .then(|| {
                        Symbol::new(self.declared[0].clone()).with_option(counts.spam.to_string())
                    })
                    .into_iter()
                    .collect());
            }
        }
        if self.config.servers.is_empty() {
            return Ok(Vec::new());
        }
        Err(CheckError::Temporary("no Pyzor server answered".into()))
    }
}

/// A fake Pyzor server for tests of hosts and corpora.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use tokio::net::UdpSocket;

    /// Serves on a loopback port, answering every `check` with these counts, and returns the
    /// address as `host:port`.
    pub async fn serve(count: u64, whitelist: u64) -> String {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let addr = socket.local_addr().expect("address").to_string();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((len, from)) = socket.recv_from(&mut buf).await {
                let text = String::from_utf8_lossy(&buf[..len]);
                let Some(thread) = text.lines().find_map(|l| l.strip_prefix("Thread: ")) else {
                    continue;
                };
                let answer = format!(
                    "Code: 200\nDiag: OK\nPV: 2.1\nThread: {thread}\nCount: {count}\nWL-Count: {whitelist}\n\n"
                );
                let _ = socket.send_to(answer.as_bytes(), from).await;
            }
        });
        addr
    }

    /// Reads a server response the way the check does: `(spam count, whitelist count)` when it is
    /// a `200` for `thread`, `None` otherwise. For fuzzing the response parser.
    pub fn parse_response(response: &str, thread: u16) -> Option<(u64, u64)> {
        super::parse(response, thread).map(|c| (c.spam, c.whitelist))
    }
}

#[cfg(test)]
mod tests;
