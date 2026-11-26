use std::sync::{Arc, Mutex};

use pellet_check::testing::{Fixture, conformance};
use pellet_core::Message;

use super::*;

const SPAM: &str = "From: ana@example.com\r\nSubject: offer\r\n\r\nBuy cheap watches today.\r\nLimited stock available.\r\n";

#[derive(Clone, Copy)]
enum Reply {
    Counts(u64, u64),
    WrongThread,
    Silent,
}

async fn server(reply: Reply) -> (String, Arc<Mutex<Vec<String>>>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap().to_string();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let (len, from) = socket.recv_from(&mut buf).await.unwrap();
            let text = String::from_utf8_lossy(&buf[..len]).into_owned();
            log.lock().unwrap().push(text.clone());
            let thread: u16 = text
                .lines()
                .find_map(|l| l.strip_prefix("Thread: "))
                .unwrap()
                .parse()
                .unwrap();
            let answer = match reply {
                Reply::Counts(count, wl) => {
                    format!(
                        "Code: 200\nDiag: OK\nPV: 2.1\nThread: {thread}\nCount: {count}\nWL-Count: {wl}\n\n"
                    )
                }
                Reply::WrongThread => format!(
                    "Code: 200\nDiag: OK\nPV: 2.1\nThread: {}\nCount: 99\nWL-Count: 0\n\n",
                    thread.wrapping_add(1)
                ),
                Reply::Silent => continue,
            };
            socket.send_to(answer.as_bytes(), from).await.unwrap();
        }
    });
    (addr, seen)
}

fn check(servers: Vec<String>) -> PyzorCheck {
    PyzorCheck::new(PyzorConfig {
        servers,
        min_count: 5,
        timeout: Duration::from_millis(200),
    })
}

async fn run(check: &PyzorCheck, raw: &str) -> Result<Vec<Symbol>, CheckError> {
    check.run(&Fixture::message(raw).context(Stage::Data)).await
}

#[tokio::test]
async fn reports_bulk_digests() {
    let (addr, seen) = server(Reply::Counts(12, 0)).await;
    let symbols = run(&check(vec![addr]), SPAM).await.unwrap();
    assert_eq!(symbols[0].name.as_str(), "PYZOR");
    assert_eq!(symbols[0].options, ["12"]);

    let sent = seen.lock().unwrap()[0].clone();
    let expected_digest = digest(&Message::new(SPAM.as_bytes())).unwrap();
    assert!(sent.starts_with(&format!(
        "Op: check\nOp-Digest: {expected_digest}\nThread: "
    )));
    assert!(sent.contains("\nUser: anonymous\n"));
    assert!(
        !sent.contains("watches"),
        "only the digest leaves the process"
    );
    let (unsigned, sig) = sent.trim().rsplit_once("\nSig: ").unwrap();
    let time: u64 = unsigned.rsplit_once("Time: ").unwrap().1.parse().unwrap();
    assert_eq!(sig, sign(unsigned, time));
}

#[tokio::test]
async fn whitelisted_or_rare_digests_are_quiet() {
    let (rare, _) = server(Reply::Counts(4, 0)).await;
    assert!(run(&check(vec![rare]), SPAM).await.unwrap().is_empty());
    let (listed, _) = server(Reply::Counts(50, 7)).await;
    assert!(run(&check(vec![listed]), SPAM).await.unwrap().is_empty());
}

#[tokio::test]
async fn falls_back_and_fails_temporarily() {
    let (silent, _) = server(Reply::Silent).await;
    let (wrong, _) = server(Reply::WrongThread).await;
    let (good, _) = server(Reply::Counts(9, 0)).await;
    let symbols = run(&check(vec![silent.clone(), good]), SPAM).await.unwrap();
    assert_eq!(symbols[0].options, ["9"]);
    assert!(matches!(
        run(&check(vec![silent, wrong]), SPAM).await,
        Err(CheckError::Temporary(_))
    ));
}

#[tokio::test]
async fn skips_messages_without_text_and_own_users() {
    let (addr, seen) = server(Reply::Counts(12, 0)).await;
    let check = check(vec![addr]);
    assert!(
        run(&check, "Subject: x\r\n\r\nhi\r\n")
            .await
            .unwrap()
            .is_empty()
    );
    let mut own = Fixture::message(SPAM);
    own.envelope.authenticated = true;
    assert!(
        check
            .run(&own.context(Stage::Data))
            .await
            .unwrap()
            .is_empty()
    );
    assert!(seen.lock().unwrap().is_empty());
}

#[test]
fn parses_answers() {
    let ok = "Code: 200\nDiag: OK\nPV: 2.1\nThread: 4000\nCount: 3\nWL-Count: 1\n";
    assert_eq!(
        parse(ok, 4000),
        Some(Counts {
            spam: 3,
            whitelist: 1
        })
    );
    assert_eq!(parse(ok, 4001), None);
    assert_eq!(parse("Code: 400\nThread: 4000\nCount: 3\n", 4000), None);
    assert_eq!(
        parse("Code: 200\nThread: 4000\nCount: 3\n", 4000),
        Some(Counts {
            spam: 3,
            whitelist: 0
        })
    );
}

#[tokio::test]
async fn passes_conformance() {
    let (addr, _) = server(Reply::Counts(12, 0)).await;
    conformance(
        &check(vec![addr]),
        &[
            Fixture::message(SPAM),
            Fixture::message("Subject: x\r\n\r\nhi\r\n"),
        ],
    )
    .await;
}

/// Talks to the real public server: `mise run network`. A `200` answer means the server
/// accepted the request; the digest of no lines at all is reported millions of times, which is
/// why messages without a qualifying line are never looked up.
#[tokio::test]
#[ignore = "talks to public.pyzor.org over the network"]
async fn public_server_accepts_our_requests() {
    let check = PyzorCheck::new(PyzorConfig {
        timeout: Duration::from_secs(5),
        ..PyzorConfig::default()
    });
    let digest = digest(&Message::new(SPAM.as_bytes())).unwrap();
    let server = &PyzorConfig::default().servers[0];
    let counts = check.ask(server, &digest).await;
    assert!(counts.is_some(), "public.pyzor.org gave no valid answer");
    let empty = check
        .ask(server, &digest::sha1_hex(b""))
        .await
        .expect("an answer for the empty digest");
    assert!(empty.spam > 1_000_000, "{empty:?}");
}

/// `vectors/digests.txt` holds the digests Pyzor's own client (1.1.2) computed for the messages
/// next to it; ours must equal every one.
#[test]
fn digests_match_pyzor() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors");
    let list = std::fs::read_to_string(dir.join("digests.txt")).unwrap();
    let mut wrong = Vec::new();
    for line in list.lines() {
        let (expected, name) = line.split_once(' ').unwrap();
        let raw = std::fs::read(dir.join(name)).unwrap();
        let ours = digest(&Message::new(raw)).unwrap_or_default();
        if ours != expected {
            wrong.push(format!("{name}: {ours} instead of {expected}"));
        }
    }
    assert!(list.lines().count() >= 30);
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn parse_response_accepts_only_a_200_for_the_thread() {
    let ok = "Code: 200\nDiag: OK\nThread: 7\nCount: 12\nWL-Count: 1\n\n";
    assert_eq!(testing::parse_response(ok, 7), Some((12, 1)));
    assert_eq!(testing::parse_response(ok, 8), None);
    assert_eq!(
        testing::parse_response("Code: 200\nThread: 7\nCount: 3\n", 7),
        Some((3, 0))
    );
    assert_eq!(
        testing::parse_response("Code: 500\nThread: 7\nCount: 3\n", 7),
        None
    );
    assert_eq!(
        testing::parse_response("Code: 200\nThread: 7\nCount: -1\n", 7),
        None
    );
    assert_eq!(testing::parse_response("\u{0}\u{ff}Count:\n", 7), None);
}
