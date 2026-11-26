//! The binary end to end, fed through standard input.

use std::{
    io::Write,
    process::{Command, Stdio},
};

fn pellet(args: &[&str], stdin: &str) -> (bool, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pellet"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    (
        output.status.success(),
        String::from_utf8(output.stdout).unwrap(),
    )
}

const BARE: &str = "X-Mailer: test\r\n\r\nhello\r\n";

#[test]
fn prints_symbols_for_a_message() {
    let (ok, out) = pellet(&["check", "-"], BARE);
    assert!(ok);
    assert!(
        out.starts_with("action: tag  score: "),
        "bundled scores apply: {out}"
    );
    assert!(out.contains("MISSING_ESSENTIAL_HEADERS"), "{out}");
}

#[test]
fn applies_scores_and_thresholds_from_the_config() {
    let dir = std::env::temp_dir().join(format!("pellet-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("pellet.toml");
    std::fs::write(
        &config,
        "[rules]\nbundled = false\n[thresholds]\nreject = 9.0\n[scores]\nMISSING_ESSENTIAL_HEADERS = 7.0\nMISSING_FROM = 2.0\n",
    )
    .unwrap();
    let (ok, out) = pellet(
        &["check", "--json", "--config", config.to_str().unwrap(), "-"],
        BARE,
    );
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(ok);
    let verdict: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(verdict["action"], "reject");
    assert_eq!(verdict["score"], 9.0);
    assert_eq!(verdict["symbols"][0]["name"], "MISSING_ESSENTIAL_HEADERS");
}

#[test]
fn authenticated_flag_reaches_the_checks() {
    let (_, plain) = pellet(&["check", "-"], BARE);
    let (_, authenticated) = pellet(&["check", "--authenticated", "-"], BARE);
    assert!(plain.contains("MISSING_DATE"));
    assert!(!authenticated.contains("MISSING_DATE"));
}

#[test]
fn fails_on_a_missing_file() {
    let (ok, _) = pellet(&["check", "/nonexistent/message.eml"], "");
    assert!(!ok);
}

#[test]
fn learns_into_a_model_file_and_checks_with_it() {
    let dir = std::env::temp_dir().join(format!("pellet-learn-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("pellet.toml");
    std::fs::write(
        &config,
        "[rules]\nbundled = false\n[classifier]\nbits = 16\nmin_ham = 3\nmin_spam = 3\n",
    )
    .unwrap();
    let write = |name: &str, subject: &str, body: &str| {
        let path = dir.join(name);
        std::fs::write(&path, format!("Subject: {subject}\r\n\r\n{body}\r\n")).unwrap();
        path.to_str().unwrap().to_string()
    };
    let spam: Vec<String> = (0..4)
        .map(|i| {
            write(
                &format!("s{i}.eml"),
                "claim your prize",
                "winner casino bonus free prize claim now",
            )
        })
        .collect();
    let ham: Vec<String> = (0..4)
        .map(|i| {
            write(
                &format!("h{i}.eml"),
                "meeting notes",
                "agenda report review draft slides budget",
            )
        })
        .collect();
    let model = dir.join("model.bin");
    let model_arg = model.to_str().unwrap();
    let config_arg = config.to_str().unwrap();
    let mut args = vec![
        "learn", "--model", model_arg, "--config", config_arg, "--spam",
    ];
    args.extend(spam.iter().map(String::as_str));
    args.push("--ham");
    args.extend(ham.iter().map(String::as_str));
    let (ok, out) = pellet(&args, "");
    assert!(ok, "{out}");
    assert!(
        out.contains("learned 4 spam and 4 ham message(s); the model now has 4 ham and 4 spam"),
        "{out}"
    );

    let before = std::fs::read(&model).unwrap();
    let (ok, out) = pellet(
        &[
            "check", "--json", "--config", config_arg, "--model", model_arg, "-",
        ],
        "Subject: claim your prize\r\n\r\nwinner casino bonus free\r\n",
    );
    assert!(ok, "{out}");
    let verdict: serde_json::Value = serde_json::from_str(&out).unwrap();
    let names: Vec<&str> = verdict["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert!(
        names.iter().any(|n| n.starts_with("PROB_SPAM")),
        "{names:?}"
    );
    assert_eq!(
        std::fs::read(&model).unwrap(),
        before,
        "check never writes the model"
    );

    let (ok, _) = pellet(&["learn", "--model", model_arg, "--spam"], "");
    assert!(!ok, "a label needs files");
    let (ok, _) = pellet(&["learn", "--model", model_arg], "");
    assert!(!ok, "nothing to learn");
    std::fs::remove_dir_all(&dir).unwrap();
}

fn http(addr: &str, target: &str, body: &str) -> String {
    use std::io::Read;
    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    write!(
        stream,
        "POST {target} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

struct Server {
    child: std::process::Child,
    addr: String,
}

impl Server {
    fn start(config: &std::path::Path) -> Server {
        use std::io::BufRead;
        let mut child = Command::new(env!("CARGO_BIN_EXE_pellet"))
            .args(["serve", "--config", config.to_str().unwrap()])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let addr = line
            .trim()
            .strip_prefix("listening on ")
            .unwrap_or_else(|| panic!("unexpected first line {line:?}"))
            .to_string();
        Server { child, addr }
    }

    fn stop(mut self) {
        let status = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
        assert!(
            self.child.wait().unwrap().success(),
            "serve exits cleanly on SIGTERM"
        );
    }
}

#[cfg(unix)]
#[test]
fn serve_keeps_model_and_reputation_across_restarts() {
    let dir = std::env::temp_dir().join(format!("pellet-serve-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let model = dir.join("model.bin");
    let state = dir.join("state.bin");
    let config = dir.join("pellet.toml");
    std::fs::write(
        &config,
        format!(
            "[rules]\nbundled = false\n[server]\nlisten = \"127.0.0.1:0\"\n\
             [classifier]\nbits = 16\nmin_ham = 1\nmin_spam = 1\nmodel = {:?}\nsave_interval_secs = 1\n\
             [state]\npath = {:?}\nentries = 1000\n",
            model.to_str().unwrap(),
            state.to_str().unwrap()
        ),
    )
    .unwrap();
    let spam = "Subject: claim your prize\r\n\r\nwinner casino bonus free prize\r\n";
    let ham = "Subject: meeting notes\r\n\r\nagenda report review draft slides\r\n";

    let server = Server::start(&config);
    for _ in 0..5 {
        let response = http(&server.addr, "/v1/learn?label=spam&ip=192.0.2.50", spam);
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            response.contains("{\"learned\":[\"classifier\",\"reputation\"]}"),
            "{response}"
        );
    }
    server.stop();
    assert!(
        model.exists() && state.exists(),
        "model and state are saved at shutdown"
    );

    let server = Server::start(&config);
    http(&server.addr, "/v1/learn?label=ham", ham);
    let response = http(&server.addr, "/v1/check?ip=192.0.2.50", spam);
    assert!(
        response.contains("PROB_SPAM"),
        "the model survived: {response}"
    );
    assert!(
        response.contains("REPUTATION_IP_SPAM"),
        "the reputation survived: {response}"
    );
    std::thread::sleep(std::time::Duration::from_millis(2500));
    let saved = std::fs::read(&model).unwrap();
    server.stop();
    assert_eq!(
        &saved[37..45],
        &1u64.to_le_bytes(),
        "the interval save already holds the ham sample"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn check_reads_cached_feeds_without_downloading() {
    let dir = std::env::temp_dir().join(format!("pellet-feeds-cli-{}", std::process::id()));
    let feeds = dir.join("feeds");
    std::fs::create_dir_all(&feeds).unwrap();
    let url = "https://blog.example.net/wp-login.php";
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for b in url.bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let mut cache = b"PELLETF1".to_vec();
    cache.extend_from_slice(&1u64.to_le_bytes());
    cache.extend_from_slice(&hash.to_le_bytes());
    std::fs::write(feeds.join("stwt_openphish.fp"), cache).unwrap();
    let config = dir.join("pellet.toml");
    std::fs::write(
        &config,
        format!(
            "[feeds]\nenabled = [\"stwt_openphish\"]\ndir = {:?}\n",
            feeds.to_str().unwrap()
        ),
    )
    .unwrap();
    let message = format!(
        "Subject: login\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<a href=\"{url}\">Sign in</a>\r\n"
    );
    let (ok, out) = pellet(
        &["check", "--config", config.to_str().unwrap(), "-"],
        &message,
    );
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(ok, "{out}");
    assert!(out.contains("PHISHED_OPENPHISH"), "{out}");
}
