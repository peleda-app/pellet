#![allow(dead_code)]

use std::sync::OnceLock;

use pellet_core::Envelope;

pub fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime")
    })
}

/// Splits the input at the first NUL: the part before it is an envelope (lines: client address,
/// client PTR, HELO, MAIL FROM, comma-separated recipients, flags), the rest is the message.
/// Without a NUL the whole input is the message under a typical inbound envelope.
pub fn envelope_and_message(data: &[u8]) -> (Envelope, &[u8]) {
    let Some(nul) = data.iter().position(|&b| b == 0) else {
        let envelope = Envelope {
            client_ip: Some("192.0.2.1".parse().expect("address")),
            helo: Some("mail.example.com".into()),
            mail_from: Some("sender@example.com".into()),
            recipients: vec!["reader@example.org".into()],
            ..Envelope::default()
        };
        return (envelope, data);
    };
    let head = String::from_utf8_lossy(&data[..nul]);
    let mut lines = head.split('\n');
    let mut field = || lines.next().map(str::to_owned);
    let client_ip = field().and_then(|s| s.trim().parse().ok());
    let client_ptr = field().filter(|s| !s.is_empty());
    let helo = field().filter(|s| !s.is_empty());
    let mail_from = field();
    let recipients = field()
        .map(|s| s.split(',').map(str::to_owned).take(64).collect())
        .unwrap_or_default();
    let flags = field().and_then(|s| s.bytes().next()).unwrap_or(0);
    let envelope = Envelope {
        client_ip,
        client_ptr,
        helo,
        mail_from,
        recipients,
        tls: flags & 1 != 0,
        authenticated: flags & 2 != 0,
    };
    (envelope, &data[nul + 1..])
}
