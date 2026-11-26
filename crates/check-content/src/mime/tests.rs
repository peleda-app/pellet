use pellet_check::testing::{Fixture, conformance};
use pellet_core::Message;

use super::*;

fn check() -> MimeCheck {
    MimeCheck::new([
        ("exe", "BAD"),
        ("js", "BAD, NZ"),
        ("zip", "AR"),
        ("rar", "AR"),
        ("pdf", "application/pdf, NZ"),
    ])
}

async fn names(raw: &str) -> Vec<String> {
    let fixture = Fixture {
        message: Some(Message::new(raw.replace('\n', "\r\n").into_bytes())),
        ..Fixture::default()
    };
    let mut names: Vec<String> = check()
        .run(&fixture.context(Stage::Data))
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.name.to_string())
        .collect();
    names.sort();
    names
}

fn has(names: &[String], name: &str) -> bool {
    names.iter().any(|n| n == name)
}

const ALTERNATIVE: &str = "MIME-Version: 1.0
Content-Type: multipart/alternative; boundary=\"b1\"

--b1
Content-Type: text/plain; charset=utf-8

The quarterly report is ready for review by the whole team this week.
--b1
Content-Type: text/html; charset=utf-8

<p>The quarterly report is ready for review by the whole team this week.</p>
--b1--
";

fn with_attachment(name: &str, disposition: bool) -> String {
    let disposition = if disposition {
        format!("Content-Disposition: attachment; filename=\"{name}\"\n")
    } else {
        String::new()
    };
    format!(
        "MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=\"m\"

--m
Content-Type: text/plain; charset=utf-8

Please find the document attached for your records.
--m
Content-Type: application/octet-stream; name=\"{name}\"
{disposition}Content-Transfer-Encoding: base64

AAAA
--m--
"
    )
}

#[tokio::test]
async fn good_alternative() {
    assert_eq!(names(ALTERNATIVE).await, ["MIME_GOOD"]);
}

#[tokio::test]
async fn alternatives_missing_a_side_or_differing() {
    let html_only = "MIME-Version: 1.0\nContent-Type: multipart/alternative; boundary=\"b\"\n\n--b\nContent-Type: text/html; charset=utf-8\n\n<p>Hello there friend</p>\n--b--\n";
    let n = names(html_only).await;
    assert!(
        has(&n, "MIME_MA_MISSING_TEXT") && has(&n, "MIME_HTML_ONLY"),
        "{n:?}"
    );
    let differ = ALTERNATIVE.replacen(
        "<p>The quarterly report is ready for review by the whole team this week.</p>",
        "<p>Claim your exclusive casino bonus now before midnight expires tonight forever</p>",
        1,
    );
    assert!(has(&names(&differ).await, "PARTS_DIFFER"));
}

#[tokio::test]
async fn attachments_and_extensions() {
    let n = names(&with_attachment("report.exe", true)).await;
    assert!(
        has(&n, "HAS_ATTACHMENT") && has(&n, "MIME_BAD_EXTENSION"),
        "{n:?}"
    );
    assert!(has(
        &names(&with_attachment("invoice.pdf.exe", true)).await,
        "MIME_DOUBLE_BAD_EXTENSION"
    ));
    assert!(has(
        &names(&with_attachment("files.zip.rar", true)).await,
        "MIME_ARCHIVE_IN_ARCHIVE"
    ));
    assert!(has(
        &names(&with_attachment("photo\u{202E}gpj.exe", true)).await,
        "MIME_BAD_UNICODE"
    ));
    assert!(has(
        &names(&with_attachment("data.bin", false)).await,
        "CTYPE_MISSING_DISPOSITION"
    ));
    let disguised = with_attachment("report.pdf", true)
        .replace("application/octet-stream", "application/x-msdownload");
    assert!(has(&names(&disguised).await, "MIME_BAD_ATTACHMENT"));
    let clean = names(&with_attachment("report.pdf", true)).await;
    assert!(!has(&clean, "MIME_BAD_EXTENSION") && !has(&clean, "CTYPE_MISSING_DISPOSITION"));
}

#[tokio::test]
async fn top_level_content_type() {
    let n = names("Content-Type: text/plain; charset=utf-8;\n\nHello there, a short note.\n").await;
    assert!(
        has(&n, "CT_EXTRA_SEMI")
            && has(&n, "MIME_HEADER_CTYPE_ONLY")
            && has(&n, "SINGLE_SHORT_PART"),
        "{n:?}"
    );
    assert!(has(
        &names("MIME-Version: 1.0\nContent-Type: textplain\n\nx\n").await,
        "BROKEN_CONTENT_TYPE"
    ));
}

#[tokio::test]
async fn charsets_and_encodings() {
    let n = names("MIME-Version: 1.0\nContent-Type: text/plain\n\ncaf\u{e9} au lait\n").await;
    assert!(has(&n, "MISSING_CHARSET"), "{n:?}");
    let n = names("MIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 7bit\n\ncaf\u{e9}\n").await;
    assert!(has(&n, "BAD_CTE_7BIT"));
    let n = names("MIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: base64\n\nSGVsbG8gdGhlcmU=\n").await;
    assert!(has(&n, "MIME_BASE64_TEXT") && has(&n, "MIME_BASE64_TEXT_BOGUS"));
    let n = names("MIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\nLog in to your P\u{430}yPal account\n").await;
    assert!(has(&n, "MIXED_CHARSET"));
}

#[tokio::test]
async fn signed_and_encrypted() {
    let signed = "MIME-Version: 1.0\nContent-Type: multipart/signed; protocol=\"application/pgp-signature\"; boundary=\"s\"\n\n--s\nContent-Type: text/plain; charset=utf-8\n\nSigned words for the record here.\n--s\nContent-Type: application/pgp-signature\n\nsig\n--s--\n";
    assert!(has(&names(signed).await, "SIGNED_PGP"));
    let encrypted = "MIME-Version: 1.0\nContent-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"e\"\n\n--e\nContent-Type: application/pgp-encrypted\n\nVersion: 1\n--e\nContent-Type: application/octet-stream\n\nopaque\n--e--\n";
    let n = names(encrypted).await;
    assert!(
        has(&n, "ENCRYPTED_PGP") && !has(&n, "BOGUS_ENCRYPTED_AND_TEXT"),
        "{n:?}"
    );
    let bogus = encrypted.replace("--e--\n", "--e\nContent-Type: text/plain; charset=utf-8\n\nBuy cheap watches here today, best prices.\n--e--\n");
    assert!(has(&names(&bogus).await, "BOGUS_ENCRYPTED_AND_TEXT"));
    let smime = "MIME-Version: 1.0\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m\nContent-Disposition: attachment; filename=smime.p7m\n\nopaque\n";
    assert!(has(&names(smime).await, "ENCRYPTED_SMIME"));
    let inline = "MIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\n-----BEGIN PGP MESSAGE-----\nhQEMA\n-----END PGP MESSAGE-----\n";
    assert!(has(&names(inline).await, "ENCRYPTED_PGP"));
}

#[tokio::test]
async fn reports_and_attached_messages() {
    let dsn = "MIME-Version: 1.0\nContent-Type: multipart/report; report-type=delivery-status; boundary=\"r\"\n\n--r\nContent-Type: text/plain; charset=utf-8\n\nYour message could not be delivered to the recipient.\n--r\nContent-Type: message/delivery-status\n\nAction: failed\n--r\nContent-Type: message/rfc822\n\nSubject: original\n\nbody\n--r--\n";
    let n = names(dsn).await;
    assert!(has(&n, "IS_DSN") && has(&n, "HAS_MESSAGE_PARTS"), "{n:?}");
}

#[tokio::test]
async fn mixed_with_only_text_and_many_parts() {
    let mixed = "MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"x\"\n\n--x\nContent-Type: text/plain; charset=utf-8\n\nfirst part of the text body here\n--x--\n";
    assert!(has(&names(mixed).await, "CTYPE_MIXED_BOGUS"));
    let mut many =
        String::from("MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"y\"\n\n");
    for _ in 0..MAX_PARTS + 5 {
        many.push_str("--y\nContent-Type: application/octet-stream\n\nx\n");
    }
    many.push_str("--y--\n");
    assert!(has(&names(&many).await, "MIME_LIMIT_EXCEEDED"));
}

#[test]
fn script_mixing() {
    assert!(mixed_scripts("P\u{430}yPal"));
    assert!(!mixed_scripts("PayPal и Привет"));
    assert!(!mixed_scripts("café 2026"));
}

#[tokio::test]
async fn passes_conformance() {
    let fixtures: Vec<Fixture> = [
        ALTERNATIVE.to_string(),
        with_attachment("invoice.pdf.exe", false),
        String::new(),
    ]
    .into_iter()
    .map(|raw| Fixture {
        message: Some(Message::new(raw.replace('\n', "\r\n").into_bytes())),
        ..Fixture::default()
    })
    .collect();
    conformance(&check(), &fixtures).await;
}

fn attachment_with(name: &str, base64: &str) -> String {
    format!(
        "MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=\"m\"

--m
Content-Type: text/plain; charset=utf-8

Please find the document attached for your records.
--m
Content-Type: application/octet-stream; name=\"{name}\"
Content-Disposition: attachment; filename=\"{name}\"
Content-Transfer-Encoding: base64

{base64}
--m--
"
    )
}

#[tokio::test]
async fn first_bytes_reveal_disguised_files() {
    let mz =
        "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA==";
    let zip = "UEsDBBQAAAAIAAAAIQAAAAAAAAAAAAAAAAAAAAAA";
    let pdf = "JVBERi0xLjcKJcfsj6IKNSAwIG9iago8PC9MZW5ndGggNiAwIFI+PgpzdHJlYW0K";
    assert!(
        has(
            &names(&attachment_with("report.pdf", mz)).await,
            "MIME_BAD_ATTACHMENT"
        ),
        "an executable posing as a pdf"
    );
    assert!(
        has(
            &names(&attachment_with("invoice.pdf", zip)).await,
            "MIME_BAD_ATTACHMENT"
        ),
        "an archive posing as a pdf"
    );
    assert!(!has(
        &names(&attachment_with("report.pdf", pdf)).await,
        "MIME_BAD_ATTACHMENT"
    ));
    assert!(
        !has(
            &names(&attachment_with("letter.docx", zip)).await,
            "MIME_BAD_ATTACHMENT"
        ),
        "docx is a zip"
    );
    assert!(!has(
        &names(&attachment_with("files.zip", zip)).await,
        "MIME_BAD_ATTACHMENT"
    ));
    let named_exe = names(&attachment_with("setup.exe", mz)).await;
    assert!(
        has(&named_exe, "MIME_BAD_EXTENSION") && !has(&named_exe, "MIME_BAD_ATTACHMENT"),
        "{named_exe:?}"
    );
}

#[test]
fn sniffing() {
    assert_eq!(sniff(b"MZ\x90\x00"), Sniffed::Executable);
    assert_eq!(sniff(b"\x7fELF\x02"), Sniffed::Executable);
    assert_eq!(sniff(b"PK\x03\x04"), Sniffed::Archive);
    assert_eq!(sniff(&[0x1f, 0x8b, 8]), Sniffed::Archive);
    assert_eq!(sniff(b"%PDF-1.7"), Sniffed::Other);
    assert_eq!(sniff(b""), Sniffed::Other);
}
