use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use mail_parser::{Encoding, MessageParser, MessagePart, PartKind, html_to_text};
use pellet_check::{Check, CheckError, Context};
use pellet_core::{Stage, Symbol, SymbolName};

use crate::mail::Symbols;

/// Most parts looked at; more is `MIME_LIMIT_EXCEEDED`.
pub const MAX_PARTS: usize = 100;

const SYMBOLS: [&str; 31] = [
    "HAS_ATTACHMENT",
    "MIME_HTML_ONLY",
    "MIME_MA_MISSING_TEXT",
    "MIME_MA_MISSING_HTML",
    "MIME_GOOD",
    "MIME_BAD",
    "MIME_LIMIT_EXCEEDED",
    "MIME_BAD_EXTENSION",
    "MIME_DOUBLE_BAD_EXTENSION",
    "MIME_BAD_UNICODE",
    "MISSING_CHARSET",
    "MIXED_CHARSET",
    "MIME_BASE64_TEXT",
    "MIME_BASE64_TEXT_BOGUS",
    "BAD_CTE_7BIT",
    "CTYPE_MISSING_DISPOSITION",
    "CT_EXTRA_SEMI",
    "BROKEN_CONTENT_TYPE",
    "CTYPE_MIXED_BOGUS",
    "MIME_HEADER_CTYPE_ONLY",
    "ENCRYPTED_PGP",
    "ENCRYPTED_SMIME",
    "SIGNED_PGP",
    "SIGNED_SMIME",
    "BOGUS_ENCRYPTED_AND_TEXT",
    "HAS_MESSAGE_PARTS",
    "IS_DSN",
    "SINGLE_SHORT_PART",
    "PARTS_DIFFER",
    "MIME_ARCHIVE_IN_ARCHIVE",
    "MIME_BAD_ATTACHMENT",
];

/// Bytes read from the start of an attachment to tell its real type; nothing past them is decoded.
pub const HEAD_BYTES: usize = 64;

/// Extensions of formats that are zip archives inside (office documents, Java, Android, e-books).
const ZIP_CONTAINERS: [&str; 12] = [
    "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "odt", "ods", "odp", "jar", "apk", "epub",
];

/// What the first bytes of a file say it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sniffed {
    Executable,
    Archive,
    Other,
}

fn sniff(head: &[u8]) -> Sniffed {
    let starts = |magic: &[u8]| head.starts_with(magic);
    if starts(b"MZ")
        || starts(b"\x7fELF")
        || starts(&[0xcf, 0xfa, 0xed, 0xfe])
        || starts(&[0xfe, 0xed, 0xfa, 0xcf])
    {
        Sniffed::Executable
    } else if starts(b"PK\x03\x04")
        || starts(b"Rar!\x1a\x07")
        || starts(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])
        || starts(&[0x1f, 0x8b])
    {
        Sniffed::Archive
    } else {
        Sniffed::Other
    }
}

/// The first [`HEAD_BYTES`] of a part's content: base64 decoded only that far, anything else
/// taken as it is.
fn head(part: &MessagePart<'_>) -> Vec<u8> {
    let raw = part.raw_body();
    match part.encoding() {
        Encoding::Base64 => crate::mail::base64_prefix(raw, HEAD_BYTES),
        _ => raw[..raw.len().min(HEAD_BYTES)].to_vec(),
    }
}

/// Extensions a document name often hides an executable behind: `invoice.pdf.exe`.
const DECOY_EXTENSIONS: [&str; 12] = [
    "pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "gif", "txt", "rtf", "zip",
];

/// The MIME structure, at [`Stage::Data`].
///
/// | Symbols | When |
/// | --- | --- |
/// | `HAS_ATTACHMENT` | an attachment |
/// | `MIME_HTML_ONLY` | HTML and no plain text part |
/// | `MIME_MA_MISSING_TEXT`, `MIME_MA_MISSING_HTML` | a `multipart/alternative` without a plain or HTML child |
/// | `MIME_GOOD` | a `multipart/alternative` with both |
/// | `MIME_BAD` | the parser found a damaged part |
/// | `MIME_LIMIT_EXCEEDED` | more than [`MAX_PARTS`] parts |
/// | `MIME_BAD_EXTENSION`, `MIME_DOUBLE_BAD_EXTENSION` | an attachment name with an extension marked `BAD` in the extension list, the second behind a decoy such as `.pdf.exe` |
/// | `MIME_ARCHIVE_IN_ARCHIVE` | an attachment name with two archive extensions (`AR`), such as `.zip.rar` |
/// | `MIME_BAD_UNICODE` | an attachment name with bidirectional control characters |
/// | `MIME_BAD_ATTACHMENT` | an attachment whose content type is not one the extension list gives for its extension (`application/octet-stream` passes), or whose first bytes show an executable under a name not marked `BAD`, or an archive under a name that is neither an archive nor a zip-based document |
/// | `MISSING_CHARSET` | a text part with 8-bit bytes and no charset |
/// | `MIXED_CHARSET` | a word mixing Latin, Cyrillic or Greek letters |
/// | `MIME_BASE64_TEXT`, `MIME_BASE64_TEXT_BOGUS` | a text part in base64; one that decodes to plain ASCII |
/// | `BAD_CTE_7BIT` | a part declared `7bit` with 8-bit bytes |
/// | `CTYPE_MISSING_DISPOSITION` | a named non-text part without `Content-Disposition` |
/// | `CT_EXTRA_SEMI`, `BROKEN_CONTENT_TYPE` | the top-level `Content-Type` ends in `;`, or does not parse as `type/subtype` |
/// | `CTYPE_MIXED_BOGUS` | a `multipart/mixed` holding only text |
/// | `MIME_HEADER_CTYPE_ONLY` | `Content-Type` without `MIME-Version` or `Content-Transfer-Encoding` |
/// | `ENCRYPTED_PGP`, `ENCRYPTED_SMIME`, `SIGNED_PGP`, `SIGNED_SMIME` | encrypted or signed parts, MIME or inline PGP |
/// | `BOGUS_ENCRYPTED_AND_TEXT` | an encrypted MIME message that also carries readable text |
/// | `HAS_MESSAGE_PARTS`, `IS_DSN` | an attached message; a delivery status report |
/// | `SINGLE_SHORT_PART` | one text part, under 64 characters |
/// | `PARTS_DIFFER` | the plain and HTML alternatives share less than half their words |
pub struct MimeCheck {
    symbols: Symbols,
    extensions: HashMap<String, HashSet<String>>,
    types: HashMap<String, HashSet<String>>,
}

impl MimeCheck {
    /// The check with an extension list: extension to a comma-separated set of flags, as in
    /// the bundled `file-extensions` list (`BAD` for dangerous, `AR` for archives).
    pub fn new<K: AsRef<str>, V: AsRef<str>>(extensions: impl IntoIterator<Item = (K, V)>) -> Self {
        let mut flags_by_ext = HashMap::new();
        let mut types_by_ext = HashMap::new();
        for (ext, value) in extensions {
            let ext = ext.as_ref().trim().to_ascii_lowercase();
            let (types, flags): (Vec<&str>, Vec<&str>) = value
                .as_ref()
                .split(',')
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .partition(|t| t.contains('/'));
            flags_by_ext.insert(
                ext.clone(),
                flags.iter().map(|f| f.to_ascii_uppercase()).collect(),
            );
            if !types.is_empty() {
                types_by_ext.insert(ext, types.iter().map(|t| t.to_ascii_lowercase()).collect());
            }
        }
        MimeCheck {
            symbols: Symbols::new(&SYMBOLS),
            extensions: flags_by_ext,
            types: types_by_ext,
        }
    }

    fn flagged(&self, ext: &str, flag: &str) -> bool {
        self.extensions.get(ext).is_some_and(|f| f.contains(flag))
    }
}

fn is(part: &MessagePart<'_>, ctype: &str, subtype: &str) -> bool {
    part.is_content_type(ctype, subtype)
}

fn script(c: char) -> Option<u8> {
    match c {
        'a'..='z' | 'A'..='Z' => Some(0),
        '\u{0400}'..='\u{04FF}' => Some(1),
        '\u{0370}'..='\u{03FF}' => Some(2),
        _ => None,
    }
}

fn mixed_scripts(text: &str) -> bool {
    text.split(|c: char| !c.is_alphanumeric()).any(|word| {
        let mut seen = None;
        word.chars().filter_map(script).any(|s| match seen {
            None => {
                seen = Some(s);
                false
            }
            Some(first) => first != s,
        })
    })
}

fn words(text: &str) -> HashSet<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() > 2)
        .map(str::to_lowercase)
        .collect()
}

#[async_trait]
impl Check for MimeCheck {
    fn name(&self) -> &str {
        "content.mime"
    }

    fn stage(&self) -> Stage {
        Stage::Data
    }

    fn symbols(&self) -> &[SymbolName] {
        self.symbols.all()
    }

    async fn run(&self, ctx: &Context<'_>) -> Result<Vec<Symbol>, CheckError> {
        let message = ctx
            .message
            .ok_or_else(|| CheckError::Failed("no message at the data stage".into()))?;
        let mut found: Vec<&str> = Vec::new();
        let mut emit = |name: &'static str| {
            if !found.contains(&name) {
                found.push(name);
            }
        };

        if let Some(ct) = message.header("content-type") {
            let raw = ct.value_str();
            if raw.trim_end().ends_with(';') {
                emit("CT_EXTRA_SEMI");
            }
            let main = raw.split(';').next().unwrap_or_default().trim();
            if main
                .split_once('/')
                .is_none_or(|(t, s)| t.trim().is_empty() || s.trim().is_empty())
            {
                emit("BROKEN_CONTENT_TYPE");
            }
            if message.header("mime-version").is_none()
                && message.header("content-transfer-encoding").is_none()
            {
                emit("MIME_HEADER_CTYPE_ONLY");
            }
        }

        let Some(parsed) = MessageParser::new().parse(message.raw()) else {
            return Ok(self.to_symbols(found));
        };
        let parts: Vec<MessagePart<'_>> = parsed.parts().take(MAX_PARTS + 1).collect();
        if parts.len() > MAX_PARTS {
            emit("MIME_LIMIT_EXCEEDED");
        }
        let parts = &parts[..parts.len().min(MAX_PARTS)];

        let mut has_plain = false;
        let mut has_html = false;
        let mut text_parts = 0;
        let mut leaf_parts = 0;
        let mut encrypted_mime = false;
        let mut readable_text = false;
        let mut single_text = String::new();

        for part in parts {
            if part.has_problems() {
                emit("MIME_BAD");
            }
            match part.kind() {
                PartKind::Multipart => {
                    let children: Vec<MessagePart<'_>> = part.children().collect();
                    if is(part, "multipart", "alternative") {
                        let plain = children.iter().any(|c| is(c, "text", "plain"));
                        let html = children.iter().any(|c| is(c, "text", "html"));
                        if !plain {
                            emit("MIME_MA_MISSING_TEXT");
                        }
                        if !html {
                            emit("MIME_MA_MISSING_HTML");
                        }
                        if plain && html {
                            emit("MIME_GOOD");
                            let text = |subtype: &str| {
                                children
                                    .iter()
                                    .find(|c| is(c, "text", subtype))
                                    .and_then(|c| c.text())
                                    .map(|t| t.into_owned())
                                    .unwrap_or_default()
                            };
                            let (a, b) =
                                (words(&text("plain")), words(&html_to_text(&text("html"))));
                            if a.len() >= 10 && b.len() >= 10 {
                                let shared = a.intersection(&b).count();
                                if shared * 2 < a.union(&b).count() {
                                    emit("PARTS_DIFFER");
                                }
                            }
                        }
                    }
                    if is(part, "multipart", "mixed")
                        && !children.is_empty()
                        && children.iter().all(|c| c.is_text())
                    {
                        emit("CTYPE_MIXED_BOGUS");
                    }
                    let protocol = part
                        .content_type()
                        .and_then(|c| c.attribute("protocol"))
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    if is(part, "multipart", "encrypted") {
                        encrypted_mime = true;
                        if protocol.contains("pgp") {
                            emit("ENCRYPTED_PGP");
                        }
                    }
                    if is(part, "multipart", "signed") {
                        if protocol.contains("pgp") {
                            emit("SIGNED_PGP");
                        } else if protocol.contains("pkcs7") {
                            emit("SIGNED_SMIME");
                        }
                    }
                    if is(part, "multipart", "report")
                        && part
                            .content_type()
                            .and_then(|c| c.attribute("report-type"))
                            .is_some_and(|r| r.eq_ignore_ascii_case("delivery-status"))
                    {
                        emit("IS_DSN");
                    }
                }
                PartKind::Message(_) => {
                    leaf_parts += 1;
                    emit("HAS_MESSAGE_PARTS");
                }
                kind => {
                    leaf_parts += 1;
                    let content_type = part.content_type();
                    let subtype = content_type
                        .as_ref()
                        .and_then(|c| c.subtype())
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    if subtype.contains("pkcs7-mime") {
                        let smime = content_type
                            .as_ref()
                            .and_then(|c| c.attribute("smime-type"))
                            .unwrap_or_default()
                            .to_ascii_lowercase();
                        if smime.contains("signed") {
                            emit("SIGNED_SMIME");
                        } else {
                            encrypted_mime = true;
                            emit("ENCRYPTED_SMIME");
                        }
                    }
                    if is(part, "message", "delivery-status") {
                        emit("IS_DSN");
                    }
                    let raw_body = part.raw_body();
                    if part
                        .content_transfer_encoding()
                        .is_some_and(|e| e.trim().eq_ignore_ascii_case("7bit"))
                        && !raw_body.is_ascii()
                    {
                        emit("BAD_CTE_7BIT");
                    }
                    if matches!(kind, PartKind::Text | PartKind::Html) {
                        text_parts += 1;
                        if matches!(kind, PartKind::Text) && is(part, "text", "plain") {
                            has_plain = true;
                        }
                        if matches!(kind, PartKind::Html) {
                            has_html = true;
                        }
                        if content_type
                            .as_ref()
                            .and_then(|c| c.attribute("charset"))
                            .is_none()
                            && !raw_body.is_ascii()
                        {
                            emit("MISSING_CHARSET");
                        }
                        if part.encoding() == Encoding::Base64 {
                            emit("MIME_BASE64_TEXT");
                            if part.decoded().is_ascii() {
                                emit("MIME_BASE64_TEXT_BOGUS");
                            }
                        }
                        let text = part.text().unwrap_or_default();
                        let visible = if matches!(kind, PartKind::Html) {
                            html_to_text(&text)
                        } else {
                            text.into_owned()
                        };
                        if mixed_scripts(&visible) {
                            emit("MIXED_CHARSET");
                        }
                        if visible.contains("-----BEGIN PGP MESSAGE-----") {
                            emit("ENCRYPTED_PGP");
                        }
                        if visible.contains("-----BEGIN PGP SIGNED MESSAGE-----") {
                            emit("SIGNED_PGP");
                        }
                        if visible.trim().len() >= 20 {
                            readable_text = true;
                        }
                        single_text = visible;
                    } else if part.attachment_name().is_some()
                        && content_type
                            .as_ref()
                            .and_then(|c| c.attribute("name"))
                            .is_some()
                        && part.content_disposition().is_none()
                    {
                        emit("CTYPE_MISSING_DISPOSITION");
                    }
                }
            }
            if part.is_attachment() || part.attachment_name().is_some() {
                emit("HAS_ATTACHMENT");
            }
            if let Some(name) = part.attachment_name() {
                if name
                    .chars()
                    .any(|c| matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'))
                {
                    emit("MIME_BAD_UNICODE");
                }
                let lower = name.trim().to_lowercase();
                let pieces: Vec<&str> = lower.rsplit('.').collect();
                if pieces.len() >= 2 {
                    let last = pieces[0];
                    let before = pieces.get(1).copied().filter(|_| pieces.len() >= 3);
                    if self.flagged(last, "BAD") {
                        if before.is_some_and(|b| DECOY_EXTENSIONS.contains(&b)) {
                            emit("MIME_DOUBLE_BAD_EXTENSION");
                        } else {
                            emit("MIME_BAD_EXTENSION");
                        }
                    }
                    if self.flagged(last, "AR") && before.is_some_and(|b| self.flagged(b, "AR")) {
                        emit("MIME_ARCHIVE_IN_ARCHIVE");
                    }
                    if !part.is_text() && !part.is_multipart() && !part.is_message() {
                        let disguised = match sniff(&head(part)) {
                            Sniffed::Executable => !self.flagged(last, "BAD"),
                            Sniffed::Archive => {
                                !self.flagged(last, "AR") && !ZIP_CONTAINERS.contains(&last)
                            }
                            Sniffed::Other => false,
                        };
                        if disguised {
                            emit("MIME_BAD_ATTACHMENT");
                        }
                    }
                    if let (Some(expected), Some(ct)) = (self.types.get(last), part.content_type())
                    {
                        let declared = format!(
                            "{}/{}",
                            ct.ctype().to_ascii_lowercase(),
                            ct.subtype().unwrap_or_default().to_ascii_lowercase()
                        );
                        if declared != "application/octet-stream" && !expected.contains(&declared) {
                            emit("MIME_BAD_ATTACHMENT");
                        }
                    }
                }
            }
        }

        if has_html && !has_plain {
            emit("MIME_HTML_ONLY");
        }
        if encrypted_mime && readable_text {
            emit("BOGUS_ENCRYPTED_AND_TEXT");
        }
        if leaf_parts == 1 && text_parts == 1 {
            let trimmed = single_text.trim();
            if !trimmed.is_empty() && trimmed.chars().count() < 64 {
                emit("SINGLE_SHORT_PART");
            }
        }
        Ok(self.to_symbols(found))
    }
}

impl MimeCheck {
    fn to_symbols(&self, names: Vec<&str>) -> Vec<Symbol> {
        names.into_iter().map(|n| self.symbols.get(n)).collect()
    }
}

#[cfg(test)]
mod tests;
