use std::{
    any::{Any, TypeId},
    borrow::Cow,
    fmt,
    sync::{Arc, Mutex},
};

/// Most header fields kept from one message; the rest are counted as truncated.
const MAX_HEADERS: usize = 1000;

/// One top-level header field, unfolded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    name: String,
    value: Box<[u8]>,
}

impl Header {
    /// The field name as written, without the colon.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The raw value: line breaks of folded lines removed, leading and trailing whitespace trimmed,
    /// no decoding of encoded words or charsets.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// The raw value as text, with invalid UTF-8 replaced.
    pub fn value_str(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.value)
    }

    /// Whether the name matches, ignoring ASCII case.
    pub fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }
}

/// A message as received: the original bytes plus its top-level header fields, parsed once.
///
/// Parsing never fails. The header section ends at the first empty line, or at the end of the
/// bytes when there is none. Lines in it that are neither a field nor a continuation are counted in
/// [`Message::malformed_header_lines`]. Cheap to clone; clones share the bytes and the
/// [`Message::cached`] views.
#[derive(Clone)]
pub struct Message {
    raw: Arc<Vec<u8>>,
    headers: Arc<[Header]>,
    body_offset: usize,
    malformed: usize,
    truncated: bool,
    views: Arc<Mutex<Vec<View>>>,
}

/// A cached view: its type and the value.
type View = (TypeId, Arc<dyn Any + Send + Sync>);

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("len", &self.raw.len())
            .field("headers", &self.headers.len())
            .field("malformed", &self.malformed)
            .finish_non_exhaustive()
    }
}

impl Message {
    /// Parses the header section of `raw`. A `Vec` is kept as it is, never copied.
    pub fn new(raw: impl Into<Vec<u8>>) -> Self {
        let raw = Arc::new(raw.into());
        let mut headers: Vec<Header> = Vec::new();
        let mut current: Option<(String, Vec<u8>)> = None;
        let mut malformed = 0;
        let mut truncated = false;
        let mut body_offset = raw.len();
        let mut pos = 0;

        let mut finish = |current: &mut Option<(String, Vec<u8>)>, headers: &mut Vec<Header>| {
            if let Some((name, value)) = current.take() {
                if headers.len() < MAX_HEADERS {
                    headers.push(Header {
                        name,
                        value: trim(&value).into(),
                    });
                } else {
                    truncated = true;
                }
            }
        };

        while pos < raw.len() {
            let end = memchr_newline(&raw[pos..]).map_or(raw.len(), |i| pos + i + 1);
            let line = strip_eol(&raw[pos..end]);
            pos = end;

            if line.is_empty() {
                body_offset = pos;
                break;
            }
            if matches!(line[0], b' ' | b'\t') {
                match current.as_mut() {
                    Some((_, value)) => value.extend_from_slice(line),
                    None => malformed += 1,
                }
                continue;
            }
            finish(&mut current, &mut headers);
            match field_name(line) {
                Some(colon) => {
                    let name = String::from_utf8_lossy(&line[..colon]).into_owned();
                    current = Some((name, line[colon + 1..].to_vec()));
                }
                None => malformed += 1,
            }
        }
        finish(&mut current, &mut headers);

        Message {
            raw,
            headers: headers.into(),
            body_offset,
            malformed,
            truncated,
            views: Arc::default(),
        }
    }

    /// A view derived from the message, built once by `build` and shared by every check and
    /// clone afterwards: one per type. Checks use it so work such as decoding parts or finding
    /// links is done once per message. If two callers race to build the same view, one result is
    /// kept; `build` must not depend on which.
    pub fn cached<T: Any + Send + Sync>(&self, build: impl FnOnce(&Message) -> T) -> Arc<T> {
        let lookup = |views: &[View]| {
            views
                .iter()
                .find(|(id, _)| *id == TypeId::of::<T>())
                .and_then(|(_, view)| view.clone().downcast::<T>().ok())
        };
        if let Some(view) = lookup(&self.views.lock().unwrap_or_else(|p| p.into_inner())) {
            return view;
        }
        let built = Arc::new(build(self));
        let mut views = self.views.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(view) = lookup(&views) {
            return view;
        }
        views.push((TypeId::of::<T>(), built.clone()));
        built
    }

    /// The original bytes, unchanged.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Size of the original bytes.
    pub fn len(&self) -> usize {
        self.raw.len()
    }

    /// Whether the message has no bytes at all.
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// Top-level header fields in order of appearance.
    pub fn headers(&self) -> &[Header] {
        &self.headers
    }

    /// The first field with this name, ignoring ASCII case.
    pub fn header(&self, name: &str) -> Option<&Header> {
        self.headers.iter().find(|h| h.is(name))
    }

    /// Every field with this name, in order, ignoring ASCII case.
    pub fn headers_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Header> + 'a {
        self.headers.iter().filter(move |h| h.is(name))
    }

    /// How many fields have this name, ignoring ASCII case.
    pub fn header_count(&self, name: &str) -> usize {
        self.headers_named(name).count()
    }

    /// The bytes after the empty line that ends the header section; empty when there is none.
    pub fn body(&self) -> &[u8] {
        &self.raw[self.body_offset..]
    }

    /// Lines in the header section that were neither a field nor a continuation of one.
    pub fn malformed_header_lines(&self) -> usize {
        self.malformed
    }

    /// Whether the message had more header fields than are kept.
    pub fn headers_truncated(&self) -> bool {
        self.truncated
    }
}

fn memchr_newline(bytes: &[u8]) -> Option<usize> {
    bytes.iter().position(|&b| b == b'\n')
}

fn strip_eol(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn field_name(line: &[u8]) -> Option<usize> {
    let colon = line.iter().position(|&b| b == b':')?;
    let name = &line[..colon];
    let valid = !name.is_empty() && name.iter().all(|&b| (33..=126).contains(&b));
    valid.then_some(colon)
}

fn trim(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(start, |i| i + 1);
    &value[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(text: &str) -> Message {
        Message::new(text.as_bytes())
    }

    #[test]
    fn parses_fields_and_body() {
        let m = message(
            "From: Ana <ana@example.com>\r\nTo: bo@example.org\r\nSubject: Hi\r\n\r\nBody line\r\n",
        );
        assert_eq!(m.headers().len(), 3);
        assert_eq!(m.header("from").unwrap().value(), b"Ana <ana@example.com>");
        assert_eq!(m.header("SUBJECT").unwrap().name(), "Subject");
        assert_eq!(m.body(), b"Body line\r\n");
        assert_eq!(m.malformed_header_lines(), 0);
    }

    #[test]
    fn unfolds_continuation_lines() {
        let m = message("Subject: first\r\n second\r\n\tthird\r\n\r\n");
        assert_eq!(m.header("subject").unwrap().value(), b"first second\tthird");
    }

    #[test]
    fn accepts_bare_newlines() {
        let m = message("Date: Mon, 2 Mar 2026 10:00:00 +0000\nTo: a@example.org\n\nbody");
        assert_eq!(m.headers().len(), 2);
        assert_eq!(m.body(), b"body");
    }

    #[test]
    fn counts_duplicates_case_insensitively() {
        let m = message("From: a@example.com\r\nfrom: b@example.com\r\n\r\n");
        assert_eq!(m.header_count("FROM"), 2);
        let values: Vec<_> = m.headers_named("From").map(|h| h.value_str()).collect();
        assert_eq!(values, ["a@example.com", "b@example.com"]);
    }

    #[test]
    fn without_empty_line_everything_is_header() {
        let m = message("To: a@example.org\r\nSubject: x");
        assert_eq!(m.headers().len(), 2);
        assert!(m.body().is_empty());
    }

    #[test]
    fn counts_malformed_lines() {
        let m = message(
            " leading continuation\r\nnot a header\r\n: empty name\r\nTo: a@example.org\r\n\r\n",
        );
        assert_eq!(m.malformed_header_lines(), 3);
        assert_eq!(m.headers().len(), 1);
    }

    #[test]
    fn keeps_the_bytes_it_is_given() {
        let raw = b"Subject: x\r\n\r\nbody".to_vec();
        let address = raw.as_ptr();
        let message = Message::new(raw);
        assert_eq!(message.raw().as_ptr(), address, "no copy");
        assert_eq!(message.clone().raw().as_ptr(), address, "clones share it");
    }

    #[test]
    fn views_are_built_once_and_shared_by_clones() {
        let message = Message::new(&b"Subject: x\r\n\r\nbody"[..]);
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let build = |m: &Message| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            m.body().len()
        };
        assert_eq!(*message.cached(build), 4);
        assert_eq!(*message.clone().cached(build), 4);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            *message.cached(|_| String::from("other type")),
            "other type"
        );
    }

    #[test]
    fn empty_message() {
        let m = message("");
        assert!(m.is_empty());
        assert!(m.headers().is_empty());
        assert!(m.body().is_empty());
    }

    #[test]
    fn empty_value_is_kept() {
        let m = message("Subject:\r\n\r\n");
        assert_eq!(m.header("subject").unwrap().value(), b"");
    }

    #[test]
    fn keeps_a_bounded_number_of_headers() {
        let text = "X-A: 1\r\n".repeat(MAX_HEADERS + 5) + "\r\n";
        let m = message(&text);
        assert_eq!(m.headers().len(), MAX_HEADERS);
        assert!(m.headers_truncated());
    }

    #[test]
    fn invalid_utf8_value_is_replaced_in_text_view() {
        let m = Message::new(&b"Subject: caf\xe9\r\n\r\n"[..]);
        assert_eq!(m.header("subject").unwrap().value(), b"caf\xe9");
        assert_eq!(m.header("subject").unwrap().value_str(), "caf\u{fffd}");
    }
}
