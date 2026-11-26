/// Counts the mailboxes in an address list header value (RFC 5322 `mailbox-list`).
///
/// Commas inside quoted strings, comments and angle brackets do not separate mailboxes; empty
/// list elements are not counted. Group syntax counts each member.
pub(crate) fn count_mailboxes(value: &[u8]) -> usize {
    let mut count = 0;
    let mut has_content = false;
    let mut quoted = false;
    let mut escaped = false;
    let mut comment = 0usize;
    let mut angle = false;

    for &b in value {
        if escaped {
            escaped = false;
            continue;
        }
        match b {
            b'\\' if quoted || comment > 0 => escaped = true,
            b'"' if comment == 0 => {
                quoted = !quoted;
                has_content = true;
            }
            _ if quoted => {}
            b'(' => comment += 1,
            b')' if comment > 0 => comment -= 1,
            _ if comment > 0 => {}
            b'<' => {
                angle = true;
                has_content = true;
            }
            b'>' => angle = false,
            _ if angle => {}
            b',' | b';' | b':' => {
                if has_content && b != b':' {
                    count += 1;
                }
                has_content = false;
            }
            b' ' | b'\t' => {}
            _ => has_content = true,
        }
    }
    if has_content {
        count += 1;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::count_mailboxes;

    fn n(s: &str) -> usize {
        count_mailboxes(s.as_bytes())
    }

    #[test]
    fn counts_simple_lists() {
        assert_eq!(n("ana@example.com"), 1);
        assert_eq!(n("Ana <ana@example.com>"), 1);
        assert_eq!(n("ana@example.com, bo@example.org"), 2);
        assert_eq!(n(""), 0);
        assert_eq!(n(" , ,"), 0);
    }

    #[test]
    fn ignores_commas_in_quotes_comments_and_brackets() {
        assert_eq!(n("\"Doe, Ana\" <ana@example.com>"), 1);
        assert_eq!(n("ana@example.com (Ana, Sales)"), 1);
        assert_eq!(n("\"a\\\"b, c\" <x@example.com>, y@example.org"), 2);
        assert_eq!(n("<\"odd,local\"@example.com>"), 1);
    }

    #[test]
    fn counts_group_members() {
        assert_eq!(n("Team: ana@example.com, bo@example.org;"), 2);
        assert_eq!(n("undisclosed-recipients:;"), 0);
    }
}
