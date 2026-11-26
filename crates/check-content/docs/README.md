# pellet-check-content

## `HeadersCheck` (`content.headers`, stage `data`)

| Symbol | When |
| --- | --- |
| `MISSING_FROM` | no `From` |
| `MULTIPLE_FROM` | more than one `From` field, or more than one mailbox in it (commas in quotes, comments and angle brackets do not count) |
| `MISSING_TO` | no `To` |
| `MISSING_SUBJECT` | no `Subject` |
| `EMPTY_SUBJECT` | `Subject` with only whitespace |
| `MISSING_DATE` | no `Date`, unless the client authenticated |
| `MISSING_MID` | no `Message-ID`, unless the client authenticated |
| `MISSING_MIME_VERSION` | `Content-Type` without `MIME-Version` |
| `MULTIPLE_UNIQUE_HEADERS` | a field RFC 5322 allows once (`Date`, `From`, `Sender`, `Reply-To`, `To`, `Cc`, `Bcc`, `Message-ID`, `In-Reply-To`, `References`, `Subject`) appears more often; options name the fields |
| `MISSING_ESSENTIAL_HEADERS` | none of `From`, `To`, `Subject`, `Date`, `Message-ID` |

Needs no DNS and no state.

## `HeaderPresenceCheck` (`content.presence`, stage `data`)

`X_HDR_<NAME>` when a field is present, for a fixed set of names: `List-Unsubscribe` gives `X_HDR_LIST_UNSUBSCRIBE`. `from_symbols` builds it from the `X_HDR_*` symbols the rules reference (`RuleSet::referenced_symbols`), which is how the binary and the corpus use it.

## `HeaderFlagsCheck` (`content.flags`, stage `data`)

`HAS_LIST_UNSUB`; `MAILLIST` (`List-Id`, `Mailing-List` or `Precedence: list`); `PRECEDENCE_BULK` (`bulk`, `list`, `junk`); `HAS_X_PRIO_ZERO`, `_ONE`, `_TWO`, `_THREE`, `_FIVE` by the first digit of `X-Priority`; `MV_CASE` (`MIME-Version` with other capitals); `CTE_CASE` (top-level `Content-Transfer-Encoding` not lowercase); `PREVIOUSLY_DELIVERED` (a `Delivered-To` names an envelope recipient); `GTUBE_TEST` (searched in the body with `memchr`); `COMPLETELY_EMPTY` (no body text and no subject); `HEADER_EMPTY_DELIMITER` (a value glued to its colon).

## `AddressCheck` (`content.addresses`, stage `data`)

From, Reply-To, To and Cc against each other and the envelope; the first From mailbox counts. From: `FROM_HAS_DN` or `FROM_NO_DN`, `FROM_DN_EQ_ADDR`, `FROM_NEQ_DISPLAY_NAME` (the display name carries another address), `FROM_INVALID`, `NO_SPACE_IN_FROM`, `FROM_EQ_ENV_FROM` or `FROM_NEQ_ENV_FROM` (non-null `MAIL FROM` only), `ENV_FROM_INVALID`, `FROM_BOUNCE` (`mailer-daemon`, `postmaster`). Reply-To: `HAS_REPLYTO`, `REPLYTO_UNPARSABLE`, then one of `REPLYTO_EQ_FROM`, `REPLYTO_ADDR_EQ_FROM`, `REPLYTO_DOM_EQ_FROM_DOM`, `REPLYTO_DOM_NEQ_FROM_DOM`, plus `REPLYTO_DN_EQ_FROM_DN` and `REPLYTO_EQ_TO_ADDR` (not for mailing lists, recognized by `List-Id`, `List-Post`, `Mailing-List` or `Precedence: list`). To: `TO_DN_ALL`/`_SOME`/`_NONE`, `TO_DN_EQ_ADDR_ALL`/`_SOME`, `TO_EQ_FROM` or `TO_DOM_EQ_FROM_DOM`, `TO_MATCH_ENVRCPT_ALL`/`_SOME` (envelope recipients found in To and Cc), `TO_WRAPPED_IN_SPACES`. Counts: `RCPT_COUNT_ZERO`, `_ONE`, `_TWO`, `_THREE` (3–4), `_FIVE` (5–6), `_SEVEN` (7–11), `_TWELVE` (12–50), `_GT_50` over distinct To, Cc and Bcc addresses; `SORTED_RECIPS` (seven or more, alphabetical). Subject: `RCPT_IN_SUBJECT`, else `RCPT_DOMAIN_IN_SUBJECT`, else `RCPT_LOCAL_IN_SUBJECT` (four or more characters). `RCPT_BOUNCEMOREONE`: a null sender to several envelope recipients. `FORGED_SENDER`: `MAIL FROM` and From in different registrable domains. `FORGED_RECIPIENTS`: To and Cc name none of the envelope recipients (not for mailing lists, recognized the same way, authenticated clients, or a To or Cc alias at a forwarding service given to `AddressCheck::alias_domains`, the bundled `alias-relays` list, subdomains included). `SPOOF_DISPLAY_NAME`: the display name carries an address in another registrable domain (`FROM_NEQ_DISPLAY_NAME` when it is the same one). `HEADER_FORGED_MDN`, `HEADER_RCONFIRM_MISMATCH`: read receipts requested to an address other than the sender's.

## `EncodingCheck` (`content.encoding`, stage `data`)

For From, To, Reply-To and Subject: `*_EXCESS_BASE64` and `*_EXCESS_QP` when an RFC 2047 encoded word decodes to plain ASCII (`SUBJ_` for Subject, `REPLYTO_` for Reply-To); `FROM_NEEDS_ENCODING`, `TO_NEEDS_ENCODING`, `SUBJECT_NEEDS_ENCODING` for raw 8-bit bytes; `INVALID_FROM_8BIT` when those bytes in From are not valid UTF-8.

## `MessageIdCheck` (`content.message_id`, stage `data`)

`MID_MISSING_BRACKETS`; `INVALID_MSGID` (not `<left@right>`, or spaces); the right side: `MID_RHS_IP_LITERAL`, `MID_BARE_IP`, `MID_RHS_NOT_FQDN`, `MID_RHS_WWW`, `MID_RHS_MATCH_FROM`, `MID_RHS_MATCH_FROMTLD` (same registrable domain, another host), `MID_RHS_MATCH_TO`; `MID_CONTAINS_FROM`, `MID_CONTAINS_TO`. A missing field is left to `HeadersCheck`.

## `DateCheck` (`content.date`, stage `data`)

`INVALID_DATE`; `DATE_IN_FUTURE` (more than 2 hours ahead); `DATE_IN_PAST` (more than 24 hours behind). `with_clock` takes another clock for tests.

## `ReceivedCheck` (`content.received`, stage `data`)

`RCVD_COUNT_ZERO`, `_ONE`, `_TWO`, `_THREE` (3–4), `_FIVE` (5–6), `_SEVEN` (7–11), `_TWELVE` (12+); `RCVD_TLS_ALL`, `RCVD_TLS_LAST` or `RCVD_NO_TLS_LAST` (topmost field; `ESMTPS`, `ESMTPSA`, `SMTPS`, `TLS` words); `RCVD_VIA_SMTP_AUTH` (`ESMTPA`, `ESMTPSA`, `authenticated`); `RCVD_HELO_USER`; `RCVD_ILLEGAL_CHARS` (8-bit or control bytes); `RCVD_DOUBLE_IP_SPAM` (two or more hops naming their client by a bare address).

## `SubjectCheck` (`content.subject`, stage `data`)

`SUBJ_ALL_CAPS` (two words and ten letters, all capitals); `SUBJECT_ENDS_SPACES`; `SUBJECT_HAS_CURRENCY`.

## `MimeCheck` (`content.mime`, stage `data`)

Walks at most 100 parts (`MIME_LIMIT_EXCEEDED` beyond). Built with an extension list (extension to flags, the bundled `file-extensions` list: `BAD` dangerous, `AR` archive).

`HAS_ATTACHMENT`; `MIME_HTML_ONLY`; for `multipart/alternative`: `MIME_MA_MISSING_TEXT`, `MIME_MA_MISSING_HTML`, `MIME_GOOD` (both present), `PARTS_DIFFER` (the plain and HTML texts share under half their words, ten words each at least); `MIME_BAD` (the parser flagged a damaged part); attachment names: `MIME_BAD_EXTENSION`, `MIME_DOUBLE_BAD_EXTENSION` (behind a decoy such as `.pdf.exe`), `MIME_ARCHIVE_IN_ARCHIVE` (`.zip.rar`), `MIME_BAD_UNICODE` (bidirectional controls), `MIME_BAD_ATTACHMENT` (a content type the extension list does not give for the extension, `application/octet-stream` aside; or first bytes showing an executable under a name not marked `BAD`, or an archive under a name that is neither an archive nor a zip-based document such as `docx`). Only the first 64 bytes of an attachment are decoded for this (`HEAD_BYTES`); nothing else of an attachment is ever decoded; text parts: `MISSING_CHARSET` (8-bit bytes, no charset), `MIXED_CHARSET` (a word mixing Latin, Cyrillic and Greek), `MIME_BASE64_TEXT` and `MIME_BASE64_TEXT_BOGUS` (base64 hiding plain ASCII); `BAD_CTE_7BIT`; `CTYPE_MISSING_DISPOSITION` (a named non-text part without `Content-Disposition`); top level: `CT_EXTRA_SEMI`, `BROKEN_CONTENT_TYPE`, `MIME_HEADER_CTYPE_ONLY`; `CTYPE_MIXED_BOGUS` (`multipart/mixed` with only text); `ENCRYPTED_PGP`, `ENCRYPTED_SMIME`, `SIGNED_PGP`, `SIGNED_SMIME` (MIME and inline PGP); `BOGUS_ENCRYPTED_AND_TEXT`; `HAS_MESSAGE_PARTS`, `IS_DSN`; `SINGLE_SHORT_PART` (one text part under 64 characters).

## `HtmlCheck` (`content.html`, stage `data`)

Each HTML part, up to 512 KiB, through a small tag lexer (comments skipped): `HTML_META_REFRESH_URL`, `EXT_CSS` (a remote stylesheet), `HAS_DATA_URI`, `DATA_URI_OBFU` (a `data:` URI with HTML or script, or linked with `href`), `HTML_UNBALANCED_TAG` (`a`, `div`, `table`), `HTML_TEXT_IMG_RATIO` (images with under 200 characters of visible text), `MANY_INVISIBLE_PARTS` (three or more elements hidden by `display:none`, `visibility:hidden`, `font-size:0` or `opacity:0`).

None of these checks needs DNS or state.
