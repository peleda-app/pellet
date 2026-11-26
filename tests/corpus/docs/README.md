# pellet-corpus

Golden tests. Each fixture in `fixtures/` is `<name>.eml` (a hand-written message, invented names, `example.*` domains) plus `<name>.toml`:

```toml
description = "What the message represents"
expect = ["MISSING_MID"]     # must fire
absent = ["MISSING_FROM"]    # must not fire

[envelope]                   # pellet_core::Envelope
client_ip = "192.0.2.25"
mail_from = "ana@example.com"
recipients = ["bo@example.org"]

[dns]                        # every other name does not exist
a = { "mail.example.com" = ["192.0.2.25"] }
ptr = { "192.0.2.25" = ["mail.example.com"] }
mx = { "example.com" = ["10 mail.example.com"] }

[dns.txt]                    # also seeds SPF, DKIM keys and DMARC for the auth check
"example.com" = ["v=spf1 ip4:192.0.2.0/24 -all"]
```

Two optional keys set up the checks that depend on the deployment: `sent = [{ message_id = "plan-42@example.com", recipients = ["bo@example.org"] }]` records mail sent before the fixture arrives, for `TRUSTED_REPLY` and `SPOOF_REPLYTO`; `pyzor = { count = 40, whitelist = 0 }` starts a fake Pyzor server on a loopback port that answers with those counts (without it Pyzor is not asked). `trap@example.org` is a spam trap in every fixture.

`cargo test -p pellet-corpus` builds an engine per fixture with every check, the bundled rules included, over its records (no scores) and reports each broken expectation and each failed check. The DNS list `dnsbl.example.net` maps `127.0.0.2` to `RBL_EXAMPLE`, and `redirect.example.net` counts as a URL redirector besides the bundled list. Signed fixtures use the RFC 8032 test key (`selector pellet`, domain `example.com`); `.eml` files are marked `-text` so their CRLF line ends survive git. A fixture must expect or forbid at least one symbol. Fixtures are checked as if it were 12 March 2026, 12:00 UTC, so dates in them stay meaningful.

A fixture may carry `label = "spam"` or `"ham"`. `classifier_separates_the_corpus` runs the labeled fixtures through the other checks, trains a classifier on them with those symbols, and requires every one to land on its side. The corpus engine registers a classifier that never speaks and never learns, so fixtures stay independent of each other.

`every_scored_symbol_is_covered_or_deferred` keeps the score table honest: each scored symbol is declared by a registered check or listed in `deferred.toml` under a reason, and a symbol that gets implemented must leave that file. Every new check adds fixtures that make it fire and that keep it quiet.
