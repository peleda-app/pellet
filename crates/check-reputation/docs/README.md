# pellet-check-reputation

Reputation, spam traps and replies to sent mail: checks that judge a message by what this deployment has seen or sent before.

## `ReputationCheck` (`reputation`, stage `data`, late)

Counts ham and spam per client address and per authenticated From domain in a `State` store, and judges the next message by them.

| Symbol | When |
| --- | --- |
| `REPUTATION_IP_SPAM`, `REPUTATION_IP_HAM` | the client address (IPv6 by its /64, IPv4-mapped as IPv4, public addresses only) has at least `min_samples` (5) and a spam share ≥ `spam_ratio` (0.8) or ≤ `ham_ratio` (0.2) |
| `REPUTATION_DOMAIN_SPAM`, `REPUTATION_DOMAIN_HAM` | the same for the domain `DMARC_POLICY_ALLOW` names; a domain without a DMARC pass is never counted, so it cannot be spoofed into a reputation |

The option is `spam/total`. Counts sit under `rep/ip/<address>` and `rep/domain/<domain>` as two little-endian `u32`, refreshed for `ttl` (30 days) on every update, written with compare-and-swap.

A message is judged on the counts before it, then counted when its signals are strong: spam for a blocklist hit (`RBL_`, `RECEIVED_`, `DBL_`, `SURBL_`, `URIBL_`, `MSBL_`, `SEM_URIBL`) together with `DMARC_POLICY_REJECT`, `DMARC_POLICY_QUARANTINE` or `SPF_FAIL`, or for `GTUBE_TEST` or `SPAM_TRAP`; ham when `DKIM_ALLOW`, `SPF_ALLOW` and `DMARC_POLICY_ALLOW` all fired without a blocklist hit. Authenticated clients are never counted. `learn(envelope, symbols, spam)` takes feedback. A state failure leaves the message unjudged and uncounted; the check never fails over it.

The scores live in `data/pellet/scores.txt`, Pellet's own score file.

## `TrapCheck` (`trap`, stage `data`)

| Symbol | When |
| --- | --- |
| `SPAM_TRAP` | an envelope recipient is a trap address, or its domain is a trap domain |

`TrapCheck::new(traps)` takes addresses and `@domain` entries (a whole domain, not its subdomains), compared without case. The symbol has no option, so trap addresses never appear in a verdict. Classifier and reputation learn a trapped message as spam.

## `ReplyCheck` (`reply`, stage `data`, late)

Recognizes replies to mail this deployment sent. The host reports each outgoing message with `record_sent(message, envelope)` (the binary exposes it as `POST /v1/sent`); an inbound message whose `In-Reply-To` or `References` names one of them is a reply.

| Symbol | When |
| --- | --- |
| `TRUSTED_REPLY` | the reply comes from a domain the sent message went to, and `DMARC_POLICY_ALLOW` vouches for that domain |
| `SPOOF_REPLYTO` | the reply fails DMARC (`DMARC_POLICY_REJECT`, `DMARC_POLICY_QUARANTINE`), or comes from a domain the sent message did not go to without a DMARC pass and without `List-Id` |

A recipient's domain without DMARC gets neither symbol, and so does an authenticated third party (a colleague a recipient forwarded to). Domains compare by their registrable part. `record_sent` keeps the envelope recipients, or `To` and `Cc` when the envelope has none, and returns `false` without a Message-ID or a recipient.

State holds fingerprints only: `sent/<FNV-1a of the Message-ID>` maps to 8-byte FNV-1a hashes of up to `max_domains` (32) recipient domains, for `ttl` (90 days). At most `max_lookups` (8) identifiers are looked up per message: `In-Reply-To` first, then `References` from the newest. Authenticated clients are not judged; a state failure leaves the message unjudged.
