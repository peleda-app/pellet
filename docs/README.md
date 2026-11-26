# Documentation

- [Plan](PLAN.md)

## Modules

| Module | |
| --- | --- |
| [pellet-core](../crates/core/docs/README.md) | envelope, message context, symbols, verdicts |
| [pellet-dns](../crates/dns/docs/README.md) | DNS lookup contract |
| [pellet-dns-hickory](../crates/dns-hickory/docs/README.md) | hickory-resolver |
| [pellet-state](../crates/state/docs/README.md) | state contract |
| [pellet-state-memory](../crates/state-memory/docs/README.md) | state in memory |
| [pellet-rules](../crates/rules/docs/README.md) | scores, rules, lists, expression language |
| [pellet-urls](../crates/urls/docs/README.md) | URL extraction and parsing |
| [pellet-feeds](../crates/feeds/docs/README.md) | remote lists: download, fingerprints, cache, refresh |
| [pellet-fetch](../crates/fetch/docs/README.md) | download contract for remote lists |
| [pellet-fetch-http](../crates/fetch-http/docs/README.md) | downloads over HTTPS with reqwest |
| [pellet-classifier](../crates/classifier/docs/README.md) | tokenizers, feature hashing, online logistic regression |
| [pellet-check](../crates/check/docs/README.md) | check contract |
| [pellet-check-auth](../crates/check-auth/docs/README.md) | SPF, DKIM, DMARC, ARC |
| [pellet-check-ip](../crates/check-ip/docs/README.md) | DNSBL, reverse DNS, HELO |
| [pellet-check-content](../crates/check-content/docs/README.md) | headers, MIME, HTML heuristics |
| [pellet-check-url](../crates/check-url/docs/README.md) | URLs, redirectors, URIBL, phishing |
| [pellet-check-rules](../crates/check-rules/docs/README.md) | rules and composites from data |
| [pellet-check-reputation](../crates/check-reputation/docs/README.md) | address and domain reputation, spam traps, replies to sent mail |
| [pellet-check-pyzor](../crates/check-pyzor/docs/README.md) | Pyzor digest lookups |
| [pellet-check-classifier](../crates/check-classifier/docs/README.md) | classifier verdict and learning |
| [pellet-engine](../crates/engine/docs/README.md) | stages, scoring, actions |
| [pellet-server](../crates/server/docs/README.md) | HTTP API |
| [pellet (binary)](../apps/pellet/docs/README.md) | config, `serve`, `check`, `learn` |
| [pellet-corpus](../tests/corpus/docs/README.md) | golden tests |
| [pellet-load](../tests/load/docs/README.md) | load report, time and memory budgets |
| [pellet-eval](../tests/eval/docs/README.md) | evaluation over real spam and ham kept outside the repository |
