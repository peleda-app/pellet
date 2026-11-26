# Decisions

Decisions taken without the maintainer, with their reasons.

## Module kinds (2026-11-26)

- `pellet-check`, `pellet-dns`, `pellet-fetch` and `pellet-state` are contracts; every `check-*` crate implements `pellet-check`, `dns-hickory` implements `pellet-dns`, `fetch-http` implements `pellet-fetch`, `state-memory` implements `pellet-state`, and each runs its contract's conformance suite.
- Downloads of remote lists were split out of `pellet-feeds`: the `Fetch` trait and its error are the `pellet-fetch` contract with a conformance suite (exact body, size limit, error status, unusable URLs, deadline, no URL in errors), and `HttpFetch` is `pellet-fetch-http`, which runs it. `FeedError` keeps its variants and converts from `FetchError`, so behaviour is unchanged.
- `pellet-feeds` stays a library as the service crate for remote lists (MOD-3): it receives the downloader as `Arc<dyn Fetch>` and keeps the pure `parse`, but it still writes and reads its own fingerprint cache files and sleeps between refreshes. Putting the cache and the clock behind contracts would add two traits for one caller, so it is not done.
- `pellet-dns` keeps `normalize`, `is_reserved_invalid`, `list_query` and `is_listable` next to the `Resolver` trait. MOD-1 lets a contract hold the pure checks every caller must run and the wire helpers both sides share: the trait requires every implementation to refuse names through `normalize` and `.invalid` through `is_reserved_invalid`, the conformance suite tests exactly that, and checks build DNS list names with `list_query` and skip unlistable addresses with `is_listable`. Moving them to a separate library would make the contract depend on a crate for its own guarantees.
- `pellet-engine` and `pellet-server` are libraries: they receive every check as `Arc<dyn Check>`.

## Fuzzing (2026-11-26)

- `fuzz/` has one target per decoder of untrusted input: `message` (header parsing), `urls` (link extraction and URL parsing), `pipeline` (every offline check through the engine over a hostile envelope and message), `auth` (DNS TXT records and messages through `mail-auth`), `server` (HTTP requests to every route), `feeds` (remote list bodies, gzip included), `classifier` (model files and tokens), `pyzor` (digests and server answers) and `rules_expr` (the rule language).
- The Pyzor answer parser is reachable for fuzzing through `testing::parse_response` behind the existing `testing` feature, so the public API without the feature is unchanged.
- `fuzz/seeds` points the message targets at `tests/corpus/fixtures`; `fuzz/regressions/` keeps inputs that once crashed a target.
- `mise run check` runs `dojo check` only when dojo is checked out beside this repository, because CI checks out Pellet alone.
