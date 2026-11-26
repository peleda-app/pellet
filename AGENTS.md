# Agent guide

Read [docs/RULES.md](docs/RULES.md) first: the rules of every repository of the workspace, synced from dojo. Then [docs/PLAN.md](docs/PLAN.md). This guide adds what is specific to Pellet.

Pellet is a spam filter for weak hardware: a Rust library and an optional HTTP service that turns an SMTP envelope and message into a verdict of named symbols, a score and an action. One Cargo workspace.

Status: early development. Core types, the check, state and DNS contracts, in-memory state, the hickory resolver, the engine, header, connection (DNSBL, reverse DNS, HELO) and authentication (SPF, DKIM, ARC, DMARC) checks, header, address, encoding, Message-ID, Date, Received, subject, MIME, HTML and URL checks, the DNS lists of the rules data, the classifier with feedback and auto-learning, reputation kept in a state snapshot, spam traps, replies to sent mail, Pyzor lookups, remote lists (feeds) as cached fingerprints, the rule language with the imported Stalwart rules data and the late rules check, the HTTP server with the rspamd protocol, `pellet check`, `pellet learn`, `pellet serve` and the corpus exist; tuning on real mail (phase 7) is next. Scored symbols nothing emits are listed with reasons in `tests/corpus/deferred.toml`. Run `mise run check` before considering a change done, and `mise run load` after a change on the message path.

## Layout

- `crates/*`: Rust libraries, contracts and their implementations
- `apps/pellet`: the binary, the only place that picks implementations
- `data/`: scores, rules and lists compiled into `pellet-rules`; `data/stalwart/` is imported by `scripts/import-stalwart-rules.sh` and never edited by hand
- `tests/corpus`: golden tests, hand-written messages and the symbols they must produce
- `tests/eval`: evaluation over real spam and ham downloaded to a cache outside the repository (`mise run eval`); real mail never enters the repository
- `tests/load`: load report and release-build time and memory budgets over generated messages (`mise run load`)
- `fuzz/`: cargo-fuzz targets for every decoder of untrusted input (`bash fuzz/run.sh <target> [secs]`, `mise run fuzz`)
- `docs/`: project-wide docs; every crate and app also has its own `docs/` folder

Crate directories drop the prefix, package names keep it: `crates/check-auth` is `pellet-check-auth`.

## Modules and contracts

- **Contract crates** (`pellet-check`, `pellet-dns`, `pellet-fetch`, `pellet-state`) hold only traits, the types in their signatures, their error type, their conformance suite and the pure checks every caller and implementation must share (for example `pellet_dns::normalize`). No I/O.
- **Implementation crates** are named `<contract>-<kind>` and depend on their contract and `pellet-core`, never on another implementation.
- **One composition root.** Only `apps/pellet` depends on implementation crates; the engine receives contracts as `Arc<dyn Trait>` through a builder.
- **Object-safe traits.** Every contract trait is `Send + Sync` and usable as `dyn Trait`; async methods use `#[async_trait]`; no generic parameters on contract methods.
- **Nothing leaks.** No parser, resolver or HTTP library types cross a contract boundary, including in errors.
- **Errors per contract.** One `thiserror` enum per contract; libraries never return `anyhow::Error`; only binaries may use `anyhow`.
- **Conformance tests.** Every contract ships a suite behind its `testing` feature, and every implementation runs it.
- **Guarantees, not mechanics.** Every public trait, method and type gets a doc comment that says what it guarantees: deadlines, what happens on missing data or network failure, concurrency.
- **Small modules.** A crate has one job.
- **Bounded memory.** Every cache, list and model has a configured cap; nothing grows with traffic.

## Docs

Every crate and app has `docs/README.md`: what it does, its public API with guarantees, for a check the symbols it emits and when. A change to behavior, symbols or public API updates its docs in the same change.

## Rules

- **English** in every file: code, comments, docs, commit messages.
- **Clean room.** Never read, copy or translate Stalwart server code (AGPL-3.0). Its spam filter rules repository is MIT OR Apache-2.0 and may be imported; rspamd and SpamAssassin are Apache-2.0 and may be ported with attribution in `NOTICE`. See "Data and sources" in the plan.
- **Parsing boundary.** Pellet's purpose is reading raw SMTP envelopes and messages, so it parses untrusted mail itself (headers, MIME, HTML, URLs, DNS records through `mail-auth`, Pyzor answers, remote lists) instead of using a sandboxed parser. Its hardening: input caps on every parser, linear-time scanners, no panics on hostile input, and a fuzz target in `fuzz/` for each decoder.
- **No real data.** Tests, fixtures and docs use invented messages, addresses on `example.com`/`example.org` and made-up names. Fixtures are hand-written files.
- **Never log content or secrets.** Logs, metrics and trace attributes carry symbol names, scores, ids, counts and timings, never addresses, subjects, bodies or keys.
- **Comments are rare.** Doc comments on the public API are required; inside function bodies, comment only what a reader cannot infer.
- **Tests sit next to the code** in `#[cfg(test)]` modules and never touch the network; DNS and HTTP go through in-process fakes. The only exceptions are `#[ignore]`d tests against real third-party servers, run by `mise run network`.
- **Dependencies** go in `[workspace.dependencies]` in the root `Cargo.toml`.
- **Commits and PR titles:** one line in Conventional Commits form with the module as scope (`feat(check-auth): ...`), no body.

## Releases

- Every released artifact is signed and attested, as in `peleda-app/rowboat` (`.github/workflows/publish.yml`; GitHub still names it `peleda-app/skein` until the rename): container images with BuildKit provenance (`mode=max`) and an SBOM, a keyless `cosign sign` of the manifest digest and `actions/attest-build-provenance`; binaries and archives with `SHA256SUMS`, a build provenance attestation and a `cosign sign-blob --bundle` per file; npm packages with `--provenance` through npm trusted publishing; crates through crates.io trusted publishing.
- Publishing runs only in GitHub Actions (environment `release`, `id-token: write`), never from a laptop. Actions are pinned by commit SHA.
