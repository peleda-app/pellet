# Plan

Pellet is a spam filter: a Rust library and an optional HTTP service that looks at an incoming message and its SMTP envelope and returns a verdict made of named symbols, a score and an action. It does not receive mail, deliver mail or store mailboxes; a mail server calls it at each SMTP stage and acts on what it says.

Licensed `MIT OR Apache-2.0`. The repository stays private until the contract settles.

## Principles

- **Runs on weak hardware.** One slow core and tens of megabytes are enough. No Redis, no database server, no scripting runtime. Memory is bounded by configuration, never by traffic: the classifier has a fixed size, caches have a cap, big feeds live on disk.
- **Every verdict explains itself.** A verdict is the list of symbols that fired, each with its score and options. Nothing contributes to the score without a symbol.
- **Data over code.** Weights, rules and lists are data files loaded at start and reloadable without a rebuild. Code implements checks; data decides how much they matter.
- **People are the best signal.** Marks from the mail client ("spam", "not spam") train the classifier and, over time, the weights.
- **A false positive costs more than a missed spam.** Defaults tag rather than reject until a deployment has its own statistics.
- **The network is optional.** A check that needs DNS or HTTP has a deadline; when it fails or times out it emits a `*_FAIL` or nothing, and the verdict still arrives.
- **Never log content.** Logs, metrics and traces carry symbol names, scores, counts and timings, never addresses, subjects or bodies.

## Stages

A host calls the engine at each SMTP stage with what it knows so far. A stage can end the conversation early, so a blocklisted client never gets to send a body.

| Stage | Input | Typical checks | Early result |
| --- | --- | --- | --- |
| `connect` | client IP, reverse DNS | DNSBL, PTR, rate | `554` |
| `helo` | HELO/EHLO name | HELO shape and match | — |
| `mail` | `MAIL FROM` | SPF | — |
| `rcpt` | each `RCPT TO` | recipient count, spam traps | `550` per recipient |
| `data` | raw message bytes | DKIM, DMARC, ARC, headers, MIME, HTML, URLs, rules, classifier | final verdict |

Hosts that only have the finished message (a sidecar, the CLI) run every stage at once on `data`.

## Verdict

- **Symbol:** a name (`DMARC_POLICY_REJECT`), a score and optional short options (`["example.org"]`). Scores come from the score table; a symbol missing from it scores 0 and is still reported.
- **Composite:** a symbol defined as an expression over other symbols; it can replace the symbols it consumes.
- **Score:** the sum of symbol scores after composites.
- **Action:** `accept`, `tag` (add headers, deliver to junk), `greylist` (temporary `451`), `reject`. Thresholds are configuration; the starting values come with the imported data and are checked during the data phase.

The host decides what an action means for its mailboxes. Pellet adds `X-Spam-Score` and `X-Spam-Symbols` headers when asked.

## Architecture

```
            SMTP server, sidecar caller or CLI
                        │  envelope + message, stage by stage
                        ▼
  ┌──────────────────────────────────────────────────────┐
  │ engine: stages → checks → composites → score → action │
  └──────────────────────────────────────────────────────┘
        │                     │                    │
        ▼                     ▼                    ▼
   checks (dyn Check)    state (dyn State)    dns (dyn Resolver)
   auth · ip · content   reputation, caches,   DNSBL, URIBL, PTR,
   url · rules ·         greylisting, model,   SPF/DKIM/DMARC
   classifier            training samples
        │
        ▼
   data: scores, rules, lists (pellet-rules)
```

### Ways to use it

1. **Library in an SMTP server.** Build an `Engine` with the checks you want and call it at each stage; early rejects cost no body transfer.
2. **Sidecar service.** Run the `pellet` binary and `POST` the message with envelope fields to its HTTP API.
3. **Command line.** `pellet check message.eml` prints the verdict and every symbol, for testing rules and investigating false positives.

## Modules

Same rules as Skein (the mail engine layer of Rowboat): contract crates hold traits and their types only; implementations are `<contract>-<kind>` and never depend on each other; only `apps/pellet` picks implementations.

| Crate | Kind | Job |
| --- | --- | --- |
| `pellet-core` | data | envelope, message context, symbols, verdicts, actions |
| `pellet-dns` | contract | lookups for checks |
| `pellet-dns-hickory` | implementation | hickory-resolver with a bounded cache and deadlines |
| `pellet-state` | contract | expiring keys with compare-and-swap |
| `pellet-state-memory` | implementation | in memory |
| `pellet-rules` | data | score table, rule and list formats, loader, expression language |
| `pellet-urls` | library | URL extraction and parsing from text and HTML; no I/O |
| `pellet-feeds` | library | remote lists: bounded fingerprint sets, cache, refresh |
| `pellet-fetch` | contract | downloads of remote lists |
| `pellet-fetch-http` | implementation | reqwest with a deadline and a size limit |
| `pellet-classifier` | library | tokenizers, feature hashing, online logistic regression; no I/O |
| `pellet-check` | contract | one piece of analysis that emits symbols |
| `pellet-check-auth` | implementation | SPF, DKIM, DMARC, ARC |
| `pellet-check-ip` | implementation | DNSBL, PTR, HELO |
| `pellet-check-content` | implementation | headers, From, Subject, recipients, Received, dates, Message-ID, MIME, HTML |
| `pellet-check-url` | implementation | URL extraction, redirectors, URIBL, phishing |
| `pellet-check-rules` | implementation | rules and composites from data |
| `pellet-check-reputation` | implementation | client address and authenticated domain reputation, spam traps, replies to sent mail, in `State` |
| `pellet-check-pyzor` | implementation | Pyzor digest lookups over UDP, off by default |
| `pellet-check-classifier` | implementation | classifier verdict, learning from feedback and strong signals |
| `pellet-engine` | library | stages, ordering, deadlines, composites, scoring, actions |
| `pellet-server` | library | HTTP API: check, learn, sent mail, health; the rspamd protocol |
| `pellet` (`apps/pellet`) | binary | config, composition, `serve`, `check`, `learn` |
| `pellet-corpus` (`tests/corpus`) | tests | golden messages and their expected symbols |
| `pellet-load` (`tests/load`) | tests | generated messages, time and memory budgets, load report |
| `pellet-eval` (`tests/eval`) | tests | detection and false positive rates over public spam and ham corpora, kept outside the repository |

## Classifier

- **Features:** normalized words, URL and sender domains, header shapes and the symbols other checks emitted, hashed into a fixed table (2^18 entries by default, configurable). Different tokenizers or hash seeds make a model unusable, so the model file records both.
- **Model:** FTRL-proximal logistic regression, trained online one message at a time. Each entry keeps the two FTRL accumulators as `f32` and the weight is derived from them, so one table of 8 bytes per entry serves both prediction and training: 2 MB at 2^18, nothing else grows.
- **Samples:** marks from people, plus auto-learning from strong signals (blocklist hits together with a DMARC or SPF failure for spam; DKIM, SPF and DMARC all passing with no blocklist hit for ham). Each sample updates the model at once, so no sample store is needed; a reservoir for retraining after a reset can come with persistent state.
- **Cold start:** the classifier stays silent until it has a minimum number of samples of each class. It can be seeded from a public corpus, but those are old; local samples replace them quickly.

## Data and sources

Clean-room rules for everything Pellet learns from:

| Source | License | What Pellet takes |
| --- | --- | --- |
| Stalwart spam filter rules (`stalwartlabs/spam-filter`) | MIT OR Apache-2.0 | scores, TOML rules, lists: imported into `data/` as is, with the source commit recorded and attribution in `NOTICE` |
| rspamd | Apache-2.0 | symbol meanings, maps, rule logic; code may be ported with attribution in `NOTICE` |
| SpamAssassin rules | Apache-2.0 | regular expressions and scores, with attribution |
| Stalwart server (`stalwartlabs/stalwart`) | AGPL-3.0 | nothing. Its code is not read while writing Pellet and never copied or translated. Checks for symbols that only its code emits are written from the symbol's name, rspamd and the RFCs |
| External feeds (OpenPhish, PhishTank, disposable domains, Spamhaus and other DNS lists) | their own terms | off by default; each deployment enables them and accepts their terms. Spamhaus refuses queries through public resolvers, so it needs a local resolver or a DQS key |
| Crates (`mail-parser`, `mail-auth`, `hickory-resolver`, `psl`, `idna`, `decancer`, `unicode-security`) | checked when added, enforced by `cargo deny` | parsing, authentication, DNS, domains, Unicode confusables |

## Budget

| Resource | Target |
| --- | --- |
| Resident memory | under 30 MB steady with the default model, under 50 MB during training |
| CPU | a few milliseconds per message on one slow ARM core, excluding network waits |
| Disk | data files and the model, a few MB; big feeds kept on disk with an in-memory filter |
| Dependencies | no services besides a DNS resolver |

The corpus tests check behavior; `tests/load` (`pellet-load`) measures time per message, growth with input size, peak memory and the HTTP API against budgets in a release build, and CI publishes its report on every push.

## Work plan

1. **Core and engine** (done). `pellet-core`, `pellet-check`, `pellet-state` with `state-memory`, `pellet-engine` with stages, deadlines and scoring, `pellet check` on the command line, the corpus harness, and the first real check: essential headers in `check-content`. Done when that check's symbols come back from `pellet check` and from a corpus test. Steps:
   - `pellet-core`: `Stage`, `Envelope`, `Message` (raw bytes plus the unfolded top-level header list, parsed once), validated `SymbolName`, `Symbol`, `ScoreTable`, `Thresholds`, `Action`, `Verdict`. Deeper MIME parsing stays inside the checks that need it until a shared parsed view proves worth a crate of its own.
   - `pellet-check`: the `Check` trait (name, stage, declared symbols, `run`), `Context` (stage, envelope, message, symbols from earlier stages), `CheckError`; fakes and a conformance suite behind `testing`. Checks receive DNS and state at construction in the composition root, so the contract depends on `pellet-core` only.
   - `pellet-state`: `Key`, `Entry`, `Expect`, `State` with compare-and-swap and expiry on the Tokio clock, so suites run on paused time; `state-memory` with an entry cap that evicts expired, then least recently used keys.
   - `pellet-engine`: builder, a `Session` that walks the stages and accumulates symbols, every check of a stage run concurrently under one deadline, undeclared symbols dropped and failures recorded, scores summed, the action picked from thresholds, `X-Spam-*` headers.
   - `check-content`: `MISSING_*`, `EMPTY_SUBJECT`, `MULTIPLE_FROM`, `MULTIPLE_UNIQUE_HEADERS`, `MISSING_ESSENTIAL_HEADERS`.
   - `apps/pellet`: `pellet check <file.eml>` with envelope flags, an optional score file, text or JSON output.
   - `tests/corpus`: `fixtures/<name>.eml` with `fixtures/<name>.toml` (envelope, `expect`, `absent`), run through the engine.
2. **Authentication and connection** (done). `pellet-dns`, `dns-hickory`, `check-auth`, `check-ip`. Done when corpus messages with passing, failing and missing SPF, DKIM and DMARC give the expected symbols against a fake resolver. `mail-auth` cannot use another resolver, so `check-auth` resolves through its own hickory instance with a bounded cache owned by the check, and tests seed that cache; SPF runs at `data` together with DMARC, which needs its result.
3. **Data** (done). `pellet-rules` (formats, loader, expression language), import of the Stalwart rules data with `NOTICE`, `check-rules` with composites. Done when every imported rule parses and the score table loads. Decided: the rule syntax of the Stalwart rules repository is accepted unchanged, so imports stay a copy; the interpreter is our own, written from the data files and our spec in `crates/rules/docs/README.md`. Steps:
   - `pellet-rules`: lexer, parser and evaluator for the expressions the data uses (literals, lists, `$SYMBOL`, fields, indexes, `! && || == != < <= > >= + - * /`, the functions in the data), first-match conditions, static checks at load (syntax, function names and arity, variables known to the scope).
   - Data formats: `scores.txt`, `[rule.*]` tables (scope, priority, condition, enable), `[dnsbl.*]` and `[http-list.*]` tables parsed and kept for later phases, plain lists by file name. Lists referenced by name with `key_exists`.
   - `scripts/import-stalwart-rules.sh` copies the upstream files into `data/stalwart/`, folds the bare newlines inside their strings (the upstream files are not valid TOML), and records the commit in `data/stalwart/SOURCE.md`; `NOTICE` carries the attribution. The data is compiled into `pellet-rules`.
   - Engine: late checks, which run after the other checks of their stage and see their symbols.
   - `check-rules`: a late `data` check running the `any`, `header` and `email` scopes by priority, each rule seeing the symbols of the rules before it; `url` and `dnsbl` scopes wait for URL extraction in phase 4. Addresses and subject come from `mail-parser`, registrable domains from `psl`.
   - The binary loads the bundled scores as defaults under its own `[scores]`.
4. **Content and URLs** (done). `check-content` and `check-url`, covering the symbols in the score table that no data rule emits. Done when each of those symbols has a corpus message that triggers it or is listed as deliberately skipped. Coverage is enforced by `tests/corpus`: every scored symbol is declared by a registered check or listed in `tests/corpus/deferred.toml` with a reason, and the test fails when either side drifts. Slices, each its own commit:
   - Headers and addresses (done): header presence (`X_HDR_*` for every header a rule references), list and priority headers, From/Reply-To/To relations and the envelope, recipient counts, needless or missing encoding, Message-ID, Date, Received, subject shape.
   - MIME (done): structure, attachments and extensions, charsets, encodings, HTML-only and text/HTML differences, signed and encrypted parts.
   - URLs (done): extraction from text and HTML, redirector unwrapping, link text against target, IP and obfuscated hosts, the `url` rule scope.
   - DNS lists from the data (done): `ip`, `domain`, `email` and `url` scopes, `hash()` for hashed lists.
5. **Classifier** (done). `pellet-classifier`, `check-classifier`, auto-learning, the `learn` command. Done when a model trained on the corpus separates its spam and ham and stays within the memory budget. Steps:
   - `pellet-classifier`: a `Document` (subject, body text, link domains, sender domain, header names, symbols), tokens with prefixes per kind (words, word pairs, domains, headers, symbols), seeded FNV-1a hashing into the table, FTRL-proximal training and prediction, counts of samples per class, and a versioned binary model format that refuses another tokenizer version, table size or seed. No I/O.
   - A separation test: invented spam and ham generated from disjoint and shared vocabularies, trained and then judged on messages it did not see.
   - `check-classifier`: a late `data` check holding the model in memory, emitting `PROB_SPAM_*`, `PROB_HAM_*` or `PROB_SPAM_UNCERTAIN` by probability band once both classes have their minimum sample count; `learn` for feedback; auto-learning from strong signals. Persistence is the host's: until persistent state exists, the binary keeps the model in a file.
   - Binary: `pellet learn --model FILE --spam|--ham MESSAGE...` and `pellet check --model FILE`.
6. **Server and persistence** (done). `pellet-server`, a persistent `State` implementation, bounded external feeds. Done when the binary serves check and learn requests and survives a restart with its model and reputation. Slices, each its own commit:
   - Server (done): `pellet-server` with `POST /v1/check` (the raw message as the body, envelope fields in the query), `POST /v1/learn?label=spam|ham`, `GET /health`, an optional bearer token and a message size limit; `pellet serve` keeps the classifier model in a file, saved on an interval when it changed and on shutdown.
   - Persistent state (done), together with its first user (sender and IP reputation). Decided: files with snapshots. `MemoryState` exports and imports its live entries; the binary writes them to a file atomically on an interval and at shutdown and reads them at start. Memory stays bounded by the entry cap, nothing new is linked in, and losing the last interval is harmless by the `State` contract. Reputation counts ham and spam per client address (IPv6 by /64) and per From domain that passed DMARC, learns from the same strong signals as the classifier, and emits Pellet's own `REPUTATION_*` symbols, scored in `data/pellet/scores.txt`.
   - External feeds (done; OpenPhish, PhishTank, disposable and free mail domains) fetched on their refresh interval into bounded lists, off by default.
   - After the phase (done): spam traps (`SPAM_TRAP`), replies to sent mail recorded through `/v1/sent` (`TRUSTED_REPLY`, `SPOOF_REPLYTO`), the Pyzor client and the rspamd protocol, as decided below.
7. **Tuning.** False positive and false negative rates over the corpus, weights fitted from feedback. Ongoing. `mise run eval` measures them over the untroubled.org spam archive and the SpamAssassin public corpus, downloaded to a cache outside the repository.

## Decisions

- **Host protocols:** the library, Pellet's HTTP API, and the rspamd HTTP protocol (`/checkv2`, `/learnspam`, `/learnham`, `/ping`), so mail servers and proxies that call rspamd call Pellet unchanged. No milter: Postfix and Sendmail reach Pellet through rspamd's milter proxy or their own rspamd support.
- **Collaborative checks:** a Pyzor client (`check-pyzor`), off by default because it sends a digest of every message to a third party. No DCC: its client is not under an open source license.
- **Classifier model:** one per deployment. Per-user models multiply memory (2 MB each at the default size) for little gain on small installations; feedback from every user trains the shared model.
