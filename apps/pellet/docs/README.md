# pellet (binary)

```
pellet check <file.eml | -> [--config pellet.toml] [--model model.bin] [--ip ADDR] [--ptr NAME]
             [--helo NAME] [--from ADDR] [--rcpt ADDR]... [--tls] [--authenticated] [--json] [--headers]
pellet learn --model model.bin [--spam FILE...] [--ham FILE...] [--config pellet.toml]
pellet serve [--config pellet.toml]
```

State (reputation and sent mail) lives in memory under `[state] entries`. With `[state] path`, every command loads the snapshot at start; `serve` also writes it every `save_interval_secs` and at shutdown (atomically, expiry kept as Unix time so time spent stopped counts). `check` reads it and never writes it.

Remote lists (`[feeds] enabled`) are kept as fingerprints in memory, 8 bytes per key. Every command publishes their cached copies from `[feeds] dir`; only `serve` downloads them, each on its own schedule from its definition, and keeps the last good copy when a download fails.

`serve` runs the HTTP API of `pellet-server` on `[server] listen` and prints `listening on ADDR` once bound; the rspamd routes make it a drop-in for mail servers that call rspamd (the default port is rspamd's, 11334). Report every outgoing message to `/v1/sent` so replies to it get `TRUSTED_REPLY` or `SPOOF_REPLYTO`. With `[classifier] model` it loads that file (or starts a new model), learns from `/v1/learn` (classifier and reputation both take the message) and auto-learning, saves the model every `save_interval_secs` when it changed, and again on SIGTERM or Ctrl-C after in-flight requests finish. Logs go to standard error at `warn`; set `PELLET_LOG=info` or `debug` for more.

`learn` runs the other checks on each message, so their symbols become features, trains the classifier on the spam and ham files together in a fixed shuffled order (the model follows its latest samples, so a long run of one label, such as all spam in one call and all ham in the next, skews it towards that label), and writes the model file (created with `[classifier] bits` when missing, replaced atomically). `check --model` adds the classifier; it reads the file and never writes it, so anything auto-learned during a check is dropped.

`check` runs every stage on the message and prints the action, the score and one line per symbol with its score and stage, then failed checks; `--json` prints the verdict as JSON, `--headers` adds the `X-Spam-*` fields. Runs on a single-threaded runtime.

## Config

```toml
deadline_ms = 5000      # per stage

[thresholds]            # a missing key turns that action off; a missing table tags at 6.0
tag = 6.0
greylist = 4.0
reject = 15.0

[rules]
bundled = true          # the rules, lists and scores compiled in; false starts empty
dns_lists = false       # query the public DNS lists the rules define (their terms apply)

[classifier]
bits = 18               # table size of a new model: 2^bits entries, 8 bytes each
min_ham = 50            # samples needed before PROB_* symbols appear
min_spam = 50
auto_learn = true
model = "/var/lib/pellet/model.bin"   # for serve; none means no classifier there
save_interval_secs = 60

[state]
path = "/var/lib/pellet/state.bin"   # snapshot of reputation and other state; none keeps it in memory
entries = 100000        # most keys in memory
save_interval_secs = 60

[feeds]                 # remote lists from the rules data; their terms of use apply
enabled = ["stwt_openphish", "stwt_disposable_domains"]
dir = "/var/lib/pellet/feeds"   # cache, needed when any list is enabled
max_entries = 200000    # cap per list, whatever its definition allows

[traps]
addresses = ["trap@example.org", "@bait.example.net"]   # SPAM_TRAP; none by default

[replies]
enabled = true          # recognize replies to mail reported through /v1/sent
ttl_days = 90           # how long a sent message is remembered

[pyzor]                 # sends a digest of each message to a third-party server
enabled = false
servers = ["public.pyzor.org:24441"]
min_count = 5           # reports needed for PYZOR
timeout_ms = 2000

[server]
listen = "127.0.0.1:11334"
token = "change-me"     # optional; Authorization: Bearer or rspamd's Password header
max_message_size = 10485760

[scores]                # on top of the bundled scores
MISSING_MID = 2.5

[dns]
nameservers = ["127.0.0.1"]   # empty: system configuration
timeout_ms = 2000
cache_size = 4096
hostname = "mx.example.org"   # for SPF macros

[[dnsbl]]                     # none by default; each list has its own terms of use
zone = "zen.example.org"
ipv6 = true
results = [{ codes = [2, 3], symbol = "RBL_EXAMPLE_SBL" }]
```

Unknown keys are refused. Checks registered: `ip.rdns`, `ip.helo`, `ip.from_host`, `content.headers`, `content.presence`, `content.flags`, `content.addresses`, `content.encoding`, `content.message_id`, `content.date`, `content.received`, `content.subject`, `content.mime`, `content.html`, `url`, `auth`, `rules`, `rules.dnsbl` with `dns_lists = true`, `classifier` with `--model` or `[classifier] model`, `reputation`, `reply` unless `[replies] enabled = false`, `trap` with `[traps] addresses`, `pyzor` with `[pyzor] enabled`, and `ip.dnsbl` when lists are configured. With the bundled data the scores are Stalwart's, so a verdict's total and action reflect them.
