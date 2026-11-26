# pellet-load

Load tests with generated messages: invented shapes of known size, the same on every run, through the full engine and through the HTTP API.

The engine has every check but `auth` (its `mail-auth` resolver would measure network waits instead of work); DNS goes to an in-process fake, the classifier is an untrained 2^18 model that still predicts, reputation lives in memory. Nothing touches the network except the loopback port of the `serve` scenario.

## Report

```sh
mise run load                                     # release build, both scenarios
cargo run --release -p pellet-load -- --scenario engine --messages 20 --concurrency 4
```

Prints Markdown tables: p50, p99, max and messages per second for each kind of message, resident memory after each kind, and for `serve` the times of check and learn requests over HTTP. CI writes the same tables to the job summary.

| Kind | What it stresses |
| --- | --- |
| `plain` | everyday personal mail |
| `newsletter-400-links` | HTML with a plain alternative, link extraction, URL checks |
| `attachment-1mb`, `attachment-8mb` | base64 attachments that most checks must skip |
| `text-1mb` | a long plain body |
| `no-spaces-1mb` | a body with no word breaks |
| `headers-2000` | many header fields |
| `mime-depth-60` | deeply nested multipart containers |
| `unicode-256kb` | text whose lowercase form is longer than the original |

Memory is the peak (`VmHWM`) on Linux and the current resident size elsewhere.

## Budgets

`cargo test --release -p pellet-load` runs `tests/budget.rs`; a debug build skips it.

- **Time:** the slowest message of each kind stays under a ceiling about ten times what a laptop measures.
- **Linearity:** eight times the input takes at most twenty times as long, so a quadratic path fails even on a fast machine.
- **Memory:** peak resident memory stays under 96 MB with 11 MB messages in flight (Linux only, where the peak is reported).
- **API:** 500 requests over HTTP, a tenth of them learns, eight at a time, each within 250 ms at p99.
