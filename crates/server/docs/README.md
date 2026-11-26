# pellet-server

`router(engine, hooks, config)`: an axum router, to serve alone (`pellet serve`) or mount in another application. `Hooks` holds `learners`, anything that learns from a marked message (`Learner`: `name`, `learn`), and `sent`, a `SentLog` that remembers mail the host sent (`record`). The composition root adapts the classifier, reputation and reply checks to them, so this crate knows no check.

| Route | Request | Response |
| --- | --- | --- |
| `POST /v1/check` | the raw message as the body; envelope in the query: `ip`, `ptr`, `helo`, `from` (empty for the null sender), `rcpt` (repeat for several), `tls`, `authenticated` | the verdict as JSON, plus `headers`: the `X-Spam-*` fields as name–value pairs |
| `POST /v1/learn` | the raw message; `label=spam` or `label=ham` and the same envelope fields | `{"learned": [names]}`: the `Learner`s that took it, in order. The message goes through the checks first, so their symbols (without `PROB_*`) go along. `404` when no learner is configured |
| `POST /v1/sent` | a message the host sent; `rcpt` (repeat) for its envelope recipients, else its `To` and `Cc` count | `{"recorded": true}` when remembered, `false` without a Message-ID or a recipient; `404` without a `SentLog` |
| `POST /checkv2` | the rspamd protocol, below | rspamd's check result |
| `POST /learnspam`, `POST /learnham` | the rspamd protocol | `{"success": true}`; `404` without learners |
| `GET /health` | | `ok`, never behind the token |
| `GET /ping` | | `pong`, never behind the token |

## rspamd protocol

Mail servers and proxies that already call rspamd can call Pellet unchanged. The envelope comes from request headers: `IP`, `Helo`, `From`, `Rcpt` (repeat), `Hostname` (`unknown` means no PTR), `User` (any value marks an authenticated client), `TLS-Version` or `TLS-Cipher` (TLS). Other headers (`Queue-Id`, `Deliver-To`, `Pass`, `Settings`, ...) are ignored; a `Compression` header gets `415`, since compressed bodies are not supported. The token may come as `Authorization: Bearer` or as rspamd's `Password` header.

`/checkv2` answers with `score`, `required_score` (the reject threshold, else the tag threshold), `action` (`no action`, `add header`, `greylist`, `reject`), `symbols` keyed by name with `score`, `metric_score` and `options`, `message-id`, `time_real`, and `milter.add_headers` carrying the `X-Spam-*` fields, so rspamd's milter proxy can add them.

`ServerConfig`: `token` (when set, every route but `/health` and `/ping` needs `Authorization: Bearer <token>`, or `Password: <token>`, compared in constant time, else `401`) and `max_message_size` (default 10 MiB, larger bodies get `413`). Unknown query keys and malformed values get `400` with `{"error": "..."}`.

Logs carry score, action and counts at `debug`, never content.

```
curl --data-binary @message.eml 'http://127.0.0.1:11334/v1/check?ip=192.0.2.7&from=ana%40example.com&rcpt=bo%40example.org'
```
