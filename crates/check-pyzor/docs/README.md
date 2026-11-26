# pellet-check-pyzor

## `PyzorCheck` (`pyzor`, stage `data`)

Asks a Pyzor server how many people reported the message's digest as spam. Off in the binary until `[pyzor] enabled = true`: every checked message then sends one UDP datagram to a third-party server, and the server's terms apply.

| Symbol | When |
| --- | --- |
| `PYZOR` | at least `min_count` (5) spam reports and fewer than `min_count` whitelist entries; the option is the report count |

`PyzorConfig`: `servers` (`host:port`, asked in order until one answers; default `public.pyzor.org:24441`), `min_count`, `timeout` per server (2 s). Names resolve through the system resolver.

Only the digest leaves the process, as an anonymous `check` request (protocol 2.1, signed with the anonymous key). `digest(message)` is the hex SHA-1 over the lines of the text parts after normalization: tokens of ten or more characters, addresses (`x@y`), URLs (`scheme:rest`), HTML tags and all whitespace are dropped, and lines shorter than eight characters are skipped. With at most four lines all are used; otherwise three lines from 20% and three from 60% of the way through. Text parts without a declared charset keep only their ASCII, and bytes the charset cannot decode are dropped. HTML parts are reduced to their text nodes, each trimmed and joined by a space, with `script`, `style` and comments left out and entities decoded as HTML does (legacy names without a semicolon included). Messages with no qualifying line and messages from authenticated clients are not looked up.

When no server answers in time the check fails with `CheckError::Temporary`; the engine records the failure and the message goes on without the symbol.

Written from the documented protocol; no Pyzor code is used. DCC is not implemented: its client is not under an open source license.

`testing::serve(count, whitelist)` (feature `testing`) starts a fake server on a loopback port; `testing::parse_response(response, thread)` reads an answer the way the check does, for the `pyzor` fuzz target.

The unit tests use that fake. `vectors/` holds 30 invented messages (plain, multipart, base64, quoted-printable, undeclared 8-bit, CRLF, many HTML shapes) with the digests Pyzor's own client 1.1.2 computed for them, and `digests_match_pyzor` requires ours to equal each; the reference digests were produced by running the client, not by reading its code. One ignored test talks to `public.pyzor.org` (`mise run network`) to confirm the server answers our requests.
