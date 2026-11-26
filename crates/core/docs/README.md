# pellet-core

Plain data shared by every module. No I/O.

| Type | Guarantees |
| --- | --- |
| `Stage` | `Connect < Helo < Mail < Rcpt < Data`; lowercase in config and output |
| `Envelope` | what the conversation revealed so far; `mail_from = Some("")` is the null reverse path; missing fields deserialize to defaults |
| `Message` | the original bytes, unchanged and never copied (a `Vec` is kept as given, clones share it), plus the unfolded top-level header fields parsed once; `cached::<T>(build)` keeps one view per type, built once and shared by every check and clone, so decoding and link finding happen once per message; parsing never fails; the header section ends at the first empty line or at the end; at most 1000 fields kept (`headers_truncated`); stray lines counted in `malformed_header_lines`; header names match ignoring ASCII case |
| `SymbolName` | 1–64 bytes of `A-Z`, `0-9`, `_`, starting with a letter; validated on deserialization |
| `Symbol` | a name and at most 8 options of at most 128 bytes, cut on a character boundary |
| `ScoreTable` | finite scores only; unknown symbols score `0.0`; a symbol can force `tag`, `greylist` or `reject` whatever the total |
| `Thresholds`, `Action` | the action is the one whose threshold is the highest reached, the more severe on a tie; no threshold, never; default tags at `6.0` |
| `Verdict` | symbols sorted by score then name, each once; failures in the order seen; its JSON form is what the API and CLI print |
