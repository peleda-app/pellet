# Data

Scores, rules and lists loaded by `pellet-rules` and compiled into it.

- `stalwart/`: imported from Stalwart Spam Filter Rules (MIT); see `stalwart/SOURCE.md`. Do not edit by hand; run `scripts/import-stalwart-rules.sh` to update, and put Pellet's own additions elsewhere.
  - `rules/*.toml`: `[rule.*]` tables (`scope`, `priority`, `condition`, optional `enable`) and `[dnsbl.*]` tables (`zone`, `tag`)
  - `lists/scores.txt`: `SYMBOL = score`
  - `lists/http_lists.toml`: remote lists, fetched only when a deployment turns them on
  - `lists/*.txt`: one key per line (`key = value` lines keep the key), referenced by file name with `_` turned into `-`
- `pellet/scores.txt`: scores for symbols Pellet defines itself (`REPUTATION_*`), loaded after the imported scores.
- `pellet/click_trackers.txt`: click-tracking hosts of mail delivery services (`click-trackers`), whose links are not judged as phishing.
- `pellet/alias_relays.txt`: forwarding services that hand out aliases (`alias-relays`), so mail to an alias there is not taken for forged recipients.
