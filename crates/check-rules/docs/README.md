# pellet-check-rules

## `RulesCheck` (`rules`, stage `data`, late)

Runs the rules of a `RuleSet` after every other check of the `data` stage. Rules run one at a time in priority order, each seeing every symbol so far: from earlier stages, from the other checks of this stage, and from the rules before it.

| Scope | Runs | Extra variables |
| --- | --- | --- |
| `any` | once | |
| `header` | per top-level header field | `name`, `name_lower`, `value` (unfolded), `value_lower`, `raw` (`Name: value`), `raw_lower` |
| `email` | per address: `env_from`, each `env_to`, then `from`, `reply_to`, `to`, `cc`, `bcc` mailboxes | `location`, `email`, `name`, `local`, `domain`, `sld` |
| `url` | per distinct link in the plain and HTML parts | `url`, `scheme`, `host`, `path` and `path_query` (lowercased), `sld` |
| `domain`, `ip` | not here: DNS list definitions | |

Message variables in every scope: `subject` (decoded), `from` and `reply_to` (the first mailbox, a map of `name`, `local`, `domain`, `email`, `sld`), `env_from` (the same map, `null` for the null sender), `body` (the first text part, at most 64 KiB). Addresses are lowercased; `sld` is the registrable domain from the public suffix list. Parsing uses `mail-parser`; a message it cannot parse has an empty subject and no header addresses.

A result names a symbol only if the rule set declares it (`RuleSet::symbols`); anything else emits nothing. Each symbol is emitted once, without options.

## `DnsListCheck` (`rules.dnsbl`, stage `data`, late)

Runs the `[dnsbl.*]` definitions of a `RuleSet` against a `pellet-dns` resolver. Each list's `zone` is evaluated for every item of its scope; a string is the name to query. Every A record of the answer goes to `tag` as `octets`; a string result names the symbol, if `RuleSet::dnsbl_symbols` declares it.

| Scope | Items (`location`) | Variables |
| --- | --- | --- |
| `ip` | the client (`tcp`) and public addresses in `Received` fields (`received`) | `ip`, `ip_reverse`, `is_v4`, `is_v6`, `location` |
| `domain` | registrable domains of links (`url`), From (`from`), Reply-To (`reply_to`), `MAIL FROM` (`env_from`), and every `DKIM_ALLOW` option (`dkim_pass`) | `value`, `domain`, `sld`, `location` |
| `email` | From, Reply-To and `MAIL FROM` addresses | `email`, `location` |
| `url` | distinct links | `url`, `scheme`, `host`, `path`, `path_query`, `sld` |

Identical names are asked once and at most 64 per message (`MAX_QUERIES`). Failed lookups are left out; the check never fails over DNS. `ip` and `domain` symbols carry the item as their option. Skipped for authenticated clients. The binary registers it only with `[rules] dns_lists = true`: the lists in the data are public services with their own terms.
