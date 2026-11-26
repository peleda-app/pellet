# pellet-rules

Rule, score and list data, its loader, and the expression language that evaluates it. No I/O at run time: `RuleSet::bundled()` reads the files of `data/stalwart/` compiled into the crate, then Pellet's own `data/pellet/scores.txt` (scores on top) and its own lists `data/pellet/click_trackers.txt` (`click-trackers`) and `data/pellet/alias_relays.txt` (`alias-relays`).

## Data

| File | Read by | |
| --- | --- | --- |
| `rules/*.toml` `[rule.ID]` | `Rule` | `scope` (`any`, `header`, `email`, `url`, `domain`, `ip`), `priority` (lower first, ties by id), `condition`, optional `enable` |
| `rules/*.toml` `[dnsbl.ID]` | `DnsblRule` | `scope`, `zone` (the name to query, or false), `tag` (the symbol for an answer, reading `octets`) |
| `lists/http_lists.toml` `[http-list.ID]` | `HttpList` | `url`; the list is named `ID` in lowercase; nothing is fetched here |
| `lists/scores.txt` | `ScoreTable` | `SYMBOL = number`, or `SYMBOL = tag|greylist|reject` to force that action |
| `lists/*.txt` | `Lists` | one key per line, `key = value` keeps both, `#` comments; named after the file with `_` turned into `-`; keys lowercased |

Remote lists (`[http-list.*]`) carry their URL, format (`list`, or `csv` with `separator`, `index.key`, `skip-first`), `gzipped`, `refresh`, `retry`, `timeout` and `limits`. Their keys reach `key_exists` through `Lists::remote()`, a handle every clone of the lists shares, holding `Fingerprints` (sorted FNV-1a hashes of the lowercased keys, 8 bytes each). `pellet-feeds` fills them.

Loading checks everything and fails with the file and the table id: TOML syntax, unknown keys, unknown scopes, every expression's syntax, function names and arities, and that every variable exists in the rule's scope (`MESSAGE_VARIABLES` plus `Scope::variables`). Disabled tables are checked, then left out. A list that does not exist is empty, so `key_exists` on it is false.

`RuleSet::dnsbl_symbols()` lists every symbol-shaped literal in the DNS list `tag`s, `RuleSet::referenced_symbols()` every `$NAME` the rules read.

`RuleSet::symbols(scopes)` lists what the rules of those scopes can emit: every symbol-shaped string literal in a `then` or `else`, and, for computed names such as `'FREEMAIL_' + to_uppercase(location)`, every scored symbol that starts with the literal prefix.

## Conditions

```toml
condition = [ { if = "contains(subject, '!')", then = "'SUBJECT_HAS_EXCLAIM'" },
              { if = "len(subject) > 200", then = "'LONG_SUBJ'" },
              { else = false } ]
```

The first clause whose `if` is truthy gives the result, otherwise `else`, otherwise `null`. A plain string or boolean is a condition with only an `else`. A rule's result is the symbol to emit when it is a string.

## Expressions

| | |
| --- | --- |
| Literals | `'text'` (escapes `\'`, `\\`, `\n`, `\t`; a backslash before any other character keeps that character), `12`, `1.5`, `true`, `false`, `[a, b]` |
| Variables | `subject`; fields `from.local`; indexes `octets[3]` (out of range is `null`) |
| Symbols | `$NAME`: true when the symbol has fired so far |
| Operators, loosest first | `\|\|`, `&&`, `== !=`, `< <= > >=`, `+ -`, `* /`, unary `! -` |

Values are null, booleans, integers, floats, strings, lists and maps. Evaluation never fails: a mismatched kind gives `null`, which is falsy, as are `false`, `0`, `""`, `[]` and an empty map. Numbers compare across integer and float; strings compare with strings; other kinds are equal only to their own kind. `+` adds numbers, concatenates lists, and concatenates text when either side is a string. Division by zero is `null`. `&&` and `||` short-circuit and give booleans. A string's `words` field is its list of alphanumeric words.

| Function | Result |
| --- | --- |
| `contains(s, x)` | substring for a string, element for a list |
| `contains_ignore_case(s, x)` | the same, ignoring case |
| `starts_with(s, p)`, `ends_with(s, p)` | strings only |
| `is_empty(x)` | `null`, `""`, `[]`, empty map |
| `key_exists(list, key)` | the named list holds the key (lowercased); an empty key is false |
| `if_then(c, a, b)` | `a` when `c` is truthy, else `b`; only one side is evaluated |
| `is_intersect(a, b)` | two lists share an element |
| `trim`, `to_lowercase`, `to_uppercase` | strings only |
| `split(s, sep)` | list of parts |
| `split_once(s, sep)` | `[before, after]`, or `[s]` without the separator |
| `len(x)` | characters of a string, items of a list, else 0 |
| `has_digits(s)` | any ASCII digit |
| `bit_and(a, b)` | integers |
| `hash(s, algorithm)` | lowercase hex digest of a string with `md5` or `sha1`; anything else is `null` |

The language is written from the Stalwart rules data, which it accepts unchanged; it is not a port of any interpreter.
