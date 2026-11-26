# pellet-eval

Pellet over real mail: public spam and ham corpora, downloaded once into a cache outside the repository and never committed (they hold real addresses and the senders keep their copyright).

```sh
mise run eval                                  # download if missing, then report
PELLET_EVAL_MONTH=2026-09 mise run eval -- --limit 500
```

`scripts/eval.sh` keeps everything under `PELLET_EVAL_DIR` (default `~/.cache/pellet-eval`):

| Corpus | What | Terms |
| --- | --- | --- |
| [untroubled.org spam archive](https://www.untroubled.org/spam/), one month (`PELLET_EVAL_MONTH`, default `2026-10`) | spam caught by Bruce Guenter's bait addresses since 1998, one raw message per file | "Permission is hereby granted to use this archive without restriction"; the author asks that a client fetch at most once a day |
| [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/), `20030228_easy_ham`, `_hard_ham`, `_spam` | ham and spam from 2002–2003 with full headers, some addresses obfuscated | collected for testing spam filters offline; never send these messages into a live mail system |

The archives are fetched only when missing from the cache. Extraction needs `bsdtar` (libarchive) or `7z`.

## What it reports

Only the checks that judge content run: headers, addresses, encoding, Message-ID, Received, subject, MIME, HTML, URLs and the bundled rules. DNS, authentication, dates and reputation are left out, since a message from 2003 or with forged headers would be judged by today's DNS and clock.

1. **Rules and heuristics:** per corpus, the share of messages at or above the tag and reject thresholds and the median score; the scoring symbols most frequent in spam; the symbols that push flagged ham over the threshold; the file names of the highest-scoring ham, to look at by hand.
2. **With the classifier:** every second message trains a classifier (in a fixed random order, one pass), the others are judged with it; the classifier's own accuracy, then the same tables.

Online training follows its last examples: training all spam, then all ham, leaves a model that calls everything ham. The training set is shuffled for that reason.
