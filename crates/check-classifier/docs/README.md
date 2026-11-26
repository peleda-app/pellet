# pellet-check-classifier

## `ClassifierCheck` (`classifier`, stage `data`, late)

Holds a `Model` in memory and runs after the other checks of the stage, so their symbols are features (its own `PROB_*` never are). `document(message, envelope, symbols)` builds what it reads: decoded subject, the visible text of the first text or HTML body (64 KiB at most), registrable domains of the links, the From domain, header names, symbols.

| Symbol | Probability of spam |
| --- | --- |
| `PROB_SPAM_HIGH` | ≥ 0.95 |
| `PROB_SPAM_MEDIUM` | 0.80 – 0.95 |
| `PROB_SPAM_LOW` | 0.60 – 0.80 |
| `PROB_SPAM_UNCERTAIN` | 0.40 – 0.60 |
| `PROB_HAM_LOW` | 0.20 – 0.40 |
| `PROB_HAM_MEDIUM` | 0.05 – 0.20 |
| `PROB_HAM_HIGH` | < 0.05 |

The option is the probability with two decimals. Nothing is emitted until the model has `min_ham` and `min_spam` samples (50 each by default).

- `learn(message, envelope, symbols, spam)`: feedback from a person.
- Auto-learning (on by default, never for authenticated clients): spam for a blocklist hit (symbols starting `RBL_`, `RECEIVED_`, `DBL_`, `SURBL_`, `URIBL_`, `MSBL_`, `SEM_URIBL`) together with `DMARC_POLICY_REJECT`, `DMARC_POLICY_QUARANTINE` or `SPF_FAIL`, or for `GTUBE_TEST` or `SPAM_TRAP`; ham when `DKIM_ALLOW`, `SPF_ALLOW` and `DMARC_POLICY_ALLOW` all fired without a blocklist hit.
- `samples()` gives (ham, spam) without copying the model; `snapshot()` hands the model to the host to keep; `updates()` counts samples learned since the check was built. A check's output depends on its model, which learning changes.

Training is online: the model leans towards its latest samples. Feed spam and ham mixed; a long run of one label (thousands of spam, then thousands of ham) leaves it judging nearly everything as that last label. `pellet learn` shuffles the files it is given for this reason.
