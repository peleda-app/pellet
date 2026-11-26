# pellet-check-auth

## `AuthCheck` (`auth`, stage `data`)

SPF, DKIM, ARC and DMARC through `mail-auth` (Apache-2.0 OR MIT). `mail-auth` resolves with its own hickory resolver, not through `pellet-dns`; the check gives it a bounded cache per record type (`cache_entries`, default 2048) that honors every answer's TTL. Configure with `AuthConfig`: `nameservers` (empty: the system configuration), `hostname` (for SPF macros), `cache_entries`, `dns_timeout`.

| Symbols | When |
| --- | --- |
| `SPF_ALLOW`, `SPF_FAIL`, `SPF_SOFTFAIL`, `SPF_NEUTRAL`, `SPF_NA`, `SPF_DNSFAIL`, `SPF_PERMFAIL` | SPF for `MAIL FROM`, or for the HELO name with a null sender; only with a client address; option: the domain |
| `DKIM_SIGNED` | signatures present; options: signing domains |
| `DKIM_ALLOW` | a signature verified; options: its domains |
| `DKIM_REJECT` | a signature failed, or the body or a signed header changed |
| `DKIM_TEMPFAIL`, `DKIM_PERMFAIL` | a key lookup failed temporarily; the key is missing or invalid |
| `DKIM_NA` | no signatures |
| `ARC_SIGNED`, `ARC_ALLOW`, `ARC_REJECT`, `ARC_INVALID`, `ARC_DNSFAIL` | an ARC chain exists, and how it validated |
| `ARC_NA` | no ARC chain |
| `DMARC_POLICY_ALLOW` | DMARC passed; option: the From domain |
| `DMARC_POLICY_REJECT`, `DMARC_POLICY_QUARANTINE`, `DMARC_POLICY_SOFTFAIL` | DMARC failed under `p=reject`, `p=quarantine`, `p=none` |
| `DMARC_NA`, `DMARC_DNSFAIL`, `DMARC_BAD_POLICY` | no record or no single From domain; a lookup failed; the record is broken |
| `AUTH_NA` | none of SPF, DKIM, DMARC apply |

Skipped for authenticated clients. A message `mail-auth` cannot parse gets `DKIM_NA`, `ARC_NA` and `DMARC_NA`.

## Testing

The `testing` feature turns on `mail-auth`'s test mode, in which every lookup that misses the cache answers "no such name", and adds `AuthCheck::add_txt_record(name, record)` to seed SPF, DKIM and DMARC records. Enable it only from dev-dependencies: a build that unifies it into the binary would never query DNS.
