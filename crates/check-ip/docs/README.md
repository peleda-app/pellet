# pellet-check-ip

Connection and sender checks. None runs for authenticated clients; the address-based ones skip addresses `is_listable` (from `pellet-dns`) rejects (unspecified, loopback, private, shared `100.64/10`, link-local, multicast, broadcast, unique local IPv6). IPv4-mapped IPv6 counts as IPv4.

## `DnsblCheck` (`ip.dnsbl`, stage `connect`)

Asks every configured `DnsblZone` concurrently. Only answers in `127.0.0.0/8` count, and only codes a `DnsblResult` maps; the symbol carries the zone as its option. IPv6 clients are asked only of zones marked `ipv6`. Zones that fail are left out; when all fail the check reports a temporary error. No zones are configured by default.

## `ReverseDnsCheck` (`ip.rdns`, stage `connect`)

| Symbol | When |
| --- | --- |
| `RDNS_NONE` | no PTR record |
| `RDNS_DNSFAIL` | the PTR lookup timed out or failed |

Nothing is looked up when the host set `client_ptr`.

## `FromHostCheck` (`ip.from_host`, stage `data`)

`FROMHOST_NORES_A_OR_MX`: the domain of the first From address definitely has no A, AAAA or MX record. Timeouts do not count; skipped for authenticated clients.

## `HeloCheck` (`ip.helo`, stage `helo`)

| Symbol | When |
| --- | --- |
| `HELO_BAREIP` | an address, bare or as `[literal]` |
| `HELO_NOT_FQDN` | no dot, or not a valid DNS name |
| `HELO_NORES_A_OR_MX` | definitely no A, AAAA or MX record (timeouts do not count) |
| `HELO_IPREV_MISMATCH` | the client has PTR names and none equals the HELO name |
