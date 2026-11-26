# pellet-dns

The `Resolver` contract: `ipv4`, `ipv6`, `txt`, `mx` and `ptr` lookups for checks.

Guarantees: names go through `normalize` (1–253 bytes, labels of 1–63 letters, digits, `-`, `_`, no `-` at either end; lowercased, trailing dot dropped) and an invalid name is `InvalidName` without a query; names under `.invalid` are `NotFound` without a query; `Ok` always has at least one record; host names come back lowercase without the trailing dot; every call ends within the implementation's deadline. `NotFound` covers `NXDOMAIN` and NODATA; `Timeout` and `Failed` say nothing about the name (`is_definite` tells them apart).

`is_listable(ip)` tells whether an address can be in a public DNS list at all: not unspecified, loopback, private, shared (`100.64/10`), link-local, multicast, broadcast or unique local; IPv4-mapped IPv6 is judged as IPv4.

`list_query(ip, zone)` builds the query name for a DNS list: reversed octets for IPv4, reversed nibbles for IPv6.

## Conformance

Enable `testing`; `testing::offline(&resolver)` checks refused and reserved names without the network. `testing::FakeResolver` answers from records set with `with_ipv4`, `with_txt`, `with_ptr` and friends, fails names set with `with_error`, and counts the lookups that reached it.
