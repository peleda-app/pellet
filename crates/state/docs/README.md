# pellet-state

The `State` contract: keys of 1–256 bytes without control characters, values up to 32 MiB, versions that are never reused for a key, and `Expect::{Any, Absent, Version}` for compare-and-swap on `put` and `delete`.

Guarantees: read-after-write; of concurrent writes with the same expectation at most one wins and the rest get `Conflict`; a value with a time to live is gone once it elapses on the Tokio clock; any key may be evicted early by an implementation with a cap, so losing a key must be harmless; values come back byte for byte. `Unavailable` means the outcome of a write is unknown.

## Conformance

Enable `testing`; call `testing::conformance(&state)` in a normal Tokio test and `testing::expiry(&state)` in a `start_paused = true` test. Keys live under `conformance/`.
