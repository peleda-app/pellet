# pellet-check

The `Check` contract: a name, a stage, the symbols it may emit, and `run(&Context)`.

`Context` carries the stage, the envelope as known at that stage, the message (always present at `data`, absent before) and the symbols of earlier stages. Anything else a check needs (DNS, state, data) it gets when the composition root builds it, so this crate depends on `pellet-core` only.

A late check (`late()` returns true) runs after the other checks of its stage and finds their symbols in `Context::earlier`; rules and composites are late.

An implementation must keep: stable name and symbols; only declared symbols emitted, each once; the same output for the same context and outside data; `run` safe to call concurrently. Errors (`CheckError::Temporary`, `CheckError::Failed`) never stop a verdict; their text never holds message content.

## Conformance

Enable `testing` and call `testing::conformance(&check, &fixtures)` with `Fixture`s that make the check fire and that do not. The feature also ships `FixedCheck`, `FailingCheck` and `SlowCheck` for engine tests.
