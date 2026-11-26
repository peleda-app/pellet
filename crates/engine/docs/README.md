# pellet-engine

`Engine::builder()` takes checks, a `ScoreTable`, `Thresholds` and a per-stage deadline (default 5 s), and refuses duplicate check names and non-finite thresholds. The engine is cheap to clone.

`engine.session(envelope)` walks one SMTP conversation:

- `run(stage)` for stages before `data`, `data(message)` for the last one. Stages may be skipped, never repeated or run backwards (`SessionError::OutOfOrder`). A skipped stage never runs later.
- `envelope_mut()` fills in the envelope between stages; each stage sees it as it is then.
- Every check of a stage runs concurrently under one deadline; then the late checks (`Check::late`) run concurrently under the same deadline and see the symbols of the others. A late check is recorded as `Deadline`, an error as `Error`, an undeclared symbol is dropped and recorded as `Undeclared`; the verdict always arrives.
- The same symbol from several checks counts once, its options merged.
- Each call returns the verdict so far: every symbol from every stage, scored, summed, mapped to an action; a fired symbol with a forced action (`ScoreTable::force`) makes the action at least that strict.

`engine.check_message(envelope, message)` runs every stage on a finished message. `headers(&verdict)` renders `X-Spam-Score`, `X-Spam-Action` and `X-Spam-Symbols` as single-line printable ASCII.

Logs carry stage, score, action and counts at `debug`, never content.
