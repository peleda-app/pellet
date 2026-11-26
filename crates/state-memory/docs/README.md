# pellet-state-memory

`MemoryState::new(cap)`: `State` in memory, at most `cap` keys. When a new key would pass the cap, expired keys go first, then the least recently used (by reads and writes) in a batch of about an eighth of the cap. Versions come from one counter. Nothing survives the process by itself: `export` gives every live key with its value and remaining time to live, and `import` writes such entries back under the cap, so a host can keep them in a file (`pellet serve` does). Passes both conformance suites.
