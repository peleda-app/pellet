# pellet-feeds

Remote lists for rules (`key_exists`), from the `[http-list.*]` definitions of the rules data: OpenPhish, PhishTank, disposable and free mail domains. Nothing is fetched unless a deployment enables a list; each list has its own terms of use.

- `parse(list, body, cap)`: gunzips when the list says so (never past `max_size`), takes one key per line or the configured CSV field (header skipped when `skip-first`, quotes stripped), drops blank lines, `#` comments and keys longer than `max_entry_size`, keeps at most `min(max_entries, cap)`, and turns them into `Fingerprints` (8 bytes per key). An empty result is an error, so a broken download never empties a list.
- `refresh(list, fetch, remote, dir, cap)`: download, parse, publish to the rule set's `RemoteLists`, cache as `<dir>/<name>.fp` (atomically).
- `restore(list, remote, dir)`: publishes the cache and tells how long until the list is due.
- `keep_fresh(...)`: one task per list, forever: restore, then download when due; after a failure wait `retry` and keep the last good copy; after a success wait `refresh`.
- Downloads go through the `pellet-fetch` contract (`Arc<dyn Fetch>`); the binary passes `pellet-fetch-http`. `FetchError` becomes `FeedError::Download` or `FeedError::TooLarge`.

Cache format: `PELLETF1`, the count as `u64`, then the sorted fingerprints, little endian.
