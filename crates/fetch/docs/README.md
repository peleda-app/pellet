# pellet-fetch

The download contract for remote lists (`pellet-feeds`).

- `Fetch::fetch(url, timeout, max_size)`: the whole body as served, or `FetchError`.
- `FetchError::Download`: unusable URL, failed connection, passed deadline or error status. `FetchError::TooLarge(max_size)`: the body is longer than `max_size`; reading stops there.
- Error messages never contain the URL.

An implementation must keep every guarantee on the trait. Run the conformance suite from its tests with a dev-dependency on `pellet-fetch` with the `testing` feature: serve the four URLs described by `testing::Urls` (a body, a large body, a 404 and one that never answers in time) and call `pellet_fetch::testing::conformance(&fetch, &urls).await`.
