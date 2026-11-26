# pellet-fetch-http

`HttpFetch` implements the `pellet-fetch` contract over HTTP and HTTPS with reqwest (rustls).

- `HttpFetch::new()`: one client, user agent `pellet/<version>`.
- Each call sets the list's `timeout` on the request, reads the body chunk by chunk and stops with `TooLarge` as soon as it passes `max_size`.
- Error messages are reqwest's without the URL.

Its tests run `pellet_fetch::testing::conformance` against a small HTTP/1.1 server on `127.0.0.1`.
