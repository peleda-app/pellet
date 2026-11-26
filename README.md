# Pellet

Pellet is a spam filter for weak hardware. A mail server calls it at each SMTP stage, or sends it a finished message over HTTP, and gets back a verdict: the named symbols that fired, a score and an action (accept, tag, greylist, reject). It checks SPF, DKIM, DMARC and ARC, DNS blocklists, headers, MIME, HTML and URLs, runs data-driven rules, and learns from people marking mail as spam or not.

It runs as a Rust library or as a small service, in tens of megabytes on one slow core.

Status: early development. See [docs/PLAN.md](docs/PLAN.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in Pellet by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
