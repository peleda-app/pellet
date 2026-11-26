# pellet-urls

URL extraction and parsing for checks. Pure functions, no I/O; nothing is fetched or followed.

- `Url::parse`: `scheme://[user@]host[:port]/path?query#fragment`, or a bare `www.` link as `http`. The host is lowercased; a missing host, or one with spaces or characters no host name has, does not parse. `host_ip` also reads hosts written as one decimal or hexadecimal number (`host_is_numeric`). `registrable` gives the domain under its public suffix. `has_known_suffix` tells whether the host ends in a suffix of the public suffix list, so text such as `yarn.lock` or `94.75` is not taken for a domain. `redirect_target` finds the first absolute URL in a query parameter, percent-decoded.
- `from_text`: `http://`, `https://`, `ftp://` and `www.` links in plain text, ending at whitespace, quotes or brackets, sentence punctuation trimmed.
- `from_html`: `href`, `src` and `action` targets (skipping `#`, `mailto:`, `tel:`, `cid:`, `javascript:`, `data:`), the visible text of each `<a>` as `anchor_text`, then links written in visible text outside anchors. Comments are skipped. Links that do not parse are kept with `url: None`.

Both return at most `MAX_LINKS` (200) links, in one pass over the text (links are found in an ASCII-lowercased copy, whose byte positions match the original).

- `message_links(message)`: the links of every plain and HTML part and of the subject, with each part's `leftover` (visible characters that are neither a written link nor an anchor's text), found once and cached on the message. `url`, `rules`, `rules.dnsbl` and `classifier` all read this one view.
