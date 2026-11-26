# pellet-check-url

## `UrlCheck` (`url`, stage `data`)

Links from the plain and HTML parts and the subject, through `pellet-urls`. Built with the known redirector hosts (the bundled `url-redirectors` list) and, optionally, click trackers (`click-trackers`), which only keep `PHISHING` off.

| Symbol | When |
| --- | --- |
| `URL_ONLY`, `BODY_URI_ONLY` | a plain part, or an HTML part with anchors, holding fewer than ten characters besides its links |
| `URL_IN_SUBJECT` | the subject has a link |
| `HTTP_TO_IP` | a web link to an IP address, including numeric hosts |
| `SUSPICIOUS_URL` | a user name before `@`, or a host written as a number |
| `HTTP_TO_HTTPS` | the anchor shows `https://…` and links over `http` |
| `PHISHING` | the anchor shows a domain whose registrable domain differs from where the link ends up after unwrapping known redirectors (up to five); option: the shown domain. The shown text must end in a suffix of the public suffix list, and is not a domain when it is a bare mail address or a bare file name whose extension is also a top-level domain (`README.md`, `build.sh`). A link that stops at a known redirector without showing where it leads, or at a click tracker given to `UrlCheck::click_trackers` (the bundled `click-trackers` list, subdomains included), is not judged |
| `HOMOGRAPH_URL` | a host label mixing Latin with Cyrillic, Greek or other letters; accented Latin letters (`é`, `ė`, `š`) count as Latin |
| `MIXED_CHARSET_URL` | a non-ASCII host whose labels use different scripts |
| `ZERO_WIDTH_SPACE_URL` | zero-width characters in a link |
| `UNPARSABLE_URL` | an attribute link that does not parse |
| `URI_COUNT_ODD` | plain and HTML parts with an odd number of distinct links between them |
| `REDIRECTOR_URL`, `URL_REDIRECTOR_INSECURE`, `URL_REDIRECTOR_NESTED` | a link through a known redirector (option: its host), over `http`, into another redirector |

Needs no DNS and no state. URI blocklists are DNS lists from the rules data, a later step.
