//! URL extraction and parsing from mail text and HTML for Pellet checks.
//!
//! Plain data and pure functions: nothing here does I/O or follows a link. `message_links` finds
//! the links of a message once and caches them on it, so every check shares that work.

mod extract;
mod message;
mod url;

pub use extract::{Link, MAX_LINKS, Source, from_html, from_text};
pub use message::{MessageLinks, PartLinks, leftover, message_links};
pub use url::{Url, percent_decode};
