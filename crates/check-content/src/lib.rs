//! Header, sender, subject, recipient, date, MIME and HTML heuristics.

mod address;
mod addresses;
mod date;
mod encoding;
mod flags;
mod headers;
mod html;
mod mail;
mod message_id;
mod mime;
mod presence;
mod received;
mod subject;

pub use addresses::AddressCheck;
pub use date::{DateCheck, FUTURE_SLACK, PAST_SLACK};
pub use encoding::EncodingCheck;
pub use flags::HeaderFlagsCheck;
pub use headers::HeadersCheck;
pub use html::HtmlCheck;
pub use message_id::MessageIdCheck;
pub use mime::{MAX_PARTS, MimeCheck};
pub use presence::HeaderPresenceCheck;
pub use received::ReceivedCheck;
pub use subject::SubjectCheck;
