//! Connection checks: DNS blocklists, reverse DNS and HELO.
//!
//! None of these checks run for authenticated clients, and the address-based ones skip
//! addresses that cannot be listed (loopback, private, link-local, shared, multicast).

mod dnsbl;
mod from_host;
mod helo;
mod rdns;

pub use dnsbl::{DnsblCheck, DnsblResult, DnsblZone};
pub use from_host::FromHostCheck;
pub use helo::HeloCheck;
pub use pellet_dns::is_listable;
pub use rdns::ReverseDnsCheck;

use pellet_core::{Symbol, SymbolName};

fn emit(declared: &[SymbolName], name: &str) -> Symbol {
    Symbol::new(
        declared
            .iter()
            .find(|d| d.as_str() == name)
            .expect("declared symbol")
            .clone(),
    )
}
