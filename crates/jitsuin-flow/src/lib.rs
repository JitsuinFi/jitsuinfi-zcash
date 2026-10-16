//! JitsuinFi role flows on top of the wallet and the board scanner (HNK-05 onward).
//!
//! - [`financier`]: check the board, register the entry, wait for confirmation, pay the advance.
//! - [`supplier`]: sign the entry for the agreed financier, verify the advance receipt.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

pub mod financier;
pub mod supplier;

#[derive(Debug)]
pub enum Error {
    Core(jitsuin_core::Error),
    Wallet(jitsuin_wallet::Error),
    Board(jitsuin_board::Error),
    InvalidDeal(&'static str),
    /// The supplier-signed entry does not match the deal.
    EntryMismatch(&'static str),
    /// The event is not allowed in the current state; the state is unchanged.
    UnexpectedEvent {
        state: &'static str,
        event: &'static str,
    },
    Timeout(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Core(e) => write!(f, "core: {e}"),
            Error::Wallet(e) => write!(f, "wallet: {e}"),
            Error::Board(e) => write!(f, "board: {e}"),
            Error::InvalidDeal(m) => write!(f, "invalid deal: {m}"),
            Error::EntryMismatch(m) => write!(f, "supplier entry rejected: {m}"),
            Error::UnexpectedEvent { state, event } => {
                write!(f, "event {event} is not allowed in state {state}")
            }
            Error::Timeout(m) => write!(f, "timeout: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<jitsuin_core::Error> for Error {
    fn from(e: jitsuin_core::Error) -> Self {
        Error::Core(e)
    }
}

impl From<jitsuin_wallet::Error> for Error {
    fn from(e: jitsuin_wallet::Error) -> Self {
        Error::Wallet(e)
    }
}

impl From<jitsuin_board::Error> for Error {
    fn from(e: jitsuin_board::Error) -> Self {
        Error::Board(e)
    }
}

/// Today as days since the Unix epoch (UTC), the date unit of invoices and receipts.
pub fn days_since_epoch() -> u32 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (secs / 86_400) as u32
}
