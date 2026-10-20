//! JitsuinFi role flows on top of the wallet and the board scanner (HNK-05 onward).
//!
//! - [`financier`]: check the board, register the entry, wait for confirmation, pay the advance.
//! - [`supplier`]: sign the entry for the agreed financier, verify the advance receipt.
//! - [`buyer`]: repayment request (ZIP-321 URI and QR) with a buyer-signed receipt.
//! - [`settlement`]: financier detects the repayment, records it as settled, optionally posts a
//!   `settled` entry to the board.
//! - [`fund`]: JitsuinFi Vault solvency computed by a member from the fund's viewing key (HNK-15).
//! - [`history`]: the buyer's history chain checked against the board and the minimum standard
//!   before a new invoice is registered (HNK-20).

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

pub mod buyer;
mod codec;
pub mod financier;
pub mod fund;
pub mod history;
pub mod receipts;
pub mod settlement;
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
    Qr(String),
    /// The repayment does not cover the amount due yet.
    NotSettled {
        paid_zat: u64,
        due_zat: u64,
    },
    History(jitsuin_board::history::HistoryError),
    /// The buyer's history does not meet the financier's minimum standard.
    BelowStandard(&'static str),
    /// A stored deal snapshot that cannot be read back (HNK-26.T10).
    Snapshot(&'static str),
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
            Error::Qr(m) => write!(f, "qr: {m}"),
            Error::NotSettled { paid_zat, due_zat } => {
                write!(f, "not settled: {paid_zat} of {due_zat} zat paid")
            }
            Error::History(e) => write!(f, "history: {e}"),
            Error::BelowStandard(m) => write!(f, "below minimum standard: {m}"),
            Error::Snapshot(m) => write!(f, "deal snapshot: {m}"),
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
