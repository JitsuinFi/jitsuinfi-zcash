//! Hanko core: canonical invoices, buyer signatures and shielded registry entries.
//!
//! "Zcash stops double-spending. Hanko stops double-financing."
//!
//! Pure logic only (no network, no chain access). Zcash integration lives in separate crates.

pub mod entry;
pub mod error;
pub mod invoice;

pub use entry::{BoardEntry, EntryKind, ENTRY_LEN, MEMO_LEN};
pub use error::Error;
pub use invoice::{sign_invoice, verify_invoice, Invoice};
