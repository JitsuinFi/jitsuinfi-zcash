//! JitsuinFi core: canonical invoices, buyer signatures, shielded registry entries and signed
//! receipts.
//!
//! "Zcash stops double-spending. JitsuinFi stops double-financing."
//!
//! Pure logic only (no network, no chain access). Zcash integration lives in separate crates.

pub mod entry;
pub mod error;
pub mod invoice;
pub mod receipt;

pub use entry::{financier_commitment, BoardEntry, EntryKind, ENTRY_LEN, MEMO_LEN};
pub use error::Error;
pub use invoice::{sign_invoice, verify_invoice, Invoice};
pub use receipt::{Receipt, ReceiptKind, RECEIPT_LEN};
