//! JitsuinFi core: canonical invoices, buyer signatures, shielded registry entries and signed
//! receipts.
//!
//! "Zcash stops double-spending. JitsuinFi stops double-financing."
//!
//! Pure logic only (no network, no chain access). Zcash integration lives in separate crates.

pub mod assignment;
pub mod bundle;
pub mod entry;
pub mod error;
pub mod history;
pub mod invoice;
pub mod memo;
pub mod nullifier;
pub mod receipt;
pub mod seal;
pub mod settled;

pub use assignment::Assignment;
pub use bundle::{Bundle, BundleReport};
pub use entry::{financier_commitment, settled_tag, BoardEntry, EntryKind, ENTRY_LEN, MEMO_LEN};
pub use error::Error;
pub use history::{BuyerIdentity, HistoryCert};
pub use invoice::{sign_invoice, verify_invoice, Invoice};
pub use memo::MemoItem;
pub use nullifier::{document_hash, nullifier};
pub use receipt::{Receipt, ReceiptKind, RECEIPT_LEN};
pub use seal::{verify_chain, ChainStatus, DocKind, Role, Seal, SealContent, Signers, SEAL_LEN};
pub use settled::{SettledEntry, SettlementDoc, SETTLED_LATE, SETTLED_ON_TIME};
