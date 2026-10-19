use core::fmt;

/// Errors returned by `jitsuin-core` encoding, decoding and verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Invoice ID is empty, longer than 32 bytes, or not printable ASCII.
    InvalidInvoiceId,
    /// Amount must be greater than zero.
    InvalidAmount,
    /// Due date is before the issue date.
    InvalidDates,
    /// A public key is not a valid Ed25519 point.
    InvalidPublicKey,
    /// The signing key does not match the public key stored in the invoice.
    KeyMismatch,
    /// Signature verification failed.
    BadSignature,
    /// Unknown magic bytes.
    BadMagic,
    /// Unsupported invoice format version.
    UnsupportedVersion(u8),
    /// Unknown registry entry kind.
    UnknownEntryKind(u8),
    /// Unknown receipt kind.
    UnknownReceiptKind(u8),
    /// Receipt or seal is signed by a different key than expected.
    UnexpectedSigner,
    /// Unknown sealed document kind.
    UnknownDocKind(u8),
    /// Unknown seal role.
    UnknownRole(u8),
    /// Seal is for another document (kind, id or hash differ).
    SealMismatch,
    /// Seal step, role or link to the previous seal does not follow the policy.
    SealOrder,
    /// One key holds two roles of the same deal.
    SelfApproval,
    /// More seals than the policy has roles.
    TooManySeals,
    /// Address is empty, too long, or not ASCII alphanumeric.
    InvalidAddress,
    /// Unknown flag value in a settled entry.
    InvalidFlag(u8),
    /// Verification bundle has a missing, repeated or unknown item.
    BadBundle,
    /// History certificates are not a gap-free chain from index 0, or repeat an invoice.
    HistoryOrder,
    /// Both entries name the same financier: a re-post, not double financing.
    NotDoubleSigned,
    /// Memo does not start with the ZIP-302 arbitrary-data marker `0xFF`.
    NotArbitraryDataMemo,
    /// Input ended before all fields were read.
    Truncated,
    /// Extra bytes after a complete invoice.
    TrailingBytes,
    /// Memo padding after the entry is not all zero.
    NonZeroPadding,
    /// Discount or tenor class is not defined, or only one of the two is disclosed (HNK-08).
    InvalidBucket,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidInvoiceId => write!(f, "invoice id must be 1-32 printable ASCII bytes"),
            Error::InvalidAmount => write!(f, "amount must be greater than zero"),
            Error::InvalidDates => write!(f, "due date is before issue date"),
            Error::InvalidPublicKey => write!(f, "invalid Ed25519 public key"),
            Error::KeyMismatch => write!(f, "signing key does not match the invoice public key"),
            Error::BadSignature => write!(f, "signature verification failed"),
            Error::BadMagic => write!(f, "unknown magic bytes"),
            Error::UnsupportedVersion(v) => write!(f, "unsupported format version {v}"),
            Error::UnknownEntryKind(k) => write!(f, "unknown registry entry kind 0x{k:02x}"),
            Error::UnknownReceiptKind(k) => write!(f, "unknown receipt kind 0x{k:02x}"),
            Error::UnexpectedSigner => write!(f, "signed by an unexpected key"),
            Error::UnknownDocKind(k) => write!(f, "unknown document kind 0x{k:02x}"),
            Error::UnknownRole(r) => write!(f, "unknown seal role 0x{r:02x}"),
            Error::SealMismatch => write!(f, "seal is for another document"),
            Error::SealOrder => write!(f, "seal out of policy order"),
            Error::SelfApproval => write!(f, "one key holds two roles"),
            Error::TooManySeals => write!(f, "more seals than the policy allows"),
            Error::InvalidAddress => write!(f, "address must be 1-512 ASCII alphanumeric bytes"),
            Error::InvalidFlag(v) => write!(f, "invalid settled flag 0x{v:02x}"),
            Error::BadBundle => write!(f, "malformed verification bundle"),
            Error::HistoryOrder => write!(f, "history chain has a gap, a fork or a repeat"),
            Error::NotDoubleSigned => write!(f, "same financier commitment: not double financing"),
            Error::NotArbitraryDataMemo => write!(f, "memo is not ZIP-302 arbitrary data (0xFF)"),
            Error::Truncated => write!(f, "input truncated"),
            Error::TrailingBytes => write!(f, "unexpected trailing bytes"),
            Error::NonZeroPadding => write!(f, "memo padding is not zero"),
            Error::InvalidBucket => write!(f, "discount/tenor class is not defined"),
        }
    }
}

impl std::error::Error for Error {}
