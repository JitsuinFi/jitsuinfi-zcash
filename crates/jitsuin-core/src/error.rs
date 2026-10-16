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
    /// Memo does not start with the ZIP-302 arbitrary-data marker `0xFF`.
    NotArbitraryDataMemo,
    /// Input ended before all fields were read.
    Truncated,
    /// Extra bytes after a complete invoice.
    TrailingBytes,
    /// Memo padding after the entry is not all zero.
    NonZeroPadding,
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
            Error::NotArbitraryDataMemo => write!(f, "memo is not ZIP-302 arbitrary data (0xFF)"),
            Error::Truncated => write!(f, "input truncated"),
            Error::TrailingBytes => write!(f, "unexpected trailing bytes"),
            Error::NonZeroPadding => write!(f, "memo padding is not zero"),
        }
    }
}

impl std::error::Error for Error {}
