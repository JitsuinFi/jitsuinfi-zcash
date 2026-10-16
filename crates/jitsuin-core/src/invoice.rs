//! Canonical invoice encoding and buyer signatures (HNK-01).
//!
//! Layout (all integers little-endian), see vault `07-Architecture/Format Data`:
//!
//! | field                   | size |
//! |-------------------------|------|
//! | magic `JTSI`            | 4    |
//! | version                 | 1    |
//! | invoice_id length       | 1    |
//! | invoice_id (ASCII)      | 1-32 |
//! | supplier_ephemeral_pk   | 32   |
//! | buyer_pk                | 32   |
//! | amount_zat              | 8    |
//! | issue_date (days)       | 4    |
//! | due_date (days)         | 4    |
//! | terms_hash              | 32   |

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::error::Error;

pub const INVOICE_MAGIC: &[u8; 4] = b"JTSI";
pub const INVOICE_VERSION: u8 = 1;
pub const MAX_INVOICE_ID_LEN: usize = 32;

/// An invoice as signed by the buyer. Amounts are in zatoshi, dates in days since the Unix epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invoice {
    pub invoice_id: String,
    pub supplier_ephemeral_pk: [u8; 32],
    pub buyer_pk: [u8; 32],
    pub amount_zat: u64,
    pub issue_date: u32,
    pub due_date: u32,
    pub terms_hash: [u8; 32],
}

impl Invoice {
    /// Checks every field rule before encoding or after decoding.
    pub fn validate(&self) -> Result<(), Error> {
        let id = self.invoice_id.as_bytes();
        if id.is_empty()
            || id.len() > MAX_INVOICE_ID_LEN
            || !id.iter().all(|b| (0x21..=0x7e).contains(b))
        {
            return Err(Error::InvalidInvoiceId);
        }
        if self.amount_zat == 0 {
            return Err(Error::InvalidAmount);
        }
        if self.due_date < self.issue_date {
            return Err(Error::InvalidDates);
        }
        VerifyingKey::from_bytes(&self.supplier_ephemeral_pk)
            .map_err(|_| Error::InvalidPublicKey)?;
        VerifyingKey::from_bytes(&self.buyer_pk).map_err(|_| Error::InvalidPublicKey)?;
        Ok(())
    }

    /// Deterministic canonical bytes: the same invoice always encodes to the same bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let id = self.invoice_id.as_bytes();
        let mut out = Vec::with_capacity(4 + 1 + 1 + id.len() + 32 + 32 + 8 + 4 + 4 + 32);
        out.extend_from_slice(INVOICE_MAGIC);
        out.push(INVOICE_VERSION);
        out.push(id.len() as u8);
        out.extend_from_slice(id);
        out.extend_from_slice(&self.supplier_ephemeral_pk);
        out.extend_from_slice(&self.buyer_pk);
        out.extend_from_slice(&self.amount_zat.to_le_bytes());
        out.extend_from_slice(&self.issue_date.to_le_bytes());
        out.extend_from_slice(&self.due_date.to_le_bytes());
        out.extend_from_slice(&self.terms_hash);
        Ok(out)
    }

    /// Strict decoder: rejects unknown magic or version, truncated input and trailing bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.take(4)? != INVOICE_MAGIC {
            return Err(Error::BadMagic);
        }
        let version = r.byte()?;
        if version != INVOICE_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let id_len = r.byte()? as usize;
        let id = r.take(id_len)?;
        let invoice_id = String::from_utf8(id.to_vec()).map_err(|_| Error::InvalidInvoiceId)?;
        let invoice = Invoice {
            invoice_id,
            supplier_ephemeral_pk: r.array()?,
            buyer_pk: r.array()?,
            amount_zat: u64::from_le_bytes(r.array()?),
            issue_date: u32::from_le_bytes(r.array()?),
            due_date: u32::from_le_bytes(r.array()?),
            terms_hash: r.array()?,
        };
        if !r.is_empty() {
            return Err(Error::TrailingBytes);
        }
        invoice.validate()?;
        Ok(invoice)
    }
}

/// Buyer signs the canonical bytes. The key must match `invoice.buyer_pk`.
pub fn sign_invoice(buyer: &SigningKey, invoice: &Invoice) -> Result<Signature, Error> {
    if buyer.verifying_key().to_bytes() != invoice.buyer_pk {
        return Err(Error::KeyMismatch);
    }
    Ok(buyer.sign(&invoice.to_canonical_bytes()?))
}

/// Strict verification (rejects non-canonical signatures and weak keys).
pub fn verify_invoice(invoice: &Invoice, signature: &Signature) -> Result<(), Error> {
    let vk = VerifyingKey::from_bytes(&invoice.buyer_pk).map_err(|_| Error::InvalidPublicKey)?;
    vk.verify_strict(&invoice.to_canonical_bytes()?, signature)
        .map_err(|_| Error::BadSignature)
}

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, pos: 0 }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        let slice = self.bytes.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    pub(crate) fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub(crate) fn rest(&self) -> &'a [u8] {
        &self.bytes[self.pos..]
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pos == self.bytes.len()
    }
}
