//! Invoice nullifier and document hashes (HNK-02.T1, DEV-04).
//!
//! `N = BLAKE2b-256(personalization = "JitsuinNullifier", canonical invoice bytes)`.
//!
//! The same invoice always gives the same N, whatever signature the buyer produced: Ed25519 is
//! deterministic only by convention, and a signer with random nonces can make several valid
//! signatures for one invoice. N cannot be guessed without the invoice because the canonical bytes
//! cover the supplier's random per-invoice key. N is the document id of the invoice: every board
//! entry, receipt and seal of the invoice refers to it, the way SignBaliola groups the stamps of one
//! document by its document id.

use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::invoice::Invoice;

pub const NULLIFIER_PERSONALIZATION: &[u8; 16] = b"JitsuinNullifier";

/// N of a valid invoice.
pub fn nullifier(invoice: &Invoice) -> Result<[u8; 32], Error> {
    let bytes = invoice.to_canonical_bytes()?;
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(NULLIFIER_PERSONALIZATION)
        .hash(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    Ok(out)
}

/// SHA-256 of an off-chain document (the PDF behind `terms_hash`), computed on the client so the
/// file never leaves the device. SHA-256 keeps it checkable with standard tools (`shasum -a 256`).
pub fn document_hash(file: &[u8]) -> [u8; 32] {
    Sha256::digest(file).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    /// HNK-01 test vector invoice (vault `Format Data`).
    fn vector() -> Invoice {
        Invoice {
            invoice_id: "TES-INV-0001".into(),
            supplier_ephemeral_pk: SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes(),
            buyer_pk: SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes(),
            amount_zat: 1_000_000_000,
            issue_date: 20_377,
            due_date: 20_437,
            terms_hash: [9; 32],
        }
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn nullifier_vector() {
        // Cross-checked with Python:
        // hashlib.blake2b(canonical, digest_size=32, person=b"JitsuinNullifier")
        assert_eq!(
            hex(&nullifier(&vector()).unwrap()),
            "3513c284b075c8efbd27da2de1ad9eb673bcbb8c45ae087a9a594c35c8064a6e"
        );
    }

    #[test]
    fn nullifier_depends_on_every_invoice_field_only() {
        // No signature is an input: re-signing the invoice cannot change N.
        let inv = vector();
        let n = nullifier(&inv).unwrap();
        assert_eq!(nullifier(&inv.clone()).unwrap(), n);

        let mut changed = inv.clone();
        changed.invoice_id = "TES-INV-0002".into();
        assert_ne!(nullifier(&changed).unwrap(), n);
        let mut changed = inv.clone();
        changed.supplier_ephemeral_pk = SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes();
        assert_ne!(nullifier(&changed).unwrap(), n);

        let mut invalid = inv;
        invalid.amount_zat = 0;
        assert_eq!(nullifier(&invalid), Err(Error::InvalidAmount));
    }

    #[test]
    fn document_hash_is_sha256() {
        // Cross-checked with Python: hashlib.sha256(b"TES-terms")
        assert_eq!(
            hex(&document_hash(b"TES-terms")),
            "00082d1119307d17036738bf382daab1bfe963280b44b7dc050f5ad30542b229"
        );
    }
}
