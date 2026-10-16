//! Assignment letter (surat pengalihan, cessie notice) of one invoice to a financier
//! (HNK-19.T2, DEV-06).
//!
//! The buyer's seal is the written acknowledgment of the assignment (Pasal 613 KUHPerdata: an
//! assignment binds the debtor once notified or acknowledged in writing). Sealed in the order
//! supplier, buyer, financier (`DocKind::Assignment`).
//!
//! Canonical layout (integers little-endian), see vault `07-Architecture/Format Data`:
//!
//! | field                          | size   |
//! |--------------------------------|--------|
//! | magic `JTSA`                   | 4      |
//! | version                        | 1      |
//! | nullifier N of the invoice     | 32     |
//! | amount the buyer pays (zat)    | 8      |
//! | due date (days since epoch)    | 4      |
//! | financier public key (Ed25519) | 32     |
//! | terms hash (SHA-256 of letter) | 32     |
//! | financier address length       | 2      |
//! | financier address (ASCII)      | 1-512  |

use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::error::Error;
use crate::invoice::{Invoice, Reader};
use crate::nullifier::nullifier;
use crate::seal::{
    next_content, sealed_document_hash, verify_chain, ChainStatus, DocKind, Seal, Signers,
};

pub const ASSIGNMENT_MAGIC: &[u8; 4] = b"JTSA";
pub const ASSIGNMENT_VERSION: u8 = 1;
pub const MAX_ADDRESS_LEN: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    pub nullifier: [u8; 32],
    pub amount_zat: u64,
    pub due_date: u32,
    pub financier_pk: [u8; 32],
    pub terms_hash: [u8; 32],
    /// Shielded address where the buyer pays at maturity.
    pub financier_address: String,
}

impl Assignment {
    /// Assignment of `invoice` to the financier: N, amount and due date come from the invoice.
    pub fn for_invoice(
        invoice: &Invoice,
        financier_pk: [u8; 32],
        financier_address: &str,
        terms_hash: [u8; 32],
    ) -> Result<Self, Error> {
        let a = Assignment {
            nullifier: nullifier(invoice)?,
            amount_zat: invoice.amount_zat,
            due_date: invoice.due_date,
            financier_pk,
            terms_hash,
            financier_address: financier_address.to_string(),
        };
        a.validate()?;
        Ok(a)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.amount_zat == 0 {
            return Err(Error::InvalidAmount);
        }
        VerifyingKey::from_bytes(&self.financier_pk).map_err(|_| Error::InvalidPublicKey)?;
        let a = self.financier_address.as_bytes();
        if a.is_empty() || a.len() > MAX_ADDRESS_LEN || !a.iter().all(u8::is_ascii_alphanumeric) {
            return Err(Error::InvalidAddress);
        }
        Ok(())
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let addr = self.financier_address.as_bytes();
        let mut out = Vec::with_capacity(115 + addr.len());
        out.extend_from_slice(ASSIGNMENT_MAGIC);
        out.push(ASSIGNMENT_VERSION);
        out.extend_from_slice(&self.nullifier);
        out.extend_from_slice(&self.amount_zat.to_le_bytes());
        out.extend_from_slice(&self.due_date.to_le_bytes());
        out.extend_from_slice(&self.financier_pk);
        out.extend_from_slice(&self.terms_hash);
        out.extend_from_slice(&(addr.len() as u16).to_le_bytes());
        out.extend_from_slice(addr);
        Ok(out)
    }

    /// Strict decoder: unknown magic or version, truncated input, trailing bytes and invalid
    /// fields are rejected.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.take(4)? != ASSIGNMENT_MAGIC {
            return Err(Error::BadMagic);
        }
        let version = r.byte()?;
        if version != ASSIGNMENT_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let nullifier = r.array()?;
        let amount_zat = u64::from_le_bytes(r.array()?);
        let due_date = u32::from_le_bytes(r.array()?);
        let financier_pk = r.array()?;
        let terms_hash = r.array()?;
        let len = usize::from(u16::from_le_bytes(r.array()?));
        let addr = r.take(len)?;
        if !r.is_empty() {
            return Err(Error::TrailingBytes);
        }
        let a = Assignment {
            nullifier,
            amount_zat,
            due_date,
            financier_pk,
            terms_hash,
            financier_address: String::from_utf8(addr.to_vec())
                .map_err(|_| Error::InvalidAddress)?,
        };
        a.validate()?;
        Ok(a)
    }

    /// Hash that the seals sign.
    pub fn doc_hash(&self) -> Result<[u8; 32], Error> {
        Ok(sealed_document_hash(&self.to_canonical_bytes()?))
    }

    /// Keys allowed to seal: supplier and buyer from the invoice, financier from this letter.
    pub fn signers(&self, invoice: &Invoice) -> Signers {
        Signers {
            supplier: Some(invoice.supplier_ephemeral_pk),
            buyer: Some(invoice.buyer_pk),
            financier: Some(self.financier_pk),
        }
    }

    /// Next seal in the order supplier, buyer, financier.
    pub fn seal_next(&self, signer: &SigningKey, seals: &[Seal]) -> Result<Seal, Error> {
        let c = next_content(
            DocKind::Assignment,
            self.nullifier,
            self.doc_hash()?,
            seals,
            0,
        )?;
        Ok(Seal::sign(signer, c))
    }

    /// Checks that the letter matches `invoice` (N, amount, due date) and verifies the seals.
    pub fn verify(&self, invoice: &Invoice, seals: &[Seal]) -> Result<ChainStatus, Error> {
        if self.nullifier != nullifier(invoice)?
            || self.amount_zat != invoice.amount_zat
            || self.due_date != invoice.due_date
        {
            return Err(Error::SealMismatch);
        }
        verify_chain(
            DocKind::Assignment,
            &self.nullifier,
            &self.doc_hash()?,
            seals,
            &self.signers(invoice),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::Role;

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    fn invoice() -> Invoice {
        Invoice {
            invoice_id: "TES-INV-0003".into(),
            supplier_ephemeral_pk: key(1).verifying_key().to_bytes(),
            buyer_pk: key(2).verifying_key().to_bytes(),
            amount_zat: 50_000,
            issue_date: 20_377,
            due_date: 20_437,
            terms_hash: [9; 32],
        }
    }

    fn letter() -> Assignment {
        Assignment::for_invoice(
            &invoice(),
            key(3).verifying_key().to_bytes(),
            "utest1financier",
            [5; 32],
        )
        .unwrap()
    }

    #[test]
    fn roundtrip_and_strict_decoder() {
        let a = letter();
        let bytes = a.to_canonical_bytes().unwrap();
        assert_eq!(&bytes[..4], b"JTSA");
        assert_eq!(bytes.len(), 115 + "utest1financier".len());
        assert_eq!(Assignment::from_canonical_bytes(&bytes).unwrap(), a);

        let mut b = bytes.clone();
        b[4] = 2;
        assert_eq!(
            Assignment::from_canonical_bytes(&b),
            Err(Error::UnsupportedVersion(2))
        );
        let mut b = bytes.clone();
        b.push(0);
        assert_eq!(
            Assignment::from_canonical_bytes(&b),
            Err(Error::TrailingBytes)
        );
        assert_eq!(
            Assignment::from_canonical_bytes(&bytes[..bytes.len() - 1]),
            Err(Error::Truncated)
        );
        let mut bad = a.clone();
        bad.financier_address = "utest1&x".into();
        assert_eq!(bad.to_canonical_bytes(), Err(Error::InvalidAddress));
        let mut bad = a;
        bad.amount_zat = 0;
        assert_eq!(bad.validate(), Err(Error::InvalidAmount));
    }

    #[test]
    fn sealed_by_supplier_buyer_financier_in_order() {
        let (inv, a) = (invoice(), letter());
        let mut seals = Vec::new();
        assert_eq!(
            a.verify(&inv, &seals),
            Ok(ChainStatus::Incomplete {
                next: Role::Supplier
            })
        );
        seals.push(a.seal_next(&key(1), &seals).unwrap());
        seals.push(a.seal_next(&key(2), &seals).unwrap());
        assert_eq!(
            a.verify(&inv, &seals),
            Ok(ChainStatus::Incomplete {
                next: Role::Financier
            })
        );
        seals.push(a.seal_next(&key(3), &seals).unwrap());
        assert_eq!(a.verify(&inv, &seals), Ok(ChainStatus::Sealed));
    }

    #[test]
    fn rejects_wrong_signers_and_letters_for_another_invoice() {
        let (inv, a) = (invoice(), letter());
        // the buyer cannot seal the supplier's step
        let s = vec![a.seal_next(&key(2), &[]).unwrap()];
        assert_eq!(a.verify(&inv, &s), Err(Error::UnexpectedSigner));

        let mut other = inv.clone();
        other.amount_zat += 1;
        let s = vec![a.seal_next(&key(1), &[]).unwrap()];
        assert_eq!(a.verify(&other, &s), Err(Error::SealMismatch));

        // a financier that is also the buyer would approve its own deal
        let selfish = Assignment::for_invoice(&inv, inv.buyer_pk, "utest1x", [5; 32]).unwrap();
        assert_eq!(selfish.verify(&inv, &[]), Err(Error::SelfApproval));

        // changing the letter after sealing breaks the seals
        let mut changed = a.clone();
        changed.financier_address = "utest1other".into();
        let s = vec![a.seal_next(&key(1), &[]).unwrap()];
        assert_eq!(changed.verify(&inv, &s), Err(Error::SealMismatch));
    }
}
