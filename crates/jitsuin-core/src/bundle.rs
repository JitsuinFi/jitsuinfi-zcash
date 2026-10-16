//! Verification bundle (HNK-19.T6): everything a holder hands to an auditor or judge to verify a
//! deal offline, the private counterpart of SignBaliola's public verification link. Whoever gets
//! the bundle learns the deal; nobody else does.
//!
//! Layout: magic `JTSB`, version, then items `type (1) ‖ length (u16 LE) ‖ bytes`:
//!
//! | type | item                              |
//! |------|-----------------------------------|
//! | 1    | canonical invoice                 |
//! | 2    | buyer signature on the invoice    |
//! | 3    | canonical assignment letter       |
//! | 4    | seal on the assignment (in order) |
//! | 5    | canonical settlement document     |
//!
//! Text form for links and files: base64url without padding.

use ed25519_dalek::Signature;

use crate::assignment::Assignment;
use crate::error::Error;
use crate::invoice::{verify_invoice, Invoice, Reader};
use crate::nullifier::nullifier;
use crate::seal::{ChainStatus, Seal};
use crate::settled::SettlementDoc;

pub const BUNDLE_MAGIC: &[u8; 4] = b"JTSB";
pub const BUNDLE_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    pub invoice: Invoice,
    pub buyer_signature: [u8; 64],
    pub assignment: Option<Assignment>,
    pub assignment_seals: Vec<Seal>,
    pub settlement: Option<SettlementDoc>,
}

/// What the bundle proves without the chain. The board part (register and settled entries) is
/// checked by `jitsuin-board` with the same bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleReport {
    pub nullifier: [u8; 32],
    /// `None` when the bundle has no assignment letter.
    pub assignment: Option<ChainStatus>,
}

impl Bundle {
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = BUNDLE_MAGIC.to_vec();
        out.push(BUNDLE_VERSION);
        let mut item = |kind: u8, bytes: &[u8]| {
            out.push(kind);
            out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
            out.extend_from_slice(bytes);
        };
        item(1, &self.invoice.to_canonical_bytes()?);
        item(2, &self.buyer_signature);
        if let Some(a) = &self.assignment {
            item(3, &a.to_canonical_bytes()?);
        }
        for s in &self.assignment_seals {
            item(4, &s.to_bytes());
        }
        if let Some(d) = &self.settlement {
            item(5, &d.to_canonical_bytes());
        }
        Ok(out)
    }

    /// Strict decoder: one invoice and one signature, at most one letter and one settlement
    /// document, seals only with a letter, known item types only.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.take(4)? != BUNDLE_MAGIC {
            return Err(Error::BadMagic);
        }
        let version = r.byte()?;
        if version != BUNDLE_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let (mut invoice, mut sig, mut assignment, mut settlement) = (None, None, None, None);
        let mut seals = Vec::new();
        while !r.is_empty() {
            let kind = r.byte()?;
            let len = usize::from(u16::from_le_bytes(r.array()?));
            let body = r.take(len)?;
            match kind {
                1 if invoice.is_none() => invoice = Some(Invoice::from_canonical_bytes(body)?),
                2 if sig.is_none() => {
                    sig = Some(<[u8; 64]>::try_from(body).map_err(|_| Error::Truncated)?)
                }
                3 if assignment.is_none() => {
                    assignment = Some(Assignment::from_canonical_bytes(body)?)
                }
                4 => seals.push(Seal::from_bytes(body)?),
                5 if settlement.is_none() => {
                    settlement = Some(SettlementDoc::from_canonical_bytes(body)?)
                }
                _ => return Err(Error::BadBundle),
            }
        }
        let (Some(invoice), Some(buyer_signature)) = (invoice, sig) else {
            return Err(Error::BadBundle);
        };
        if assignment.is_none() && !seals.is_empty() {
            return Err(Error::BadBundle);
        }
        Ok(Bundle {
            invoice,
            buyer_signature,
            assignment,
            assignment_seals: seals,
            settlement,
        })
    }

    /// Verifies the buyer signature, N, the letter against the invoice and its seals, and that
    /// the settlement document matches the letter.
    pub fn verify(&self) -> Result<BundleReport, Error> {
        verify_invoice(&self.invoice, &Signature::from_bytes(&self.buyer_signature))?;
        let n = nullifier(&self.invoice)?;
        let assignment = match &self.assignment {
            Some(a) => Some(a.verify(&self.invoice, &self.assignment_seals)?),
            None => None,
        };
        if let Some(doc) = &self.settlement {
            let expected = match &self.assignment {
                Some(a) => SettlementDoc::for_assignment(a),
                None => return Err(Error::BadBundle),
            };
            if doc != &expected {
                return Err(Error::SealMismatch);
            }
        }
        Ok(BundleReport {
            nullifier: n,
            assignment,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invoice::sign_invoice;
    use ed25519_dalek::SigningKey;

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    fn bundle() -> Bundle {
        let invoice = Invoice {
            invoice_id: "TES-INV-0003".into(),
            supplier_ephemeral_pk: key(1).verifying_key().to_bytes(),
            buyer_pk: key(2).verifying_key().to_bytes(),
            amount_zat: 40_000,
            issue_date: 10,
            due_date: 40,
            terms_hash: [9; 32],
        };
        let sig = sign_invoice(&key(2), &invoice).unwrap().to_bytes();
        let a = Assignment::for_invoice(
            &invoice,
            key(3).verifying_key().to_bytes(),
            "utest1financier",
            [5; 32],
        )
        .unwrap();
        let mut seals = Vec::new();
        for k in [key(1), key(2), key(3)] {
            let s = a.seal_next(&k, &seals).unwrap();
            seals.push(s);
        }
        Bundle {
            settlement: Some(SettlementDoc::for_assignment(&a)),
            invoice,
            buyer_signature: sig,
            assignment: Some(a),
            assignment_seals: seals,
        }
    }

    #[test]
    fn roundtrip_and_verify() {
        let b = bundle();
        let bytes = b.to_bytes().unwrap();
        assert_eq!(&bytes[..4], b"JTSB");
        let back = Bundle::from_bytes(&bytes).unwrap();
        assert_eq!(back, b);
        let report = back.verify().unwrap();
        assert_eq!(report.assignment, Some(ChainStatus::Sealed));
        assert_eq!(report.nullifier, nullifier(&b.invoice).unwrap());
    }

    #[test]
    fn rejects_tampered_or_malformed_bundles() {
        let b = bundle();
        let mut forged = b.clone();
        forged.invoice.amount_zat += 1;
        assert_eq!(forged.verify(), Err(Error::BadSignature));

        let mut swapped = b.clone();
        swapped.assignment_seals.swap(0, 1);
        assert_eq!(swapped.verify(), Err(Error::SealOrder));

        let mut wrong_doc = b.clone();
        wrong_doc.settlement.as_mut().unwrap().amount_zat += 1;
        assert_eq!(wrong_doc.verify(), Err(Error::SealMismatch));

        let mut bytes = b.to_bytes().unwrap();
        bytes.extend_from_slice(&[9, 0, 0]);
        assert_eq!(Bundle::from_bytes(&bytes), Err(Error::BadBundle));
        let bytes = b.to_bytes().unwrap();
        assert_eq!(
            Bundle::from_bytes(&bytes[..bytes.len() - 1]),
            Err(Error::Truncated)
        );

        let mut no_letter = b;
        no_letter.assignment = None;
        let bytes = no_letter.to_bytes().unwrap();
        assert_eq!(Bundle::from_bytes(&bytes), Err(Error::BadBundle));
    }
}
