//! Exhibit A (HNK-30.T5, M-03, D-40): the shareable evidence of a double financing. It carries
//! what the public board already shows (N and two register entries with their positions) plus the
//! supplier's per-invoice public key, and nothing about the deal: no invoice, no amount, no buyer,
//! no financier (the commitments are salted hashes).
//!
//! Layout: magic `JTSX` (4), version (1), N (32), supplier key (32), then two entries, each
//! `length (1) ‖ entry bytes with memo marker (136 or 168) ‖ flag (1)`, the flag `1` followed by
//! the board position `txid (32, display order) ‖ height (4) ‖ tx index (4) ‖ output index (4)`
//! (LE), or `0` for an entry that was only offered, never posted. Same entry encoding as `JTSP`.
//!
//! What it proves on its own: the key signed register entries for N for two different financier
//! commitments (and, against the board, that both are there in that order). What it does not
//! prove on its own: that the key is the supplier key of the invoice behind N. Anyone holding the
//! invoice checks that with [`Exhibit::binds`]; the full `JTSP` proof carries the invoice for an
//! auditor or a court.

use crate::entry::BoardEntry;
use crate::error::Error;
use crate::invoice::{Invoice, Reader};
use crate::nullifier::nullifier;
use crate::proof::{txid_bytes, DoubleSignProof, EntryAt, ProofReport};

pub const EXHIBIT_MAGIC: &[u8; 4] = b"JTSX";
pub const EXHIBIT_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exhibit {
    pub nullifier: [u8; 32],
    pub supplier_pk: [u8; 32],
    pub first: BoardEntry,
    pub second: BoardEntry,
    pub first_at: Option<EntryAt>,
    pub second_at: Option<EntryAt>,
}

impl Exhibit {
    /// The exhibit of a full proof: the proof is verified first, then the invoice is dropped.
    pub fn from_proof(p: &DoubleSignProof) -> Result<Self, Error> {
        let r = p.verify()?;
        Ok(Exhibit {
            nullifier: r.nullifier,
            supplier_pk: r.supplier_pk,
            first: p.first.clone(),
            second: p.second.clone(),
            first_at: p.first_at.clone(),
            second_at: p.second_at.clone(),
        })
    }

    /// Valid when both entries are register entries for N signed by the supplier key, and the
    /// financier commitments differ.
    pub fn verify(&self) -> Result<ProofReport, Error> {
        for e in [&self.first, &self.second] {
            if !e.kind.is_register() || e.nullifier != self.nullifier {
                return Err(Error::SealMismatch);
            }
            e.verify(&self.supplier_pk)?;
        }
        if self.first.financier_commitment == self.second.financier_commitment {
            return Err(Error::NotDoubleSigned);
        }
        Ok(ProofReport {
            nullifier: self.nullifier,
            supplier_pk: self.supplier_pk,
            first_commitment: self.first.financier_commitment,
            second_commitment: self.second.financier_commitment,
        })
    }

    /// For a holder of the invoice: true when N is the invoice's fingerprint and the key is its
    /// supplier key, so the double signature is about this invoice.
    pub fn binds(&self, invoice: &Invoice) -> Result<bool, Error> {
        Ok(nullifier(invoice)? == self.nullifier
            && invoice.supplier_ephemeral_pk == self.supplier_pk)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = EXHIBIT_MAGIC.to_vec();
        out.push(EXHIBIT_VERSION);
        out.extend_from_slice(&self.nullifier);
        out.extend_from_slice(&self.supplier_pk);
        for (e, at) in [
            (&self.first, &self.first_at),
            (&self.second, &self.second_at),
        ] {
            let len = e.encoded_len();
            out.push(len as u8);
            out.extend_from_slice(&e.to_memo_bytes()[..len]);
            match at {
                None => out.push(0),
                Some(p) => {
                    out.push(1);
                    out.extend_from_slice(&txid_bytes(&p.txid)?);
                    out.extend_from_slice(&p.height.to_le_bytes());
                    out.extend_from_slice(&p.tx_index.to_le_bytes());
                    out.extend_from_slice(&p.output_index.to_le_bytes());
                }
            }
        }
        Ok(out)
    }

    /// Strict decoder. Does not verify; call [`Exhibit::verify`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.take(4)? != EXHIBIT_MAGIC {
            return Err(Error::BadMagic);
        }
        let version = r.byte()?;
        if version != EXHIBIT_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let nullifier = r.array()?;
        let supplier_pk = r.array()?;
        let mut entry = || -> Result<(BoardEntry, Option<EntryAt>), Error> {
            let len = usize::from(r.byte()?);
            let e = BoardEntry::from_memo_bytes(r.take(len)?)?;
            let at = match r.byte()? {
                0 => None,
                1 => {
                    let txid: [u8; 32] = r.array()?;
                    Some(EntryAt {
                        txid: txid.iter().map(|b| format!("{b:02x}")).collect(),
                        height: u32::from_le_bytes(r.array()?),
                        tx_index: u32::from_le_bytes(r.array()?),
                        output_index: u32::from_le_bytes(r.array()?),
                    })
                }
                _ => return Err(Error::BadBundle),
            };
            Ok((e, at))
        };
        let (first, first_at) = entry()?;
        let (second, second_at) = entry()?;
        if !r.is_empty() {
            return Err(Error::TrailingBytes);
        }
        Ok(Exhibit {
            nullifier,
            supplier_pk,
            first,
            second,
            first_at,
            second_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::EntryKind;
    use crate::invoice::sign_invoice;
    use ed25519_dalek::SigningKey;

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    fn proof() -> DoubleSignProof {
        let inv = Invoice {
            invoice_id: "TES-INV-0417".into(),
            supplier_ephemeral_pk: key(1).verifying_key().to_bytes(),
            buyer_pk: key(2).verifying_key().to_bytes(),
            amount_zat: 40_000,
            issue_date: 1,
            due_date: 31,
            terms_hash: [9; 32],
        };
        let n = nullifier(&inv).unwrap();
        DoubleSignProof {
            buyer_signature: sign_invoice(&key(2), &inv).unwrap().to_bytes(),
            first: BoardEntry::sign(&key(1), EntryKind::Register, n, [0xAA; 32], 0, 0),
            second: BoardEntry::sign(&key(1), EntryKind::Register, n, [0xBB; 32], 0, 0),
            first_at: Some(EntryAt {
                txid: "33".repeat(32),
                height: 10,
                tx_index: 1,
                output_index: 0,
            }),
            second_at: None,
            invoice: inv,
        }
    }

    #[test]
    fn the_exhibit_keeps_the_proof_and_drops_the_deal() {
        let p = proof();
        let x = Exhibit::from_proof(&p).unwrap();
        assert_eq!(x.verify().unwrap(), p.verify().unwrap());
        let bytes = x.to_bytes().unwrap();
        assert_eq!(&bytes[..4], b"JTSX");
        assert_eq!(Exhibit::from_bytes(&bytes).unwrap(), x);
        // nothing of the invoice is in it: not its id, amount, buyer key or terms
        let inv = p.invoice.to_canonical_bytes().unwrap();
        for part in [
            &inv[6..6 + 12],
            &p.invoice.buyer_pk[..],
            &[9u8; 32][..],
            &40_000u64.to_le_bytes()[..],
        ] {
            assert!(
                !bytes.windows(part.len()).any(|w| w == part),
                "exhibit leaks {part:02x?}"
            );
        }
        assert!(x.binds(&p.invoice).unwrap());
    }

    #[test]
    fn a_griefer_cannot_bind_its_own_key_to_someone_elses_invoice() {
        let p = proof();
        let n = p.first.nullifier;
        // two entries signed by an unrelated key for the same N verify as an exhibit ...
        let fake = Exhibit {
            nullifier: n,
            supplier_pk: key(9).verifying_key().to_bytes(),
            first: BoardEntry::sign(&key(9), EntryKind::Register, n, [0xAA; 32], 0, 0),
            second: BoardEntry::sign(&key(9), EntryKind::Register, n, [0xCC; 32], 0, 0),
            first_at: None,
            second_at: None,
        };
        assert!(fake.verify().is_ok());
        // ... but not against the invoice: the key is not its supplier key
        assert!(!fake.binds(&p.invoice).unwrap());
        // and a mismatched or re-posted pair fails on its own
        let mut x = Exhibit::from_proof(&p).unwrap();
        x.second = x.first.clone();
        assert_eq!(x.verify(), Err(Error::NotDoubleSigned));
        let mut y = Exhibit::from_proof(&p).unwrap();
        y.supplier_pk = key(9).verifying_key().to_bytes();
        assert_eq!(y.verify(), Err(Error::BadSignature));
    }
}
