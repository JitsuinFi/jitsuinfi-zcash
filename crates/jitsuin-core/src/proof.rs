//! Double-signature proof (HNK-07.T1): the supplier signed register entries for the same invoice
//! for two different financiers. Verifiable offline by anyone given the proof; the board shows
//! outsiders only hashes.
//!
//! Layout: magic `JTSP` (4), version (1), invoice length (2, LE), canonical invoice, buyer
//! signature (64), then two entries, each `length (1) ‖ entry bytes with memo marker (136 or
//! 168) ‖ flag (1)`, the flag `1` followed by the board position `txid (32, display order) ‖
//! height (4) ‖ tx index (4) ‖ output index (4)` (LE), or `0` for an entry that is not on chain.

use ed25519_dalek::Signature;

use crate::entry::BoardEntry;
use crate::error::Error;
use crate::invoice::{verify_invoice, Invoice, Reader};
use crate::nullifier::nullifier;

pub const PROOF_MAGIC: &[u8; 4] = b"JTSP";
pub const PROOF_VERSION: u8 = 1;

/// Where an entry sits on chain; ordering = (height, tx index, output index).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryAt {
    /// Display-order txid as 64 hex characters.
    pub txid: String,
    pub height: u32,
    pub tx_index: u32,
    pub output_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoubleSignProof {
    pub invoice: Invoice,
    pub buyer_signature: [u8; 64],
    /// The entry that registered first (on the board).
    pub first: BoardEntry,
    /// The second entry for another financier: on the board after a race, or offered off-chain
    /// to the financier that caught it.
    pub second: BoardEntry,
    pub first_at: Option<EntryAt>,
    /// `None` when the second entry was only offered, never posted.
    pub second_at: Option<EntryAt>,
}

/// What the proof establishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofReport {
    pub nullifier: [u8; 32],
    pub supplier_pk: [u8; 32],
    pub first_commitment: [u8; 32],
    pub second_commitment: [u8; 32],
}

impl DoubleSignProof {
    /// Valid when the buyer signed the invoice, both entries are register entries for its N
    /// signed by the supplier's key from the invoice, and the financier commitments differ.
    pub fn verify(&self) -> Result<ProofReport, Error> {
        verify_invoice(&self.invoice, &Signature::from_bytes(&self.buyer_signature))?;
        let n = nullifier(&self.invoice)?;
        let pk = self.invoice.supplier_ephemeral_pk;
        for e in [&self.first, &self.second] {
            if !e.kind.is_register() || e.nullifier != n {
                return Err(Error::SealMismatch);
            }
            e.verify(&pk)?;
        }
        if self.first.financier_commitment == self.second.financier_commitment {
            // The same financier re-posting is not double financing.
            return Err(Error::NotDoubleSigned);
        }
        Ok(ProofReport {
            nullifier: n,
            supplier_pk: pk,
            first_commitment: self.first.financier_commitment,
            second_commitment: self.second.financier_commitment,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let inv = self.invoice.to_canonical_bytes()?;
        let mut out = PROOF_MAGIC.to_vec();
        out.push(PROOF_VERSION);
        out.extend_from_slice(&(inv.len() as u16).to_le_bytes());
        out.extend_from_slice(&inv);
        out.extend_from_slice(&self.buyer_signature);
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

    /// Strict decoder. Does not verify; call [`DoubleSignProof::verify`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.take(4)? != PROOF_MAGIC {
            return Err(Error::BadMagic);
        }
        let version = r.byte()?;
        if version != PROOF_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let len = usize::from(u16::from_le_bytes(r.array()?));
        let invoice = Invoice::from_canonical_bytes(r.take(len)?)?;
        let buyer_signature = r.array()?;
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
        Ok(DoubleSignProof {
            invoice,
            buyer_signature,
            first,
            second,
            first_at,
            second_at,
        })
    }
}

fn txid_bytes(txid: &str) -> Result<[u8; 32], Error> {
    let b = txid.as_bytes();
    if b.len() != 64 {
        return Err(Error::BadBundle);
    }
    let mut out = [0u8; 32];
    for (i, pair) in b.chunks(2).enumerate() {
        let s = std::str::from_utf8(pair).map_err(|_| Error::BadBundle)?;
        out[i] = u8::from_str_radix(s, 16).map_err(|_| Error::BadBundle)?;
    }
    Ok(out)
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

    fn invoice() -> Invoice {
        Invoice {
            invoice_id: "TES-INV-0003".into(),
            supplier_ephemeral_pk: key(1).verifying_key().to_bytes(),
            buyer_pk: key(2).verifying_key().to_bytes(),
            amount_zat: 40_000,
            issue_date: 1,
            due_date: 31,
            terms_hash: [9; 32],
        }
    }

    fn proof(second_commitment: [u8; 32]) -> DoubleSignProof {
        let inv = invoice();
        let n = nullifier(&inv).unwrap();
        DoubleSignProof {
            buyer_signature: sign_invoice(&key(2), &inv).unwrap().to_bytes(),
            first: BoardEntry::sign(&key(1), EntryKind::Register, n, [0xAA; 32], 2, 3),
            second: BoardEntry::sign_with_history(&key(1), n, second_commitment, 2, 3, [7; 32]),
            first_at: Some(EntryAt {
                txid: "33".repeat(32),
                height: 10,
                tx_index: 1,
                output_index: 0,
            }),
            second_at: Some(EntryAt {
                txid: "ab".repeat(32),
                height: 12,
                tx_index: 0,
                output_index: 2,
            }),
            invoice: inv,
        }
    }

    #[test]
    fn valid_proof_roundtrips_and_verifies() {
        let p = proof([0xBB; 32]);
        let report = p.verify().unwrap();
        assert_eq!(report.first_commitment, [0xAA; 32]);
        assert_eq!(report.second_commitment, [0xBB; 32]);
        let bytes = p.to_bytes().unwrap();
        assert_eq!(&bytes[..4], b"JTSP");
        assert_eq!(DoubleSignProof::from_bytes(&bytes).unwrap(), p);
        // offered, not posted: only the first entry has a position
        let mut offline = p.clone();
        offline.second_at = None;
        let bytes = offline.to_bytes().unwrap();
        assert_eq!(DoubleSignProof::from_bytes(&bytes).unwrap(), offline);
    }

    #[test]
    fn same_commitment_is_not_double_financing() {
        assert_eq!(proof([0xAA; 32]).verify(), Err(Error::NotDoubleSigned));
    }

    #[test]
    fn forged_or_mismatched_proofs_fail() {
        // a griefer's entry is not signed by the supplier key from the invoice
        let mut p = proof([0xBB; 32]);
        let n = p.first.nullifier;
        p.second = BoardEntry::sign(&key(9), EntryKind::Register, n, [0xBB; 32], 2, 3);
        assert_eq!(p.verify(), Err(Error::BadSignature));
        // an entry for another invoice
        let mut p = proof([0xBB; 32]);
        p.second = BoardEntry::sign(&key(1), EntryKind::Register, [8; 32], [0xBB; 32], 2, 3);
        assert_eq!(p.verify(), Err(Error::SealMismatch));
        // an invoice the buyer never signed
        let mut p = proof([0xBB; 32]);
        p.invoice.amount_zat += 1;
        assert_eq!(p.verify(), Err(Error::BadSignature));
        // malformed bytes
        let bytes = proof([0xBB; 32]).to_bytes().unwrap();
        assert_eq!(
            DoubleSignProof::from_bytes(&bytes[..bytes.len() - 1]),
            Err(Error::Truncated)
        );
        let mut extra = bytes;
        extra.push(0);
        assert_eq!(
            DoubleSignProof::from_bytes(&extra),
            Err(Error::TrailingBytes)
        );
    }
}
