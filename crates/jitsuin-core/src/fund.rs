//! JitsuinFi Vault memo items (HNK-15.T2): what members of a pooled fund read with the full
//! viewing key of the fund's operational account.
//!
//! - **Receivable note** (`JTN1`, 48 bytes): travels with every advance, so members see each
//!   financed invoice's N, face value and due date, but not its parties or content.
//! - **Liability root** (`JTLR`, 144 bytes): per period, the root and total of the Merkle sum
//!   tree of member deposits (HNK-15.T1), signed by the fund manager key. Members check their
//!   own deposit against the root (T1) and assets against the total (solvency, T2).
//!
//! Receivable note: magic (4), N (32), face amount (8, LE), due date (4, LE).
//! Liability root: magic (4), period (4, LE), root (32), total (8, LE), manager key (32),
//! manager signature over the preceding bytes (64).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::error::Error;
use crate::invoice::Reader;

pub const NOTE_MAGIC: &[u8; 4] = b"JTN1";
pub const NOTE_LEN: usize = 4 + 32 + 8 + 4;
pub const ROOT_MAGIC: &[u8; 4] = b"JTLR";
pub const ROOT_SIGNED_LEN: usize = 4 + 4 + 32 + 8 + 32;
pub const ROOT_LEN: usize = ROOT_SIGNED_LEN + 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceivableNote {
    pub nullifier: [u8; 32],
    pub face_zat: u64,
    pub due_date: u32,
}

impl ReceivableNote {
    pub fn to_bytes(&self) -> [u8; NOTE_LEN] {
        let mut out = [0u8; NOTE_LEN];
        out[..4].copy_from_slice(NOTE_MAGIC);
        out[4..36].copy_from_slice(&self.nullifier);
        out[36..44].copy_from_slice(&self.face_zat.to_le_bytes());
        out[44..48].copy_from_slice(&self.due_date.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > NOTE_LEN {
            return Err(Error::TrailingBytes);
        }
        let mut r = Reader::new(bytes);
        if r.take(4)? != NOTE_MAGIC {
            return Err(Error::BadMagic);
        }
        let note = ReceivableNote {
            nullifier: r.array()?,
            face_zat: u64::from_le_bytes(r.array()?),
            due_date: u32::from_le_bytes(r.array()?),
        };
        if note.face_zat == 0 {
            return Err(Error::InvalidAmount);
        }
        Ok(note)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiabilityRoot {
    pub period: u32,
    pub root: [u8; 32],
    pub total_zat: u64,
    pub manager_pk: [u8; 32],
    pub signature: [u8; 64],
}

impl LiabilityRoot {
    pub fn sign(manager: &SigningKey, period: u32, root: [u8; 32], total_zat: u64) -> Self {
        let mut r = LiabilityRoot {
            period,
            root,
            total_zat,
            manager_pk: manager.verifying_key().to_bytes(),
            signature: [0; 64],
        };
        r.signature = manager.sign(&r.signed_part()).to_bytes();
        r
    }

    fn signed_part(&self) -> [u8; ROOT_SIGNED_LEN] {
        let mut out = [0u8; ROOT_SIGNED_LEN];
        out[..4].copy_from_slice(ROOT_MAGIC);
        out[4..8].copy_from_slice(&self.period.to_le_bytes());
        out[8..40].copy_from_slice(&self.root);
        out[40..48].copy_from_slice(&self.total_zat.to_le_bytes());
        out[48..80].copy_from_slice(&self.manager_pk);
        out
    }

    /// Valid when signed by `manager_pk` (published to the members).
    pub fn verify(&self, manager_pk: &[u8; 32]) -> Result<(), Error> {
        if &self.manager_pk != manager_pk {
            return Err(Error::UnexpectedSigner);
        }
        let vk = VerifyingKey::from_bytes(manager_pk).map_err(|_| Error::InvalidPublicKey)?;
        vk.verify_strict(&self.signed_part(), &Signature::from_bytes(&self.signature))
            .map_err(|_| Error::BadSignature)
    }

    pub fn to_bytes(&self) -> [u8; ROOT_LEN] {
        let mut out = [0u8; ROOT_LEN];
        out[..ROOT_SIGNED_LEN].copy_from_slice(&self.signed_part());
        out[ROOT_SIGNED_LEN..].copy_from_slice(&self.signature);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > ROOT_LEN {
            return Err(Error::TrailingBytes);
        }
        let mut r = Reader::new(bytes);
        if r.take(4)? != ROOT_MAGIC {
            return Err(Error::BadMagic);
        }
        Ok(LiabilityRoot {
            period: u32::from_le_bytes(r.array()?),
            root: r.array()?,
            total_zat: u64::from_le_bytes(r.array()?),
            manager_pk: r.array()?,
            signature: r.array()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_and_root_roundtrip() {
        let note = ReceivableNote {
            nullifier: [7; 32],
            face_zat: 40_000,
            due_date: 20_772,
        };
        assert_eq!(ReceivableNote::from_bytes(&note.to_bytes()).unwrap(), note);
        let mut zero = note;
        zero.face_zat = 0;
        assert_eq!(
            ReceivableNote::from_bytes(&zero.to_bytes()),
            Err(Error::InvalidAmount)
        );

        let manager = SigningKey::from_bytes(&[3; 32]);
        let pk = manager.verifying_key().to_bytes();
        let root = LiabilityRoot::sign(&manager, 1, [9; 32], 1_000_000);
        let back = LiabilityRoot::from_bytes(&root.to_bytes()).unwrap();
        assert_eq!(back, root);
        back.verify(&pk).unwrap();
        // a root posted by anyone else, or with a changed total, is rejected
        let fake = LiabilityRoot::sign(&SigningKey::from_bytes(&[4; 32]), 1, [9; 32], 1);
        assert_eq!(fake.verify(&pk), Err(Error::UnexpectedSigner));
        let mut lowered = root;
        lowered.total_zat = 1;
        assert_eq!(lowered.verify(&pk), Err(Error::BadSignature));
    }
}
