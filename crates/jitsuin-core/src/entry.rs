//! Shielded registry board entries carried in a Zcash memo (HNK-02.T2).
//!
//! Memo layout (512 bytes, ZIP-302 arbitrary data), see vault `07-Architecture/Format Data`:
//!
//! | offset | field                                  | size |
//! |--------|----------------------------------------|------|
//! | 0      | memo marker `0xFF`                     | 1    |
//! | 1      | magic `JTS1`                           | 4    |
//! | 5      | kind                                   | 1    |
//! | 6      | nullifier                              | 32   |
//! | 38     | financier commitment                   | 32   |
//! | 70     | discount bucket                        | 1    |
//! | 71     | tenor bucket                           | 1    |
//! | 72     | supplier signature over bytes 1..72    | 64   |
//! | 136    | zero padding                           | 376  |
//!
//! Kind `0x03` (register with buyer history, HNK-20, DEV-10) adds a 32-byte history tag after the
//! tenor bucket, inside the signed part: the signature covers bytes 1..104 and the entry is 168
//! bytes. The tag anchors the buyer's history chain on the board (`history::successor_tag`).
//!
//! The nullifier is an input here; how it is derived is HNK-02.T1. A `settled` entry has its own
//! layout with [`settled_tag`] instead of N and two signatures (`settled::SettledEntry`, DEV-08).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::error::Error;
use crate::invoice::Reader;

pub const MEMO_LEN: usize = 512;
pub const MEMO_ARBITRARY_DATA: u8 = 0xFF;
pub const ENTRY_MAGIC: &[u8; 4] = b"JTS1";
/// Bytes covered by the supplier signature (memo offsets 1..72).
pub const SIGNED_LEN: usize = 4 + 1 + 32 + 32 + 1 + 1;
/// Encoded entry length including the memo marker.
pub const ENTRY_LEN: usize = 1 + SIGNED_LEN + 64;
/// Encoded length of a register entry with a history tag (kind `0x03`).
pub const TAGGED_ENTRY_LEN: usize = ENTRY_LEN + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryKind {
    Register = 0x01,
    Settled = 0x02,
    /// Register entry anchoring the buyer's history chain (HNK-20).
    RegisterWithHistory = 0x03,
}

impl EntryKind {
    /// Both register kinds count for registration and double financing.
    pub fn is_register(self) -> bool {
        matches!(self, EntryKind::Register | EntryKind::RegisterWithHistory)
    }
}

impl TryFrom<u8> for EntryKind {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Error> {
        match value {
            0x01 => Ok(EntryKind::Register),
            0x02 => Ok(EntryKind::Settled),
            0x03 => Ok(EntryKind::RegisterWithHistory),
            other => Err(Error::UnknownEntryKind(other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardEntry {
    pub kind: EntryKind,
    pub nullifier: [u8; 32],
    pub financier_commitment: [u8; 32],
    pub discount_bucket: u8,
    pub tenor_bucket: u8,
    /// Present exactly for kind `RegisterWithHistory`.
    pub history_tag: Option<[u8; 32]>,
    pub supplier_sig: [u8; 64],
}

impl BoardEntry {
    /// Builds an entry signed with the supplier's ephemeral key for this invoice.
    pub fn sign(
        supplier_ephemeral: &SigningKey,
        kind: EntryKind,
        nullifier: [u8; 32],
        financier_commitment: [u8; 32],
        discount_bucket: u8,
        tenor_bucket: u8,
    ) -> Self {
        let mut entry = BoardEntry {
            kind,
            nullifier,
            financier_commitment,
            discount_bucket,
            tenor_bucket,
            history_tag: None,
            supplier_sig: [0; 64],
        };
        entry.supplier_sig = supplier_ephemeral.sign(&entry.signed_part()).to_bytes();
        entry
    }

    /// Register entry that also carries the buyer's history tag (kind `RegisterWithHistory`).
    pub fn sign_with_history(
        supplier_ephemeral: &SigningKey,
        nullifier: [u8; 32],
        financier_commitment: [u8; 32],
        discount_bucket: u8,
        tenor_bucket: u8,
        history_tag: [u8; 32],
    ) -> Self {
        let mut entry = BoardEntry {
            kind: EntryKind::RegisterWithHistory,
            nullifier,
            financier_commitment,
            discount_bucket,
            tenor_bucket,
            history_tag: Some(history_tag),
            supplier_sig: [0; 64],
        };
        entry.supplier_sig = supplier_ephemeral.sign(&entry.signed_part()).to_bytes();
        entry
    }

    /// Length of the encoded entry including the memo marker (136 or 168 bytes).
    pub fn encoded_len(&self) -> usize {
        if self.history_tag.is_some() {
            TAGGED_ENTRY_LEN
        } else {
            ENTRY_LEN
        }
    }

    /// Verifies the supplier signature. Only holders of the invoice know the supplier ephemeral key,
    /// so only they can verify; entries without a valid signature are ignored (anti-griefing).
    pub fn verify(&self, supplier_ephemeral_pk: &[u8; 32]) -> Result<(), Error> {
        let vk =
            VerifyingKey::from_bytes(supplier_ephemeral_pk).map_err(|_| Error::InvalidPublicKey)?;
        if (self.kind == EntryKind::RegisterWithHistory) != self.history_tag.is_some() {
            return Err(Error::BadSignature);
        }
        vk.verify_strict(
            &self.signed_part(),
            &Signature::from_bytes(&self.supplier_sig),
        )
        .map_err(|_| Error::BadSignature)
    }

    /// Full 512-byte memo, zero padded after the entry.
    pub fn to_memo_bytes(&self) -> [u8; MEMO_LEN] {
        let mut memo = [0u8; MEMO_LEN];
        memo[0] = MEMO_ARBITRARY_DATA;
        let msg = self.signed_part();
        memo[1..1 + msg.len()].copy_from_slice(&msg);
        memo[1 + msg.len()..self.encoded_len()].copy_from_slice(&self.supplier_sig);
        memo
    }

    /// Strict decoder for register entries. Accepts the 136- or 168-byte entry alone or a padded
    /// memo; padding must be zero. Does not verify the signature (see [`BoardEntry::verify`]).
    pub fn from_memo_bytes(memo: &[u8]) -> Result<Self, Error> {
        if memo.len() > MEMO_LEN {
            return Err(Error::TrailingBytes);
        }
        let mut r = Reader::new(memo);
        if r.byte()? != MEMO_ARBITRARY_DATA {
            return Err(Error::NotArbitraryDataMemo);
        }
        if r.take(4)? != ENTRY_MAGIC {
            return Err(Error::BadMagic);
        }
        let kind = EntryKind::try_from(r.byte()?)?;
        // Settled entries have their own layout (`SettledEntry`, DEV-08).
        if !kind.is_register() {
            return Err(Error::UnknownEntryKind(kind as u8));
        }
        let nullifier = r.array()?;
        let financier_commitment = r.array()?;
        let discount_bucket = r.byte()?;
        let tenor_bucket = r.byte()?;
        let history_tag = if kind == EntryKind::RegisterWithHistory {
            Some(r.array()?)
        } else {
            None
        };
        let entry = BoardEntry {
            kind,
            nullifier,
            financier_commitment,
            discount_bucket,
            tenor_bucket,
            history_tag,
            supplier_sig: r.array()?,
        };
        if r.rest().iter().any(|b| *b != 0) {
            return Err(Error::NonZeroPadding);
        }
        Ok(entry)
    }
}

/// `financier_commitment = BLAKE2b-256(financier_pk ‖ salt)`. The salt stays with the financier and
/// the supplier, so the board does not reveal who financed the invoice.
pub fn financier_commitment(financier_pk: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .to_state()
        .update(financier_pk)
        .update(salt)
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// Board tag of a `settled` entry: `BLAKE2b-256(N ‖ "settled")`. Only holders of N can link it to
/// the register entry, so the public board shows that some invoice was settled, not which one.
pub fn settled_tag(nullifier: &[u8; 32]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .to_state()
        .update(nullifier)
        .update(b"settled")
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

impl BoardEntry {
    /// Bytes covered by the supplier signature (memo offsets 1..72, or 1..104 with a tag).
    fn signed_part(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIGNED_LEN + 32);
        out.extend_from_slice(ENTRY_MAGIC);
        out.push(self.kind as u8);
        out.extend_from_slice(&self.nullifier);
        out.extend_from_slice(&self.financier_commitment);
        out.push(self.discount_bucket);
        out.push(self.tenor_bucket);
        if let Some(tag) = &self.history_tag {
            out.extend_from_slice(tag);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagged_register_entry_roundtrip() {
        let k = SigningKey::from_bytes(&[1; 32]);
        let pk = k.verifying_key().to_bytes();
        let e = BoardEntry::sign_with_history(&k, [7; 32], [8; 32], 2, 3, [9; 32]);
        assert_eq!(e.encoded_len(), 168);
        let memo = e.to_memo_bytes();
        assert_eq!(memo[5], 0x03);
        assert_eq!(&memo[72..104], &[9; 32]);
        let back = BoardEntry::from_memo_bytes(&memo).unwrap();
        assert_eq!(back, e);
        back.verify(&pk).unwrap();
        assert!(back.kind.is_register());
        // the tag is signed
        let mut forged = back.clone();
        forged.history_tag = Some([1; 32]);
        assert_eq!(forged.verify(&pk), Err(Error::BadSignature));
        // a v1 entry still decodes and has no tag
        let v1 = BoardEntry::sign(&k, EntryKind::Register, [7; 32], [8; 32], 2, 3);
        assert_eq!(v1.encoded_len(), 136);
        let back = BoardEntry::from_memo_bytes(&v1.to_memo_bytes()[..136]).unwrap();
        assert_eq!(back.history_tag, None);
        back.verify(&pk).unwrap();
        // truncated tagged entry
        assert_eq!(
            BoardEntry::from_memo_bytes(&memo[..167]),
            Err(Error::Truncated)
        );
    }
}
