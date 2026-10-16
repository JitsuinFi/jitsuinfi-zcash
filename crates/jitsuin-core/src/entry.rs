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
//! The nullifier is an input here; how it is derived is HNK-02.T1.

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryKind {
    Register = 0x01,
    Settled = 0x02,
}

impl TryFrom<u8> for EntryKind {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Error> {
        match value {
            0x01 => Ok(EntryKind::Register),
            0x02 => Ok(EntryKind::Settled),
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
        let msg = signed_part(
            kind,
            &nullifier,
            &financier_commitment,
            discount_bucket,
            tenor_bucket,
        );
        BoardEntry {
            kind,
            nullifier,
            financier_commitment,
            discount_bucket,
            tenor_bucket,
            supplier_sig: supplier_ephemeral.sign(&msg).to_bytes(),
        }
    }

    /// Verifies the supplier signature. Only holders of the invoice know the supplier ephemeral key,
    /// so only they can verify; entries without a valid signature are ignored (anti-griefing).
    pub fn verify(&self, supplier_ephemeral_pk: &[u8; 32]) -> Result<(), Error> {
        let vk =
            VerifyingKey::from_bytes(supplier_ephemeral_pk).map_err(|_| Error::InvalidPublicKey)?;
        let msg = signed_part(
            self.kind,
            &self.nullifier,
            &self.financier_commitment,
            self.discount_bucket,
            self.tenor_bucket,
        );
        vk.verify_strict(&msg, &Signature::from_bytes(&self.supplier_sig))
            .map_err(|_| Error::BadSignature)
    }

    /// Full 512-byte memo, zero padded after the entry.
    pub fn to_memo_bytes(&self) -> [u8; MEMO_LEN] {
        let mut memo = [0u8; MEMO_LEN];
        memo[0] = MEMO_ARBITRARY_DATA;
        let msg = signed_part(
            self.kind,
            &self.nullifier,
            &self.financier_commitment,
            self.discount_bucket,
            self.tenor_bucket,
        );
        memo[1..1 + SIGNED_LEN].copy_from_slice(&msg);
        memo[1 + SIGNED_LEN..ENTRY_LEN].copy_from_slice(&self.supplier_sig);
        memo
    }

    /// Strict decoder. Accepts the 136-byte entry alone or a padded memo; padding must be zero.
    /// Does not verify the signature (see [`BoardEntry::verify`]).
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
        let entry = BoardEntry {
            kind,
            nullifier: r.array()?,
            financier_commitment: r.array()?,
            discount_bucket: r.byte()?,
            tenor_bucket: r.byte()?,
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

fn signed_part(
    kind: EntryKind,
    nullifier: &[u8; 32],
    financier_commitment: &[u8; 32],
    discount_bucket: u8,
    tenor_bucket: u8,
) -> [u8; SIGNED_LEN] {
    let mut out = [0u8; SIGNED_LEN];
    out[..4].copy_from_slice(ENTRY_MAGIC);
    out[4] = kind as u8;
    out[5..37].copy_from_slice(nullifier);
    out[37..69].copy_from_slice(financier_commitment);
    out[69] = discount_bucket;
    out[70] = tenor_bucket;
    out
}
