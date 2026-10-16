//! Jitsuin Seal: chained multi-party signatures over one document (HNK-19.T1, D-21).
//!
//! The SignBaliola concept, kept private: each document kind has a fixed order of roles; every
//! seal signs the document and the hash of the previous seal, so the order cannot be changed
//! afterwards; one role signs once, and one key cannot hold two roles (no self-approval). The
//! document is `Sealed` when every role of its policy has signed. Seals travel in shielded memos
//! or in a verification bundle, never on the public board.
//!
//! Seal layout (200 bytes), see vault `07-Architecture/Format Data`:
//!
//! | offset | field                                      | size |
//! |--------|--------------------------------------------|------|
//! | 0      | magic `JTL1`                               | 4    |
//! | 4      | document kind                              | 1    |
//! | 5      | document id (N of the invoice)             | 32   |
//! | 37     | document hash                              | 32   |
//! | 69     | step (index in the policy)                 | 1    |
//! | 70     | role                                       | 1    |
//! | 71     | flag (role-specific attestation, else 0)   | 1    |
//! | 72     | hash of the previous seal (zero at step 0) | 32   |
//! | 104    | signer public key (Ed25519)                | 32   |
//! | 136    | signature over bytes 0..136                | 64   |

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::error::Error;
use crate::invoice::Reader;

pub const SEAL_MAGIC: &[u8; 4] = b"JTL1";
pub const SEAL_SIGNED_LEN: usize = 4 + 1 + 32 + 32 + 1 + 1 + 1 + 32 + 32;
pub const SEAL_LEN: usize = SEAL_SIGNED_LEN + 64;
pub const SEAL_HASH_PERSONALIZATION: &[u8; 16] = b"JitsuinSealHash_";
pub const DOCUMENT_HASH_PERSONALIZATION: &[u8; 16] = b"JitsuinDocument_";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DocKind {
    Invoice = 0x01,
    /// Assignment of the receivable to the financier (cessie notice).
    Assignment = 0x02,
    Settlement = 0x03,
}

impl TryFrom<u8> for DocKind {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Error> {
        match value {
            0x01 => Ok(DocKind::Invoice),
            0x02 => Ok(DocKind::Assignment),
            0x03 => Ok(DocKind::Settlement),
            other => Err(Error::UnknownDocKind(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Role {
    Supplier = 0x01,
    Buyer = 0x02,
    Financier = 0x03,
}

impl TryFrom<u8> for Role {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Error> {
        match value {
            0x01 => Ok(Role::Supplier),
            0x02 => Ok(Role::Buyer),
            0x03 => Ok(Role::Financier),
            other => Err(Error::UnknownRole(other)),
        }
    }
}

/// Order of roles that must seal each document kind.
pub fn policy(kind: DocKind) -> &'static [Role] {
    match kind {
        DocKind::Invoice => &[Role::Buyer],
        DocKind::Assignment => &[Role::Supplier, Role::Buyer, Role::Financier],
        DocKind::Settlement => &[Role::Buyer, Role::Financier],
    }
}

/// Hash of a document's canonical bytes, as sealed. Different personalization from N.
pub fn sealed_document_hash(canonical: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(DOCUMENT_HASH_PERSONALIZATION)
        .hash(canonical);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seal {
    pub doc_kind: DocKind,
    pub doc_id: [u8; 32],
    pub doc_hash: [u8; 32],
    pub step: u8,
    pub role: Role,
    pub flag: u8,
    pub prev: [u8; 32],
    pub signer_pk: [u8; 32],
    pub signature: [u8; 64],
}

/// What a seal commits to; the signer key is added by [`Seal::sign`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealContent {
    pub doc_kind: DocKind,
    pub doc_id: [u8; 32],
    pub doc_hash: [u8; 32],
    pub step: u8,
    pub role: Role,
    pub flag: u8,
    pub prev: [u8; 32],
}

impl Seal {
    pub fn sign(signer: &SigningKey, content: SealContent) -> Self {
        let signer_pk = signer.verifying_key().to_bytes();
        let msg = signed_part(&content, &signer_pk);
        Seal {
            doc_kind: content.doc_kind,
            doc_id: content.doc_id,
            doc_hash: content.doc_hash,
            step: content.step,
            role: content.role,
            flag: content.flag,
            prev: content.prev,
            signer_pk,
            signature: signer.sign(&msg).to_bytes(),
        }
    }

    pub fn content(&self) -> SealContent {
        SealContent {
            doc_kind: self.doc_kind,
            doc_id: self.doc_id,
            doc_hash: self.doc_hash,
            step: self.step,
            role: self.role,
            flag: self.flag,
            prev: self.prev,
        }
    }

    /// Signature check against the seal's own key (`verify_strict`). Who may sign is checked by
    /// [`verify_chain`].
    pub fn verify_signature(&self) -> Result<(), Error> {
        let vk = VerifyingKey::from_bytes(&self.signer_pk).map_err(|_| Error::InvalidPublicKey)?;
        vk.verify_strict(
            &signed_part(&self.content(), &self.signer_pk),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| Error::BadSignature)
    }

    /// `BLAKE2b-256("JitsuinSealHash_", seal bytes)`; the next seal signs this value.
    pub fn hash(&self) -> [u8; 32] {
        let hash = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(SEAL_HASH_PERSONALIZATION)
            .hash(&self.to_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_bytes());
        out
    }

    pub fn to_bytes(&self) -> [u8; SEAL_LEN] {
        let mut out = [0u8; SEAL_LEN];
        out[..SEAL_SIGNED_LEN].copy_from_slice(&signed_part(&self.content(), &self.signer_pk));
        out[SEAL_SIGNED_LEN..].copy_from_slice(&self.signature);
        out
    }

    /// Strict decoder for exactly [`SEAL_LEN`] bytes. Does not verify the signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > SEAL_LEN {
            return Err(Error::TrailingBytes);
        }
        let mut r = Reader::new(bytes);
        if r.take(4)? != SEAL_MAGIC {
            return Err(Error::BadMagic);
        }
        let seal = Seal {
            doc_kind: DocKind::try_from(r.byte()?)?,
            doc_id: r.array()?,
            doc_hash: r.array()?,
            step: r.byte()?,
            role: Role::try_from(r.byte()?)?,
            flag: r.byte()?,
            prev: r.array()?,
            signer_pk: r.array()?,
            signature: r.array()?,
        };
        Ok(seal)
    }
}

/// Keys allowed to seal each role of one deal: the supplier's per-invoice key and the buyer key
/// come from the invoice, the financier key from the assignment letter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Signers {
    pub supplier: Option<[u8; 32]>,
    pub buyer: Option<[u8; 32]>,
    pub financier: Option<[u8; 32]>,
}

impl Signers {
    pub fn key(&self, role: Role) -> Option<[u8; 32]> {
        match role {
            Role::Supplier => self.supplier,
            Role::Buyer => self.buyer,
            Role::Financier => self.financier,
        }
    }

    /// One key may not hold two roles (no self-approval).
    fn check_distinct(&self) -> Result<(), Error> {
        let keys: Vec<[u8; 32]> = [self.supplier, self.buyer, self.financier]
            .into_iter()
            .flatten()
            .collect();
        for (i, a) in keys.iter().enumerate() {
            if keys[i + 1..].contains(a) {
                return Err(Error::SelfApproval);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainStatus {
    /// The next role in the policy has not sealed yet.
    Incomplete {
        next: Role,
    },
    Sealed,
}

/// Verifies a chain of seals for one document against its policy and the allowed keys.
pub fn verify_chain(
    doc_kind: DocKind,
    doc_id: &[u8; 32],
    doc_hash: &[u8; 32],
    seals: &[Seal],
    signers: &Signers,
) -> Result<ChainStatus, Error> {
    signers.check_distinct()?;
    let roles = policy(doc_kind);
    if seals.len() > roles.len() {
        return Err(Error::TooManySeals);
    }
    let mut prev = [0u8; 32];
    for (i, seal) in seals.iter().enumerate() {
        if seal.doc_kind != doc_kind || &seal.doc_id != doc_id || &seal.doc_hash != doc_hash {
            return Err(Error::SealMismatch);
        }
        if usize::from(seal.step) != i || seal.role != roles[i] || seal.prev != prev {
            return Err(Error::SealOrder);
        }
        if signers.key(seal.role) != Some(seal.signer_pk) {
            return Err(Error::UnexpectedSigner);
        }
        seal.verify_signature()?;
        prev = seal.hash();
    }
    Ok(match roles.get(seals.len()) {
        Some(next) => ChainStatus::Incomplete { next: *next },
        None => ChainStatus::Sealed,
    })
}

/// Content of the next seal after `seals` (step, role and previous hash from the policy).
pub fn next_content(
    doc_kind: DocKind,
    doc_id: [u8; 32],
    doc_hash: [u8; 32],
    seals: &[Seal],
    flag: u8,
) -> Result<SealContent, Error> {
    let roles = policy(doc_kind);
    let role = *roles.get(seals.len()).ok_or(Error::TooManySeals)?;
    Ok(SealContent {
        doc_kind,
        doc_id,
        doc_hash,
        step: seals.len() as u8,
        role,
        flag,
        prev: seals.last().map(Seal::hash).unwrap_or([0; 32]),
    })
}

fn signed_part(c: &SealContent, signer_pk: &[u8; 32]) -> [u8; SEAL_SIGNED_LEN] {
    let mut out = [0u8; SEAL_SIGNED_LEN];
    out[..4].copy_from_slice(SEAL_MAGIC);
    out[4] = c.doc_kind as u8;
    out[5..37].copy_from_slice(&c.doc_id);
    out[37..69].copy_from_slice(&c.doc_hash);
    out[69] = c.step;
    out[70] = c.role as u8;
    out[71] = c.flag;
    out[72..104].copy_from_slice(&c.prev);
    out[104..136].copy_from_slice(signer_pk);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const N: [u8; 32] = [7; 32];

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    fn signers() -> Signers {
        Signers {
            supplier: Some(key(1).verifying_key().to_bytes()),
            buyer: Some(key(2).verifying_key().to_bytes()),
            financier: Some(key(3).verifying_key().to_bytes()),
        }
    }

    fn doc_hash() -> [u8; 32] {
        sealed_document_hash(b"TES-assignment")
    }

    /// Supplier, Buyer, Financier seals over one assignment.
    fn assignment_chain() -> Vec<Seal> {
        let mut seals = Vec::new();
        for k in [key(1), key(2), key(3)] {
            let c = next_content(DocKind::Assignment, N, doc_hash(), &seals, 0).unwrap();
            seals.push(Seal::sign(&k, c));
        }
        seals
    }

    fn check(seals: &[Seal]) -> Result<ChainStatus, Error> {
        verify_chain(DocKind::Assignment, &N, &doc_hash(), seals, &signers())
    }

    #[test]
    fn chain_progresses_in_policy_order() {
        let seals = assignment_chain();
        assert_eq!(
            check(&[]),
            Ok(ChainStatus::Incomplete {
                next: Role::Supplier
            })
        );
        assert_eq!(
            check(&seals[..1]),
            Ok(ChainStatus::Incomplete { next: Role::Buyer })
        );
        assert_eq!(
            check(&seals[..2]),
            Ok(ChainStatus::Incomplete {
                next: Role::Financier
            })
        );
        assert_eq!(check(&seals), Ok(ChainStatus::Sealed));
        assert_eq!(
            next_content(DocKind::Assignment, N, doc_hash(), &seals, 0),
            Err(Error::TooManySeals)
        );
    }

    #[test]
    fn rejects_skips_reorders_and_wrong_signers() {
        let seals = assignment_chain();
        // buyer first (skipping the supplier)
        assert_eq!(check(&seals[1..2]), Err(Error::SealOrder));
        // swapped order
        assert_eq!(
            check(&[seals[1].clone(), seals[0].clone()]),
            Err(Error::SealOrder)
        );
        // the right step and role, signed by someone else
        let c = next_content(DocKind::Assignment, N, doc_hash(), &seals[..1], 0).unwrap();
        let impostor = Seal::sign(&key(9), c);
        assert_eq!(
            check(&[seals[0].clone(), impostor]),
            Err(Error::UnexpectedSigner)
        );
        // a seal for another document
        let other = next_content(DocKind::Assignment, [8; 32], doc_hash(), &[], 0).unwrap();
        assert_eq!(
            check(&[Seal::sign(&key(1), other)]),
            Err(Error::SealMismatch)
        );
    }

    #[test]
    fn rejects_tampering_and_broken_links() {
        let seals = assignment_chain();
        let mut tampered = seals.clone();
        tampered[1].flag = 1;
        assert_eq!(check(&tampered), Err(Error::BadSignature));
        // re-signed earlier seal breaks the link of the next one
        let c = next_content(DocKind::Assignment, N, doc_hash(), &[], 1).unwrap();
        let resealed = vec![Seal::sign(&key(1), c), seals[1].clone()];
        assert_eq!(check(&resealed), Err(Error::SealOrder));
    }

    #[test]
    fn one_key_cannot_hold_two_roles() {
        let mut s = signers();
        s.buyer = s.supplier;
        assert_eq!(
            verify_chain(DocKind::Assignment, &N, &doc_hash(), &[], &s),
            Err(Error::SelfApproval)
        );
    }

    #[test]
    fn bytes_roundtrip_and_strict_decoder() {
        let seal = assignment_chain().remove(1);
        let bytes = seal.to_bytes();
        assert_eq!(bytes.len(), 200);
        assert_eq!(&bytes[..4], b"JTL1");
        assert_eq!(bytes[70], Role::Buyer as u8);
        assert_eq!(Seal::from_bytes(&bytes).unwrap(), seal);
        assert_eq!(Seal::from_bytes(&bytes[..199]), Err(Error::Truncated));
        let mut b = bytes;
        b[4] = 9;
        assert_eq!(Seal::from_bytes(&b), Err(Error::UnknownDocKind(9)));
        let mut b = bytes;
        b[70] = 9;
        assert_eq!(Seal::from_bytes(&b), Err(Error::UnknownRole(9)));
        let mut long = bytes.to_vec();
        long.push(0);
        assert_eq!(Seal::from_bytes(&long), Err(Error::TrailingBytes));
    }

    #[test]
    fn policies_follow_the_design() {
        assert_eq!(policy(DocKind::Invoice), &[Role::Buyer]);
        assert_eq!(
            policy(DocKind::Assignment),
            &[Role::Supplier, Role::Buyer, Role::Financier]
        );
        assert_eq!(policy(DocKind::Settlement), &[Role::Buyer, Role::Financier]);
        assert_ne!(sealed_document_hash(b"x"), [0; 32]);
    }
}
