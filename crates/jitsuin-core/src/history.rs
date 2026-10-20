//! Buyer payment history as a chain anchored on the board (HNK-20.T1, D-20, DEV-10).
//!
//! - **Keys.** One master secret per buyer (in the web app: a passkey PRF output). It derives the
//!   buyer's identity key and one key per invoice by index, so the public board cannot link the
//!   invoices of one buyer.
//! - **Chain.** For every financed invoice the identity key signs a history certificate: index,
//!   invoice key, supplier key, N, amount, due date, financier key, and the hash of the previous
//!   certificate. The supplier key lets a verifier ignore forged entries that copy a tag.
//! - **Anchor.** The register entry of the invoice carries the certificate's successor tag
//!   `BLAKE2b-256("JitsuinHistTag__", identity_pk ‖ hash of the previous certificate)`. A chain the
//!   buyer renumbers or forks does not match the tags on the board, two entries with the same tag
//!   expose equivocation, and a hidden later invoice shows up as an existing successor of the
//!   disclosed head. Outsiders cannot compute the tags, except the first one of each identity.
//!
//! Certificate layout (277 bytes): magic `JTSH` (4), version (1), index (4, LE), invoice key (32),
//! supplier key (32), N (32), amount_zat (8, LE), due_date (4, LE), financier key (32), previous
//! hash (32), identity key (32), identity signature over the preceding bytes (64).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::error::Error;
use crate::invoice::{Invoice, Reader};
use crate::nullifier::nullifier;

pub const HISTORY_MAGIC: &[u8; 4] = b"JTSH";
pub const HISTORY_VERSION: u8 = 1;
pub const HISTORY_SIGNED_LEN: usize = 4 + 1 + 4 + 32 + 32 + 32 + 8 + 4 + 32 + 32 + 32;
pub const HISTORY_CERT_LEN: usize = HISTORY_SIGNED_LEN + 64;
const KEY_PERSONALIZATION: &[u8; 16] = b"JitsuinBuyerKey_";
const CERT_HASH_PERSONALIZATION: &[u8; 16] = b"JitsuinHistory__";
const TAG_PERSONALIZATION: &[u8; 16] = b"JitsuinHistTag__";

/// A buyer's key material. No `Debug`: it holds the master secret.
#[derive(Clone)]
pub struct BuyerIdentity {
    master: [u8; 32],
}

impl Drop for BuyerIdentity {
    /// Overwrites the master secret when the identity goes out of scope (P-07, HNK-27.T9).
    fn drop(&mut self) {
        for b in self.master.iter_mut() {
            // SAFETY: `b` is a valid, aligned `&mut u8`; volatile so the write is not elided.
            unsafe { std::ptr::write_volatile(b, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl BuyerIdentity {
    /// From 32 bytes of master secret (for example a WebAuthn PRF output).
    pub fn from_master_secret(master: [u8; 32]) -> Self {
        BuyerIdentity { master }
    }

    fn derive(&self, input: &[u8]) -> SigningKey {
        let hash = blake2b_simd::Params::new()
            .hash_length(32)
            .key(&self.master)
            .personal(KEY_PERSONALIZATION)
            .hash(input);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(hash.as_bytes());
        SigningKey::from_bytes(&seed)
    }

    /// Long-term identity key (KYC-bound by the financiers); signs the history certificates.
    pub fn identity_key(&self) -> SigningKey {
        self.derive(b"identity")
    }

    /// Key used as `buyer_pk` in the invoice at position `index` of the history.
    pub fn invoice_key(&self, index: u32) -> SigningKey {
        let mut input = b"invoice".to_vec();
        input.extend_from_slice(&index.to_le_bytes());
        self.derive(&input)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryCert {
    pub index: u32,
    pub invoice_pk: [u8; 32],
    /// Supplier's per-invoice key (verifies the register entry that carries the tag).
    pub supplier_pk: [u8; 32],
    pub nullifier: [u8; 32],
    pub amount_zat: u64,
    pub due_date: u32,
    pub financier_pk: [u8; 32],
    pub prev: [u8; 32],
    pub identity_pk: [u8; 32],
    pub signature: [u8; 64],
}

impl HistoryCert {
    /// Certificate for `invoice` at position `index`, chained after `prev` (none for index 0).
    /// The invoice must use the buyer's key for that index.
    pub fn issue(
        identity: &BuyerIdentity,
        index: u32,
        invoice: &Invoice,
        financier_pk: [u8; 32],
        prev: Option<&HistoryCert>,
    ) -> Result<Self, Error> {
        if invoice.buyer_pk != identity.invoice_key(index).verifying_key().to_bytes() {
            return Err(Error::KeyMismatch);
        }
        let prev_hash = match (index, prev) {
            (0, None) => [0u8; 32],
            (i, Some(p)) if p.index.checked_add(1) == Some(i) => p.hash(),
            _ => return Err(Error::HistoryOrder),
        };
        let id = identity.identity_key();
        let mut cert = HistoryCert {
            index,
            invoice_pk: invoice.buyer_pk,
            supplier_pk: invoice.supplier_ephemeral_pk,
            nullifier: nullifier(invoice)?,
            amount_zat: invoice.amount_zat,
            due_date: invoice.due_date,
            financier_pk,
            prev: prev_hash,
            identity_pk: id.verifying_key().to_bytes(),
            signature: [0; 64],
        };
        cert.signature = id.sign(&cert.signed_part()).to_bytes();
        Ok(cert)
    }

    fn signed_part(&self) -> [u8; HISTORY_SIGNED_LEN] {
        let mut out = [0u8; HISTORY_SIGNED_LEN];
        out[..4].copy_from_slice(HISTORY_MAGIC);
        out[4] = HISTORY_VERSION;
        out[5..9].copy_from_slice(&self.index.to_le_bytes());
        out[9..41].copy_from_slice(&self.invoice_pk);
        out[41..73].copy_from_slice(&self.supplier_pk);
        out[73..105].copy_from_slice(&self.nullifier);
        out[105..113].copy_from_slice(&self.amount_zat.to_le_bytes());
        out[113..117].copy_from_slice(&self.due_date.to_le_bytes());
        out[117..149].copy_from_slice(&self.financier_pk);
        out[149..181].copy_from_slice(&self.prev);
        out[181..213].copy_from_slice(&self.identity_pk);
        out
    }

    pub fn verify_signature(&self) -> Result<(), Error> {
        let vk =
            VerifyingKey::from_bytes(&self.identity_pk).map_err(|_| Error::InvalidPublicKey)?;
        vk.verify_strict(&self.signed_part(), &Signature::from_bytes(&self.signature))
            .map_err(|_| Error::BadSignature)
    }

    pub fn hash(&self) -> [u8; 32] {
        let hash = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(CERT_HASH_PERSONALIZATION)
            .hash(&self.to_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_bytes());
        out
    }

    /// Tag the register entry of this certificate's invoice must carry.
    pub fn tag(&self) -> [u8; 32] {
        successor_tag(&self.identity_pk, &self.prev)
    }

    pub fn to_bytes(&self) -> [u8; HISTORY_CERT_LEN] {
        let mut out = [0u8; HISTORY_CERT_LEN];
        out[..HISTORY_SIGNED_LEN].copy_from_slice(&self.signed_part());
        out[HISTORY_SIGNED_LEN..].copy_from_slice(&self.signature);
        out
    }

    /// Strict decoder for exactly [`HISTORY_CERT_LEN`] bytes. Does not verify the signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > HISTORY_CERT_LEN {
            return Err(Error::TrailingBytes);
        }
        let mut r = Reader::new(bytes);
        if r.take(4)? != HISTORY_MAGIC {
            return Err(Error::BadMagic);
        }
        let version = r.byte()?;
        if version != HISTORY_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        Ok(HistoryCert {
            index: u32::from_le_bytes(r.array()?),
            invoice_pk: r.array()?,
            supplier_pk: r.array()?,
            nullifier: r.array()?,
            amount_zat: u64::from_le_bytes(r.array()?),
            due_date: u32::from_le_bytes(r.array()?),
            financier_pk: r.array()?,
            prev: r.array()?,
            identity_pk: r.array()?,
            signature: r.array()?,
        })
    }
}

/// Tag of the certificate that follows the one hashing to `prev_hash` (zero: the first one).
pub fn successor_tag(identity_pk: &[u8; 32], prev_hash: &[u8; 32]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(TAG_PERSONALIZATION)
        .to_state()
        .update(identity_pk)
        .update(prev_hash)
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// Tag a certificate after `head` would carry (the first tag for an empty history).
pub fn next_tag(identity_pk: &[u8; 32], head: Option<&HistoryCert>) -> [u8; 32] {
    successor_tag(identity_pk, &head.map(HistoryCert::hash).unwrap_or([0; 32]))
}

/// Checks a disclosed chain: indices 0..k without gaps, each linked to the previous certificate,
/// one identity, valid signatures, distinct invoices. The board checks are in `jitsuin-board`.
pub fn verify_certs(certs: &[HistoryCert], identity_pk: &[u8; 32]) -> Result<(), Error> {
    let mut prev = [0u8; 32];
    for (i, c) in certs.iter().enumerate() {
        if &c.identity_pk != identity_pk {
            return Err(Error::UnexpectedSigner);
        }
        if c.index as usize != i || c.prev != prev {
            return Err(Error::HistoryOrder);
        }
        if certs[..i].iter().any(|p| p.nullifier == c.nullifier) {
            return Err(Error::HistoryOrder);
        }
        c.verify_signature()?;
        prev = c.hash();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> BuyerIdentity {
        BuyerIdentity::from_master_secret([0x42; 32])
    }

    fn invoice(index: u32) -> Invoice {
        Invoice {
            invoice_id: format!("TES-INV-H{index}"),
            supplier_ephemeral_pk: SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes(),
            buyer_pk: identity().invoice_key(index).verifying_key().to_bytes(),
            amount_zat: 10_000,
            issue_date: 10,
            due_date: 40,
            terms_hash: [9; 32],
        }
    }

    fn chain(n: u32) -> Vec<HistoryCert> {
        let fin = SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes();
        let mut certs: Vec<HistoryCert> = Vec::new();
        for i in 0..n {
            let c = HistoryCert::issue(&identity(), i, &invoice(i), fin, certs.last()).unwrap();
            certs.push(c);
        }
        certs
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn key_derivation_vector_and_unlinkable_invoice_keys() {
        // Cross-checked with Python: hashlib.blake2b(b"invoice" + (0).to_bytes(4, "little"),
        // digest_size=32, key=b"\x42"*32, person=b"JitsuinBuyerKey_")
        let id = identity();
        assert_eq!(
            hex(&id.invoice_key(0).to_bytes()),
            "b467d39acc924edc21c631f77e1f1a6781dbd254efa0cc344ab1c7beaf34ac98"
        );
        let keys: Vec<_> = (0..3)
            .map(|i| id.invoice_key(i).verifying_key().to_bytes())
            .collect();
        assert_ne!(keys[0], keys[1]);
        assert!(!keys.contains(&id.identity_key().verifying_key().to_bytes()));
        // same master secret, same keys (a passkey on another device)
        assert_eq!(
            BuyerIdentity::from_master_secret([0x42; 32])
                .invoice_key(2)
                .to_bytes(),
            id.invoice_key(2).to_bytes()
        );
    }

    #[test]
    fn chain_links_and_tags() {
        let certs = chain(3);
        let id_pk = identity().identity_key().verifying_key().to_bytes();
        verify_certs(&certs, &id_pk).unwrap();
        assert_eq!(certs[0].tag(), next_tag(&id_pk, None));
        assert_eq!(certs[1].tag(), next_tag(&id_pk, Some(&certs[0])));
        assert_eq!(certs[2].prev, certs[1].hash());
        let bytes = certs[1].to_bytes();
        assert_eq!(bytes.len(), 277);
        assert_eq!(HistoryCert::from_bytes(&bytes).unwrap(), certs[1]);
        assert_eq!(
            HistoryCert::from_bytes(&bytes[..276]),
            Err(Error::Truncated)
        );
    }

    #[test]
    fn rejects_gaps_forks_and_wrong_keys() {
        let certs = chain(3);
        let id_pk = identity().identity_key().verifying_key().to_bytes();
        // gap: index 1 left out
        assert_eq!(
            verify_certs(&[certs[0].clone(), certs[2].clone()], &id_pk),
            Err(Error::HistoryOrder)
        );
        // starting in the middle
        assert_eq!(verify_certs(&certs[1..], &id_pk), Err(Error::HistoryOrder));
        // the builder refuses to renumber an invoice (its key belongs to another index); a
        // hand-built fork is caught by the board anchor (`jitsuin-board` history checks)
        let fin = SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes();
        let fork1 =
            HistoryCert::issue(&identity(), 1, &invoice(2), fin, Some(&certs[0])).unwrap_err();
        assert_eq!(fork1, Error::KeyMismatch);
        let other = HistoryCert::issue(&identity(), 2, &invoice(2), fin, Some(&certs[0]));
        assert_eq!(other, Err(Error::HistoryOrder));
        // tampering
        let mut t = certs.clone();
        t[1].due_date += 1;
        assert_eq!(verify_certs(&t, &id_pk), Err(Error::BadSignature));
        // another identity
        let stranger = BuyerIdentity::from_master_secret([7; 32])
            .identity_key()
            .verifying_key()
            .to_bytes();
        assert_eq!(
            verify_certs(&certs, &stranger),
            Err(Error::UnexpectedSigner)
        );
    }
}
