//! Mailbox cryptography (HNK-23.T2, P-04): the browser side of the relay's mailboxes.
//!
//! - **Mailbox key.** The X25519 secret comes from the passkey's second PRF output (the role's
//!   inbox salt): `BLAKE2b-256(key = prf_second, personalization = "JitsuinMailbox__", "x25519")`.
//! - **`mailbox_id`** = `BLAKE2b-512("JitsuinMailboxId_v1\n" ‖ mailbox_pk)[0..32]`, as the relay
//!   computes it (jitsuinfi-backend `src/crypto.ts`).
//! - **Ownership proof** for a relay challenge (`eph_pk`, `nonce`):
//!   `BLAKE2b-512("JitsuinMailboxProof_v1\n" ‖ purpose ‖ 0x00 ‖ X25519(mailbox_secret, eph_pk) ‖
//!   nonce ‖ mailbox_pk)[0..32]`.
//! - **Sealed message**, the construction of libsodium's `crypto_box_seal`: an ephemeral X25519
//!   key `e`, `nonce = BLAKE2b-192(e_pk ‖ recipient_pk)`, XSalsa20-Poly1305 under the box key of
//!   `e` and the recipient; output `e_pk ‖ box` (48 bytes longer than the message). The caller
//!   gives `e`'s secret (32 random bytes, WebCrypto in the browser), so this crate needs no RNG.
//!
//! Keys that give an all-zero shared secret (low order) are refused everywhere.

use blake2b_simd::Params;
use crypto_box::aead::generic_array::GenericArray;
use crypto_box::aead::Aead;
use crypto_box::{PublicKey as BoxPublic, SalsaBox, SecretKey as BoxSecret};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::Error;

const KEY_PERSONALIZATION: &[u8; 16] = b"JitsuinMailbox__";
const ID_DOMAIN: &[u8] = b"JitsuinMailboxId_v1\n";
const PROOF_DOMAIN: &[u8] = b"JitsuinMailboxProof_v1\n";

/// Bytes a sealed message adds to its plaintext: the ephemeral key and the Poly1305 tag.
pub const SEAL_OVERHEAD: usize = 48;

/// What a relay challenge is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Register,
    Read,
}

impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::Register => "register",
            Purpose::Read => "read",
        }
    }

    pub fn parse(s: &str) -> Result<Self, Error> {
        match s {
            "register" => Ok(Purpose::Register),
            "read" => Ok(Purpose::Read),
            _ => Err(Error::InvalidMailboxKey),
        }
    }
}

/// `mailbox_id` of a mailbox key.
pub fn mailbox_id(mailbox_pk: &[u8; 32]) -> [u8; 32] {
    let h = Params::new()
        .hash_length(64)
        .to_state()
        .update(ID_DOMAIN)
        .update(mailbox_pk)
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.as_bytes()[..32]);
    out
}

/// The proof tag both sides compute from the shared secret.
pub fn proof_tag(
    purpose: Purpose,
    shared: &[u8; 32],
    nonce: &[u8; 32],
    mailbox_pk: &[u8; 32],
) -> [u8; 32] {
    let h = Params::new()
        .hash_length(64)
        .to_state()
        .update(PROOF_DOMAIN)
        .update(purpose.as_str().as_bytes())
        .update(&[0])
        .update(shared)
        .update(nonce)
        .update(mailbox_pk)
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.as_bytes()[..32]);
    out
}

fn contributory(secret: &[u8; 32], peer: &[u8; 32]) -> Result<[u8; 32], Error> {
    let shared = StaticSecret::from(*secret).diffie_hellman(&PublicKey::from(*peer));
    if !shared.was_contributory() {
        return Err(Error::InvalidMailboxKey);
    }
    Ok(*shared.as_bytes())
}

fn seal_nonce(eph_pk: &[u8; 32], recipient_pk: &[u8; 32]) -> [u8; 24] {
    let h = Params::new()
        .hash_length(24)
        .to_state()
        .update(eph_pk)
        .update(recipient_pk)
        .finalize();
    let mut out = [0u8; 24];
    out.copy_from_slice(h.as_bytes());
    out
}

/// Seals `message` to `recipient_pk` with the ephemeral secret `eph_secret` (32 random bytes,
/// used once).
pub fn seal(
    recipient_pk: &[u8; 32],
    eph_secret: &[u8; 32],
    message: &[u8],
) -> Result<Vec<u8>, Error> {
    contributory(eph_secret, recipient_pk)?;
    let eph = BoxSecret::from(*eph_secret);
    let eph_pk = *eph.public_key().as_bytes();
    let nonce = seal_nonce(&eph_pk, recipient_pk);
    let sealed = SalsaBox::new(&BoxPublic::from(*recipient_pk), &eph)
        .encrypt(GenericArray::from_slice(&nonce), message)
        .map_err(|_| Error::SealedMessage)?;
    let mut out = Vec::with_capacity(SEAL_OVERHEAD + message.len());
    out.extend_from_slice(&eph_pk);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// A mailbox key, derived from the passkey's second PRF output.
pub struct MailboxKeys {
    secret: [u8; 32],
    public: [u8; 32],
}

impl MailboxKeys {
    pub fn from_prf(prf_second: &[u8; 32]) -> Self {
        let h = Params::new()
            .hash_length(32)
            .key(prf_second)
            .personal(KEY_PERSONALIZATION)
            .to_state()
            .update(b"x25519")
            .finalize();
        let mut secret = [0u8; 32];
        secret.copy_from_slice(h.as_bytes());
        let public = *PublicKey::from(&StaticSecret::from(secret)).as_bytes();
        MailboxKeys { secret, public }
    }

    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    pub fn id(&self) -> [u8; 32] {
        mailbox_id(&self.public)
    }

    /// Answer to a relay challenge.
    pub fn proof(
        &self,
        purpose: Purpose,
        eph_pk: &[u8; 32],
        nonce: &[u8; 32],
    ) -> Result<[u8; 32], Error> {
        let shared = contributory(&self.secret, eph_pk)?;
        Ok(proof_tag(purpose, &shared, nonce, &self.public))
    }

    /// Opens a message sealed to this mailbox.
    pub fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, Error> {
        if sealed.len() < SEAL_OVERHEAD {
            return Err(Error::SealedMessage);
        }
        let mut eph_pk = [0u8; 32];
        eph_pk.copy_from_slice(&sealed[..32]);
        contributory(&self.secret, &eph_pk)?;
        let nonce = seal_nonce(&eph_pk, &self.public);
        SalsaBox::new(&BoxPublic::from(eph_pk), &BoxSecret::from(self.secret))
            .decrypt(GenericArray::from_slice(&nonce), &sealed[32..])
            .map_err(|_| Error::SealedMessage)
    }
}

impl Drop for MailboxKeys {
    fn drop(&mut self) {
        // Best effort: the secret does not outlive the keys in this struct.
        self.secret = [0u8; 32];
        core::hint::black_box(&self.secret);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Fixed vector shared with jitsuinfi-backend `tests/vectors.test.ts`: the relay must compute
    /// the same id and accept the same proof.
    #[test]
    fn vector_matches_the_relay() {
        let k = MailboxKeys::from_prf(&[0x11; 32]);
        let eph_pk = *PublicKey::from(&StaticSecret::from([0x22; 32])).as_bytes();
        let proof = k.proof(Purpose::Register, &eph_pk, &[0x33; 32]).unwrap();
        assert_eq!(
            [hex(&k.public()), hex(&k.id()), hex(&eph_pk), hex(&proof)],
            [MAILBOX_PK, MAILBOX_ID, EPH_PK, PROOF_REGISTER]
        );
        // the relay's side: X25519(e, mailbox_pk) gives the same shared secret
        let shared = contributory(&[0x22; 32], &k.public()).unwrap();
        assert_eq!(
            proof_tag(Purpose::Register, &shared, &[0x33; 32], &k.public()),
            proof
        );
        assert_ne!(k.proof(Purpose::Read, &eph_pk, &[0x33; 32]).unwrap(), proof);
    }

    const MAILBOX_PK: &str = "721e61a2e3a16f2e7806c392b1367c8edb7c11c0132d2b5d3164290d60fce400";
    const MAILBOX_ID: &str = "171e3bf4c1a8af89725083cc6ceac9bb9400ebcf9caac626f1b6779e667559c2";
    const EPH_PK: &str = "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20";
    const PROOF_REGISTER: &str = "7d4a818d24e88f5a20279120ae3dad9e64409b7f9b0de59b415ce565ef84f7a2";

    #[test]
    fn sealed_messages_open_only_for_their_mailbox() {
        let alice = MailboxKeys::from_prf(&[1; 32]);
        let bob = MailboxKeys::from_prf(&[2; 32]);
        let msg = b"JTSM\x01 a deal document";
        let sealed = seal(&alice.public(), &[7; 32], msg).unwrap();
        assert_eq!(sealed.len(), msg.len() + SEAL_OVERHEAD);
        assert_eq!(alice.open(&sealed).unwrap(), msg);
        assert_eq!(bob.open(&sealed), Err(Error::SealedMessage));
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(alice.open(&tampered), Err(Error::SealedMessage));
        assert_eq!(alice.open(&sealed[..40]), Err(Error::SealedMessage));
        // a new ephemeral key, a different box
        assert_ne!(seal(&alice.public(), &[8; 32], msg).unwrap(), sealed);
        assert_eq!(
            alice
                .open(&seal(&alice.public(), &[8; 32], b"").unwrap())
                .unwrap(),
            b""
        );
    }

    #[test]
    fn low_order_keys_are_refused() {
        let k = MailboxKeys::from_prf(&[1; 32]);
        for bad in [[0u8; 32], {
            let mut one = [0u8; 32];
            one[0] = 1;
            one
        }] {
            assert_eq!(seal(&bad, &[7; 32], b"x"), Err(Error::InvalidMailboxKey));
            assert_eq!(
                k.proof(Purpose::Read, &bad, &[0; 32]),
                Err(Error::InvalidMailboxKey)
            );
            let mut sealed = vec![0u8; 60];
            sealed[..32].copy_from_slice(&bad);
            assert_eq!(k.open(&sealed), Err(Error::InvalidMailboxKey));
        }
    }

    #[test]
    fn keys_depend_only_on_the_prf_output() {
        assert_eq!(
            MailboxKeys::from_prf(&[3; 32]).public(),
            MailboxKeys::from_prf(&[3; 32]).public()
        );
        assert_ne!(
            MailboxKeys::from_prf(&[3; 32]).public(),
            MailboxKeys::from_prf(&[4; 32]).public()
        );
        assert_eq!(Purpose::parse("read"), Ok(Purpose::Read));
        assert!(Purpose::parse("write").is_err());
    }
}
