//! Keys derived from a role's master secret (a WebAuthn PRF output, P-01 – P-03).
//!
//! - **Supplier per-invoice key (P-03, HNK-24.T1):** replaces the random key the supplier had to
//!   back up as plaintext JSON. `BLAKE2b-256(key = master, personalization "JitsuinSupplKey_",
//!   "invoice" ‖ len(invoice_id) u16 LE ‖ invoice_id ‖ buyer_pk)`. `buyer_pk` is the buyer's
//!   per-invoice key `invoice_pk(k)`, unique per buyer invoice, so the same `invoice_id` reused
//!   for another buyer (or another invoice of the same buyer) gives an unrelated key. The length
//!   prefix keeps `(id, pk)` pairs from colliding. A holder of one invoice cannot find the
//!   supplier's other board entries: each entry verifies only with its own invoice's key.
//! - **Local storage keys (HNK-24.T3):** an encryption key and an index key for the deal
//!   documents the web app keeps on the device, `BLAKE2b-256(key = master, personalization
//!   "JitsuinStoreKey_", "store-enc" | "store-idx")`. Separate from every signing key.
//!
//! Masters are wiped when dropped.

use ed25519_dalek::SigningKey;

const SUPPLIER_KEY_PERSONALIZATION: &[u8; 16] = b"JitsuinSupplKey_";
const STORE_KEY_PERSONALIZATION: &[u8; 16] = b"JitsuinStoreKey_";

fn keyed(master: &[u8; 32], personal: &[u8; 16], input: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .key(master)
        .personal(personal)
        .hash(input);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

fn wipe(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        // SAFETY: `b` is a valid, aligned `&mut u8`; volatile so the write is not elided.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// A supplier's master secret. No `Debug`: it holds the secret.
#[derive(Clone)]
pub struct SupplierMaster {
    master: [u8; 32],
}

impl Drop for SupplierMaster {
    fn drop(&mut self) {
        wipe(&mut self.master);
    }
}

impl SupplierMaster {
    /// From 32 bytes of master secret (the supplier role's PRF output).
    pub fn from_master_secret(master: [u8; 32]) -> Self {
        SupplierMaster { master }
    }

    /// Per-invoice signing key for `invoice_id` addressed to the buyer key `buyer_pk`.
    /// `None` when `invoice_id` is longer than a u16 length allows.
    pub fn invoice_key(&self, invoice_id: &str, buyer_pk: &[u8; 32]) -> Option<SigningKey> {
        let id = invoice_id.as_bytes();
        let len = u16::try_from(id.len()).ok()?;
        let mut input = Vec::with_capacity(7 + 2 + id.len() + 32);
        input.extend_from_slice(b"invoice");
        input.extend_from_slice(&len.to_le_bytes());
        input.extend_from_slice(id);
        input.extend_from_slice(buyer_pk);
        let mut seed = keyed(&self.master, SUPPLIER_KEY_PERSONALIZATION, &input);
        let key = SigningKey::from_bytes(&seed);
        wipe(&mut seed);
        Some(key)
    }

    /// Local storage keys of the supplier role (see [`storage_keys`]).
    pub fn storage_keys(&self) -> StorageKeys {
        storage_keys(&self.master)
    }
}

/// Encryption key and index key for the deal documents kept on the device. No `Debug`.
pub struct StorageKeys {
    /// AES-256-GCM key for the documents.
    pub encryption: [u8; 32],
    /// HMAC-SHA-256 key that turns a document id (for example N) into its record name, so the
    /// local database does not show which invoices are stored.
    pub index: [u8; 32],
}

impl Drop for StorageKeys {
    fn drop(&mut self) {
        wipe(&mut self.encryption);
        wipe(&mut self.index);
    }
}

/// Storage keys from any role's master secret (buyer or supplier). Different roles have
/// different masters (different PRF salts), so their stores never share keys.
pub fn storage_keys(master: &[u8; 32]) -> StorageKeys {
    StorageKeys {
        encryption: keyed(master, STORE_KEY_PERSONALIZATION, b"store-enc"),
        index: keyed(master, STORE_KEY_PERSONALIZATION, b"store-idx"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn invoice_key_is_stable_and_unique_per_invoice() {
        let m = SupplierMaster::from_master_secret([0x11; 32]);
        let a = m.invoice_key("TES-INV-0001", &[0x22; 32]).unwrap();
        // the same master, id and buyer key give the same key (a new device, a reload)
        assert_eq!(
            a.to_bytes(),
            m.invoice_key("TES-INV-0001", &[0x22; 32])
                .unwrap()
                .to_bytes()
        );
        // another id, another buyer key or another master give another key
        for other in [
            m.invoice_key("TES-INV-0002", &[0x22; 32]).unwrap(),
            m.invoice_key("TES-INV-0001", &[0x23; 32]).unwrap(),
            SupplierMaster::from_master_secret([0x12; 32])
                .invoice_key("TES-INV-0001", &[0x22; 32])
                .unwrap(),
        ] {
            assert_ne!(a.to_bytes(), other.to_bytes());
        }
        // an id that does not fit the u16 length is refused
        assert!(m.invoice_key(&"x".repeat(70_000), &[0x22; 32]).is_none());
    }

    #[test]
    fn supplier_key_vector() {
        let m = SupplierMaster::from_master_secret([0x11; 32]);
        let k = m.invoice_key("TES-INV-0001", &[0x22; 32]).unwrap();
        assert_eq!(hex(&k.to_bytes()), VECTOR_SUPPLIER_SEED);
    }

    #[test]
    fn storage_keys_are_separate_and_per_master() {
        let s = storage_keys(&[0x11; 32]);
        assert_ne!(s.encryption, s.index);
        assert_ne!(storage_keys(&[0x12; 32]).encryption, s.encryption);
        assert_eq!(hex(&s.encryption), VECTOR_STORE_ENC);
        assert_eq!(hex(&s.index), VECTOR_STORE_IDX);
        // the supplier helper gives the same keys as the free function
        let m = SupplierMaster::from_master_secret([0x11; 32]);
        assert_eq!(m.storage_keys().encryption, s.encryption);
    }

    const VECTOR_SUPPLIER_SEED: &str =
        "bb1354a579aa2d4b4335ff9e5cc9f841692839b1903e52d279ef282730f91051";
    const VECTOR_STORE_ENC: &str =
        "1d2dff152b74df11c200d74ec263ab5f7e03ad2dc508a9024f0bee2eeb095f2f";
    const VECTOR_STORE_IDX: &str =
        "8d112917040c154cf60c7d5fef8d19e459583c7d2a43906c7acb365967c7c666";
}
