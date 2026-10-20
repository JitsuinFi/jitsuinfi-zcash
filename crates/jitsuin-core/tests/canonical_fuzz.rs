//! Fuzz of the invoice canonicalisation (HNK-30.T1, AC-HNK-30.1, W-16).
//!
//! The demo claims "two exits": whatever a supplier changes in a buyer-signed invoice, the result
//! is either refused (偽: malformed, or the buyer signature no longer holds) or has the same
//! nullifier N as the original (重: already financed). A mutation that keeps a valid buyer
//! signature under a *new* N would let one invoice be financed twice. These tests mutate the
//! canonical bytes and the decoded fields with a fixed-seed generator (reproducible, no extra
//! dependency) and fail on the first such mutation.

use ed25519_dalek::{Signature, SigningKey};
use jitsuin_core::{nullifier, sign_invoice, verify_invoice, Invoice};

/// Exits of one attempt.
#[derive(Debug, PartialEq)]
enum Exit {
    /// Not an invoice: decoding or field validation refused it.
    Malformed,
    /// 偽: the buyer signature does not hold for these bytes.
    BadSeal,
    /// 重: valid signature, same N as the original.
    SameN,
}

/// xorshift64*: deterministic, so a failure reproduces with the same seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn original() -> (Invoice, Signature, [u8; 32]) {
    let buyer = SigningKey::from_bytes(&[2; 32]);
    let inv = Invoice {
        invoice_id: "TES-INV-0417".into(),
        supplier_ephemeral_pk: SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes(),
        buyer_pk: buyer.verifying_key().to_bytes(),
        amount_zat: 1_250_000_000,
        issue_date: 20_377,
        due_date: 20_467,
        terms_hash: [9; 32],
    };
    let sig = sign_invoice(&buyer, &inv).unwrap();
    let n = nullifier(&inv).unwrap();
    (inv, sig, n)
}

/// What a financier's check does with bytes and a signature that a supplier presents.
fn attempt(bytes: &[u8], sig: &Signature, n0: &[u8; 32]) -> Exit {
    let Ok(inv) = Invoice::from_canonical_bytes(bytes) else {
        return Exit::Malformed;
    };
    if verify_invoice(&inv, sig).is_err() {
        return Exit::BadSeal;
    }
    let n = nullifier(&inv).expect("a decoded invoice has a nullifier");
    assert_eq!(
        &n, n0,
        "TWO EXITS BROKEN: bytes {bytes:02x?} keep the buyer signature under a new N"
    );
    Exit::SameN
}

fn mutate(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut b = base.to_vec();
    for _ in 0..=rng.below(3) {
        match rng.below(7) {
            0 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] ^= 1 << rng.below(8);
            }
            1 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] = rng.next() as u8;
            }
            2 => {
                let i = rng.below(b.len() + 1);
                b.insert(i, rng.next() as u8);
            }
            3 if !b.is_empty() => {
                let i = rng.below(b.len());
                b.remove(i);
            }
            4 if b.len() > 1 => {
                let (i, j) = (rng.below(b.len()), rng.below(b.len()));
                b.swap(i, j);
            }
            5 => b.extend_from_slice(&[0, b' ', b'\n'][..1 + rng.below(3)]),
            _ => {
                // an ASCII case flip or space in the invoice id, the most "human" edit
                let i = 6 + rng.below(12);
                if i < b.len() {
                    b[i] = match b[i] {
                        c @ b'A'..=b'Z' => c + 32,
                        c @ b'a'..=b'z' => c - 32,
                        _ => b' ',
                    };
                }
            }
        }
    }
    b
}

#[test]
fn byte_mutations_only_reach_the_two_exits() {
    let (inv, sig, n0) = original();
    let base = inv.to_canonical_bytes().unwrap();
    assert_eq!(attempt(&base, &sig, &n0), Exit::SameN);
    let mut rng = Rng(0x4a49_5453_5549_4e00);
    let (mut malformed, mut bad, mut same) = (0, 0, 0);
    for _ in 0..20_000 {
        match attempt(&mutate(&mut rng, &base), &sig, &n0) {
            Exit::Malformed => malformed += 1,
            Exit::BadSeal => bad += 1,
            Exit::SameN => same += 1,
        }
    }
    println!("20000 byte mutations: malformed {malformed}, bad seal {bad}, same N {same}");
    assert!(
        bad > 0 && malformed > 0,
        "the generator must reach both refusals"
    );
}

#[test]
fn field_mutations_only_reach_the_two_exits() {
    let (inv, sig, n0) = original();
    let mut rng = Rng(0x0417_0417_0417_0417);
    let ids = [
        "TES-INV-0417 ",
        " TES-INV-0417",
        "tes-inv-0417",
        "TES-INV-417",
        "TES-INV-00417",
        "TES-INV-0417\u{200b}",
        "TES\u{2011}INV-0417",
        "TES-INV-O417",
    ];
    let mut tried = 0;
    for round in 0..12_000 {
        let mut m = inv.clone();
        match round % 7 {
            0 => m.invoice_id = ids[rng.below(ids.len())].into(),
            1 => m.amount_zat = inv.amount_zat.wrapping_add(1 + rng.below(1_000_000) as u64),
            2 => m.issue_date = inv.issue_date.wrapping_sub(rng.below(30) as u32 + 1),
            3 => m.due_date = inv.due_date + rng.below(90) as u32 + 1,
            4 => m.terms_hash[rng.below(32)] ^= 1 << rng.below(8),
            5 => {
                m.supplier_ephemeral_pk = SigningKey::from_bytes(&[(rng.below(250) + 3) as u8; 32])
                    .verifying_key()
                    .to_bytes()
            }
            _ => {
                m.buyer_pk = SigningKey::from_bytes(&[(rng.below(250) + 3) as u8; 32])
                    .verifying_key()
                    .to_bytes()
            }
        }
        let exit = match m.to_canonical_bytes() {
            Ok(bytes) => attempt(&bytes, &sig, &n0),
            Err(_) => Exit::Malformed,
        };
        assert_ne!(
            exit,
            Exit::SameN,
            "a changed field cannot keep the same N: {m:?}"
        );
        tried += 1;
    }
    println!("{tried} field mutations: all refused");
}

#[test]
fn a_second_signature_on_the_same_invoice_keeps_n() {
    // Ed25519 signatures with other nonces, or a malleated S, must not change N (N ignores the
    // signature) and a malleated S must be refused by the strict check.
    let (inv, sig, n0) = original();
    let bytes = inv.to_canonical_bytes().unwrap();
    let mut raw = sig.to_bytes();
    // S + L (the group order) is the classic malleation; strict verification refuses it.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut carry = 0u16;
    for i in 0..32 {
        let v = raw[32 + i] as u16 + L[i] as u16 + carry;
        raw[32 + i] = v as u8;
        carry = v >> 8;
    }
    assert_eq!(
        attempt(&bytes, &Signature::from_bytes(&raw), &n0),
        Exit::BadSeal
    );
}
