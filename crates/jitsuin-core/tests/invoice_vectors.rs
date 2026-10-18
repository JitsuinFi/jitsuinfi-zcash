//! HNK-01.T3: unit tests + test vector for the canonical invoice and buyer signature.
//!
//! `vectors/invoice_v1.txt` is produced by `vectors/gen_invoice_vector.py`, an independent
//! pure-Python implementation of the layout and of RFC 8032 Ed25519 (it self-checks against
//! RFC 8032 test 1). These tests require jitsuin-core to reproduce it byte for byte.
//! Covers TEST-HNK-01 U-HNK-01.1 – U-HNK-01.5.

use ed25519_dalek::{Signature, SigningKey};
use jitsuin_core::{sign_invoice, verify_invoice, Error, Invoice};

const VECTOR: &str = include_str!("vectors/invoice_v1.txt");

type Mutate = Box<dyn Fn(&mut Invoice)>;

fn field(name: &str) -> &'static str {
    VECTOR
        .lines()
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| l.strip_prefix(name).and_then(|r| r.strip_prefix('=')))
        .unwrap_or_else(|| panic!("vector field {name} missing"))
}

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    hex(s).try_into().expect("length")
}

fn buyer() -> SigningKey {
    SigningKey::from_bytes(&arr(field("buyer_seed")))
}

fn invoice() -> Invoice {
    Invoice {
        invoice_id: field("invoice_id").to_string(),
        supplier_ephemeral_pk: arr(field("supplier_ephemeral_pk")),
        buyer_pk: arr(field("buyer_pk")),
        amount_zat: field("amount_zat").parse().unwrap(),
        issue_date: field("issue_date").parse().unwrap(),
        due_date: field("due_date").parse().unwrap(),
        terms_hash: arr(field("terms_hash")),
    }
}

#[test]
fn vector_keys_match_seeds() {
    assert_eq!(
        buyer().verifying_key().to_bytes(),
        arr::<32>(field("buyer_pk"))
    );
    let supplier = SigningKey::from_bytes(&arr(field("supplier_seed")));
    assert_eq!(
        supplier.verifying_key().to_bytes(),
        arr::<32>(field("supplier_ephemeral_pk"))
    );
}

/// U-HNK-01.1: encode then decode gives the same invoice.
#[test]
fn roundtrip() {
    let inv = invoice();
    let bytes = inv.to_canonical_bytes().unwrap();
    assert_eq!(Invoice::from_canonical_bytes(&bytes).unwrap(), inv);
}

/// U-HNK-01.2: encoding twice gives identical bytes, equal to the independent vector.
#[test]
fn canonical_bytes_are_deterministic_and_match_vector() {
    let inv = invoice();
    let a = inv.to_canonical_bytes().unwrap();
    let b = inv.clone().to_canonical_bytes().unwrap();
    assert_eq!(a, b);
    assert_eq!(a, hex(field("canonical")));
}

/// U-HNK-01.3: signing twice gives identical signatures (RFC 8032), equal to the vector.
#[test]
fn signature_is_deterministic_and_matches_vector() {
    let inv = invoice();
    let s1 = sign_invoice(&buyer(), &inv).unwrap();
    let s2 = sign_invoice(&buyer(), &inv).unwrap();
    assert_eq!(s1.to_bytes(), s2.to_bytes());
    assert_eq!(s1.to_bytes().to_vec(), hex(field("signature")));
    verify_invoice(&inv, &s1).unwrap();
}

/// The vector signature verifies on its own, without signing in Rust first.
#[test]
fn vector_signature_verifies() {
    let sig = Signature::from_bytes(&arr(field("signature")));
    verify_invoice(&invoice(), &sig).unwrap();
}

/// U-HNK-01.4: changing any single field makes verification fail.
#[test]
fn any_field_change_breaks_the_signature() {
    let inv = invoice();
    let sig = sign_invoice(&buyer(), &inv).unwrap();
    let other_pk = SigningKey::from_bytes(&[7u8; 32])
        .verifying_key()
        .to_bytes();
    let mutations: Vec<(&str, Mutate)> = vec![
        (
            "invoice_id",
            Box::new(|i| i.invoice_id = "TES-INV-0002".into()),
        ),
        (
            "supplier_ephemeral_pk",
            Box::new(move |i| i.supplier_ephemeral_pk = other_pk),
        ),
        ("amount_zat", Box::new(|i| i.amount_zat += 1)),
        ("issue_date", Box::new(|i| i.issue_date -= 1)),
        ("due_date", Box::new(|i| i.due_date += 1)),
        ("terms_hash", Box::new(|i| i.terms_hash[0] ^= 1)),
    ];
    for (name, mutate) in mutations {
        let mut changed = inv.clone();
        mutate(&mut changed);
        assert_eq!(
            verify_invoice(&changed, &sig),
            Err(Error::BadSignature),
            "{name}"
        );
    }
    // A different buyer key cannot verify the original buyer's signature.
    let mut other_buyer = inv.clone();
    other_buyer.buyer_pk = other_pk;
    assert_eq!(verify_invoice(&other_buyer, &sig), Err(Error::BadSignature));
}

#[test]
fn signing_with_a_key_that_is_not_the_buyer_is_refused() {
    let wrong = SigningKey::from_bytes(&[9u8; 32]);
    assert_eq!(sign_invoice(&wrong, &invoice()), Err(Error::KeyMismatch));
}

/// U-HNK-01.5: empty or invalid fields are rejected, both when encoding and when decoding.
#[test]
fn invalid_fields_are_rejected() {
    let bad_point: [u8; 32] = arr(field("invalid_point"));
    let cases: Vec<(&str, Mutate, Error)> = vec![
        (
            "empty id",
            Box::new(|i| i.invoice_id.clear()),
            Error::InvalidInvoiceId,
        ),
        (
            "id too long",
            Box::new(|i| i.invoice_id = "X".repeat(33)),
            Error::InvalidInvoiceId,
        ),
        (
            "id with space",
            Box::new(|i| i.invoice_id = "TES INV".into()),
            Error::InvalidInvoiceId,
        ),
        (
            "id non-ascii",
            Box::new(|i| i.invoice_id = "TES-INVÉ".into()),
            Error::InvalidInvoiceId,
        ),
        (
            "zero amount",
            Box::new(|i| i.amount_zat = 0),
            Error::InvalidAmount,
        ),
        (
            "due before issue",
            Box::new(|i| i.due_date = i.issue_date - 1),
            Error::InvalidDates,
        ),
        (
            "bad supplier key",
            Box::new(move |i| i.supplier_ephemeral_pk = bad_point),
            Error::InvalidPublicKey,
        ),
        (
            "bad buyer key",
            Box::new(move |i| i.buyer_pk = bad_point),
            Error::InvalidPublicKey,
        ),
    ];
    for (name, mutate, want) in cases {
        let mut inv = invoice();
        mutate(&mut inv);
        assert_eq!(inv.to_canonical_bytes(), Err(want), "{name}");
    }
    // Longest allowed id (32) still encodes.
    let mut max = invoice();
    max.invoice_id = "X".repeat(32);
    assert!(max.to_canonical_bytes().is_ok());
}

#[test]
fn decoder_is_strict() {
    let good = hex(field("canonical"));

    let mut bad_magic = good.clone();
    bad_magic[0] = b'X';
    assert_eq!(
        Invoice::from_canonical_bytes(&bad_magic),
        Err(Error::BadMagic)
    );

    let mut bad_version = good.clone();
    bad_version[4] = 2;
    assert_eq!(
        Invoice::from_canonical_bytes(&bad_version),
        Err(Error::UnsupportedVersion(2))
    );

    assert_eq!(
        Invoice::from_canonical_bytes(&good[..good.len() - 1]),
        Err(Error::Truncated)
    );
    assert_eq!(Invoice::from_canonical_bytes(&[]), Err(Error::Truncated));

    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(
        Invoice::from_canonical_bytes(&trailing),
        Err(Error::TrailingBytes)
    );

    let mut zero_amount = good.clone();
    let amount_at = 4 + 1 + 1 + field("invoice_id").len() + 32 + 32;
    zero_amount[amount_at..amount_at + 8].fill(0);
    assert_eq!(
        Invoice::from_canonical_bytes(&zero_amount),
        Err(Error::InvalidAmount)
    );
}
