//! HNK-12.T2: the test vectors printed in `docs/zip-shielded-receivable-registry.md` are read from
//! the specification itself and recomputed here, so the document and the code cannot drift apart.

use ed25519_dalek::SigningKey;
use jitsuin_core::history::BuyerIdentity;
use jitsuin_core::{
    document_hash, financier_commitment, nullifier, settled_tag, sign_invoice, Invoice,
};

/// The "Test vectors" section of the specification.
fn spec() -> String {
    let all = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/zip-shielded-receivable-registry.md"
    ))
    .expect("the specification is in docs/");
    let start = all.find("## Test vectors").expect("a Test vectors section");
    let end = all[start..]
        .find("\n## Reference")
        .map_or(all.len(), |e| start + e);
    all[start..end].to_string()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The value after `name =` in the test-vector block.
fn value(spec: &str, name: &str) -> String {
    spec.lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix(name)?
                .trim()
                .strip_prefix('=')
                .map(|v| v.trim().to_string())
        })
        .unwrap_or_else(|| panic!("no `{name} =` line in the specification"))
}

/// The output column of the table row whose input contains `input`.
fn row(spec: &str, input: &str) -> String {
    spec.lines()
        .filter(|l| l.starts_with('|') && l.contains(input))
        .find_map(|l| {
            l.split('|')
                .nth(2)
                .map(|c| c.trim().trim_matches('`').to_string())
        })
        .unwrap_or_else(|| panic!("no vector row for {input}"))
}

#[test]
fn the_specification_vectors_hold() {
    let s = spec();
    let supplier = SigningKey::from_bytes(&[1; 32]);
    let buyer = SigningKey::from_bytes(&[2; 32]);
    let inv = Invoice {
        invoice_id: "TES-INV-0001".into(),
        supplier_ephemeral_pk: supplier.verifying_key().to_bytes(),
        buyer_pk: buyer.verifying_key().to_bytes(),
        amount_zat: 1_000_000_000,
        issue_date: 20_377,
        due_date: 20_437,
        terms_hash: [9; 32],
    };
    assert_eq!(
        hex(&inv.to_canonical_bytes().unwrap()),
        value(&s, "canonical")
    );
    assert_eq!(
        hex(&sign_invoice(&buyer, &inv).unwrap().to_bytes()),
        value(&s, "sig_buyer")
    );
    assert_eq!(hex(&nullifier(&inv).unwrap()), value(&s, "N"));

    assert_eq!(
        hex(&document_hash(b"TES-terms")),
        row(&s, "SHA-256(\"TES-terms\")")
    );
    assert_eq!(
        hex(&financier_commitment(&[3; 32], &[4; 32])),
        row(&s, "financier_commitment(")
    );
    assert_eq!(hex(&settled_tag(&[7; 32])), row(&s, "settled_tag("));
    let id = BuyerIdentity::from_master_secret([0x42; 32]);
    assert_eq!(
        hex(&id.invoice_key(0).to_bytes()),
        row(&s, "buyer invoice seed")
    );
}
