//! Fuzz of the browser's invoice entry points (HNK-30.T1, AC-HNK-30.1, W-16): the JSON the app
//! encodes and the base64url it passes around. Every textual variant of one invoice must encode to
//! the same canonical bytes (same N) or be refused; none may yield other bytes.

use ed25519_dalek::SigningKey;
use jitsuin_wasm::api::{invoice_encode, invoice_nullifier};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

struct Keys {
    sup: String,
    buy: String,
    terms: String,
}

fn keys() -> Keys {
    Keys {
        sup: hex(&SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes()),
        buy: hex(&SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes()),
        terms: hex(&[9; 32]),
    }
}

fn json(
    id: &str,
    sup: &str,
    buy: &str,
    amount: &str,
    terms: &str,
    sep: &str,
    reverse: bool,
) -> String {
    let mut f = [
        format!("\"invoice_id\":{sep}\"{id}\""),
        format!("\"supplier_pk\":{sep}\"{sup}\""),
        format!("\"buyer_pk\":{sep}\"{buy}\""),
        format!("\"amount_zat\":{sep}{amount}"),
        format!("\"issue_date\":{sep}20377"),
        format!("\"due_date\":{sep}20467"),
        format!("\"terms_hash\":{sep}\"{terms}\""),
    ];
    if reverse {
        f.reverse();
    }
    format!("{{{sep}{}{sep}}}", f.join(&format!(",{sep}")))
}

#[test]
fn textual_variants_encode_to_one_canonical_invoice_or_fail() {
    let k = keys();
    let base = invoice_encode(&json(
        "TES-INV-0417",
        &k.sup,
        &k.buy,
        "1250000000",
        &k.terms,
        "",
        false,
    ))
    .unwrap();
    let n0 = invoice_nullifier(&base).unwrap();
    let mut variants = Vec::new();
    for sep in ["", " ", "\n", "\t", "  \r\n"] {
        for reverse in [false, true] {
            variants.push(json(
                "TES-INV-0417",
                &k.sup,
                &k.buy,
                "1250000000",
                &k.terms,
                sep,
                reverse,
            ));
            variants.push(json(
                "TES-INV-0417",
                &k.sup.to_uppercase(),
                &k.buy,
                "1250000000",
                &k.terms,
                sep,
                reverse,
            ));
            variants.push(json(
                "TES-INV-0417",
                &k.sup,
                &k.buy,
                "1250000000",
                &k.terms.to_uppercase(),
                sep,
                reverse,
            ));
            for amount in [
                "1.25e9",
                "1250000000.0",
                "01250000000",
                "+1250000000",
                "1250000000e0",
                "\"1250000000\"",
            ] {
                variants.push(json(
                    "TES-INV-0417",
                    &k.sup,
                    &k.buy,
                    amount,
                    &k.terms,
                    sep,
                    reverse,
                ));
            }
            for sup in [
                format!("0x{}", k.sup),
                format!(" {}", k.sup),
                k.sup[..62].to_string(),
            ] {
                variants.push(json(
                    "TES-INV-0417",
                    &sup,
                    &k.buy,
                    "1250000000",
                    &k.terms,
                    sep,
                    reverse,
                ));
            }
            for id in [
                "TES-INV-0417 ",
                "tes-inv-0417",
                "TES\u{2011}INV-0417",
                "TES-INV-0417\u{200b}",
            ] {
                variants.push(json(
                    id,
                    &k.sup,
                    &k.buy,
                    "1250000000",
                    &k.terms,
                    sep,
                    reverse,
                ));
            }
        }
    }
    let plain = json(
        "TES-INV-0417",
        &k.sup,
        &k.buy,
        "1250000000",
        &k.terms,
        "",
        false,
    );
    variants.push(format!("{{\"invoice_id\":\"TES-INV-9999\",{}", &plain[1..]));
    variants.push(format!("{},\"extra\":1}}", &plain[..plain.len() - 1]));
    let (mut same, mut other, mut refused) = (0, 0, 0);
    for text in &variants {
        match invoice_encode(text) {
            Ok(b) if b == base => same += 1,
            // another canonical invoice is fine only when a signed field really changed (the id);
            // the buyer signature then fails (tested in jitsuin-core canonical_fuzz)
            Ok(b) => {
                let n = invoice_nullifier(&b).unwrap();
                assert_ne!(n, n0);
                assert!(
                    text.contains("tes-inv")
                        || text.contains("TES-INV-0417 ")
                        || text.contains("9999"),
                    "unexpected new bytes from {text}"
                );
                other += 1;
            }
            Err(_) => refused += 1,
        }
    }
    println!("{} JSON variants: {same} same canonical bytes, {other} a really different id, {refused} refused", variants.len());

    let mut b64_same = 0;
    for v in [
        format!("{base}="),
        format!("{base}=="),
        base.replace('-', "+").replace('_', "/"),
        format!(" {base}\n"),
        format!("{base}A"),
    ] {
        if let Ok(n) = invoice_nullifier(&v) {
            assert_eq!(n, n0, "base64 variant {v:?} gave another N");
            b64_same += 1;
        }
    }
    println!("base64 variants decoding to the same N: {b64_same}, the rest refused");
}
