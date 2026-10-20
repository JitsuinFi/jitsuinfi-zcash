//! Native tests of the browser API: known vectors, and the same results as the Rust flows.

use ed25519_dalek::SigningKey;
use jitsuin_core::{
    Assignment, BoardEntry, Bundle, BuyerIdentity, EntryKind, HistoryCert, Invoice, SettledEntry,
    SettlementDoc, SETTLED_ON_TIME,
};
use serde_json::Value;

use crate::api::{self, b64, hex};

const MASTER: &str = "4242424242424242424242424242424242424242424242424242424242424242";

fn key(b: u8) -> SigningKey {
    SigningKey::from_bytes(&[b; 32])
}

fn parse(s: &str) -> Value {
    serde_json::from_str(s).unwrap()
}

/// Invoice addressed to the buyer key at index 0 of `MASTER`, supplier key 0x01.
fn invoice_b64() -> String {
    let buyer = BuyerIdentity::from_master_secret([0x42; 32]).invoice_key(0);
    api::invoice_encode(
        &serde_json::json!({
            "invoice_id": "TES-INV-0005",
            "supplier_pk": hex(&key(1).verifying_key().to_bytes()),
            "buyer_pk": hex(&buyer.verifying_key().to_bytes()),
            "amount_zat": 40_000u64,
            "issue_date": 20_000u32,
            "due_date": 20_030u32,
            "terms_hash": api::document_hash(b"TES-terms"),
        })
        .to_string(),
    )
    .unwrap()
}

fn invoice() -> Invoice {
    Invoice::from_canonical_bytes(&base64_decode(&invoice_b64())).unwrap()
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .unwrap()
}

fn letter() -> Assignment {
    Assignment::for_invoice(
        &invoice(),
        key(3).verifying_key().to_bytes(),
        "utest1financier",
        [5; 32],
    )
    .unwrap()
}

#[test]
fn vectors_match_the_rust_core() {
    // HNK-01 test vector invoice → N vector from Format Data
    let inv = api::invoice_encode(
        &serde_json::json!({
            "invoice_id": "TES-INV-0001",
            "supplier_pk": hex(&key(1).verifying_key().to_bytes()),
            "buyer_pk": hex(&key(2).verifying_key().to_bytes()),
            "amount_zat": 1_000_000_000u64,
            "issue_date": 20_377u32,
            "due_date": 20_437u32,
            "terms_hash": "09".repeat(32),
        })
        .to_string(),
    )
    .unwrap();
    assert_eq!(
        api::invoice_nullifier(&inv).unwrap(),
        "3513c284b075c8efbd27da2de1ad9eb673bcbb8c45ae087a9a594c35c8064a6e"
    );
    assert_eq!(
        api::document_hash(b"TES-terms"),
        "00082d1119307d17036738bf382daab1bfe963280b44b7dc050f5ad30542b229"
    );
    // key derivation vector: invoice seed for master 0x42, index 0
    let seed = [
        0xb4, 0x67, 0xd3, 0x9a, 0xcc, 0x92, 0x4e, 0xdc, 0x21, 0xc6, 0x31, 0xf7, 0x7e, 0x1f, 0x1a,
        0x67, 0x81, 0xdb, 0xd2, 0x54, 0xef, 0xa0, 0xcc, 0x34, 0x4a, 0xb1, 0xc7, 0xbe, 0xaf, 0x34,
        0xac, 0x98,
    ];
    let keys = parse(&api::buyer_keys(MASTER, 0).unwrap());
    assert_eq!(
        keys["invoice_pk"],
        hex(&SigningKey::from_bytes(&seed).verifying_key().to_bytes())
    );
}

#[test]
fn buyer_screens_produce_what_the_rust_flow_produces() {
    let inv_b64 = invoice_b64();
    // invoice signature verifies with the invoice's buyer key
    let sig = api::buyer_sign_invoice(MASTER, 0, &inv_b64).unwrap();
    assert_eq!(sig.len(), 128);
    // wrong index → refused (the key does not match the invoice)
    assert!(api::buyer_sign_invoice(MASTER, 1, &inv_b64).is_err());

    // letter: supplier seals, then the buyer
    let a_b64 = b64(&letter().to_canonical_bytes().unwrap());
    let s0 = api::supplier_seal_assignment(&"01".repeat(32), &inv_b64, &a_b64).unwrap();
    // the buyer refuses a letter that the supplier has not sealed yet
    assert!(api::buyer_seal_assignment(MASTER, 0, &inv_b64, &a_b64, "").is_err());
    let s1 = api::buyer_seal_assignment(MASTER, 0, &inv_b64, &a_b64, &s0).unwrap();
    let seals: Vec<jitsuin_core::Seal> = [s0, s1]
        .iter()
        .map(|s| jitsuin_core::Seal::from_bytes(&base64_decode(s)).unwrap())
        .collect();
    assert_eq!(
        letter().verify(&invoice(), &seals).unwrap(),
        jitsuin_core::ChainStatus::Incomplete {
            next: jitsuin_core::Role::Financier
        }
    );

    // repayment QR: same URI as jitsuin-flow builds natively
    let r = parse(&api::buyer_repayment(MASTER, 0, &inv_b64, &a_b64, 20_029).unwrap());
    let buyer = BuyerIdentity::from_master_secret([0x42; 32]).invoice_key(0);
    let native = jitsuin_flow::buyer::repayment_request(&buyer, &letter(), 20_029).unwrap();
    assert_eq!(r["uri"], native.uri);
    assert!(r["qr_svg"].as_str().unwrap().contains("<svg"));
}

#[test]
fn bundle_and_board_checks_in_the_browser() {
    let inv = invoice();
    let a = letter();
    let buyer = BuyerIdentity::from_master_secret([0x42; 32]).invoice_key(0);
    let mut seals = Vec::new();
    for k in [key(1), buyer.clone(), key(3)] {
        let s = a.seal_next(&k, &seals).unwrap();
        seals.push(s);
    }
    let bundle = Bundle {
        invoice: inv.clone(),
        buyer_signature: jitsuin_core::sign_invoice(&buyer, &inv).unwrap().to_bytes(),
        assignment: Some(a.clone()),
        assignment_seals: seals,
        settlement: Some(SettlementDoc::for_assignment(&a)),
    };
    let bundle_b64 = b64(&bundle.to_bytes().unwrap());
    let v = parse(&api::verify_bundle(&bundle_b64).unwrap());
    assert_eq!(v["assignment"], "Sealed");

    // board as the backend serves it: one register entry and one settled entry
    let n = jitsuin_core::nullifier(&inv).unwrap();
    let register = BoardEntry::sign(&key(1), EntryKind::Register, n, [0xBB; 32], 0, 0);
    let doc = SettlementDoc::for_assignment(&a);
    let settled = SettledEntry::countersign(
        &doc,
        &doc.buyer_seal(&buyer),
        &inv.buyer_pk,
        &key(3),
        SETTLED_ON_TIME,
    )
    .unwrap();
    let board = serde_json::json!([
        { "txid": "aa".repeat(32), "height": 10, "tx_index": 0, "output_index": 1,
          "memo": b64(&register.to_memo_bytes()) },
        { "txid": "bb".repeat(32), "height": 12, "tx_index": 0, "output_index": 0,
          "memo": b64(&settled.to_memo_bytes()) },
        { "txid": "cc".repeat(32), "height": 13, "tx_index": 0, "output_index": 0,
          "memo": b64(&[0xFF, 1, 2, 3]) },
    ])
    .to_string();
    let on = parse(&api::bundle_on_board(&bundle_b64, &board).unwrap());
    assert_eq!(on["register"]["status"], "Registered");
    assert_eq!(on["settled"]["on_time"], true);

    // a tampered bundle is rejected before looking at the board
    let mut forged = bundle;
    forged.invoice.amount_zat += 1;
    let forged_b64 = b64(&forged.to_bytes().unwrap());
    assert!(api::bundle_on_board(&forged_b64, &board).is_err());
}

#[test]
fn history_and_proofs_in_the_browser() {
    let id = BuyerIdentity::from_master_secret([0x42; 32]);
    let inv = invoice();
    let inv_b64 = invoice_b64();
    let fin_pk = hex(&key(3).verifying_key().to_bytes());
    let c0_b64 = api::buyer_history_cert(MASTER, 0, &inv_b64, &fin_pk, "").unwrap();
    let c0 = HistoryCert::from_bytes(&base64_decode(&c0_b64)).unwrap();
    let entry = BoardEntry::sign_with_history(&key(1), c0.nullifier, [0xBB; 32], 0, 0, c0.tag());
    let board = serde_json::json!([
        { "txid": "aa".repeat(32), "height": 10, "tx_index": 0, "output_index": 0,
          "memo": b64(&entry.to_memo_bytes()) },
    ])
    .to_string();
    let id_pk = hex(&id.identity_key().verifying_key().to_bytes());
    let allow = serde_json::json!([fin_pk]).to_string();
    let certs = serde_json::json!([c0_b64]).to_string();
    // before the due date: open; after due + grace: default
    let open = parse(&api::verify_history(&certs, &id_pk, &allow, &board, 20_010, 7).unwrap());
    assert_eq!(open["lines"][0]["outcome"], "Open");
    let late = parse(&api::verify_history(&certs, &id_pk, &allow, &board, 20_040, 7).unwrap());
    assert_eq!(late["defaults"], 1);
    // the next index comes from the anchored chain (P-09): 1 after certificate 0
    let next = parse(&api::history_next(&certs, &id_pk, &board).unwrap());
    assert_eq!(
        (
            next["next_index"].clone(),
            next["successor_on_board"].clone()
        ),
        (serde_json::json!(1), serde_json::json!(false))
    );
    // a device without certificate 0 sees its successor tag taken on the board
    let lost = parse(&api::history_next("[]", &id_pk, &board).unwrap());
    assert_eq!(
        (
            lost["next_index"].clone(),
            lost["successor_on_board"].clone()
        ),
        (serde_json::json!(0), serde_json::json!(true))
    );
    // certificate 0 not on this board: dropped, index 0 reused
    let none = parse(&api::history_next(&certs, &id_pk, "[]").unwrap());
    assert_eq!(
        (none["next_index"].clone(), none["dropped"].clone()),
        (serde_json::json!(0), serde_json::json!([0]))
    );
    // hiding certificate 0 is detected
    assert!(api::verify_history("[]", &id_pk, &allow, &board, 20_040, 7)
        .unwrap_err()
        .contains("did not disclose"));

    // double-signature proof
    let n = jitsuin_core::nullifier(&inv).unwrap();
    let buyer = id.invoice_key(0);
    let proof = jitsuin_core::DoubleSignProof {
        invoice: inv.clone(),
        buyer_signature: jitsuin_core::sign_invoice(&buyer, &inv).unwrap().to_bytes(),
        first: BoardEntry::sign(&key(1), EntryKind::Register, n, [0xA1; 32], 0, 0),
        second: BoardEntry::sign(&key(1), EntryKind::Register, n, [0xB2; 32], 0, 0),
        first_at: None,
        second_at: None,
    };
    let p = parse(&api::verify_proof(&b64(&proof.to_bytes().unwrap())).unwrap());
    assert_eq!(p["second_commitment"], "b2".repeat(32));
}

#[test]
fn screen_helpers_build_a_verifiable_bundle() {
    let inv_b64 = invoice_b64();
    assert_eq!(
        api::public_key(&"01".repeat(32)).unwrap(),
        hex(&key(1).verifying_key().to_bytes())
    );
    let fields = parse(&api::invoice_decode(&inv_b64).unwrap());
    assert_eq!(fields["invoice_id"], "TES-INV-0005");
    let fin_pk = hex(&key(3).verifying_key().to_bytes());
    let a_b64 =
        api::assignment_encode(&inv_b64, &fin_pk, "utest1financier", &"05".repeat(32)).unwrap();
    let s0 = api::supplier_seal_assignment(&"01".repeat(32), &inv_b64, &a_b64).unwrap();
    let s1 = api::buyer_seal_assignment(MASTER, 0, &inv_b64, &a_b64, &s0).unwrap();
    let sig = api::buyer_sign_invoice(MASTER, 0, &inv_b64).unwrap();
    let bundle = api::bundle_build(
        &serde_json::json!({ "invoice": inv_b64, "buyer_signature": sig, "assignment": a_b64,
                             "seals": [s0, s1], "with_settlement": true })
        .to_string(),
    )
    .unwrap();
    let v = parse(&api::verify_bundle(&bundle).unwrap());
    assert_eq!(v["assignment"], "AwaitingSeal:Financier");
    // a bundle with a forged signature is refused at build time
    assert!(api::bundle_build(
        &serde_json::json!({ "invoice": inv_b64, "buyer_signature": "00".repeat(64) }).to_string()
    )
    .is_err());
}

#[test]
fn outsiders_only_see_hashes() {
    let n = jitsuin_core::nullifier(&invoice()).unwrap();
    let e = BoardEntry::sign(&key(1), EntryKind::Register, n, [0xBB; 32], 2, 3);
    let d = parse(&api::board_memo_describe(&b64(&e.to_memo_bytes())).unwrap());
    assert_eq!(d["kind"], "Register");
    assert_eq!(d["nullifier"], hex(&n));
    assert!(api::board_memo_describe(&b64(&[0xFF, 1, 2])).is_err());
}

#[test]
fn the_seal_chain_closes_with_the_financier_and_breaks_on_a_changed_amount() {
    let inv_b64 = invoice_b64();
    let a_b64 = b64(&letter().to_canonical_bytes().unwrap());
    let s0 = api::supplier_seal_assignment(&"01".repeat(32), &inv_b64, &a_b64).unwrap();
    let s1 = api::buyer_seal_assignment(MASTER, 0, &inv_b64, &a_b64, &s0).unwrap();
    let two = serde_json::json!([s0, s1]).to_string();
    assert_eq!(
        api::assignment_status(&inv_b64, &a_b64, &serde_json::json!([s0]).to_string()).unwrap(),
        "AwaitingSeal:Buyer"
    );
    assert_eq!(
        api::assignment_status(&inv_b64, &a_b64, &two).unwrap(),
        "AwaitingSeal:Financier"
    );
    // the financier's seal needs the financier's key, and the two seals before it
    assert!(api::financier_seal_assignment(&"02".repeat(32), &inv_b64, &a_b64, &two).is_err());
    assert!(api::financier_seal_assignment(
        &"03".repeat(32),
        &inv_b64,
        &a_b64,
        &serde_json::json!([s0]).to_string()
    )
    .is_err());
    let s2 = api::financier_seal_assignment(&"03".repeat(32), &inv_b64, &a_b64, &two).unwrap();
    let three = serde_json::json!([s0, s1, s2]).to_string();
    assert_eq!(
        api::assignment_status(&inv_b64, &a_b64, &three).unwrap(),
        "Sealed"
    );
    // one zat more on the invoice: the letter and its seals no longer match
    let mut j = parse(&api::invoice_decode(&inv_b64).unwrap());
    j["amount_zat"] = serde_json::json!(40_001u64);
    let changed = api::invoice_encode(&j.to_string()).unwrap();
    assert!(api::assignment_status(&changed, &a_b64, &three).is_err());
}

#[test]
fn two_register_entries_for_two_financiers_make_a_verifiable_proof() {
    let inv_b64 = invoice_b64();
    let fin_a = hex(&key(3).verifying_key().to_bytes());
    let fin_b = hex(&key(4).verifying_key().to_bytes());
    let a = parse(
        &api::supplier_register_entry(
            &"01".repeat(32),
            &inv_b64,
            &fin_a,
            &"0a".repeat(32),
            None,
            None,
        )
        .unwrap(),
    );
    let b = parse(
        &api::supplier_register_entry(
            &"01".repeat(32),
            &inv_b64,
            &fin_b,
            &"0b".repeat(32),
            Some(2),
            Some(3),
        )
        .unwrap(),
    );
    // only the invoice's supplier key may register it
    assert!(api::supplier_register_entry(
        &"02".repeat(32),
        &inv_b64,
        &fin_a,
        &"0a".repeat(32),
        None,
        None
    )
    .is_err());
    // the board reads N and the commitment from each memo
    let da = parse(&api::board_memo_describe(a["memo"].as_str().unwrap()).unwrap());
    let db = parse(&api::board_memo_describe(b["memo"].as_str().unwrap()).unwrap());
    // classes: omitted = 0/0, given = signed into the entry; half or unknown classes refused
    let ea = jitsuin_core::BoardEntry::from_memo_bytes(&base64_decode(a["memo"].as_str().unwrap()))
        .unwrap();
    assert_eq!((ea.discount_bucket, ea.tenor_bucket), (0, 0));
    let eb = jitsuin_core::BoardEntry::from_memo_bytes(&base64_decode(b["memo"].as_str().unwrap()))
        .unwrap();
    assert_eq!((eb.discount_bucket, eb.tenor_bucket), (2, 3));
    for (d, t) in [(Some(2), None), (Some(99), Some(3))] {
        assert!(api::supplier_register_entry(
            &"01".repeat(32),
            &inv_b64,
            &fin_a,
            &"0a".repeat(32),
            d,
            t
        )
        .is_err());
    }
    assert_eq!(da["nullifier"], db["nullifier"]);
    assert_ne!(da["financier_commitment"], db["financier_commitment"]);
    let sig = api::buyer_sign_invoice(MASTER, 0, &inv_b64).unwrap();
    let proof = api::double_sign_proof(
        &inv_b64,
        &sig,
        a["memo"].as_str().unwrap(),
        b["memo"].as_str().unwrap(),
        None,
        None,
    )
    .unwrap();
    let r = parse(&api::verify_proof(&proof).unwrap());
    assert_eq!(r["first_commitment"], a["commitment"]);
    assert_eq!(r["second_commitment"], b["commitment"]);
    // the same entry twice proves nothing
    assert!(api::double_sign_proof(
        &inv_b64,
        &sig,
        a["memo"].as_str().unwrap(),
        a["memo"].as_str().unwrap(),
        None,
        None,
    )
    .is_err());
    // with board positions the proof passes the board check that `jitsuin verify` runs
    let at = |txid: &str, height: u32| {
        format!(r#"{{"txid":"{txid}","height":{height},"tx_index":1,"output_index":0}}"#)
    };
    let (ta, tb) = ("aa".repeat(32), "bb".repeat(32));
    let positioned = api::double_sign_proof(
        &inv_b64,
        &sig,
        a["memo"].as_str().unwrap(),
        b["memo"].as_str().unwrap(),
        Some(&at(&ta, 10)),
        Some(&at(&tb, 12)),
    )
    .unwrap();
    let p = jitsuin_core::DoubleSignProof::from_bytes(&base64_decode(&positioned)).unwrap();
    let rec = |txid: &str, height: u32, memo: &str| jitsuin_board::BoardRecord {
        txid: txid.into(),
        position: jitsuin_board::Position {
            height,
            tx_index: 1,
            output_index: 0,
        },
        entry: jitsuin_core::BoardEntry::from_memo_bytes(&base64_decode(memo)).unwrap(),
    };
    let board = [
        rec(&ta, 10, a["memo"].as_str().unwrap()),
        rec(&tb, 12, b["memo"].as_str().unwrap()),
    ];
    assert!(jitsuin_board::verify_proof_on_board(&p, &board));
    let r = parse(&api::verify_proof(&positioned).unwrap());
    assert_eq!(r["first_at"]["height"], 10);
    assert_eq!(
        (
            r["first_at"]["tx_index"].clone(),
            r["first_at"]["output_index"].clone()
        ),
        (serde_json::json!(1), serde_json::json!(0))
    );
    // without the first position the board check fails, as in `jitsuin verify`
    let unpositioned = jitsuin_core::DoubleSignProof::from_bytes(&base64_decode(&proof)).unwrap();
    assert!(!jitsuin_board::verify_proof_on_board(&unpositioned, &board));
    // positions in the wrong order, or a bad txid, are refused
    for (fa, fb) in [(at(&ta, 12), at(&tb, 10)), (at("zz", 10), at(&tb, 12))] {
        assert!(api::double_sign_proof(
            &inv_b64,
            &sig,
            a["memo"].as_str().unwrap(),
            b["memo"].as_str().unwrap(),
            Some(&fa),
            Some(&fb),
        )
        .is_err());
    }
}

#[test]
fn assignment_decode_shows_what_is_sealed() {
    let inv_b64 = invoice_b64();
    let fin = hex(&key(3).verifying_key().to_bytes());
    let terms = api::document_hash(b"TES-letter");
    let a_b64 = api::assignment_encode(&inv_b64, &fin, "utest1financier", &terms).unwrap();
    let d = parse(&api::assignment_decode(&a_b64, &inv_b64).unwrap());
    let inv = invoice();
    assert_eq!(d["nullifier"], hex(&jitsuin_core::nullifier(&inv).unwrap()));
    assert_eq!(d["amount_zat"], inv.amount_zat);
    assert_eq!(d["due_date"], inv.due_date);
    assert_eq!(d["financier_pk"], fin);
    assert_eq!(d["financier_address"], "utest1financier");
    assert_eq!(d["terms_hash"], terms);
    assert_eq!(d["matches_invoice"], true);
    // without an invoice nothing is claimed about the match
    assert!(parse(&api::assignment_decode(&a_b64, "").unwrap())["matches_invoice"].is_null());
    // a letter for another invoice is flagged
    let mut j = parse(&api::invoice_decode(&inv_b64).unwrap());
    j["supplier_pk"] = Value::String(fin.clone());
    j["amount_zat"] = Value::from(40_001u64);
    let other = api::invoice_encode(&j.to_string()).unwrap();
    assert_eq!(
        parse(&api::assignment_decode(&a_b64, &other).unwrap())["matches_invoice"],
        false
    );
    assert!(api::assignment_decode("not-a-letter", "").is_err());
}

#[test]
fn financier_commitment_is_derived_and_matches_the_supplier_entry() {
    let inv_b64 = invoice_b64();
    let secret = "03".repeat(32);
    let o = parse(&api::financier_commitment(&secret, &inv_b64).unwrap());
    // asking again (a retry after a crash) gives the same opening
    assert_eq!(
        parse(&api::financier_commitment(&secret, &inv_b64).unwrap()),
        o
    );
    let n = jitsuin_core::nullifier(&invoice()).unwrap();
    let (salt, c) = jitsuin_core::commitment_opening(&key(3), &n);
    assert_eq!(o["salt"], hex(&salt));
    assert_eq!(o["commitment"], hex(&c));
    // the supplier signs an entry for exactly that commitment from the opening
    let fin = hex(&key(3).verifying_key().to_bytes());
    let e = parse(
        &api::supplier_register_entry(
            &"01".repeat(32),
            &inv_b64,
            &fin,
            o["salt"].as_str().unwrap(),
            None,
            None,
        )
        .unwrap(),
    );
    assert_eq!(e["commitment"], o["commitment"]);
}

/// Invoice `index` of `MASTER`'s buyer, supplier key 0x01, due `due`.
fn history_invoice(index: u32, due: u32) -> String {
    let buyer = BuyerIdentity::from_master_secret([0x42; 32]).invoice_key(index);
    api::invoice_encode(
        &serde_json::json!({
            "invoice_id": format!("TES-INV-H{index}"),
            "supplier_pk": hex(&key(1).verifying_key().to_bytes()),
            "buyer_pk": hex(&buyer.verifying_key().to_bytes()),
            "amount_zat": 30_000u64 + u64::from(index),
            "issue_date": due - 60,
            "due_date": due,
            "terms_hash": api::document_hash(b"TES-terms"),
        })
        .to_string(),
    )
    .unwrap()
}

#[test]
fn a_repaid_history_verifies_and_a_hidden_invoice_is_caught() {
    let fin_pk = hex(&key(3).verifying_key().to_bytes());
    let fin_sk = "03".repeat(32);
    let terms = api::document_hash(b"TES-assignment");
    let mut certs: Vec<String> = Vec::new();
    let mut board = Vec::new();
    // invoice 0 is repaid on its due date, invoice 1 three days late
    for (i, (due, paid)) in [(20_000u32, 20_000u32), (20_030, 20_033)]
        .into_iter()
        .enumerate()
    {
        let i = i as u32;
        let inv = history_invoice(i, due);
        let prev = certs.last().cloned().unwrap_or_default();
        let cert = api::buyer_history_cert(MASTER, i, &inv, &fin_pk, &prev).unwrap();
        let reg = parse(
            &api::supplier_register_history_entry(
                &"01".repeat(32),
                &inv,
                &fin_pk,
                &"0a".repeat(32),
                &cert,
                Some(2),
                Some(3),
            )
            .unwrap(),
        );
        // the tag-only variant signs the same entry without certificate k
        let tag = jitsuin_core::HistoryCert::from_bytes(&base64_decode(&cert))
            .unwrap()
            .tag();
        let tagged = parse(
            &api::supplier_register_tagged_entry(
                &"01".repeat(32),
                &inv,
                &fin_pk,
                &"0a".repeat(32),
                &hex(&tag),
                Some(2),
                Some(3),
            )
            .unwrap(),
        );
        assert_eq!(tagged, reg);
        let letter = api::assignment_encode(&inv, &fin_pk, "utest1financier", &terms).unwrap();
        let pay = parse(&api::buyer_repayment(MASTER, i, &inv, &letter, paid).unwrap());
        let settled = parse(
            &api::financier_settle(&fin_sk, &inv, &letter, pay["memo"].as_str().unwrap()).unwrap(),
        );
        assert_eq!(settled["on_time"], paid <= due);
        // the settlement belongs to its financier only
        assert!(api::financier_settle(
            &"04".repeat(32),
            &inv,
            &letter,
            pay["memo"].as_str().unwrap()
        )
        .is_err());
        for (k, memo) in [
            reg["memo"].as_str().unwrap(),
            settled["memo"].as_str().unwrap(),
        ]
        .into_iter()
        .enumerate()
        {
            board.push(serde_json::json!({ "txid": format!("{i}{k}").repeat(32), "height": 10 + 2 * i + k as u32,
                "tx_index": 0, "output_index": 0, "memo": memo }));
        }
        certs.push(cert);
    }
    let board = serde_json::Value::Array(board).to_string();
    let id_pk = hex(&BuyerIdentity::from_master_secret([0x42; 32])
        .identity_key()
        .verifying_key()
        .to_bytes());
    let allow = serde_json::json!([fin_pk]).to_string();
    let all = serde_json::json!(certs).to_string();
    let r = parse(&api::verify_history(&all, &id_pk, &allow, &board, 20_100, 7).unwrap());
    assert_eq!(
        (
            r["on_time"].as_u64(),
            r["late"].as_u64(),
            r["defaults"].as_u64()
        ),
        (Some(1), Some(1), Some(0))
    );
    assert_eq!(r["lines"][1]["outcome"], "PaidLate");
    // leaving out the late invoice, or the first one, is caught
    let first_only = serde_json::json!([certs[0]]).to_string();
    assert!(api::verify_history(&first_only, &id_pk, &allow, &board, 20_100, 7).is_err());
    let second_only = serde_json::json!([certs[1]]).to_string();
    assert!(api::verify_history(&second_only, &id_pk, &allow, &board, 20_100, 7).is_err());
}

#[test]
fn byte_secrets_are_zeroed_after_use() {
    let inv_b64 = invoice_b64();
    let mut master = [0x42u8; 32];
    let sig = api::with_secret(&mut master, |m| api::buyer_sign_invoice(m, 0, &inv_b64)).unwrap();
    // same signature as the hex API, and the caller's bytes are zero afterwards
    assert_eq!(sig, api::buyer_sign_invoice(MASTER, 0, &inv_b64).unwrap());
    assert_eq!(master, [0u8; 32]);
    // a wrong length is refused and still wiped
    let mut short = [7u8; 16];
    assert!(api::with_secret(&mut short, |m| api::buyer_keys(m, 0)).is_err());
    assert_eq!(short, [0u8; 16]);
    // an error inside the call still leaves the secret wiped
    let mut supplier = [0x02u8; 32];
    let fin = hex(&key(3).verifying_key().to_bytes());
    let r = api::with_secret(&mut supplier, |k| {
        api::supplier_register_entry(k, &inv_b64, &fin, &"0a".repeat(32), None, None)
    });
    assert!(r.is_err()); // 0x02 is not the invoice's supplier key
    assert_eq!(supplier, [0u8; 32]);
}

#[test]
fn supplier_master_keys_and_storage_keys() {
    let master = "11".repeat(32);
    let buyer = "22".repeat(32);
    let secret = api::supplier_invoice_secret(&master, "TES-INV-0001", &buyer).unwrap();
    // same vector as jitsuin-core keys.rs (cross-checked with Python hashlib)
    assert_eq!(
        hex(&secret),
        "bb1354a579aa2d4b4335ff9e5cc9f841692839b1903e52d279ef282730f91051"
    );
    let pk = api::supplier_invoice_public_key(&master, "TES-INV-0001", &buyer).unwrap();
    assert_eq!(api::public_key(&hex(&secret)).unwrap(), pk);
    // another buyer key, another supplier key
    let other =
        api::supplier_invoice_public_key(&master, "TES-INV-0001", &"23".repeat(32)).unwrap();
    assert_ne!(other, pk);
    let s = api::storage_keys(&master).unwrap();
    assert_eq!(s.len(), 64);
    assert_eq!(
        hex(&s[..32]),
        "1d2dff152b74df11c200d74ec263ab5f7e03ad2dc508a9024f0bee2eeb095f2f"
    );
    // the byte path wipes the master
    let mut m = [0x11u8; 32];
    let viaby = api::with_secret(&mut m, api::storage_keys).unwrap();
    assert_eq!(viaby, s);
    assert_eq!(m, [0u8; 32]);
}

#[test]
fn proofs_and_the_rate_index_are_checked_against_board_data_as_in_the_cli() {
    use serde_json::json;
    let inv_b64 = invoice_b64();
    let entry = |fin: u8, salt: &str, d: Option<u8>, t: Option<u8>| {
        let fin = hex(&key(fin).verifying_key().to_bytes());
        parse(&api::supplier_register_entry(&"01".repeat(32), &inv_b64, &fin, salt, d, t).unwrap())
    };
    let a = entry(3, &"0a".repeat(32), Some(2), Some(3));
    let b = entry(4, &"0b".repeat(32), None, None);
    let (ma, mb) = (a["memo"].as_str().unwrap(), b["memo"].as_str().unwrap());
    let sig = api::buyer_sign_invoice(MASTER, 0, &inv_b64).unwrap();
    let (ta, tb) = ("aa".repeat(32), "bb".repeat(32));
    let at = |txid: &str, height: u32| {
        format!(r#"{{"txid":"{txid}","height":{height},"tx_index":1,"output_index":0}}"#)
    };
    let item = |txid: &str, height: u32, memo: &str| {
        format!(
            r#"{{"txid":"{txid}","height":{height},"tx_index":1,"output_index":0,"memo":"{memo}"}}"#
        )
    };
    let board = format!("[{},{}]", item(&ta, 10, ma), item(&tb, 12, mb));
    let only_first = format!("[{}]", item(&ta, 10, ma));

    // positions on the board: the proof holds
    let positioned = api::double_sign_proof(
        &inv_b64,
        &sig,
        ma,
        mb,
        Some(&at(&ta, 10)),
        Some(&at(&tb, 12)),
    )
    .unwrap();
    let r = parse(&api::verify_proof_on_board(&positioned, &board).unwrap());
    assert_eq!(r["holds"], true);
    assert_eq!(r["signatures"]["ok"], true);
    assert_eq!(
        (
            r["first"]["on_board"].clone(),
            r["second"]["on_board"].clone(),
            r["ordered"].clone()
        ),
        (json!(true), json!(true), json!(true))
    );
    assert_eq!(r["first"]["claimed_at"]["height"], 10);

    // the second entry claimed on chain but missing from this board: fails, and says which
    let r = parse(&api::verify_proof_on_board(&positioned, &only_first).unwrap());
    assert_eq!(r["holds"], false);
    assert_eq!(r["first"]["on_board"], true);
    assert_eq!(r["second"]["on_board"], false);

    // second entry offered off-chain (no position): still holds
    let offchain =
        api::double_sign_proof(&inv_b64, &sig, ma, mb, Some(&at(&ta, 10)), None).unwrap();
    let r = parse(&api::verify_proof_on_board(&offchain, &only_first).unwrap());
    assert_eq!(r["holds"], true);
    assert_eq!(r["second"]["on_board"], Value::Null);
    assert_eq!(r["ordered"], Value::Null);

    // no position for the first entry: FAIL in the web, as in `jitsuin verify` (BL-D27-05)
    let unpositioned = api::double_sign_proof(&inv_b64, &sig, ma, mb, None, None).unwrap();
    let r = parse(&api::verify_proof_on_board(&unpositioned, &board).unwrap());
    assert_eq!(r["holds"], false);
    assert_eq!(r["first"]["claimed_at"], Value::Null);
    assert_eq!(r["first"]["on_board"], Value::Null);

    // a claimed position that is not where the entry is
    let moved = api::double_sign_proof(
        &inv_b64,
        &sig,
        ma,
        mb,
        Some(&at(&ta, 11)),
        Some(&at(&tb, 12)),
    )
    .unwrap();
    assert_eq!(
        parse(&api::verify_proof_on_board(&moved, &board).unwrap())["first"]["on_board"],
        false
    );

    // a forged buyer signature: the signature check fails, so the proof does not hold
    let mut p = jitsuin_core::DoubleSignProof::from_bytes(&base64_decode(&positioned)).unwrap();
    p.buyer_signature[0] ^= 1;
    let forged = b64(&p.to_bytes().unwrap());
    let r = parse(&api::verify_proof_on_board(&forged, &board).unwrap());
    assert_eq!(
        (r["holds"].clone(), r["signatures"]["ok"].clone()),
        (json!(false), json!(false))
    );

    // the rate index from board data is the CLI's `rate_index_json` of the same records
    let records: Vec<jitsuin_board::BoardRecord> = [(&ta, 10, ma), (&tb, 12, mb)]
        .iter()
        .map(|(t, h, m)| jitsuin_board::BoardRecord {
            txid: t.to_string(),
            position: jitsuin_board::Position {
                height: *h,
                tx_index: 1,
                output_index: 0,
            },
            entry: jitsuin_core::BoardEntry::from_memo_bytes(&base64_decode(m)).unwrap(),
        })
        .collect();
    for k in [1, 5, 9] {
        let web = parse(&api::rate_index(&board, k).unwrap());
        let cli = jitsuin_board::rate_index_json(&jitsuin_board::rate_index(&records, k as usize));
        assert_eq!(web, cli);
    }
    let i = parse(&api::rate_index(&board, 5).unwrap());
    assert_eq!(
        (i["entries"].clone(), i["invoices"].clone(), i["k"].clone()),
        (json!(2), json!(1), json!(5))
    );
    assert!(api::rate_index("not json", 5).is_err());
}

#[test]
fn mailbox_keys_proof_and_sealed_messages_through_the_api() {
    // same vector as jitsuin-core mailbox.rs and jitsuinfi-backend tests/vectors.test.ts
    let prf = hex(&[0x11; 32]);
    let k: Value = serde_json::from_str(&api::mailbox_keys(&prf).unwrap()).unwrap();
    assert_eq!(
        k["mailbox_pk"],
        "721e61a2e3a16f2e7806c392b1367c8edb7c11c0132d2b5d3164290d60fce400"
    );
    assert_eq!(
        k["mailbox_id"],
        "171e3bf4c1a8af89725083cc6ceac9bb9400ebcf9caac626f1b6779e667559c2"
    );
    let proof = api::mailbox_proof(
        &prf,
        "register",
        "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20",
        &hex(&[0x33; 32]),
    )
    .unwrap();
    assert_eq!(
        proof,
        "7d4a818d24e88f5a20279120ae3dad9e64409b7f9b0de59b415ce565ef84f7a2"
    );
    assert!(api::mailbox_proof(&prf, "write", &hex(&[9; 32]), &hex(&[0; 32])).is_err());

    // seal to the mailbox, open with the same PRF output; the ephemeral secret is wiped
    let mut eph = [5u8; 32];
    let sealed = api::mailbox_seal(
        k["mailbox_pk"].as_str().unwrap(),
        &mut eph,
        b"JTSM document",
    )
    .unwrap();
    assert_eq!(eph, [0; 32]);
    assert_eq!(api::mailbox_open(&prf, &sealed).unwrap(), b"JTSM document");
    assert!(api::mailbox_open(&hex(&[0x12; 32]), &sealed).is_err());
    let mut short = [5u8; 16];
    assert!(api::mailbox_seal(k["mailbox_pk"].as_str().unwrap(), &mut short, b"x").is_err());
    assert_eq!(short, [0; 16]);
}

#[test]
fn message_signatures_cover_only_relay_headers() {
    let secret = hex(&[0x42; 32]);
    let bytes = b"JitsuinMsgSig_v1\n{\"type\":\"invoice.sign_request\"}";
    let r: Value = serde_json::from_str(&api::message_sign(&secret, bytes).unwrap()).unwrap();
    let pk = SigningKey::from_bytes(&[0x42; 32]).verifying_key();
    assert_eq!(r["signer"], hex(&pk.to_bytes()));
    let sig: [u8; 64] = (0..64)
        .map(|i| u8::from_str_radix(&r["sig"].as_str().unwrap()[i * 2..i * 2 + 2], 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    pk.verify_strict(bytes, &ed25519_dalek::Signature::from_bytes(&sig))
        .unwrap();
    // an invoice, a seal or any other bytes are refused
    assert!(api::message_sign(&secret, b"JTSI\x01...").is_err());
    assert_eq!(
        api::mailbox_id_of("721e61a2e3a16f2e7806c392b1367c8edb7c11c0132d2b5d3164290d60fce400")
            .unwrap(),
        "171e3bf4c1a8af89725083cc6ceac9bb9400ebcf9caac626f1b6779e667559c2"
    );
}
