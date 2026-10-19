//! End-to-end tests of the `jitsuin` binary on the sample boards in `examples/verify/`
//! (U-HNK-09.1, U-HNK-09.2) and `examples/index/` (HNK-08). The samples are rebuilt here from fixed keys and must match the
//! committed files byte for byte; `JITSUIN_REGEN=1 cargo test -p jitsuin-cli --test samples`
//! rewrites them after an intended change.

use std::path::{Path, PathBuf};
use std::process::Command;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use jitsuin_board::{lookup, proof_from_lookup, BoardRecord, Collected, Position, SettledRecord};
use jitsuin_core::{
    financier_commitment, nullifier, sign_invoice, Assignment, BoardEntry, Bundle, EntryKind,
    Invoice, SettledEntry, SettlementDoc, SETTLED_ON_TIME,
};

const BOARD: &str = "examples/verify/board-sample.json";
const PROOF: &str = "examples/verify/proof-sample.txt";
const BUNDLE: &str = "examples/verify/bundle-sample.txt";
const EXPECTED: &str = "examples/verify/expected-output.txt";
const INDEX_BOARD: &str = "examples/index/board-sample.json";
const INDEX_EXPECTED: &str = "examples/index/expected-output.txt";
/// 2026-10-19 in days since the Unix epoch.
const TODAY: u32 = 20_745;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn key(b: u8) -> SigningKey {
    SigningKey::from_bytes(&[b; 32])
}

fn pk(b: u8) -> [u8; 32] {
    key(b).verifying_key().to_bytes()
}

fn invoice(id: &str, supplier: u8, buyer: u8, amount_zat: u64) -> Invoice {
    Invoice {
        invoice_id: id.into(),
        supplier_ephemeral_pk: pk(supplier),
        buyer_pk: pk(buyer),
        amount_zat,
        issue_date: TODAY,
        due_date: TODAY + 45,
        terms_hash: [0x7e; 32],
    }
}

fn at(txid_byte: &str, height: u32, tx_index: u32, output_index: u32) -> (String, Position) {
    (
        txid_byte.repeat(32),
        Position {
            height,
            tx_index,
            output_index,
        },
    )
}

struct Samples {
    board: String,
    proof: String,
    bundle: String,
}

/// TES-INV-0901 registered for two financiers (double financing), TES-INV-0902 financed once,
/// settled, with an earlier griefing entry for its N, plus one memo that is not an entry.
fn samples() -> Samples {
    let mut c = Collected::default();
    let mut put = |(txid, position): (String, Position), memo: &[u8]| c.add(&txid, position, memo);

    // Deal A: supplier key 1 signs N for financier 3, then again for financier 4.
    let inv_a = invoice("TES-INV-0901", 1, 2, 2_500_000);
    let sig_a = sign_invoice(&key(2), &inv_a).unwrap().to_bytes();
    let n_a = nullifier(&inv_a).unwrap();
    let entry = |supplier: u8, n, financier: u8, salt: u8| {
        BoardEntry::sign(
            &key(supplier),
            EntryKind::Register,
            n,
            financier_commitment(&pk(financier), &[salt; 32]),
            3,
            2,
        )
    };
    put(
        at("a1", 4_600_010, 1, 0),
        &entry(1, n_a, 3, 0x31).to_memo_bytes(),
    );
    put(
        at("a2", 4_600_025, 0, 1),
        &entry(1, n_a, 4, 0x41).to_memo_bytes(),
    );

    // Deal B: a griefer posts N first with its own key; the supplier's entry comes later.
    let inv_b = invoice("TES-INV-0902", 5, 6, 4_000_000);
    let sig_b = sign_invoice(&key(6), &inv_b).unwrap().to_bytes();
    let n_b = nullifier(&inv_b).unwrap();
    put(
        at("b0", 4_600_028, 0, 0),
        &entry(9, n_b, 9, 0x99).to_memo_bytes(),
    );
    put(
        at("b1", 4_600_030, 2, 0),
        &entry(5, n_b, 7, 0x71).to_memo_bytes(),
    );

    let letter =
        Assignment::for_invoice(&inv_b, pk(7), "utest1financiersample", [0x5a; 32]).unwrap();
    let mut seals = Vec::new();
    for signer in [key(5), key(6), key(7)] {
        let s = letter.seal_next(&signer, &seals).unwrap();
        seals.push(s);
    }
    let doc = SettlementDoc::for_assignment(&letter);
    let settled = SettledEntry::countersign(
        &doc,
        &doc.buyer_seal(&key(6)),
        &pk(6),
        &key(7),
        SETTLED_ON_TIME,
    )
    .unwrap();
    put(at("b2", 4_600_090, 0, 0), &settled.to_memo_bytes());

    // Not an entry: right magic, unknown kind.
    let mut junk = [0u8; 512];
    junk[0] = 0xff;
    junk[1..5].copy_from_slice(b"JTS1");
    junk[5] = 0x09;
    put(at("c1", 4_600_040, 0, 2), &junk);
    c.sort();

    let proof = proof_from_lookup(&lookup(&c.records, &n_a, &pk(1)), &inv_a, sig_a).unwrap();
    let bundle = Bundle {
        invoice: inv_b,
        buyer_signature: sig_b,
        assignment: Some(letter),
        assignment_seals: seals,
        settlement: Some(doc),
    };
    Samples {
        board: snapshot(&c.records, &c.settled, &junk),
        proof: URL_SAFE_NO_PAD.encode(proof.to_bytes().unwrap()) + "\n",
        bundle: URL_SAFE_NO_PAD.encode(bundle.to_bytes().unwrap()) + "\n",
    }
}

/// Snapshot with the rejected memo kept (a real board can carry junk).
fn snapshot(records: &[BoardRecord], settled: &[SettledRecord], junk: &[u8]) -> String {
    let item = |txid: &str, p: Position, memo: &[u8]| {
        serde_json::json!({
            "txid": txid, "height": p.height, "tx_index": p.tx_index,
            "output_index": p.output_index, "memo": URL_SAFE_NO_PAD.encode(memo),
        })
    };
    let (junk_txid, junk_at) = at("c1", 4_600_040, 0, 2);
    let mut items: Vec<(Position, serde_json::Value)> = records
        .iter()
        .map(|r| {
            (
                r.position,
                item(&r.txid, r.position, &r.entry.to_memo_bytes()),
            )
        })
        .chain(settled.iter().map(|s| {
            (
                s.position,
                item(&s.txid, s.position, &s.entry.to_memo_bytes()),
            )
        }))
        .chain([(junk_at, item(&junk_txid, junk_at, junk))])
        .collect();
    items.sort_by_key(|(p, _)| *p);
    let items: Vec<_> = items.into_iter().map(|(_, v)| v).collect();
    serde_json::to_string_pretty(&items).unwrap() + "\n"
}

fn jitsuin(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_jitsuin"))
        .args(args)
        .current_dir(root())
        .env_remove("JITSUIN_DEVTOOL")
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(root().join(rel))
        .unwrap()
        .replace('\r', "")
}

fn regen() -> bool {
    std::env::var("JITSUIN_REGEN").as_deref() == Ok("1")
}

fn write_samples(s: &Samples) {
    std::fs::create_dir_all(root().join("examples/verify")).unwrap();
    std::fs::write(root().join(BOARD), &s.board).unwrap();
    std::fs::write(root().join(PROOF), &s.proof).unwrap();
    std::fs::write(root().join(BUNDLE), &s.bundle).unwrap();
    std::fs::create_dir_all(root().join("examples/index")).unwrap();
    std::fs::write(root().join(INDEX_BOARD), index_board()).unwrap();
}

/// A small market for the rate index: 17 invoices (one with two entries), classes picked so
/// that two tenor classes reach k = 5 and three do not, plus one 0/0 and one invalid entry.
fn index_board() -> String {
    let mut c = Collected::default();
    let mut i = 0u32;
    let mut post = |n: u8, discount: u8, tenor: u8, kind: EntryKind| {
        let supplier = key(n);
        let entry = match kind {
            EntryKind::RegisterWithHistory => BoardEntry::sign_with_history(
                &supplier,
                [n; 32],
                [n ^ 0x55; 32],
                discount,
                tenor,
                [n ^ 0xaa; 32],
            ),
            _ => BoardEntry::sign(&supplier, kind, [n; 32], [n ^ 0x55; 32], discount, tenor),
        };
        let (txid, position) = at(&format!("{:02x}", 0xd0 + i), 4_601_000 + 7 * i, i % 3, 0);
        c.add(&txid, position, &entry.to_memo_bytes());
        i += 1;
    };
    // 31-60 days: six at 2-3%, three at 1-2%.
    for n in 1..=6 {
        post(n, 3, 2, EntryKind::Register);
    }
    for n in 7..=9 {
        post(n, 2, 2, EntryKind::RegisterWithHistory);
    }
    // 61-90 days: five at 3-5%.
    for n in 10..=14 {
        post(n, 4, 3, EntryKind::Register);
    }
    post(15, 1, 1, EntryKind::Register); // <= 30 days: one invoice, not shown
    post(16, 0, 0, EntryKind::Register); // not disclosed
    post(17, 9, 9, EntryKind::Register); // invalid classes
    post(1, 7, 5, EntryKind::Register); // second entry for N 1: counted once, with 3/2
    c.sort();
    let items: Vec<serde_json::Value> = c
        .records
        .iter()
        .map(|r| {
            serde_json::json!({
                "txid": r.txid, "height": r.position.height, "tx_index": r.position.tx_index,
                "output_index": r.position.output_index,
                "memo": URL_SAFE_NO_PAD.encode(r.entry.to_memo_bytes()),
            })
        })
        .collect();
    serde_json::to_string_pretty(&items).unwrap() + "\n"
}

#[test]
fn samples_are_reproducible_from_the_code() {
    let s = samples();
    if regen() {
        write_samples(&s);
        return;
    }
    assert_eq!(read(BOARD), s.board);
    assert_eq!(read(PROOF), s.proof);
    assert_eq!(read(BUNDLE), s.bundle);
    assert_eq!(read(INDEX_BOARD), index_board());
}

#[test]
fn sample_verification_matches_the_expected_output() {
    if regen() {
        write_samples(&samples());
    }
    let (code, out, err) = jitsuin(&[
        "verify", "--board", BOARD, "--proof", PROOF, "--bundle", BUNDLE,
    ]);
    if regen() {
        std::fs::write(root().join(EXPECTED), &out).unwrap();
    }
    assert_eq!((code, err.as_str()), (0, ""));
    assert_eq!(out, read(EXPECTED));
    assert!(out.contains("=> DOUBLE FINANCING PROVEN"));
    assert!(out.contains("=> DEAL VERIFIED"));
    assert!(out.contains("1 entry for N ignored"));
    assert!(out.contains("unknown registry entry kind 0x09"));
}

#[test]
fn json_report_has_the_same_verdicts() {
    let (code, out, _) = jitsuin(&[
        "verify", "--board", BOARD, "--proof", PROOF, "--bundle", BUNDLE, "--json",
    ]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["pass"], true);
    assert_eq!(v["board"]["source"], "snapshot");
    assert_eq!(v["entries"].as_array().unwrap().len(), 4);
    assert_eq!(v["settled"].as_array().unwrap().len(), 1);
    assert_eq!(v["rejected"].as_array().unwrap().len(), 1);
    let docs = v["documents"].as_array().unwrap();
    assert_eq!(docs[0]["conclusion"], "DOUBLE FINANCING PROVEN");
    assert_eq!(docs[1]["conclusion"], "DEAL VERIFIED");
}

#[test]
fn a_proof_or_bundle_that_does_not_match_the_board_fails_with_exit_1() {
    let dir = std::env::temp_dir().join("jitsuin-cli-e2e");
    std::fs::create_dir_all(&dir).unwrap();
    // Board without deal B's settled entry and without deal A's second entry.
    let items: Vec<serde_json::Value> = serde_json::from_str(&read(BOARD)).unwrap();
    let cut: Vec<_> = items
        .into_iter()
        .filter(|i| {
            let t = i["txid"].as_str().unwrap();
            !t.starts_with("a2") && !t.starts_with("b2")
        })
        .collect();
    let board = dir.join("board-cut.json");
    std::fs::write(&board, serde_json::to_string(&cut).unwrap()).unwrap();
    let board = board.to_str().unwrap();

    let (code, out, _) = jitsuin(&["verify", "--board", board, "--proof", PROOF]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("FAIL  second entry: not on the board at 4600025/0/1"));
    assert!(out.contains("=> PROOF DOES NOT HOLD"));

    let (code, out, _) = jitsuin(&["verify", "--board", board, "--bundle", BUNDLE]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("PASS  registration: registered once"));
    assert!(out.contains("FAIL  settlement"));

    // A tampered proof no longer verifies at all.
    let mut bytes = URL_SAFE_NO_PAD.decode(read(PROOF).trim()).unwrap();
    let last = bytes.len() - 20;
    bytes[last] ^= 1;
    let forged = dir.join("proof-forged.bin");
    std::fs::write(&forged, &bytes).unwrap();
    let (code, out, _) = jitsuin(&[
        "verify",
        "--board",
        BOARD,
        "--proof",
        forged.to_str().unwrap(),
    ]);
    assert_eq!(code, 1, "{out}");
}

#[test]
fn usage_and_input_errors_exit_2() {
    let (code, _, err) = jitsuin(&["verify"]);
    assert_eq!(code, 2);
    assert!(err.starts_with("error: give the board"));
    let (code, _, err) = jitsuin(&["verify", "--board", "examples/verify/missing.json"]);
    assert_eq!(code, 2);
    assert!(err.contains("cannot read"));
    let (code, _, err) = jitsuin(&["verify", "--board", BOARD, "--proof", BOARD]);
    assert_eq!(code, 2);
    assert!(err.contains("not a double-signature proof") || err.contains("neither binary"));
    let (code, out, _) = jitsuin(&["--help"]);
    assert_eq!(code, 0);
    assert!(out.contains("jitsuin verify (--ufvk <UFVK> | --board <FILE>)"));
    let (code, out, _) = jitsuin(&["--version"]);
    assert_eq!((code, out.as_str()), (0, "jitsuin 0.1.0\n"));
}

#[test]
fn index_sample_matches_the_expected_output() {
    if regen() {
        write_samples(&samples());
    }
    let (code, out, err) = jitsuin(&["index", "--board", INDEX_BOARD]);
    if regen() {
        std::fs::write(root().join(INDEX_EXPECTED), &out).unwrap();
    }
    assert_eq!((code, err.as_str()), (0, ""));
    assert_eq!(out, read(INDEX_EXPECTED));
    assert!(out.contains("k = 5"));
    assert!(out.contains("18 register entries, 17 invoices"));
}

#[test]
fn index_json_and_higher_k() {
    let (code, out, _) = jitsuin(&["index", "--board", INDEX_BOARD, "--json"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        (v["k"].as_u64(), v["invoices"].as_u64()),
        (Some(5), Some(17))
    );
    assert_eq!(
        (v["undisclosed"].as_u64(), v["invalid"].as_u64()),
        (Some(1), Some(1))
    );
    let tenors = v["tenors"].as_array().unwrap();
    let shown: Vec<_> = tenors.iter().filter(|t| t["published"] == true).collect();
    assert_eq!(shown.len(), 2);
    assert_eq!(shown[0]["label"], "31-60 days");
    assert_eq!(shown[0]["invoices"], 9);
    assert_eq!(shown[0]["median_discount"]["label"], "2-3%");
    assert_eq!(shown[0]["other"], 3);
    assert_eq!(shown[1]["median_discount"]["label"], "3-5%");
    // Unpublished classes carry no count.
    assert!(tenors[0].get("invoices").is_none());
    assert_eq!(v["classes"]["discount_bps"].as_array().unwrap().len(), 7);

    let (_, out, _) = jitsuin(&["index", "--board", INDEX_BOARD, "--json", "--k", "6"]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let shown = v["tenors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| t["published"] == true)
        .count();
    assert_eq!((v["k"].as_u64(), shown), (Some(6), 1));

    // The verify sample has two invoices only: nothing reaches k.
    let (code, out, _) = jitsuin(&["index", "--board", BOARD]);
    assert_eq!(code, 0);
    assert_eq!(out.matches("fewer than 5 invoices").count(), 5);
    let (code, _, err) = jitsuin(&["index", "--board", INDEX_BOARD, "--k", "2"]);
    assert_eq!(code, 2);
    assert!(err.contains("at least 5"));
}
