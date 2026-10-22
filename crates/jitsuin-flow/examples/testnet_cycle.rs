//! Testnet end to end (HNK-17.T1, HNK-03.T5): one invoice backed by a real PDF goes through the
//! whole JitsuinFi cycle on Zcash testnet, then a second financier is offered the same invoice.
//! Test data only (TES-); keys are fresh per run.
//!
//! ```text
//! JITSUIN_TESTNET_DIR=~/.hanko-tes/testnet JITSUIN_DEVTOOL=~/.hanko-tes/bin/zcash-devtool \
//!   cargo run -p jitsuin-flow --example testnet_cycle -- invoice.pdf out/
//! ```
//!
//! `JITSUIN_TESTNET_DIR` holds three zcash-devtool wallets: `wallet-a` (+ `wallet-a.age`, the
//! financier, pays the entries, the advance and the settled entry), `wallet-b` (+ `wallet-b.age`,
//! supplier and buyer: receives the advance, repays) and `board-watch` (the board's UFVK). The
//! run writes the invoice, the letter PDF, the bundle, the proof and the txids to the out folder;
//! `jitsuin verify --ufvk <board UFVK> --bundle out/bundle.txt --proof out/proof.txt` checks them.
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use jitsuin_board::{lookup, lwd, proof_from_offer, scan, Lookup};
use jitsuin_core::{
    commitment_opening, document_hash, nullifier, sign_invoice, Assignment, Bundle, BuyerIdentity,
    Invoice, SettlementDoc,
};
use jitsuin_flow::financier::{Deal, Event, Financier, Flow, State};
use jitsuin_flow::settlement::Status;
use jitsuin_wallet::Devtool;
use sha2::{Digest, Sha256};

const LWD: &str = "https://testnet.zec.rocks:443";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn seed(tag: &str, run: u64) -> [u8; 32] {
    Sha256::new()
        .chain_update(tag)
        .chain_update(run.to_le_bytes())
        .finalize()
        .into()
}

fn out(dir: &str, name: &str, text: &str) {
    std::fs::write(format!("{dir}/{name}"), text).unwrap();
    println!("  saved {dir}/{name}");
}

fn letter_pdf(id: &str, n: &str, fin: &str, addr: &str) -> Vec<u8> {
    let lines = [
        format!("Notice of assignment: invoice {id} (test data)"),
        format!("Fingerprint N: {n}"),
        format!("Financier key: {fin}"),
        format!("Pay to: {addr}"),
        "Seals in order: supplier, buyer, financier (with the advance).".into(),
    ];
    let mut c = String::from("BT /F1 10 Tf 40 780 Td 14 TL\n");
    for l in &lines {
        let l: String = l.chars().take(110).collect();
        c += &format!("({l}) Tj T*\n");
    }
    c += "ET\n";
    let objs = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".into(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>".into(),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".into(),
        format!("<< /Length {} >>\nstream\n{c}endstream", c.len()),
    ];
    let mut b = b"%PDF-1.4\n".to_vec();
    let mut offs = vec![];
    for (i, o) in objs.iter().enumerate() {
        offs.push(b.len());
        b.extend(format!("{} 0 obj\n{o}\nendobj\n", i + 1).bytes());
    }
    let x = b.len();
    b.extend(b"xref\n0 6\n0000000000 65535 f \n");
    for o in offs {
        b.extend(format!("{o:010} 00000 n \n").bytes());
    }
    b.extend(format!("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{x}\n%%EOF\n").bytes());
    b
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (pdf_path, dir) = match args.as_slice() {
        [_, pdf, dir] => (pdf.clone(), dir.clone()),
        _ => panic!("usage: testnet_cycle <invoice.pdf> <out-dir>"),
    };
    std::fs::create_dir_all(&dir).unwrap();
    let t = std::env::var("JITSUIN_TESTNET_DIR").expect("JITSUIN_TESTNET_DIR: the test wallets");
    let bin = std::env::var("JITSUIN_DEVTOOL").unwrap_or_else(|_| "zcash-devtool".into());
    let wallet_a =
        Devtool::new(&bin, format!("{t}/wallet-a")).with_identity(format!("{t}/wallet-a.age"));
    let wallet_b =
        Devtool::new(&bin, format!("{t}/wallet-b")).with_identity(format!("{t}/wallet-b.age"));
    let board_watch = Devtool::new(&bin, format!("{t}/board-watch"));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let today = (now / 86_400) as u32;
    let run = now / 60;

    // keys of this run: supplier per-invoice key, buyer identity, two financiers
    let supplier = SigningKey::from_bytes(&seed("supplier", run));
    let buyer_id = BuyerIdentity::from_master_secret(seed("buyer", run));
    let buyer = buyer_id.invoice_key(0);
    let fin_a = SigningKey::from_bytes(&seed("financier-a", run));
    let fin_b = SigningKey::from_bytes(&seed("financier-b", run));

    // 1. the invoice, its terms bound to the real PDF file
    let pdf = std::fs::read(&pdf_path).expect("the invoice PDF");
    let id = format!("TES-INV-E2E1-{}", run % 100_000);
    let invoice = Invoice {
        invoice_id: id.clone(),
        supplier_ephemeral_pk: supplier.verifying_key().to_bytes(),
        buyer_pk: buyer.verifying_key().to_bytes(),
        amount_zat: 100_000,
        issue_date: today,
        due_date: today + 30,
        terms_hash: document_hash(&pdf),
    };
    let n = nullifier(&invoice).unwrap();
    let sig = sign_invoice(&buyer, &invoice).unwrap();
    println!(
        "1. invoice {id}, terms = SHA-256 of the PDF {}, N {}",
        hex(&invoice.terms_hash),
        hex(&n)
    );
    out(
        &dir,
        "invoice.txt",
        &URL_SAFE_NO_PAD.encode(invoice.to_canonical_bytes().unwrap()),
    );
    out(&dir, "buyer-signature.txt", &hex(&sig.to_bytes()));

    // 2. financier A: commitment, letter, deal
    let board_address = board_watch.default_address().unwrap();
    let fin_addr = wallet_a.default_address().unwrap();
    let supplier_addr = wallet_b.default_address().unwrap();
    let fin_pk = fin_a.verifying_key().to_bytes();
    let (salt, commitment) = commitment_opening(&fin_a, &n);
    let letter = letter_pdf(&id, &hex(&n), &hex(&fin_pk), &fin_addr);
    std::fs::write(format!("{dir}/letter.pdf"), &letter).unwrap();
    let assignment =
        Assignment::for_invoice(&invoice, fin_pk, &fin_addr, document_hash(&letter)).unwrap();
    let mut flow = Flow::new(Deal {
        invoice: invoice.clone(),
        assignment: assignment.clone(),
        financier_commitment: commitment,
        supplier_address: supplier_addr.clone(),
        advance_zat: 90_000,
        min_confirmations: 1,
        history_tag: None,
        discount_bucket: 0,
        tenor_bucket: 0,
    })
    .unwrap();
    let a = Financier {
        wallet: wallet_a.clone(),
        board_watch: board_watch.clone(),
        board_address: board_address.clone(),
        lightwalletd: LWD.into(),
        key: fin_a.clone(),
    };
    println!(
        "2. board check by financier A: {:?}",
        a.check(&mut flow).unwrap().name()
    );

    // 3. supplier signs the entry for A's commitment (opened with the salt); A posts it
    let entry = jitsuin_flow::supplier::sign_register_entry(&supplier, n, &fin_pk, &salt, 0, 0);
    assert_eq!(entry.financier_commitment, commitment);
    flow.apply(Event::SupplierSigned(entry)).unwrap();
    a.register(&mut flow).unwrap();
    let entry_txid = match flow.state() {
        State::AwaitConfirmation { entry_txid } => entry_txid.clone(),
        s => panic!("after register: {s:?}"),
    };
    println!("3. register entry posted: {entry_txid}");
    out(&dir, "entry-txid.txt", &entry_txid);
    let st = a
        .wait_for_confirmation(
            &mut flow,
            Duration::from_secs(30),
            Duration::from_secs(3600),
        )
        .unwrap();
    println!("   confirmed: {}", st.name());

    // 4. seals: supplier, buyer; A pays the advance with its seal
    let s0 = assignment.seal_next(&supplier, &[]).unwrap();
    let s1 = jitsuin_flow::buyer::seal_assignment(&buyer, &assignment, &s0).unwrap();
    flow.apply(Event::AssignmentSealed(vec![s0.clone(), s1.clone()]))
        .unwrap();
    a.pay_advance(&mut flow, today).unwrap();
    let st = a
        .wait_for_advance(
            &mut flow,
            Duration::from_secs(30),
            Duration::from_secs(3600),
        )
        .unwrap()
        .clone();
    let advance_txid = match &st {
        State::Done { advance_txid, .. } => advance_txid.clone(),
        s => panic!("after advance: {s:?}"),
    };
    println!("4. advance paid and mined: {advance_txid}");
    out(&dir, "advance-txid.txt", &advance_txid);

    // 5. buyer repays from its wallet with the QR request (receipt + claim in the memo)
    let req = jitsuin_flow::buyer::repayment_request(&buyer, &assignment, today).unwrap();
    wallet_b.sync().unwrap();
    let repay_txid = wallet_b.pay_uri(&req.uri).unwrap();
    println!("5. buyer repaid: {repay_txid}");
    out(&dir, "repayment-txid.txt", &repay_txid);

    // 6. A sees it mined and posts the two-signature settled entry
    let doc = SettlementDoc::for_assignment(&assignment);
    let settled_txid = loop {
        let r = a.repayment(&doc, &invoice.buyer_pk).unwrap();
        if r.status(&doc, today, 7) == Status::Settled {
            break a.post_settled(&doc, &invoice.buyer_pk, &r).unwrap().0;
        }
        std::thread::sleep(Duration::from_secs(30));
    };
    println!("6. settled entry posted: {settled_txid}");
    out(&dir, "settled-txid.txt", &settled_txid);

    // 7. the verification bundle: invoice, buyer signature, letter with three seals, settlement
    // Ed25519 is deterministic: s2 is the seal that travelled with the advance
    let s2 = assignment
        .seal_next(&fin_a, &[s0.clone(), s1.clone()])
        .unwrap();
    let bundle = Bundle {
        invoice: invoice.clone(),
        buyer_signature: sig.to_bytes(),
        assignment: Some(assignment.clone()),
        assignment_seals: vec![s0, s1, s2],
        settlement: Some(doc),
    };
    bundle.verify().unwrap();
    out(
        &dir,
        "bundle.txt",
        &URL_SAFE_NO_PAD.encode(bundle.to_bytes().unwrap()),
    );

    // 8. the supplier offers the same invoice to financier B: B checks the board first
    let fin_b_pk = fin_b.verifying_key().to_bytes();
    let (salt_b, _) = commitment_opening(&fin_b, &n);
    let offered =
        jitsuin_flow::supplier::sign_register_entry(&supplier, n, &fin_b_pk, &salt_b, 0, 0);
    let report = scan(&board_watch, LWD).unwrap();
    let tip = lwd::latest_height(LWD).unwrap();
    let lk = lookup(&report.records, &n, &invoice.supplier_ephemeral_pk);
    let winner = match &lk {
        Lookup::Registered { winner, .. } => winner.clone(),
        other => panic!("B expected the invoice registered, got {other:?}"),
    };
    println!("8. financier B checks the board at tip {tip}: already registered at block {}; B pays nothing", winner.position.height);
    let proof = proof_from_offer(&winner, offered, &invoice, sig.to_bytes());
    proof.verify().unwrap();
    out(
        &dir,
        "proof.txt",
        &URL_SAFE_NO_PAD.encode(proof.to_bytes().unwrap()),
    );
    println!("done");
}
