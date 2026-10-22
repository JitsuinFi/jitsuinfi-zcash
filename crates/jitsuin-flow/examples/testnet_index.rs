//! Classed entries on the testnet board (HNK-27.T2, I-HNK-27.1): `count` test invoices (default 5)
//! are registered with their real discount and tenor classes (`classes_for`), so `jitsuin index`
//! can publish a tenor class, which it does only from five invoices. Registration only: no
//! advance, no repayment. Test data only (TES-); keys are fresh per run.
//!
//! ```text
//! JITSUIN_TESTNET_DIR=~/.hanko-tes/testnet JITSUIN_DEVTOOL=~/.hanko-tes/bin/zcash-devtool \
//!   cargo run -p jitsuin-flow --example testnet_index -- out/ 5
//! ```
//!
//! Uses `wallet-a` (+ `wallet-a.age`, the financier, pays each entry) and `board-watch` from
//! `JITSUIN_TESTNET_DIR`, as `testnet_cycle` does. Writes the entry txids to the out folder.
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use jitsuin_core::{
    commitment_opening, document_hash, index::classes_for, nullifier, Assignment, BuyerIdentity,
    Invoice,
};
use jitsuin_flow::financier::{Deal, Event, Financier, Flow, State};
use jitsuin_wallet::Devtool;
use sha2::{Digest, Sha256};

const LWD: &str = "https://testnet.zec.rocks:443";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn seed(tag: &str, run: u64, i: u32) -> [u8; 32] {
    Sha256::new()
        .chain_update(tag)
        .chain_update(run.to_le_bytes())
        .chain_update(i.to_le_bytes())
        .finalize()
        .into()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (dir, count) = match args.as_slice() {
        [_, dir] => (dir.clone(), 5),
        [_, dir, n] => (dir.clone(), n.parse::<u32>().expect("count: a number")),
        _ => panic!("usage: testnet_index <out-dir> [count]"),
    };
    std::fs::create_dir_all(&dir).unwrap();
    let t = std::env::var("JITSUIN_TESTNET_DIR").expect("JITSUIN_TESTNET_DIR: the test wallets");
    let bin = std::env::var("JITSUIN_DEVTOOL").unwrap_or_else(|_| "zcash-devtool".into());
    let wallet_a =
        Devtool::new(&bin, format!("{t}/wallet-a")).with_identity(format!("{t}/wallet-a.age"));
    let board_watch = Devtool::new(&bin, format!("{t}/board-watch"));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let today = (now / 86_400) as u32;
    let run = now / 60;

    let fin = SigningKey::from_bytes(&seed("financier", run, 0));
    let fin_pk = fin.verifying_key().to_bytes();
    let fin_addr = wallet_a.default_address().unwrap();
    let a = Financier {
        wallet: wallet_a.clone(),
        board_watch: board_watch.clone(),
        board_address: board_watch.default_address().unwrap(),
        lightwalletd: LWD.into(),
        key: fin.clone(),
    };
    let mut txids = String::new();
    for i in 0..count {
        // one supplier and one buyer per invoice; tenor 45 days, discounts 2 % to 6 %
        let supplier = SigningKey::from_bytes(&seed("supplier", run, i));
        let buyer = BuyerIdentity::from_master_secret(seed("buyer", run, i)).invoice_key(0);
        let amount_zat = 100_000 + 10_000 * u64::from(i);
        let advance_zat = amount_zat * (98 - u64::from(i % 5)) / 100;
        let id = format!("TES-INV-IDX-{}-{i}", run % 100_000);
        let invoice = Invoice {
            invoice_id: id.clone(),
            supplier_ephemeral_pk: supplier.verifying_key().to_bytes(),
            buyer_pk: buyer.verifying_key().to_bytes(),
            amount_zat,
            issue_date: today,
            due_date: today + 45,
            terms_hash: document_hash(id.as_bytes()),
        };
        let n = nullifier(&invoice).unwrap();
        let (discount, tenor) =
            classes_for(amount_zat, advance_zat, today, invoice.due_date).unwrap();
        let (salt, commitment) = commitment_opening(&fin, &n);
        let assignment =
            Assignment::for_invoice(&invoice, fin_pk, &fin_addr, document_hash(b"letter")).unwrap();
        let mut flow = Flow::new(Deal {
            invoice,
            assignment,
            financier_commitment: commitment,
            supplier_address: fin_addr.clone(),
            advance_zat,
            min_confirmations: 1,
            history_tag: None,
            discount_bucket: discount,
            tenor_bucket: tenor,
        })
        .unwrap();
        a.check(&mut flow).unwrap();
        // the entry's classes must be the deal's, or `check_entry` refuses it
        let entry = jitsuin_flow::supplier::sign_register_entry(
            &supplier, n, &fin_pk, &salt, discount, tenor,
        );
        flow.apply(Event::SupplierSigned(entry)).unwrap();
        a.register(&mut flow).unwrap();
        let txid = match flow.state() {
            State::AwaitConfirmation { entry_txid } => entry_txid.clone(),
            s => panic!("after register: {s:?}"),
        };
        a.wait_for_confirmation(
            &mut flow,
            Duration::from_secs(30),
            Duration::from_secs(3600),
        )
        .unwrap();
        println!(
            "{}. {id} N {} discount class {discount} tenor class {tenor}: {txid}",
            i + 1,
            &hex(&n)[..12]
        );
        txids += &format!("{id} {} d{discount} t{tenor} {txid}\n", hex(&n));
    }
    std::fs::write(format!("{dir}/index-entries.txt"), &txids).unwrap();
    println!("saved {dir}/index-entries.txt");
}
