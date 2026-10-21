//! Exhibit A of the real testnet double financing (examples/testnet, TES-INV-0003): made from the
//! full proof in the browser API, it holds against the board snapshot, binds to the invoice only
//! for a holder of that invoice, and carries none of the invoice's fields (HNK-30.T5).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jitsuin_wasm::api::{exhibit_from_proof, verify_exhibit_on_board, verify_proof};
use serde_json::Value;

fn example(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/../../examples/testnet/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
    .trim()
    .to_string()
}

const KIT_INVOICE: &str = "SlRTSQEXVEVTLUlOVi0wMDAzLTE3OTIxNzk3MDNmzWCLkouI5Q4O_qoz-vHEPO_gcpSwuH6f4Kumo892M3T4XNo00cJ8RiFIRzHpFXnD2cbPwNlLKBqhHpFiBYqpQJwAAAAAAAAGUQAAJFEAAG3JR6EwR9u_mFctb4x42gwOo0Cghvu65bHSUml6yWSx";

#[test]
fn exhibit_of_the_testnet_double_financing() {
    let proof = example("proof-tes-inv-0003.txt");
    let board = example("board-snapshot.json");
    let p: Value = serde_json::from_str(&verify_proof(&proof).unwrap()).unwrap();
    let x = exhibit_from_proof(&proof).unwrap();
    assert_eq!(
        x,
        example("exhibit-tes-inv-0003.txt"),
        "examples/testnet exhibit is this proof's"
    );

    let v: Value =
        serde_json::from_str(&verify_exhibit_on_board(&x, Some(board.clone()), None).unwrap())
            .unwrap();
    assert_eq!(v["holds"], true, "{v}");
    assert_eq!(v["signatures"]["nullifier"], p["nullifier"]);
    assert_eq!(v["first"]["on_board"], true);
    assert_eq!(v["second"]["on_board"], true);
    assert_eq!(v["ordered"], true);
    assert_eq!(
        v["binds"],
        Value::Null,
        "the exhibit alone does not say which invoice"
    );

    let with: Value = serde_json::from_str(
        &verify_exhibit_on_board(&x, Some(board.clone()), Some(KIT_INVOICE.into())).unwrap(),
    )
    .unwrap();
    assert_eq!(with["binds"], true);
    assert_eq!(with["holds"], true);

    let offline: Value =
        serde_json::from_str(&verify_exhibit_on_board(&x, None, None).unwrap()).unwrap();
    assert_eq!(offline["signatures"]["ok"], true);
    assert_eq!(
        offline["holds"], false,
        "positions are not facts without the board"
    );

    // none of the invoice's fields is in the exhibit
    let xb = URL_SAFE_NO_PAD.decode(&x).unwrap();
    let inv = URL_SAFE_NO_PAD.decode(KIT_INVOICE).unwrap();
    let id = b"TES-INV-0003-1792179703";
    let buyer_pk = &inv[6 + id.len() + 32..6 + id.len() + 64];
    for part in [&id[..], buyer_pk, &inv[inv.len() - 32..]] {
        assert!(!xb.windows(part.len()).any(|w| w == part));
    }
    assert!(xb.len() < URL_SAFE_NO_PAD.decode(&proof).unwrap().len());
}
