//! Supplier side of the advance (HNK-05.T2, HNK-19.T3): sign the register entry for the agreed
//! financier, seal the assignment letter, and verify that the advance arrived together with the
//! financier's seal that completes the letter (Sign-to-Pay).

use ed25519_dalek::SigningKey;
use jitsuin_core::{
    financier_commitment, Assignment, BoardEntry, ChainStatus, EntryKind, Invoice, ReceiptKind,
    Seal,
};
use jitsuin_wallet::WalletTx;

use crate::receipts::{received, ReceivedReceipt};

/// Signs the register entry for the financier whose commitment opening (public key and salt) was
/// shared off-chain, so the supplier signs exactly that financier's commitment.
pub fn sign_register_entry(
    supplier_ephemeral: &SigningKey,
    nullifier: [u8; 32],
    financier_pk: &[u8; 32],
    salt: &[u8; 32],
    discount_bucket: u8,
    tenor_bucket: u8,
) -> BoardEntry {
    BoardEntry::sign(
        supplier_ephemeral,
        EntryKind::Register,
        nullifier,
        financier_commitment(financier_pk, salt),
        discount_bucket,
        tenor_bucket,
    )
}

/// Same as [`sign_register_entry`], carrying the tag of the buyer's new history certificate.
pub fn sign_register_entry_with_history(
    supplier_ephemeral: &SigningKey,
    nullifier: [u8; 32],
    financier_pk: &[u8; 32],
    salt: &[u8; 32],
    discount_bucket: u8,
    tenor_bucket: u8,
    history_tag: [u8; 32],
) -> BoardEntry {
    BoardEntry::sign_with_history(
        supplier_ephemeral,
        nullifier,
        financier_commitment(financier_pk, salt),
        discount_bucket,
        tenor_bucket,
        history_tag,
    )
}

/// Every advance receipt for `nullifier` received by the supplier wallet, with its verdict
/// (signed by `financier_pk`, amount equal to the received output).
pub fn received_advances(
    txs: &[WalletTx],
    nullifier: &[u8; 32],
    financier_pk: &[u8; 32],
) -> Vec<ReceivedReceipt> {
    received(txs, ReceiptKind::Advance, nullifier, financier_pk)
}

/// Sign-to-Pay check for one received advance: the receipt is valid and the seal in the same memo
/// completes the assignment letter after the supplier and buyer seals (`Sealed`).
pub fn verify_sign_to_pay(
    advance: &ReceivedReceipt,
    invoice: &Invoice,
    assignment: &Assignment,
    supplier_and_buyer_seals: &[Seal],
) -> Result<ChainStatus, crate::Error> {
    if !advance.is_valid() {
        return Err(crate::Error::InvalidDeal("advance receipt is not valid"));
    }
    let mut chain = supplier_and_buyer_seals.to_vec();
    chain.extend(advance.seals.iter().cloned());
    Ok(assignment.verify(invoice, &chain)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipts::tests::{receipt_memo, tx};
    use crate::receipts::Verdict;
    use jitsuin_wallet::Memo;

    const N: [u8; 32] = [7; 32];

    fn financier() -> SigningKey {
        SigningKey::from_bytes(&[3; 32])
    }

    #[test]
    fn finds_the_valid_advance() {
        let pk = financier().verifying_key().to_bytes();
        let memo = Memo::Arbitrary(receipt_memo(&financier(), ReceiptKind::Advance, N, 950_000));
        let txs = vec![tx("ok", Some(10), 950_000, true, memo)];
        let found = received_advances(&txs, &N, &pk);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].verdict, Verdict::Valid);
    }

    #[test]
    fn advance_and_last_seal_arrive_together() {
        use jitsuin_core::memo::{self, MemoItem};
        use jitsuin_core::{nullifier, Receipt};
        let key = |b: u8| SigningKey::from_bytes(&[b; 32]);
        let inv = Invoice {
            invoice_id: "TES-INV-0003".into(),
            supplier_ephemeral_pk: key(1).verifying_key().to_bytes(),
            buyer_pk: key(2).verifying_key().to_bytes(),
            amount_zat: 1_000_000,
            issue_date: 1,
            due_date: 2,
            terms_hash: [9; 32],
        };
        let n = nullifier(&inv).unwrap();
        let pk = financier().verifying_key().to_bytes();
        let a = Assignment::for_invoice(&inv, pk, "utest1financier", [5; 32]).unwrap();
        let s0 = a.seal_next(&key(1), &[]).unwrap();
        let s1 = a.seal_next(&key(2), std::slice::from_ref(&s0)).unwrap();
        let prior = vec![s0, s1];
        let s2 = a.seal_next(&financier(), &prior).unwrap();
        let r = Receipt::sign(&financier(), ReceiptKind::Advance, n, 950_000, 3).unwrap();
        let m = memo::encode(&[MemoItem::Receipt(r.clone()), MemoItem::Seal(s2)]).unwrap();
        let txs = vec![tx("adv", Some(10), 950_000, true, Memo::Arbitrary(m))];
        let found = received_advances(&txs, &n, &pk);
        assert_eq!(found.len(), 1);
        assert_eq!(
            verify_sign_to_pay(&found[0], &inv, &a, &prior).unwrap(),
            ChainStatus::Sealed
        );
        // money without the last seal does not complete the letter
        let bare = r.to_memo_bytes().to_vec();
        let txs = vec![tx("bare", Some(10), 950_000, true, Memo::Arbitrary(bare))];
        let found = received_advances(&txs, &n, &pk);
        assert!(matches!(
            verify_sign_to_pay(&found[0], &inv, &a, &prior).unwrap(),
            ChainStatus::Incomplete { .. }
        ));
    }

    #[test]
    fn signed_entry_carries_the_financier_commitment() {
        let supplier = SigningKey::from_bytes(&[1; 32]);
        let pk = financier().verifying_key().to_bytes();
        let e = sign_register_entry(&supplier, N, &pk, &[4; 32], 2, 3);
        assert_eq!(e.financier_commitment, financier_commitment(&pk, &[4; 32]));
        e.verify(&supplier.verifying_key().to_bytes()).unwrap();
    }
}
