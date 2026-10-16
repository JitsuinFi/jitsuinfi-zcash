//! Supplier side of the advance (HNK-05.T2): sign the register entry for the agreed financier and
//! verify the advance receipt that arrives with the money.

use ed25519_dalek::SigningKey;
use jitsuin_core::{financier_commitment, BoardEntry, EntryKind, ReceiptKind};
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

/// Every advance receipt for `nullifier` received by the supplier wallet, with its verdict
/// (signed by `financier_pk`, amount equal to the received output).
pub fn received_advances(
    txs: &[WalletTx],
    nullifier: &[u8; 32],
    financier_pk: &[u8; 32],
) -> Vec<ReceivedReceipt> {
    received(txs, ReceiptKind::Advance, nullifier, financier_pk)
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
    fn signed_entry_carries_the_financier_commitment() {
        let supplier = SigningKey::from_bytes(&[1; 32]);
        let pk = financier().verifying_key().to_bytes();
        let e = sign_register_entry(&supplier, N, &pk, &[4; 32], 2, 3);
        assert_eq!(e.financier_commitment, financier_commitment(&pk, &[4; 32]));
        e.verify(&supplier.verifying_key().to_bytes()).unwrap();
    }
}
