//! Financier side of the repayment (HNK-06.T3, T4): detect the buyer's payment for N, record the
//! invoice as settled, and optionally post a `settled` entry to the board.
//!
//! The `settled` entry carries `settled_tag(N)` instead of N, a zero commitment field and the
//! buckets of the register entry, signed by the financier key (proposal D-18). Outsiders cannot
//! link it to the register entry; holders of N can, and verify it with the financier public key
//! from the assignment letter.

use ed25519_dalek::SigningKey;
use jitsuin_board::{scan, settled, BoardRecord};
use jitsuin_core::{settled_tag, BoardEntry, EntryKind, ReceiptKind, ENTRY_LEN};
use jitsuin_wallet::{Payment, PaymentMemo, WalletTx};

use crate::financier::{Financier, ENTRY_POST_ZAT};
use crate::receipts::{received, ReceivedReceipt};
use crate::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Unpaid,
    /// A valid repayment was seen but is not mined yet.
    Pending,
    /// Mined valid repayments cover part of the amount due.
    Partial,
    /// Mined valid repayments cover the amount due.
    Settled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repayment {
    pub due_zat: u64,
    /// Sum of valid, mined repayments.
    pub paid_zat: u64,
    /// Sum of valid repayments not mined yet.
    pub pending_zat: u64,
    /// Valid repayments (signed by the buyer, amount equal to the output).
    pub payments: Vec<ReceivedReceipt>,
    /// Repayment receipts for N that failed verification; never counted.
    pub rejected: Vec<ReceivedReceipt>,
}

impl Repayment {
    pub fn status(&self) -> Status {
        if self.paid_zat >= self.due_zat {
            Status::Settled
        } else if self.paid_zat > 0 {
            Status::Partial
        } else if self.pending_zat > 0 {
            Status::Pending
        } else {
            Status::Unpaid
        }
    }
}

/// Matches the financier wallet's received outputs to the invoice: repayment receipts for
/// `nullifier` signed by `buyer_pk` (from the invoice).
pub fn repayment(
    txs: &[WalletTx],
    nullifier: &[u8; 32],
    buyer_pk: &[u8; 32],
    due_zat: u64,
) -> Repayment {
    let (payments, rejected): (Vec<_>, Vec<_>) =
        received(txs, ReceiptKind::Repayment, nullifier, buyer_pk)
            .into_iter()
            .partition(ReceivedReceipt::is_valid);
    let sum = |mined: bool| {
        payments
            .iter()
            .filter(|p| p.mined_height.is_some() == mined)
            .map(|p| p.received_zat)
            .sum()
    };
    Repayment {
        due_zat,
        paid_zat: sum(true),
        pending_zat: sum(false),
        payments,
        rejected,
    }
}

/// `settled` entry for the invoice behind `register`, signed by the financier key.
pub fn settled_entry(financier: &SigningKey, register: &BoardEntry) -> BoardEntry {
    BoardEntry::sign(
        financier,
        EntryKind::Settled,
        settled_tag(&register.nullifier),
        // The register commitment is public; copying it would link the two entries.
        [0; 32],
        register.discount_bucket,
        register.tenor_bucket,
    )
}

impl Financier {
    /// Syncs the financier wallet (memos included) and checks the repayment for `nullifier`.
    pub fn repayment(
        &self,
        nullifier: &[u8; 32],
        buyer_pk: &[u8; 32],
        due_zat: u64,
    ) -> Result<Repayment, Error> {
        self.wallet.sync()?;
        self.wallet.enhance()?;
        Ok(repayment(
            &self.wallet.list_tx()?,
            nullifier,
            buyer_pk,
            due_zat,
        ))
    }

    /// Posts the `settled` entry once mined repayments cover the amount due. Returns the txid, or
    /// the txid of a valid `settled` entry by this financier that is already on the board.
    pub fn post_settled(
        &self,
        register: &BoardRecord,
        repayment: &Repayment,
    ) -> Result<String, Error> {
        if repayment.status() != Status::Settled {
            return Err(Error::NotSettled {
                paid_zat: repayment.paid_zat,
                due_zat: repayment.due_zat,
            });
        }
        let report = scan(&self.board_watch, &self.lightwalletd)?;
        let financier_pk = self.key.verifying_key().to_bytes();
        if let Some(existing) = settled(&report.records, &register.entry.nullifier, &financier_pk) {
            return Ok(existing.txid);
        }
        let entry = settled_entry(&self.key, &register.entry);
        self.wallet.sync()?;
        Ok(self.wallet.pay(&[Payment {
            address: self.board_address.clone(),
            amount_zat: ENTRY_POST_ZAT,
            memo: Some(PaymentMemo::Arbitrary(
                entry.to_memo_bytes()[..ENTRY_LEN].to_vec(),
            )),
        }])?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipts::tests::{receipt_memo, tx};
    use crate::receipts::Verdict;
    use jitsuin_board::{lookup, Lookup, Position};
    use jitsuin_wallet::Memo;

    const N: [u8; 32] = [7; 32];

    fn buyer() -> SigningKey {
        SigningKey::from_bytes(&[2; 32])
    }

    fn repay(k: &SigningKey, amount: u64) -> Memo {
        Memo::Arbitrary(receipt_memo(k, ReceiptKind::Repayment, N, amount))
    }

    #[test]
    fn status_follows_mined_valid_payments() {
        let pk = buyer().verifying_key().to_bytes();
        let forger = SigningKey::from_bytes(&[5; 32]);
        let due = 50_000;
        let status = |txs: &[WalletTx]| repayment(txs, &N, &pk, due).status();

        assert_eq!(status(&[]), Status::Unpaid);
        let pending = tx("p", None, 50_000, true, repay(&buyer(), 50_000));
        assert_eq!(status(std::slice::from_ref(&pending)), Status::Pending);
        let part = tx("a", Some(10), 20_000, true, repay(&buyer(), 20_000));
        assert_eq!(status(&[part.clone(), pending]), Status::Partial);
        let rest = tx("b", Some(11), 30_000, true, repay(&buyer(), 30_000));
        // forged and mismatched receipts are never counted
        let forged = tx("f", Some(9), 50_000, true, repay(&forger, 50_000));
        let short = tx("s", Some(9), 1_000, true, repay(&buyer(), 50_000));
        let txs = [forged, short, part, rest];
        let r = repayment(&txs, &N, &pk, due);
        assert_eq!(r.status(), Status::Settled);
        assert_eq!(r.paid_zat, 50_000);
        assert_eq!(r.payments.len(), 2);
        assert_eq!(r.rejected.len(), 2);
        assert!(matches!(
            r.rejected[1].verdict,
            Verdict::AmountMismatch { .. }
        ));
        // an advance receipt for the same N is not a repayment
        let adv = Memo::Arbitrary(receipt_memo(&buyer(), ReceiptKind::Advance, N, 50_000));
        assert_eq!(
            status(&[tx("x", Some(12), 50_000, true, adv)]),
            Status::Unpaid
        );
    }

    #[test]
    fn settled_entry_is_unlinkable_without_n_and_never_conflicts() {
        let supplier = SigningKey::from_bytes(&[1; 32]);
        let financier = SigningKey::from_bytes(&[3; 32]);
        let register = BoardEntry::sign(&supplier, EntryKind::Register, N, [0xBB; 32], 2, 3);
        let s = settled_entry(&financier, &register);
        assert_eq!(s.kind, EntryKind::Settled);
        assert_ne!(s.nullifier, N);
        assert_eq!(s.nullifier, settled_tag(&N));
        assert_ne!(s.financier_commitment, register.financier_commitment);
        s.verify(&financier.verifying_key().to_bytes()).unwrap();

        let at = |entry, height| BoardRecord {
            txid: format!("t{height}"),
            position: Position {
                height,
                tx_index: 0,
                output_index: 0,
            },
            entry,
        };
        let records = vec![at(register, 1), at(s, 2)];
        assert!(matches!(
            lookup(&records, &N, &supplier.verifying_key().to_bytes()),
            Lookup::Registered { .. }
        ));
        assert_eq!(
            settled(&records, &N, &financier.verifying_key().to_bytes())
                .unwrap()
                .txid,
            "t2"
        );
    }
}
