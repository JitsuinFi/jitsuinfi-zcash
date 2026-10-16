//! Financier side of the repayment (HNK-06.T3, HNK-19.T4): the watchdog matches the buyer's
//! payment to N, derives the settlement status, and countersigns the buyer's claim into a
//! `settled` entry with two signatures (D-19, DEV-08).
//!
//! The watchdog is deterministic and needs only read access plus the financier key for the
//! countersignature: a payment that is not on chain can never become `Settled`, whatever the
//! buyer claims.

use ed25519_dalek::SigningKey;
use jitsuin_board::{lwd, scan, settled};
use jitsuin_core::{ReceiptKind, Seal, SettledEntry, SettlementDoc, SETTLED_LATE, SETTLED_ON_TIME};
use jitsuin_wallet::{Payment, PaymentMemo, WalletTx};

use crate::financier::{Financier, ENTRY_POST_ZAT};
use crate::receipts::{received, ReceivedReceipt};
use crate::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Unpaid,
    /// Valid payments cover the amount but are not mined yet.
    Pending,
    /// Mined valid payments cover part of the amount, before the due date.
    Partial,
    /// The buyer signed "I paid", but no matching payment covers the amount yet.
    Claimed,
    /// Mined valid payments cover the amount.
    Settled,
    /// A buyer claim without a covering payment, past the due date plus the grace period.
    Disputed,
    /// Past the due date, not covered, and no buyer claim.
    Overdue,
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
    /// Buyer claims on the settlement document found in any repayment memo, valid or not.
    pub claims: Vec<Seal>,
}

impl Repayment {
    pub fn status(&self, doc: &SettlementDoc, today: u32, grace_days: u32) -> Status {
        let past_due = today > doc.due_date;
        if self.paid_zat >= self.due_zat {
            Status::Settled
        } else if self.paid_zat + self.pending_zat >= self.due_zat {
            Status::Pending
        } else if !self.claims.is_empty() {
            if today > doc.due_date.saturating_add(grace_days) {
                Status::Disputed
            } else {
                Status::Claimed
            }
        } else if past_due {
            Status::Overdue
        } else if self.paid_zat > 0 {
            Status::Partial
        } else {
            Status::Unpaid
        }
    }

    /// Height of the mined payment that brought the paid sum to the amount due.
    pub fn covering_height(&self) -> Option<u32> {
        let mut mined: Vec<&ReceivedReceipt> = self
            .payments
            .iter()
            .filter(|p| p.mined_height.is_some())
            .collect();
        mined.sort_by_key(|p| p.mined_height);
        let mut sum = 0;
        for p in mined {
            sum += p.received_zat;
            if sum >= self.due_zat {
                return p.mined_height;
            }
        }
        None
    }
}

/// Matches the financier wallet's received outputs to the settlement document: repayment receipts
/// for N signed by `buyer_pk` (from the invoice), plus the buyer's claims in the same memos.
pub fn repayment(txs: &[WalletTx], doc: &SettlementDoc, buyer_pk: &[u8; 32]) -> Repayment {
    let found = received(txs, ReceiptKind::Repayment, &doc.nullifier, buyer_pk);
    let mut claims: Vec<Seal> = Vec::new();
    for s in found.iter().flat_map(|r| r.seals.iter()) {
        if doc.verify_claim(s, buyer_pk).is_ok() && !claims.contains(s) {
            claims.push(s.clone());
        }
    }
    let (payments, rejected): (Vec<_>, Vec<_>) =
        found.into_iter().partition(ReceivedReceipt::is_valid);
    let sum = |mined: bool| {
        payments
            .iter()
            .filter(|p| p.mined_height.is_some() == mined)
            .map(|p| p.received_zat)
            .sum()
    };
    Repayment {
        due_zat: doc.amount_zat,
        paid_zat: sum(true),
        pending_zat: sum(false),
        payments,
        rejected,
        claims,
    }
}

/// Countersigns the buyer's claim once the repayment is settled. `paid_date` (days) of the
/// covering payment decides the flag: on time when it is not after the due date.
pub fn settle(
    financier: &SigningKey,
    doc: &SettlementDoc,
    buyer_pk: &[u8; 32],
    repayment: &Repayment,
    paid_date: u32,
) -> Result<SettledEntry, Error> {
    if repayment.paid_zat < repayment.due_zat {
        return Err(Error::NotSettled {
            paid_zat: repayment.paid_zat,
            due_zat: repayment.due_zat,
        });
    }
    let claim = repayment
        .claims
        .first()
        .ok_or(Error::InvalidDeal("no buyer claim to countersign"))?;
    let flag = if paid_date <= doc.due_date {
        SETTLED_ON_TIME
    } else {
        SETTLED_LATE
    };
    Ok(SettledEntry::countersign(
        doc, claim, buyer_pk, financier, flag,
    )?)
}

impl Financier {
    /// Syncs the financier wallet (memos included) and matches the repayment.
    pub fn repayment(&self, doc: &SettlementDoc, buyer_pk: &[u8; 32]) -> Result<Repayment, Error> {
        self.wallet.sync()?;
        self.wallet.enhance()?;
        Ok(repayment(&self.wallet.list_tx()?, doc, buyer_pk))
    }

    /// Posts the two-signature `settled` entry once mined repayments cover the amount. Returns
    /// the txid and the entry; if a valid one is already on the board, returns that one instead.
    pub fn post_settled(
        &self,
        doc: &SettlementDoc,
        buyer_pk: &[u8; 32],
        repayment: &Repayment,
    ) -> Result<(String, SettledEntry), Error> {
        let height = repayment.covering_height().ok_or(Error::NotSettled {
            paid_zat: repayment.paid_zat,
            due_zat: repayment.due_zat,
        })?;
        let financier_pk = self.key.verifying_key().to_bytes();
        let report = scan(&self.board_watch, &self.lightwalletd)?;
        if let Some(existing) = settled(&report.settled, doc, buyer_pk, &financier_pk) {
            return Ok((existing.txid, existing.entry));
        }
        let paid_date = lwd::block_time(&self.lightwalletd, height)? / 86_400;
        let entry = settle(&self.key, doc, buyer_pk, repayment, paid_date)?;
        self.wallet.sync()?;
        let txid = self.wallet.pay(&[Payment {
            address: self.board_address.clone(),
            amount_zat: ENTRY_POST_ZAT,
            memo: Some(PaymentMemo::Arbitrary(
                entry.to_memo_bytes()[..jitsuin_core::settled::SETTLED_LEN].to_vec(),
            )),
        }])?;
        Ok((txid, entry))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipts::tests::{receipt_memo, tx};
    use jitsuin_core::memo::{self, MemoItem};
    use jitsuin_core::Receipt;
    use jitsuin_wallet::Memo;

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    fn doc() -> SettlementDoc {
        SettlementDoc {
            nullifier: [7; 32],
            amount_zat: 50_000,
            due_date: 100,
        }
    }

    /// Repayment memo as the buyer's QR builds it: receipt + claim.
    fn pay(k: &SigningKey, amount: u64) -> Memo {
        let r = Receipt::sign(k, ReceiptKind::Repayment, doc().nullifier, amount, 99).unwrap();
        let claim = doc().buyer_seal(k);
        Memo::Arbitrary(memo::encode(&[MemoItem::Receipt(r), MemoItem::Seal(claim)]).unwrap())
    }

    #[test]
    fn status_follows_mined_valid_payments_and_claims() {
        let pk = key(2).verifying_key().to_bytes();
        let st = |txs: &[WalletTx], today| repayment(txs, &doc(), &pk).status(&doc(), today, 7);

        assert_eq!(st(&[], 50), Status::Unpaid);
        assert_eq!(st(&[], 101), Status::Overdue);
        let pending = tx("p", None, 50_000, true, pay(&key(2), 50_000));
        assert_eq!(st(std::slice::from_ref(&pending), 50), Status::Pending);
        let part = tx("a", Some(10), 20_000, true, pay(&key(2), 20_000));
        // a partial payment carries a claim too: not covered yet, so Claimed
        assert_eq!(st(std::slice::from_ref(&part), 50), Status::Claimed);
        let rest = tx("b", Some(11), 30_000, true, pay(&key(2), 30_000));
        assert_eq!(st(&[part.clone(), rest.clone()], 50), Status::Settled);

        // forged and mismatched receipts are never counted
        let forged = tx("f", Some(9), 50_000, true, pay(&key(5), 50_000));
        let short = tx("s", Some(9), 1_000, true, pay(&key(2), 50_000));
        let txs = [forged, short.clone(), part, rest];
        let r = repayment(&txs, &doc(), &pk);
        assert_eq!(r.paid_zat, 50_000);
        assert_eq!((r.payments.len(), r.rejected.len()), (2, 2));
        assert_eq!(r.covering_height(), Some(11));

        // a legacy receipt-only memo still counts as payment, but carries no claim
        let legacy = tx(
            "l",
            Some(12),
            50_000,
            true,
            Memo::Arbitrary(receipt_memo(
                &key(2),
                ReceiptKind::Repayment,
                [7; 32],
                50_000,
            )),
        );
        let r = repayment(std::slice::from_ref(&legacy), &doc(), &pk);
        assert_eq!(r.status(&doc(), 50, 7), Status::Settled);
        assert!(r.claims.is_empty());
    }

    #[test]
    fn a_lying_buyer_never_reaches_settled() {
        let pk = key(2).verifying_key().to_bytes();
        // the buyer signs "I paid 50_000" but sends 1_000
        let lie = tx("lie", Some(10), 1_000, true, pay(&key(2), 50_000));
        let r = repayment(std::slice::from_ref(&lie), &doc(), &pk);
        assert_eq!(r.paid_zat, 0);
        assert_eq!(r.claims.len(), 1);
        assert_eq!(r.status(&doc(), 105, 7), Status::Claimed);
        assert_eq!(r.status(&doc(), 108, 7), Status::Disputed);
        assert!(matches!(
            settle(&key(3), &doc(), &pk, &r, 99),
            Err(Error::NotSettled { .. })
        ));
    }

    #[test]
    fn countersigned_entry_verifies_with_both_keys() {
        let (pk, fin_pk) = (
            key(2).verifying_key().to_bytes(),
            key(3).verifying_key().to_bytes(),
        );
        let paid = tx("ok", Some(10), 50_000, true, pay(&key(2), 50_000));
        let r = repayment(std::slice::from_ref(&paid), &doc(), &pk);
        let on_time = settle(&key(3), &doc(), &pk, &r, 100).unwrap();
        on_time.verify(&doc(), &pk, &fin_pk).unwrap();
        assert!(on_time.on_time());
        let late = settle(&key(3), &doc(), &pk, &r, 101).unwrap();
        late.verify(&doc(), &pk, &fin_pk).unwrap();
        assert!(!late.on_time());
        // without a claim there is nothing to countersign
        let mut no_claim = r;
        no_claim.claims.clear();
        assert!(settle(&key(3), &doc(), &pk, &no_claim, 100).is_err());
    }
}
