//! Financier side of the repayment (HNK-06.T3, HNK-19.T4): the watchdog matches the buyer's
//! payment to N, derives the settlement status, and countersigns the buyer's claim into a
//! `settled` entry with two signatures (D-19, DEV-08).
//!
//! The watchdog is deterministic and needs only read access plus the financier key for the
//! countersignature: a payment that is not on chain can never become `Settled`, whatever the
//! buyer claims.

use ed25519_dalek::SigningKey;
use jitsuin_board::{lwd, scan, settled};
use jitsuin_core::{
    Receipt, ReceiptKind, Seal, SettledEntry, SettlementDoc, SETTLED_LATE, SETTLED_ON_TIME,
};
use jitsuin_wallet::{Payment, PaymentMemo, WalletTx};

use crate::codec::{Reader, Writer};
use crate::financier::{Financier, ENTRY_POST_ZAT};
use crate::receipts::{received, verdict, ReceivedReceipt};
use crate::Error;

/// Magic and version of a repayment evidence file ([`Evidence::to_bytes`]).
pub const EVIDENCE_MAGIC: &[u8; 4] = b"JTSE";
pub const EVIDENCE_VERSION: u8 = 1;

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

/// One repayment output for N as the financier's wallet saw it, valid or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidencePayment {
    pub txid: String,
    pub mined_height: Option<u32>,
    pub output_index: u32,
    pub received_zat: u64,
    pub receipt: Receipt,
}

/// The repayment of one invoice as the financier exports it when it is claimed, disputed or
/// overdue (HNK-26.T13): the settlement document, the buyer's signed claims "I paid", and every
/// repayment output for N with its txid and buyer-signed receipt. Whoever holds the file checks
/// the signatures with the buyer's key and recomputes the status from its contents
/// ([`Evidence::check`]), so the file cannot state a status of its own. The txids point to the
/// outputs on chain for anyone the financier shows its viewing key. Output values and heights
/// are the financier's reading of its wallet, signed by nobody: only that viewing key confirms
/// them, and only the wallet shows that a payment is missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub doc: SettlementDoc,
    /// The buyer's key from the invoice.
    pub buyer_pk: [u8; 32],
    /// Day the evidence was made and the grace period after the due date; they fix the status.
    pub today: u32,
    pub grace_days: u32,
    /// The buyer's claims on `doc`, each verified.
    pub claims: Vec<Seal>,
    /// Valid repayments first, then rejected ones, each in wallet order.
    pub payments: Vec<EvidencePayment>,
}

impl Evidence {
    pub fn new(
        doc: &SettlementDoc,
        buyer_pk: &[u8; 32],
        repayment: &Repayment,
        today: u32,
        grace_days: u32,
    ) -> Self {
        let payments = repayment
            .payments
            .iter()
            .chain(&repayment.rejected)
            .map(|p| EvidencePayment {
                txid: p.txid.clone(),
                mined_height: p.mined_height,
                output_index: p.output_index,
                received_zat: p.received_zat,
                receipt: p.receipt.clone(),
            })
            .collect();
        Evidence {
            doc: *doc,
            buyer_pk: *buyer_pk,
            today,
            grace_days,
            claims: repayment.claims.clone(),
            payments,
        }
    }

    /// Checks every claim and receipt again and recomputes the repayment and its status, as
    /// [`repayment`] and [`Repayment::status`] do on the wallet.
    pub fn check(&self) -> Result<(Repayment, Status), Error> {
        for c in &self.claims {
            self.doc.verify_claim(c, &self.buyer_pk)?;
        }
        let mut payments = Vec::new();
        let mut rejected = Vec::new();
        for p in &self.payments {
            if p.receipt.kind != ReceiptKind::Repayment || p.receipt.nullifier != self.doc.nullifier
            {
                return Err(Error::Format("receipt is not a repayment of this invoice"));
            }
            let r = ReceivedReceipt {
                txid: p.txid.clone(),
                mined_height: p.mined_height,
                output_index: p.output_index,
                received_zat: p.received_zat,
                receipt: p.receipt.clone(),
                verdict: verdict(&p.receipt, p.received_zat, &self.buyer_pk),
                seals: Vec::new(),
            };
            if r.is_valid() {
                payments.push(r);
            } else {
                rejected.push(r);
            }
        }
        let sum = |mined: bool| {
            payments
                .iter()
                .filter(|p| p.mined_height.is_some() == mined)
                .map(|p| p.received_zat)
                .sum()
        };
        let repayment = Repayment {
            due_zat: self.doc.amount_zat,
            paid_zat: sum(true),
            pending_zat: sum(false),
            payments,
            rejected,
            claims: self.claims.clone(),
        };
        let status = repayment.status(&self.doc, self.today, self.grace_days);
        Ok((repayment, status))
    }

    /// Evidence file, format `JTSE` v1; the console offers it for download.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut w = Writer::default();
        w.raw(EVIDENCE_MAGIC);
        w.byte(EVIDENCE_VERSION);
        w.bytes(&self.doc.to_canonical_bytes())?;
        w.raw(&self.buyer_pk);
        w.u32(self.today);
        w.u32(self.grace_days);
        w.seals(&self.claims)?;
        let n =
            u16::try_from(self.payments.len()).map_err(|_| Error::Format("too many payments"))?;
        w.raw(&n.to_le_bytes());
        for p in &self.payments {
            w.str(&p.txid)?;
            match p.mined_height {
                None => w.byte(0),
                Some(h) => {
                    w.byte(1);
                    w.u32(h);
                }
            }
            w.u32(p.output_index);
            w.u64(p.received_zat);
            w.receipt(&p.receipt);
        }
        Ok(w.out)
    }

    /// Strict decoder. Does not verify; call [`Evidence::check`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.take(4)? != EVIDENCE_MAGIC {
            return Err(Error::Format("not a repayment evidence file"));
        }
        if r.byte()? != EVIDENCE_VERSION {
            return Err(Error::Format("unsupported evidence version"));
        }
        let doc = SettlementDoc::from_canonical_bytes(r.bytes()?)?;
        let buyer_pk = r.array()?;
        let today = r.u32()?;
        let grace_days = r.u32()?;
        let claims = r.seals()?;
        let n = u16::from_le_bytes(r.array()?);
        let mut payments = Vec::with_capacity(usize::from(n));
        for _ in 0..n {
            payments.push(EvidencePayment {
                txid: r.str()?,
                mined_height: match r.byte()? {
                    0 => None,
                    1 => Some(r.u32()?),
                    _ => return Err(Error::Format("malformed evidence file")),
                },
                output_index: r.u32()?,
                received_zat: r.u64()?,
                receipt: r.receipt()?,
            });
        }
        r.finish()?;
        Ok(Evidence {
            doc,
            buyer_pk,
            today,
            grace_days,
            claims,
            payments,
        })
    }
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
    fn evidence_recomputes_the_status_from_signed_contents() {
        let pk = key(2).verifying_key().to_bytes();
        // the buyer claims 50_000 and sends 1_000; a forged receipt arrives too
        let lie = tx("lie", Some(10), 1_000, true, pay(&key(2), 50_000));
        let forged = tx("f", Some(9), 50_000, true, pay(&key(5), 50_000));
        let r = repayment(&[lie, forged], &doc(), &pk);

        let disputed = Evidence::new(&doc(), &pk, &r, 108, 7);
        let bytes = disputed.to_bytes().unwrap();
        assert_eq!(&bytes[..4], EVIDENCE_MAGIC);
        let back = Evidence::from_bytes(&bytes).unwrap();
        assert_eq!(back, disputed);
        let (rep, status) = back.check().unwrap();
        assert_eq!(status, Status::Disputed);
        assert_eq!((rep.paid_zat, rep.claims.len()), (0, 1));
        assert_eq!((rep.payments.len(), rep.rejected.len()), (0, 2));
        assert_eq!(back.payments[0].txid, "lie");
        // the same file within the grace period: Claimed
        let claimed = Evidence::new(&doc(), &pk, &r, 105, 7);
        assert_eq!(claimed.check().unwrap().1, Status::Claimed);
        // no claim and no payment after the due date: Overdue
        let none = repayment(&[], &doc(), &pk);
        let overdue = Evidence::new(&doc(), &pk, &none, 101, 7);
        assert_eq!(
            Evidence::from_bytes(&overdue.to_bytes().unwrap())
                .unwrap()
                .check()
                .unwrap()
                .1,
            Status::Overdue
        );
    }

    #[test]
    fn edited_evidence_is_refused() {
        let pk = key(2).verifying_key().to_bytes();
        let lie = tx("lie", Some(10), 1_000, true, pay(&key(2), 50_000));
        let r = repayment(std::slice::from_ref(&lie), &doc(), &pk);
        let good = Evidence::new(&doc(), &pk, &r, 108, 7);

        // a claim by another key
        let mut other_claim = good.clone();
        other_claim.claims = vec![doc().buyer_seal(&key(5))];
        assert!(other_claim.check().is_err());
        // a receipt for another invoice
        let mut other_n = good.clone();
        other_n.payments[0].receipt =
            Receipt::sign(&key(2), ReceiptKind::Repayment, [8; 32], 50_000, 99).unwrap();
        assert!(other_n.check().is_err());
        // an advance receipt in place of a repayment
        let mut advance = good.clone();
        advance.payments[0].receipt =
            Receipt::sign(&key(2), ReceiptKind::Advance, doc().nullifier, 50_000, 99).unwrap();
        assert!(advance.check().is_err());
        // a changed receipt amount breaks the buyer's signature: never counted
        let mut amount = good.clone();
        amount.payments[0].receipt.amount_zat = 1_000;
        assert_eq!(amount.check().unwrap().0.paid_zat, 0);

        let bytes = good.to_bytes().unwrap();
        let mut bad = bytes.clone();
        bad[0] = b'X';
        assert!(matches!(Evidence::from_bytes(&bad), Err(Error::Format(_))));
        let mut bad = bytes.clone();
        bad[4] = 2;
        assert!(matches!(Evidence::from_bytes(&bad), Err(Error::Format(_))));
        let mut bad = bytes.clone();
        bad.push(0);
        assert!(matches!(Evidence::from_bytes(&bad), Err(Error::Format(_))));
        assert!(Evidence::from_bytes(&bytes[..bytes.len() - 1]).is_err());
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
