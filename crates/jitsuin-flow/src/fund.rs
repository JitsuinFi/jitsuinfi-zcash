//! JitsuinFi Vault solvency check (HNK-15.T2): a member holding the full viewing key of the
//! fund's operational account computes, on its own, whether assets cover liabilities.
//!
//! - **Cash:** the account balance (the viewing key sees spends too).
//! - **Receivables:** every advance the account paid with a receivable note (N, face value, due
//!   date) and an advance receipt signed by the manager, minus repayments received for that N.
//!   Past the due date plus grace, the remainder is overdue and counted with a haircut.
//! - **Liabilities:** the total of the latest liability root signed by the manager. That the total
//!   includes every member's deposit is checked against the Merkle sum tree (HNK-15.T1).
//!
//! Members see N, amounts and dates, never the invoice's parties or content.

use std::time::{Duration, Instant};

use jitsuin_core::memo::{self, MemoItem};
use jitsuin_core::{LiabilityRoot, ReceiptKind};
use jitsuin_wallet::{Devtool, Memo, Payment, PaymentMemo, WalletTx};

use crate::financier::Financier;
use crate::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceivableStatus {
    Open,
    Repaid,
    /// Past the due date plus grace and not fully repaid.
    Overdue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receivable {
    pub nullifier: [u8; 32],
    pub face_zat: u64,
    pub due_date: u32,
    pub advance_zat: u64,
    pub advance_txid: String,
    pub repaid_zat: u64,
    pub status: ReceivableStatus,
}

impl Receivable {
    pub fn outstanding_zat(&self) -> u64 {
        self.face_zat.saturating_sub(self.repaid_zat)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundView {
    pub cash_zat: u64,
    pub receivables: Vec<Receivable>,
    /// Latest valid liability root and the txid that carried it.
    pub root: Option<(LiabilityRoot, String)>,
    /// Liability roots seen but not signed by the manager (ignored).
    pub ignored_roots: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SolvencyPolicy {
    /// Share of an overdue receivable written off, in percent (100 = counted as zero).
    pub overdue_haircut_pct: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Solvency {
    pub cash_zat: u64,
    pub open_zat: u64,
    /// Overdue receivables after the haircut.
    pub overdue_zat: u64,
    pub assets_zat: u64,
    pub liabilities_zat: u64,
    pub period: u32,
    pub solvent: bool,
}

fn items(memo: &Memo) -> Vec<MemoItem> {
    match memo {
        Memo::Arbitrary(bytes) => memo::decode(bytes).unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Builds the member's view from the operational account's transactions and balance.
pub fn fund_view(
    txs: &[WalletTx],
    cash_zat: u64,
    manager_pk: &[u8; 32],
    today: u32,
    grace_days: u32,
) -> FundView {
    let mut receivables: Vec<Receivable> = Vec::new();
    let mut roots: Vec<(LiabilityRoot, String, Option<u32>)> = Vec::new();
    let mut ignored_roots = 0;
    let mut repayments: Vec<([u8; 32], u64)> = Vec::new();
    for tx in txs {
        for out in &tx.outputs {
            let its = items(&out.memo);
            for item in &its {
                if let MemoItem::Root(r) = item {
                    if r.verify(manager_pk).is_ok() {
                        roots.push((r.clone(), tx.txid.clone(), tx.mined_height));
                    } else {
                        ignored_roots += 1;
                    }
                }
            }
            if out.received {
                // Money that arrived for an N counts as repayment; the value is on chain.
                for item in &its {
                    if let MemoItem::Receipt(r) = item {
                        if r.kind == ReceiptKind::Repayment {
                            repayments.push((r.nullifier, out.value_zat));
                        }
                    }
                }
                continue;
            }
            if out.is_change {
                continue;
            }
            // An advance paid by the fund: a manager-signed advance receipt plus a note.
            let advance = its.iter().find_map(|i| match i {
                MemoItem::Receipt(r)
                    if r.kind == ReceiptKind::Advance && r.verify(manager_pk).is_ok() =>
                {
                    Some(r.clone())
                }
                _ => None,
            });
            let note = its.iter().find_map(|i| match i {
                MemoItem::Note(n) => Some(*n),
                _ => None,
            });
            if let (Some(adv), Some(note)) = (advance, note) {
                if adv.nullifier == note.nullifier
                    && !receivables.iter().any(|r| r.nullifier == note.nullifier)
                {
                    receivables.push(Receivable {
                        nullifier: note.nullifier,
                        face_zat: note.face_zat,
                        due_date: note.due_date,
                        advance_zat: out.value_zat,
                        advance_txid: tx.txid.clone(),
                        repaid_zat: 0,
                        status: ReceivableStatus::Open,
                    });
                }
            }
        }
    }
    for r in &mut receivables {
        r.repaid_zat = repayments
            .iter()
            .filter(|(n, _)| n == &r.nullifier)
            .map(|(_, v)| v)
            .sum();
        r.status = if r.repaid_zat >= r.face_zat {
            ReceivableStatus::Repaid
        } else if today > r.due_date.saturating_add(grace_days) {
            ReceivableStatus::Overdue
        } else {
            ReceivableStatus::Open
        };
    }
    let root = roots
        .into_iter()
        .max_by_key(|(r, _, h)| (r.period, h.unwrap_or(u32::MAX)))
        .map(|(r, txid, _)| (r, txid));
    FundView {
        cash_zat,
        receivables,
        root,
        ignored_roots,
    }
}

/// Assets (cash + open receivables + overdue after haircut) against the latest liability total.
/// `None` until the manager has posted a liability root.
pub fn solvency(view: &FundView, policy: &SolvencyPolicy) -> Option<Solvency> {
    let (root, _) = view.root.as_ref()?;
    let sum = |s: ReceivableStatus| -> u64 {
        view.receivables
            .iter()
            .filter(|r| r.status == s)
            .map(Receivable::outstanding_zat)
            .sum()
    };
    let open_zat = sum(ReceivableStatus::Open);
    let haircut = policy.overdue_haircut_pct.min(100);
    let overdue_zat = sum(ReceivableStatus::Overdue) * (100 - haircut) / 100;
    let assets_zat = view.cash_zat + open_zat + overdue_zat;
    Some(Solvency {
        cash_zat: view.cash_zat,
        open_zat,
        overdue_zat,
        assets_zat,
        liabilities_zat: root.total_zat,
        period: root.period,
        solvent: assets_zat >= root.total_zat,
    })
}

/// A member's client: syncs the watch-only wallet of the operational account and builds the view.
pub fn member_view(
    fund_watch: &Devtool,
    manager_pk: &[u8; 32],
    today: u32,
    grace_days: u32,
) -> Result<FundView, Error> {
    fund_watch.sync()?;
    fund_watch.enhance()?;
    Ok(fund_view(
        &fund_watch.list_tx()?,
        fund_watch.balance_zat()?,
        manager_pk,
        today,
        grace_days,
    ))
}

/// Value of the self-send that carries a liability root.
pub const ROOT_POST_ZAT: u64 = 10_000;

impl Financier {
    /// Posts the period's liability root (root and total from the Merkle sum tree, HNK-15.T1) as
    /// a self-send from the operational account, so every viewing-key holder sees it.
    pub fn post_liability_root(
        &self,
        period: u32,
        root: [u8; 32],
        total_zat: u64,
    ) -> Result<String, Error> {
        let r = LiabilityRoot::sign(&self.key, period, root, total_zat);
        let memo = memo::encode(&[MemoItem::Root(r)])?;
        self.wallet.sync()?;
        let own = self.wallet.default_address()?;
        Ok(self.wallet.pay(&[Payment {
            address: own,
            amount_zat: ROOT_POST_ZAT,
            memo: Some(PaymentMemo::Arbitrary(memo)),
        }])?)
    }
}

/// Polls `member_view` until `done` holds or `timeout` passes.
pub fn wait_for_view(
    fund_watch: &Devtool,
    manager_pk: &[u8; 32],
    today: u32,
    grace_days: u32,
    timeout: Duration,
    done: impl Fn(&FundView) -> bool,
) -> Result<FundView, Error> {
    let started = Instant::now();
    loop {
        let v = member_view(fund_watch, manager_pk, today, grace_days)?;
        if done(&v) {
            return Ok(v);
        }
        if started.elapsed() >= timeout {
            return Err(Error::Timeout("fund view condition not reached"));
        }
        std::thread::sleep(Duration::from_secs(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use jitsuin_core::{Receipt, ReceivableNote};
    use jitsuin_wallet::TxOutput;

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    fn out(index: u32, value: u64, received: bool, items: &[MemoItem]) -> TxOutput {
        TxOutput {
            index,
            pool: "Ironwood".into(),
            value_zat: value,
            is_change: false,
            received,
            memo: Memo::Arbitrary(memo::encode(items).unwrap()),
        }
    }

    fn tx(txid: &str, height: u32, outputs: Vec<TxOutput>) -> WalletTx {
        WalletTx {
            txid: txid.into(),
            mined_height: Some(height),
            fee_zat: Some(10_000),
            outputs,
        }
    }

    fn advance(signer: &SigningKey, n: u8, paid: u64, face: u64, due: u32) -> Vec<MemoItem> {
        vec![
            MemoItem::Receipt(
                Receipt::sign(signer, ReceiptKind::Advance, [n; 32], paid, 1).unwrap(),
            ),
            MemoItem::Note(ReceivableNote {
                nullifier: [n; 32],
                face_zat: face,
                due_date: due,
            }),
        ]
    }

    fn repay(n: u8, amount: u64) -> Vec<MemoItem> {
        vec![MemoItem::Receipt(
            Receipt::sign(&key(20), ReceiptKind::Repayment, [n; 32], amount, 1).unwrap(),
        )]
    }

    fn root(signer: &SigningKey, period: u32, total: u64) -> Vec<MemoItem> {
        vec![MemoItem::Root(LiabilityRoot::sign(
            signer, period, [9; 32], total,
        ))]
    }

    fn policy() -> SolvencyPolicy {
        SolvencyPolicy {
            overdue_haircut_pct: 100,
        }
    }

    #[test]
    fn member_computes_solvency_from_the_viewing_key() {
        let m = key(3);
        let pk = m.verifying_key().to_bytes();
        let txs = vec![
            tx(
                "a1",
                10,
                vec![out(1, 30_000, false, &advance(&m, 1, 30_000, 40_000, 50))],
            ),
            tx(
                "a2",
                11,
                vec![out(1, 20_000, false, &advance(&m, 2, 20_000, 25_000, 50))],
            ),
            tx(
                "a3",
                12,
                vec![out(1, 9_000, false, &advance(&m, 3, 9_000, 10_000, 20))],
            ),
            // invoice 2 fully repaid, invoice 3 never repaid and past due
            tx("p2", 13, vec![out(0, 25_000, true, &repay(2, 25_000))]),
            tx("r1", 14, vec![out(0, 10_000, true, &root(&m, 1, 200_000))]),
            tx("r2", 15, vec![out(0, 10_000, true, &root(&m, 2, 150_000))]),
            // a root posted by an outsider to the fund's address
            tx("x", 16, vec![out(0, 10_000, true, &root(&key(4), 9, 1))]),
            // an advance signed by someone else is not the fund's receivable
            tx(
                "y",
                17,
                vec![out(
                    1,
                    1_000,
                    false,
                    &advance(&key(4), 7, 1_000, 99_000, 99),
                )],
            ),
        ];
        let v = fund_view(&txs, 100_000, &pk, 40, 7);
        let st: Vec<_> = v.receivables.iter().map(|r| r.status).collect();
        assert_eq!(
            st,
            vec![
                ReceivableStatus::Open,
                ReceivableStatus::Repaid,
                ReceivableStatus::Overdue
            ]
        );
        assert_eq!(v.ignored_roots, 1);
        let (r, txid) = v.root.clone().unwrap();
        assert_eq!((r.period, txid.as_str()), (2, "r2"));
        let s = solvency(&v, &policy()).unwrap();
        // cash 100_000 + open 40_000 + overdue 10_000 written off
        assert_eq!(
            (s.open_zat, s.overdue_zat, s.assets_zat),
            (40_000, 0, 140_000)
        );
        assert_eq!(s.liabilities_zat, 150_000);
        assert!(!s.solvent);
        // with half the overdue counted, still short
        let half = SolvencyPolicy {
            overdue_haircut_pct: 50,
        };
        assert_eq!(solvency(&v, &half).unwrap().assets_zat, 145_000);
        let rich = fund_view(&txs, 120_000, &pk, 40, 7);
        assert!(solvency(&rich, &policy()).unwrap().solvent);
    }

    #[test]
    fn no_root_no_verdict() {
        let pk = key(3).verifying_key().to_bytes();
        let v = fund_view(&[], 1_000, &pk, 1, 7);
        assert!(solvency(&v, &policy()).is_none());
    }
}
