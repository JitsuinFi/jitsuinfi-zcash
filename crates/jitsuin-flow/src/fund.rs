//! JitsuinFi Vault solvency check (HNK-15.T2): a member holding the full viewing key of the
//! fund's operational account computes, on its own, whether assets cover liabilities.
//!
//! - **Cash:** the account balance (the viewing key sees spends too).
//! - **Receivables:** every advance the account paid with a receivable note (N, face value, due
//!   date) and an advance receipt signed by the manager, minus repayments received for that N.
//!   Past the due date plus grace, the remainder is overdue and counted with a haircut: 100 % in
//!   the JitsuinFi node and `jitsuin fund` (user decision 2026-10-25), so it counts 0 until its
//!   repayment is on chain.
//! - **Liabilities:** the total of the latest liability root signed by the manager. That the total
//!   includes every member's deposit is checked against the Merkle sum tree (HNK-15.T1).
//!
//! Members see N, amounts and dates, never the invoice's parties or content.
//!
//! **Books (user decision 2026-10-25).** The operational account is also the manager's own
//! wallet, so its balance is not the fund's money. [`fund_books`] values the fund on its books
//! instead: the deposits the manager recorded and their flows (advances the fund paid out of
//! them, repayments of those advances, payouts to members), every value read from the chain.
//! [`book_solvency`] compares those assets with the liability root and checks that the wallet
//! holds at least the books' cash. [`solvency`] on a wallet view is the old, wallet-wide figure.

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

/// The fund's own transactions, as the manager's ledger lists them (user decision 2026-10-25:
/// the fund's assets are its members' money, not the whole wallet the fund shares with the
/// manager's own deals). Txids only: every value is read from the chain with the viewing key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FundBooks {
    /// Member deposits recorded by the manager (`fund.receipt`).
    pub deposits: Vec<String>,
    /// Payout transactions of past closes (`fund.payout`).
    pub payouts: Vec<String>,
}

/// One listed transaction and the value the chain shows for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BookLine {
    pub txid: String,
    pub amount_zat: u64,
}

/// The fund valued on its books (see [`fund_books`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Books {
    /// The fund alone: `cash_zat` is the books' cash, `receivables` only the advances the fund
    /// paid. Same root as the wallet view. [`solvency`] and the node's valuation read this.
    pub view: FundView,
    /// The balance of the whole wallet the fund shares with the manager.
    pub wallet_zat: u64,
    pub deposits: Vec<BookLine>,
    pub payouts: Vec<BookLine>,
    /// Listed txids the wallet does not show as mined (ignored, counted as 0).
    pub missing: Vec<String>,
    /// Advances the fund paid and repayments it got back for them.
    pub advanced_zat: u64,
    pub repaid_zat: u64,
}

fn received_zat(tx: &WalletTx) -> u64 {
    tx.outputs
        .iter()
        .filter(|o| o.received && !o.is_change)
        .map(|o| o.value_zat)
        .sum()
}

fn sent_zat(tx: &WalletTx) -> u64 {
    tx.outputs
        .iter()
        .filter(|o| !o.received && !o.is_change)
        .map(|o| o.value_zat)
        .sum()
}

/// The fund's books, replayed in chain order (height, then txid) from the wallet's transactions:
///
/// - **in:** the listed deposits (value received, change excluded);
/// - **out:** the listed payouts (value sent to others);
/// - **advances:** a receivable of `view` (manager-signed advance receipt and note) is the fund's
///   when the books' cash covered the whole advance at that point; the cash goes down by the
///   advance and the receivable counts as the fund's asset. Any other advance was paid with the
///   manager's own money and is not the fund's, nor are its repayments;
/// - **back:** repayments received for the fund's receivables.
///
/// The rule is fixed and replayed from the chain, so the manager cannot choose after the fact
/// which deals the fund financed. Network fees are not on the books: the wallet pays them.
pub fn fund_books(view: &FundView, txs: &[WalletTx], books: &FundBooks) -> Books {
    let mut mined: Vec<&WalletTx> = txs.iter().filter(|t| t.mined_height.is_some()).collect();
    mined.sort_by(|a, b| (a.mined_height, &a.txid).cmp(&(b.mined_height, &b.txid)));
    let listed = |ids: &[String]| -> Vec<String> {
        let mut seen = Vec::new();
        for id in ids {
            if !seen.contains(id) {
                seen.push(id.clone());
            }
        }
        seen
    };
    let (deposit_ids, payout_ids) = (listed(&books.deposits), listed(&books.payouts));
    let mut cash: u64 = 0;
    let mut mine: Vec<[u8; 32]> = Vec::new();
    let (mut deposits, mut payouts) = (Vec::new(), Vec::new());
    let (mut advanced_zat, mut repaid_zat) = (0u64, 0u64);
    for tx in mined {
        if deposit_ids.contains(&tx.txid) {
            let v = received_zat(tx);
            cash = cash.saturating_add(v);
            deposits.push(BookLine {
                txid: tx.txid.clone(),
                amount_zat: v,
            });
            continue;
        }
        if payout_ids.contains(&tx.txid) {
            let v = sent_zat(tx);
            cash = cash.saturating_sub(v);
            payouts.push(BookLine {
                txid: tx.txid.clone(),
                amount_zat: v,
            });
            continue;
        }
        if let Some(r) = view.receivables.iter().find(|r| r.advance_txid == tx.txid) {
            if !mine.contains(&r.nullifier) && cash >= r.advance_zat {
                cash -= r.advance_zat;
                advanced_zat += r.advance_zat;
                mine.push(r.nullifier);
            }
            continue;
        }
        for out in tx.outputs.iter().filter(|o| o.received) {
            for item in items(&out.memo) {
                if let MemoItem::Receipt(r) = item {
                    if r.kind == ReceiptKind::Repayment && mine.contains(&r.nullifier) {
                        cash = cash.saturating_add(out.value_zat);
                        repaid_zat += out.value_zat;
                    }
                }
            }
        }
    }
    let missing = deposit_ids
        .iter()
        .chain(payout_ids.iter())
        .filter(|id| {
            !deposits.iter().any(|l: &BookLine| &l.txid == *id)
                && !payouts.iter().any(|l: &BookLine| &l.txid == *id)
        })
        .cloned()
        .collect();
    Books {
        view: FundView {
            cash_zat: cash,
            receivables: view
                .receivables
                .iter()
                .filter(|r| mine.contains(&r.nullifier))
                .cloned()
                .collect(),
            root: view.root.clone(),
            ignored_roots: view.ignored_roots,
        },
        wallet_zat: view.cash_zat,
        deposits,
        payouts,
        missing,
        advanced_zat,
        repaid_zat,
    }
}

/// The verdict on the fund's books (see [`fund_books`]).
///
/// What it shows: (1) the books' assets (cash, plus the fund's open receivables, plus overdue ones
/// after the haircut) are at least the total of the latest manager-signed liability root, which
/// counts the units at par, so the fund is not below par; and (2) the wallet holds at least the
/// books' cash right now, so that cash exists.
///
/// What it does not show: that the money is set apart for the fund (the wallet is shared with the
/// manager, whose own spending can lower it after the check); that the deposit list is complete
/// (each member checks that their own deposit is listed); that a receivable note is a real
/// invoice (a bad one shows only once it is overdue).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BookSolvency {
    pub solvency: Solvency,
    pub wallet_zat: u64,
    /// The wallet holds at least the books' cash.
    pub wallet_covers: bool,
    /// Assets cover the liabilities and the wallet covers the cash.
    pub solvent: bool,
}

/// [`solvency`] of the books, plus the wallet check. `None` until a liability root is posted.
pub fn book_solvency(books: &Books, policy: &SolvencyPolicy) -> Option<BookSolvency> {
    let s = solvency(&books.view, policy)?;
    let wallet_covers = books.wallet_zat >= books.view.cash_zat;
    Some(BookSolvency {
        solvency: s,
        wallet_zat: books.wallet_zat,
        wallet_covers,
        solvent: s.solvent && wallet_covers,
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

/// [`member_view`] valued on the fund's books (see [`fund_books`]).
pub fn member_books(
    fund_watch: &Devtool,
    manager_pk: &[u8; 32],
    today: u32,
    grace_days: u32,
    books: &FundBooks,
) -> Result<Books, Error> {
    fund_watch.sync()?;
    fund_watch.enhance()?;
    let txs = fund_watch.list_tx()?;
    let view = fund_view(
        &txs,
        fund_watch.balance_zat()?,
        manager_pk,
        today,
        grace_days,
    );
    Ok(fund_books(&view, &txs, books))
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

    fn plain(index: u32, value: u64, received: bool, is_change: bool) -> TxOutput {
        TxOutput {
            index,
            pool: "Ironwood".into(),
            value_zat: value,
            is_change,
            received,
            memo: Memo::Empty,
        }
    }

    fn deposit(txid: &str, height: u32, value: u64) -> WalletTx {
        tx(txid, height, vec![plain(0, value, true, false)])
    }

    /// A payout to a member, with the wallet's change.
    fn payout(txid: &str, height: u32, value: u64) -> WalletTx {
        tx(
            txid,
            height,
            vec![plain(0, value, false, false), plain(1, 5_000, true, true)],
        )
    }

    #[test]
    fn the_books_count_member_deposits_not_the_whole_wallet() {
        let m = key(3);
        let pk = m.verifying_key().to_bytes();
        let txs = vec![
            // the manager's own money in the same wallet
            deposit("own", 5, 300_000_000),
            deposit("d1", 10, 30_000),
            deposit("d2", 11, 20_000),
            tx("r1", 12, vec![out(0, 10_000, true, &root(&m, 1, 50_000))]),
        ];
        let books = FundBooks {
            deposits: vec!["d1".into(), "d2".into()],
            payouts: vec![],
        };
        let wallet = 300_060_000;
        let v = fund_view(&txs, wallet, &pk, 40, 7);
        let b = fund_books(&v, &txs, &books);
        assert_eq!(b.view.cash_zat, 50_000);
        assert_eq!(b.wallet_zat, wallet);
        assert!(b.missing.is_empty());
        let s = book_solvency(&b, &policy()).unwrap();
        // 50 000 zat of assets for 50 000 units: one zat per unit, as deposited
        assert_eq!(
            (s.solvency.assets_zat, s.solvency.liabilities_zat),
            (50_000, 50_000)
        );
        assert!(s.wallet_covers && s.solvent);
        // the wallet-wide figure is what the books replace
        assert_eq!(solvency(&v, &policy()).unwrap().assets_zat, wallet);
    }

    #[test]
    fn the_fund_finances_an_advance_only_from_its_own_cash() {
        let m = key(3);
        let pk = m.verifying_key().to_bytes();
        let txs = vec![
            deposit("own", 1, 1_000_000),
            // before any deposit: the manager's own advance
            tx(
                "a0",
                2,
                vec![out(1, 90_000, false, &advance(&m, 1, 90_000, 100_000, 50))],
            ),
            deposit("d1", 3, 100_000),
            // more than the books hold: the manager's own again
            tx(
                "a1",
                4,
                vec![out(
                    1,
                    150_000,
                    false,
                    &advance(&m, 2, 150_000, 160_000, 50),
                )],
            ),
            // covered by the books: the fund's
            tx(
                "a2",
                5,
                vec![out(1, 80_000, false, &advance(&m, 3, 80_000, 90_000, 50))],
            ),
            tx("p0", 6, vec![out(0, 100_000, true, &repay(1, 100_000))]),
            tx("p2", 7, vec![out(0, 90_000, true, &repay(3, 90_000))]),
            payout("w1", 8, 30_000),
            tx("r1", 9, vec![out(0, 10_000, true, &root(&m, 1, 100_000))]),
        ];
        let books = FundBooks {
            deposits: vec!["d1".into(), "d1".into(), "gone".into()],
            payouts: vec!["w1".into()],
        };
        let v = fund_view(&txs, 900_000, &pk, 40, 7);
        assert_eq!(v.receivables.len(), 3);
        let b = fund_books(&v, &txs, &books);
        // 100 000 in, 80 000 out to invoice 3, 90 000 back, 30 000 paid to a member
        assert_eq!(b.view.cash_zat, 80_000);
        assert_eq!((b.advanced_zat, b.repaid_zat), (80_000, 90_000));
        assert_eq!(b.view.receivables.len(), 1);
        assert_eq!(b.view.receivables[0].nullifier, [3; 32]);
        assert_eq!(b.deposits.len(), 1);
        assert_eq!(b.payouts[0].amount_zat, 30_000);
        assert_eq!(b.missing, vec!["gone".to_string()]);
        let s = book_solvency(&b, &policy()).unwrap();
        assert_eq!(s.solvency.assets_zat, 80_000);
        assert!(!s.solvent, "80 000 of assets for 100 000 units at par");
        // a wallet that holds less than the books' cash fails the check, whatever the books say
        let poor = Books {
            wallet_zat: 70_000,
            ..b.clone()
        };
        let mut rich_books = poor.clone();
        rich_books.view.cash_zat = 120_000;
        let s = book_solvency(&rich_books, &policy()).unwrap();
        assert!(s.solvency.solvent && !s.wallet_covers && !s.solvent);
    }

    #[test]
    fn an_overdue_fund_advance_counts_zero_until_its_repayment_is_cash() {
        let m = key(3);
        let pk = m.verifying_key().to_bytes();
        let mut txs = vec![
            deposit("d1", 1, 100_000),
            tx(
                "a1",
                2,
                vec![out(1, 80_000, false, &advance(&m, 4, 80_000, 90_000, 50))],
            ),
            tx("r1", 3, vec![out(0, 10_000, true, &root(&m, 1, 100_000))]),
        ];
        let books = FundBooks {
            deposits: vec!["d1".into()],
            payouts: vec![],
        };
        let at = |txs: &[WalletTx], today: u32| {
            let v = fund_view(txs, 1_000_000, &pk, today, 7);
            book_solvency(&fund_books(&v, txs, &books), &policy()).unwrap()
        };
        assert_eq!(at(&txs, 40).solvency.assets_zat, 110_000);
        // overdue and unpaid: written off in full
        let late = at(&txs, 100);
        assert_eq!(
            (late.solvency.overdue_zat, late.solvency.assets_zat),
            (0, 20_000)
        );
        assert!(!late.solvent);
        // its repayment on chain comes back as cash
        txs.push(tx("p1", 4, vec![out(0, 90_000, true, &repay(4, 90_000))]));
        let paid = at(&txs, 100);
        assert_eq!(
            (paid.solvency.cash_zat, paid.solvency.assets_zat),
            (110_000, 110_000)
        );
        assert!(paid.solvent);
    }

    #[test]
    fn no_root_no_verdict() {
        let pk = key(3).verifying_key().to_bytes();
        let v = fund_view(&[], 1_000, &pk, 1, 7);
        assert!(solvency(&v, &policy()).is_none());
    }
}
