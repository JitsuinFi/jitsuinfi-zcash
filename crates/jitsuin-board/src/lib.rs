//! JitsuinFi registry board scanner (HNK-04).
//!
//! The board is a Zcash account that only receives; its viewing key is shared so anyone can scan
//! it with a watch-only wallet. Two views:
//! - public: every entry with a valid format, in total order (height, tx index, output index);
//! - holder of an invoice: [`lookup`] verifies supplier signatures for one nullifier, ignores
//!   entries without a valid signature (anti-griefing), and reports double financing.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

use jitsuin_core::entry::ENTRY_MAGIC;
use jitsuin_core::{
    nullifier, settled_tag, BoardEntry, Bundle, EntryKind, SettledEntry, SettlementDoc,
};
use jitsuin_wallet::{Devtool, Memo};

pub mod history;
pub mod lwd;

#[derive(Debug)]
pub enum Error {
    Wallet(jitsuin_wallet::Error),
    Lightwalletd(String),
    /// A mined transaction from the wallet was not found in its block.
    Ordering(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Wallet(e) => write!(f, "wallet: {e}"),
            Error::Lightwalletd(m) => write!(f, "lightwalletd: {m}"),
            Error::Ordering(m) => write!(f, "ordering: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<jitsuin_wallet::Error> for Error {
    fn from(e: jitsuin_wallet::Error) -> Self {
        Error::Wallet(e)
    }
}

/// Position of an output on chain. Ordering = (height, tx index, output index).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Position {
    pub height: u32,
    pub tx_index: u32,
    pub output_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardRecord {
    pub txid: String,
    pub position: Position,
    pub entry: BoardEntry,
}

/// A `settled` entry (two signatures, no N) at its position on chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettledRecord {
    pub txid: String,
    pub position: Position,
    pub entry: SettledEntry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    pub txid: String,
    pub output_index: u32,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct ScanReport {
    /// Format-valid register entries in total order.
    pub records: Vec<BoardRecord>,
    /// Format-valid `settled` entries in total order.
    pub settled: Vec<SettledRecord>,
    /// Arbitrary-data memos that are not valid entries.
    pub rejected: Vec<Rejected>,
    /// Mined transactions that touched the board.
    pub transactions: usize,
    /// Transactions not mined yet (ignored until mined).
    pub pending: usize,
    pub elapsed: Duration,
}

/// Result of checking one nullifier as a holder of the invoice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    NotFound {
        ignored_invalid: Vec<BoardRecord>,
    },
    Registered {
        winner: BoardRecord,
        ignored_invalid: Vec<BoardRecord>,
    },
    /// Same nullifier signed by the supplier for more than one financier commitment.
    DoubleFinanced {
        winner: BoardRecord,
        conflicting: Vec<BoardRecord>,
        ignored_invalid: Vec<BoardRecord>,
    },
}

/// Board outputs decoded into register entries, settled entries and rejected memos.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Collected {
    pub records: Vec<BoardRecord>,
    pub settled: Vec<SettledRecord>,
    pub rejected: Vec<Rejected>,
}

/// Decodes board outputs. `tx_order` maps txid to its index inside its block.
pub fn collect(
    txs: &[jitsuin_wallet::WalletTx],
    tx_order: &HashMap<String, u32>,
) -> Result<Collected, Error> {
    let mut out = Collected::default();
    for tx in txs {
        let Some(height) = tx.mined_height else {
            continue;
        };
        let tx_index = *tx_order
            .get(&tx.txid)
            .ok_or_else(|| Error::Ordering(format!("{} not found in block {height}", tx.txid)))?;
        for o in tx.outputs.iter().filter(|o| o.received) {
            let Memo::Arbitrary(bytes) = &o.memo else {
                continue;
            };
            let position = Position {
                height,
                tx_index,
                output_index: o.index,
            };
            let txid = tx.txid.clone();
            let is_settled = bytes.get(1..5) == Some(ENTRY_MAGIC.as_slice())
                && bytes.get(5) == Some(&(EntryKind::Settled as u8));
            let decoded = if is_settled {
                SettledEntry::from_memo_bytes(bytes).map(|entry| {
                    out.settled.push(SettledRecord {
                        txid: txid.clone(),
                        position,
                        entry,
                    })
                })
            } else {
                BoardEntry::from_memo_bytes(bytes).map(|entry| {
                    out.records.push(BoardRecord {
                        txid: txid.clone(),
                        position,
                        entry,
                    })
                })
            };
            if let Err(e) = decoded {
                out.rejected.push(Rejected {
                    txid,
                    output_index: o.index,
                    reason: e.to_string(),
                });
            }
        }
    }
    out.records.sort_by_key(|r| r.position);
    out.settled.sort_by_key(|r| r.position);
    Ok(out)
}

/// First valid register entry for `nullifier` wins. Entries whose supplier signature does not verify
/// with `supplier_ephemeral_pk` are ignored. Re-posting the same financier commitment is not a
/// conflict. Only register entries count; `settled` entries never block or conflict.
pub fn lookup(
    records: &[BoardRecord],
    nullifier: &[u8; 32],
    supplier_ephemeral_pk: &[u8; 32],
) -> Lookup {
    let mut valid: Vec<BoardRecord> = Vec::new();
    let mut ignored_invalid = Vec::new();
    for r in records
        .iter()
        .filter(|r| r.entry.kind.is_register() && &r.entry.nullifier == nullifier)
    {
        if r.entry.verify(supplier_ephemeral_pk).is_ok() {
            valid.push(r.clone());
        } else {
            ignored_invalid.push(r.clone());
        }
    }
    valid.sort_by_key(|r| r.position);
    let mut iter = valid.into_iter();
    let Some(winner) = iter.next() else {
        return Lookup::NotFound { ignored_invalid };
    };
    let conflicting: Vec<BoardRecord> = iter
        .filter(|r| r.entry.financier_commitment != winner.entry.financier_commitment)
        .collect();
    if conflicting.is_empty() {
        Lookup::Registered {
            winner,
            ignored_invalid,
        }
    } else {
        Lookup::DoubleFinanced {
            winner,
            conflicting,
            ignored_invalid,
        }
    }
}

/// First `settled` entry for the settlement document that verifies with both keys (buyer from the
/// invoice, financier from the assignment letter). Forged or one-sided entries are ignored.
pub fn settled(
    settled: &[SettledRecord],
    doc: &SettlementDoc,
    buyer_pk: &[u8; 32],
    financier_pk: &[u8; 32],
) -> Option<SettledRecord> {
    let tag = settled_tag(&doc.nullifier);
    settled
        .iter()
        .filter(|r| r.entry.tag == tag)
        .find(|r| r.entry.verify(doc, buyer_pk, financier_pk).is_ok())
        .cloned()
}

/// Board view of a verification bundle (HNK-19.T6): the register lookup for its N and, when the
/// bundle has a settlement document, the matching two-signature `settled` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleOnBoard {
    pub register: Lookup,
    pub settled: Option<SettledRecord>,
}

pub fn bundle_on_board(
    bundle: &Bundle,
    records: &[BoardRecord],
    settled_records: &[SettledRecord],
) -> Result<BundleOnBoard, jitsuin_core::Error> {
    let n = nullifier(&bundle.invoice)?;
    let register = lookup(records, &n, &bundle.invoice.supplier_ephemeral_pk);
    let settled = match (&bundle.settlement, &bundle.assignment) {
        (Some(doc), Some(a)) => settled(
            settled_records,
            doc,
            &bundle.invoice.buyer_pk,
            &a.financier_pk,
        ),
        _ => None,
    };
    Ok(BundleOnBoard { register, settled })
}

/// Syncs the watch-only board wallet, fetches full transactions (memos), resolves tx order from
/// lightwalletd, and returns every entry in total order.
pub fn scan(watch: &Devtool, lightwalletd: &str) -> Result<ScanReport, Error> {
    let started = Instant::now();
    watch.sync()?;
    watch.enhance()?;
    let txs = watch.list_tx()?;
    let pending = txs.iter().filter(|t| t.mined_height.is_none()).count();
    let mut tx_order = HashMap::new();
    let mut heights: Vec<u32> = txs.iter().filter_map(|t| t.mined_height).collect();
    heights.sort_unstable();
    heights.dedup();
    for h in heights {
        for (i, txid) in lwd::block_txids(lightwalletd, h)?.into_iter().enumerate() {
            tx_order.insert(txid, i as u32);
        }
    }
    let Collected {
        records,
        settled,
        rejected,
    } = collect(&txs, &tx_order)?;
    Ok(ScanReport {
        records,
        settled,
        rejected,
        transactions: txs.len() - pending,
        pending,
        elapsed: started.elapsed(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use jitsuin_core::EntryKind;
    use jitsuin_wallet::{TxOutput, WalletTx};

    fn rec(
        signer: &SigningKey,
        n: u8,
        commitment: u8,
        height: u32,
        tx_index: u32,
        out: u32,
    ) -> BoardRecord {
        BoardRecord {
            txid: format!("{height}-{tx_index}"),
            position: Position {
                height,
                tx_index,
                output_index: out,
            },
            entry: BoardEntry::sign(signer, EntryKind::Register, [n; 32], [commitment; 32], 0, 0),
        }
    }

    #[test]
    fn first_valid_entry_wins_and_double_financing_is_reported() {
        let supplier = SigningKey::from_bytes(&[1; 32]);
        let griefer = SigningKey::from_bytes(&[9; 32]);
        let pk = supplier.verifying_key().to_bytes();
        let records = vec![
            rec(&griefer, 7, 0xAA, 100, 0, 0), // earliest, but not signed by the supplier
            rec(&supplier, 7, 0xBB, 100, 2, 0),
            rec(&supplier, 7, 0xBB, 101, 0, 0), // re-post, same commitment
            rec(&supplier, 7, 0xCC, 102, 1, 0), // second financier
            rec(&supplier, 8, 0xDD, 99, 0, 0),
        ];
        match lookup(&records, &[7; 32], &pk) {
            Lookup::DoubleFinanced {
                winner,
                conflicting,
                ignored_invalid,
            } => {
                assert_eq!(
                    winner.position,
                    Position {
                        height: 100,
                        tx_index: 2,
                        output_index: 0
                    }
                );
                assert_eq!(conflicting.len(), 1);
                assert_eq!(conflicting[0].entry.financier_commitment, [0xCC; 32]);
                assert_eq!(ignored_invalid.len(), 1);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(
            lookup(&records, &[8; 32], &pk),
            Lookup::Registered { .. }
        ));
        assert!(matches!(
            lookup(&records, &[9; 32], &pk),
            Lookup::NotFound { .. }
        ));
    }

    #[test]
    fn settled_entries_are_separate_and_need_both_signatures() {
        let supplier = SigningKey::from_bytes(&[1; 32]);
        let buyer = SigningKey::from_bytes(&[2; 32]);
        let financier = SigningKey::from_bytes(&[3; 32]);
        let (buyer_pk, fin_pk) = (
            buyer.verifying_key().to_bytes(),
            financier.verifying_key().to_bytes(),
        );
        let doc = SettlementDoc {
            nullifier: [7; 32],
            amount_zat: 50_000,
            due_date: 10,
        };
        let entry = |b: &SigningKey, f: &SigningKey| {
            SettledEntry::countersign(
                &doc,
                &doc.buyer_seal(b),
                &b.verifying_key().to_bytes(),
                f,
                jitsuin_core::SETTLED_ON_TIME,
            )
            .unwrap()
        };
        let out = |index, memo: Vec<u8>| TxOutput {
            index,
            pool: "Ironwood".into(),
            value_zat: 10_000,
            is_change: false,
            received: true,
            memo: Memo::Arbitrary(memo),
        };
        let register = BoardEntry::sign(&supplier, EntryKind::Register, [7; 32], [0xBB; 32], 0, 0);
        let txs = vec![WalletTx {
            txid: "t".into(),
            mined_height: Some(5),
            fee_zat: None,
            outputs: vec![
                out(0, register.to_memo_bytes().to_vec()),
                // forged: the "buyer" claim is signed by the financier's colleague
                out(
                    1,
                    entry(&SigningKey::from_bytes(&[8; 32]), &financier)
                        .to_memo_bytes()
                        .to_vec(),
                ),
                out(2, entry(&buyer, &financier).to_memo_bytes().to_vec()),
            ],
        }];
        let order: HashMap<String, u32> = [("t".into(), 0)].into_iter().collect();
        let c = collect(&txs, &order).unwrap();
        assert_eq!(
            (c.records.len(), c.settled.len(), c.rejected.len()),
            (1, 2, 0)
        );
        assert!(matches!(
            lookup(&c.records, &[7; 32], &supplier.verifying_key().to_bytes()),
            Lookup::Registered { .. }
        ));
        let found = settled(&c.settled, &doc, &buyer_pk, &fin_pk).unwrap();
        assert_eq!(found.position.output_index, 2);
        let mut other = doc;
        other.amount_zat += 1;
        assert!(settled(&c.settled, &other, &buyer_pk, &fin_pk).is_none());
    }

    #[test]
    fn repost_with_same_commitment_is_not_a_conflict() {
        let s = SigningKey::from_bytes(&[1; 32]);
        let records = vec![rec(&s, 3, 0xBB, 10, 0, 0), rec(&s, 3, 0xBB, 11, 0, 0)];
        assert!(matches!(
            lookup(&records, &[3; 32], &s.verifying_key().to_bytes()),
            Lookup::Registered { .. }
        ));
    }

    #[test]
    fn collect_orders_and_rejects_bad_memos() {
        let s = SigningKey::from_bytes(&[1; 32]);
        let good = BoardEntry::sign(&s, EntryKind::Register, [1; 32], [2; 32], 0, 0)
            .to_memo_bytes()
            .to_vec();
        let mut bad = good.clone();
        bad[1] = b'X';
        let out = |index, memo: Vec<u8>, received| TxOutput {
            index,
            pool: "Ironwood".into(),
            value_zat: 10_000,
            is_change: false,
            received,
            memo: Memo::Arbitrary(memo),
        };
        let txs = vec![
            WalletTx {
                txid: "b".into(),
                mined_height: Some(5),
                fee_zat: None,
                outputs: vec![out(1, good.clone(), true), out(0, bad, true)],
            },
            WalletTx {
                txid: "a".into(),
                mined_height: Some(5),
                fee_zat: None,
                outputs: vec![out(0, good.clone(), true)],
            },
            WalletTx {
                txid: "c".into(),
                mined_height: None,
                fee_zat: None,
                outputs: vec![out(0, good.clone(), true)],
            },
            WalletTx {
                txid: "d".into(),
                mined_height: Some(4),
                fee_zat: None,
                outputs: vec![out(0, good, false)],
            },
        ];
        let order: HashMap<String, u32> = [("a".into(), 0), ("b".into(), 3), ("d".into(), 0)]
            .into_iter()
            .collect();
        let Collected {
            records, rejected, ..
        } = collect(&txs, &order).unwrap();
        let positions: Vec<_> = records
            .iter()
            .map(|r| (r.txid.as_str(), r.position.output_index))
            .collect();
        assert_eq!(positions, vec![("a", 0), ("b", 1)]);
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0].reason, "unknown magic bytes");
    }

    #[test]
    fn collect_requires_tx_order() {
        let txs = vec![WalletTx {
            txid: "x".into(),
            mined_height: Some(1),
            fee_zat: None,
            outputs: vec![],
        }];
        assert!(matches!(
            collect(&txs, &HashMap::new()),
            Err(Error::Ordering(_))
        ));
    }
}
