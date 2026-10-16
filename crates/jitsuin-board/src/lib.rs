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

use jitsuin_core::{settled_tag, BoardEntry, EntryKind};
use jitsuin_wallet::{Devtool, Memo};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    pub txid: String,
    pub output_index: u32,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct ScanReport {
    /// Format-valid entries in total order.
    pub records: Vec<BoardRecord>,
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

/// Decodes board outputs into records. `tx_order` maps txid to its index inside its block.
pub fn collect(
    txs: &[jitsuin_wallet::WalletTx],
    tx_order: &HashMap<String, u32>,
) -> Result<(Vec<BoardRecord>, Vec<Rejected>), Error> {
    let mut records = Vec::new();
    let mut rejected = Vec::new();
    for tx in txs {
        let Some(height) = tx.mined_height else {
            continue;
        };
        let tx_index = *tx_order
            .get(&tx.txid)
            .ok_or_else(|| Error::Ordering(format!("{} not found in block {height}", tx.txid)))?;
        for out in tx.outputs.iter().filter(|o| o.received) {
            let Memo::Arbitrary(bytes) = &out.memo else {
                continue;
            };
            match BoardEntry::from_memo_bytes(bytes) {
                Ok(entry) => records.push(BoardRecord {
                    txid: tx.txid.clone(),
                    position: Position {
                        height,
                        tx_index,
                        output_index: out.index,
                    },
                    entry,
                }),
                Err(e) => rejected.push(Rejected {
                    txid: tx.txid.clone(),
                    output_index: out.index,
                    reason: e.to_string(),
                }),
            }
        }
    }
    records.sort_by_key(|r| r.position);
    Ok((records, rejected))
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
        .filter(|r| r.entry.kind == EntryKind::Register && &r.entry.nullifier == nullifier)
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

/// First `settled` entry for `nullifier` signed by `financier_pk` (the key behind the financier
/// commitment, shared with the supplier and the buyer). Unsigned or foreign entries are ignored.
pub fn settled(
    records: &[BoardRecord],
    nullifier: &[u8; 32],
    financier_pk: &[u8; 32],
) -> Option<BoardRecord> {
    let tag = settled_tag(nullifier);
    records
        .iter()
        .filter(|r| r.entry.kind == EntryKind::Settled && r.entry.nullifier == tag)
        .find(|r| r.entry.verify(financier_pk).is_ok())
        .cloned()
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
    let (records, rejected) = collect(&txs, &tx_order)?;
    Ok(ScanReport {
        records,
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
    fn settled_entries_do_not_conflict_and_need_the_financier_signature() {
        let supplier = SigningKey::from_bytes(&[1; 32]);
        let financier = SigningKey::from_bytes(&[3; 32]);
        let griefer = SigningKey::from_bytes(&[9; 32]);
        let n = [7u8; 32];
        let settled_by = |k: &SigningKey, height| BoardRecord {
            txid: format!("s{height}"),
            position: Position {
                height,
                tx_index: 0,
                output_index: 0,
            },
            entry: BoardEntry::sign(k, EntryKind::Settled, settled_tag(&n), [0xBB; 32], 0, 0),
        };
        let mut records = vec![
            rec(&supplier, 7, 0xBB, 100, 0, 0),
            settled_by(&griefer, 110),
            settled_by(&financier, 120),
            // a settled-kind entry carrying N itself, even with a valid supplier signature,
            // is not a register entry
            BoardRecord {
                entry: BoardEntry::sign(&supplier, EntryKind::Settled, n, [0xCC; 32], 0, 0),
                ..rec(&supplier, 7, 0xCC, 130, 0, 0)
            },
        ];
        records.sort_by_key(|r| r.position);
        let pk = supplier.verifying_key().to_bytes();
        assert!(matches!(
            lookup(&records, &n, &pk),
            Lookup::Registered { .. }
        ));
        let found = settled(&records, &n, &financier.verifying_key().to_bytes()).unwrap();
        assert_eq!(found.txid, "s120");
        assert!(settled(&records, &[8; 32], &financier.verifying_key().to_bytes()).is_none());
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
        let (records, rejected) = collect(&txs, &order).unwrap();
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
