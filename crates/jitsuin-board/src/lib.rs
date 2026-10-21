//! JitsuinFi registry board scanner (HNK-04).
//!
//! The board is a Zcash account that only receives; its viewing key is shared so anyone can scan
//! it with a watch-only wallet. Two views:
//! - public: every entry with a valid format, in total order (height, tx index, output index);
//! - holder of an invoice: [`lookup`] verifies supplier signatures for one nullifier, ignores
//!   entries without a valid signature (anti-griefing), and reports double financing.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;
#[cfg(feature = "net")]
use std::time::Instant;

use jitsuin_core::entry::ENTRY_MAGIC;
use jitsuin_core::{
    nullifier, settled_tag, BoardEntry, Bundle, DoubleSignProof, EntryAt, EntryKind, Exhibit,
    Invoice, RateIndex, SettledEntry, SettlementDoc,
};
#[cfg(feature = "net")]
use jitsuin_wallet::Devtool;
use jitsuin_wallet::Memo;

pub mod history;
#[cfg(feature = "net")]
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

impl Collected {
    /// Decodes one board memo at `position` into a register entry, a settled entry, or a
    /// rejection. Also used by clients that get board memos from an API (`jitsuin-wasm`).
    pub fn add(&mut self, txid: &str, position: Position, memo: &[u8]) {
        let is_settled = memo.get(1..5) == Some(ENTRY_MAGIC.as_slice())
            && memo.get(5) == Some(&(EntryKind::Settled as u8));
        let decoded = if is_settled {
            SettledEntry::from_memo_bytes(memo).map(|entry| {
                self.settled.push(SettledRecord {
                    txid: txid.to_string(),
                    position,
                    entry,
                })
            })
        } else {
            BoardEntry::from_memo_bytes(memo).map(|entry| {
                self.records.push(BoardRecord {
                    txid: txid.to_string(),
                    position,
                    entry,
                })
            })
        };
        if let Err(e) = decoded {
            self.rejected.push(Rejected {
                txid: txid.to_string(),
                output_index: position.output_index,
                reason: e.to_string(),
            });
        }
    }

    /// Sorts entries into the total board order.
    pub fn sort(&mut self) {
        self.records.sort_by_key(|r| r.position);
        self.settled.sort_by_key(|r| r.position);
    }
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
            out.add(&tx.txid, position, bytes);
        }
    }
    out.sort();
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

fn entry_at(r: &BoardRecord) -> EntryAt {
    EntryAt {
        txid: r.txid.clone(),
        height: r.position.height,
        tx_index: r.position.tx_index,
        output_index: r.position.output_index,
    }
}

/// Double-signature proof after a race: both entries are on the board (HNK-07.T1).
pub fn proof_from_lookup(
    lookup: &Lookup,
    invoice: &Invoice,
    buyer_signature: [u8; 64],
) -> Option<DoubleSignProof> {
    let Lookup::DoubleFinanced {
        winner,
        conflicting,
        ..
    } = lookup
    else {
        return None;
    };
    let second = conflicting.first()?;
    Some(DoubleSignProof {
        invoice: invoice.clone(),
        buyer_signature,
        first: winner.entry.clone(),
        second: second.entry.clone(),
        first_at: Some(entry_at(winner)),
        second_at: Some(entry_at(second)),
    })
}

/// Double-signature proof without any transaction: the supplier offered `offered` to this
/// financier, but `winner` already registers the invoice for someone else.
pub fn proof_from_offer(
    winner: &BoardRecord,
    offered: BoardEntry,
    invoice: &Invoice,
    buyer_signature: [u8; 64],
) -> DoubleSignProof {
    DoubleSignProof {
        invoice: invoice.clone(),
        buyer_signature,
        first: winner.entry.clone(),
        second: offered,
        first_at: Some(entry_at(winner)),
        second_at: None,
    }
}

/// Each claim a double-signature proof makes about the board, one field per line of
/// `jitsuin verify` (and of the Verify page, through jitsuin-wasm `verifyProofOnBoard`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofOnBoard {
    /// The first entry is on the board at the claimed position; `None` when the proof gives no
    /// position for it, and then the proof does not hold.
    pub first: Option<bool>,
    /// The second entry is on the board at the claimed position; `None` when it was offered
    /// off-chain to the financier that caught it and never posted.
    pub second: Option<bool>,
    /// Both entries have a position and the first comes before the second; `None` otherwise.
    pub ordered: Option<bool>,
}

impl ProofOnBoard {
    pub fn holds(&self) -> bool {
        self.first == Some(true) && self.second != Some(false) && self.ordered != Some(false)
    }
}

/// Checks the positions a proof claims: each entry with a position is on the board exactly
/// there, and the first entry comes before the second when both are on chain.
pub fn proof_on_board(proof: &DoubleSignProof, records: &[BoardRecord]) -> ProofOnBoard {
    entries_on_board(
        (&proof.first, &proof.first_at),
        (&proof.second, &proof.second_at),
        records,
    )
}

/// The same check for an Exhibit A (`JTSX`, HNK-30.T5): its two entries and their positions.
pub fn exhibit_on_board(exhibit: &Exhibit, records: &[BoardRecord]) -> ProofOnBoard {
    entries_on_board(
        (&exhibit.first, &exhibit.first_at),
        (&exhibit.second, &exhibit.second_at),
        records,
    )
}

fn entries_on_board(
    first: (&BoardEntry, &Option<EntryAt>),
    second: (&BoardEntry, &Option<EntryAt>),
    records: &[BoardRecord],
) -> ProofOnBoard {
    let found = |e: &BoardEntry, at: &EntryAt| {
        records.iter().any(|r| {
            &r.entry == e
                && r.txid == at.txid
                && r.position
                    == Position {
                        height: at.height,
                        tx_index: at.tx_index,
                        output_index: at.output_index,
                    }
        })
    };
    let ordered = match (first.1, second.1) {
        (Some(a), Some(b)) => {
            Some((a.height, a.tx_index, a.output_index) < (b.height, b.tx_index, b.output_index))
        }
        _ => None,
    };
    ProofOnBoard {
        first: first.1.as_ref().map(|at| found(first.0, at)),
        second: second.1.as_ref().map(|at| found(second.0, at)),
        ordered,
    }
}

/// True when every position the proof claims is on the board (see [`proof_on_board`]).
pub fn verify_proof_on_board(proof: &DoubleSignProof, records: &[BoardRecord]) -> bool {
    proof_on_board(proof, records).holds()
}

/// Public rate index of the board (HNK-08). Records are put in board order first, so every
/// scanner of the same board gets the same index whatever order it collected them in.
pub fn rate_index(records: &[BoardRecord], k: usize) -> RateIndex {
    let mut ordered: Vec<&BoardRecord> = records.iter().collect();
    ordered.sort_by_key(|r| r.position);
    RateIndex::compute(ordered.into_iter().map(|r| &r.entry), k)
}

/// The rate index as JSON: what `jitsuin index --json` prints (it adds the version and the
/// board origin) and what the web index page shows through jitsuin-wasm `rateIndex`.
pub fn rate_index_json(i: &RateIndex) -> serde_json::Value {
    use jitsuin_core::index::{
        discount_class, tenor_class, Class, DISCOUNT_CLASSES, TENOR_CLASSES,
    };
    use serde_json::json;
    let label = |c: Option<&Class>| c.map_or("?", |c| c.label);
    let class =
        |c: &Class| json!({ "class": c.code, "label": c.label, "min": c.min, "max": c.max });
    json!({
        "k": i.k,
        "entries": i.entries,
        "invoices": i.invoices,
        "undisclosed": i.undisclosed,
        "invalid": i.invalid,
        "tenors": i.tenors.iter().map(|row| match &row.published {
            None => json!({
                "tenor": row.tenor,
                "label": label(tenor_class(row.tenor)),
                "published": false,
            }),
            Some(p) => json!({
                "tenor": row.tenor,
                "label": label(tenor_class(row.tenor)),
                "published": true,
                "invoices": p.invoices,
                "median_discount": {
                    "class": p.median_discount,
                    "label": label(discount_class(p.median_discount)),
                },
                "discounts": p.discounts.iter().map(|d| json!({
                    "class": d.discount,
                    "label": label(discount_class(d.discount)),
                    "invoices": d.invoices,
                })).collect::<Vec<_>>(),
                "other": p.other,
            }),
        }).collect::<Vec<_>>(),
        "classes": {
            "discount_bps": DISCOUNT_CLASSES.iter().map(class).collect::<Vec<_>>(),
            "tenor_days": TENOR_CLASSES.iter().map(class).collect::<Vec<_>>(),
        },
    })
}

#[cfg(feature = "net")]
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
    fn double_sign_proofs_from_a_race_and_from_an_offer() {
        let supplier = SigningKey::from_bytes(&[1; 32]);
        let buyer = SigningKey::from_bytes(&[2; 32]);
        let invoice = Invoice {
            invoice_id: "TES-INV-0003".into(),
            supplier_ephemeral_pk: supplier.verifying_key().to_bytes(),
            buyer_pk: buyer.verifying_key().to_bytes(),
            amount_zat: 40_000,
            issue_date: 1,
            due_date: 31,
            terms_hash: [9; 32],
        };
        let sig = jitsuin_core::sign_invoice(&buyer, &invoice)
            .unwrap()
            .to_bytes();
        let n = nullifier(&invoice).unwrap();
        let rec = |txid: &str, height, commitment| BoardRecord {
            txid: txid.repeat(32),
            position: Position {
                height,
                tx_index: 0,
                output_index: 1,
            },
            entry: BoardEntry::sign(&supplier, EntryKind::Register, n, commitment, 0, 0),
        };
        let records = vec![rec("aa", 10, [0xA1; 32]), rec("bb", 11, [0xB2; 32])];
        let pk = supplier.verifying_key().to_bytes();

        // race: both on chain
        let l = lookup(&records, &n, &pk);
        let p = proof_from_lookup(&l, &invoice, sig).unwrap();
        p.verify().unwrap();
        assert!(verify_proof_on_board(&p, &records));
        let mut moved = p.clone();
        moved.second_at.as_mut().unwrap().height = 9;
        assert!(!verify_proof_on_board(&moved, &records));

        // offer: B holds the supplier-signed entry, A is on the board; nothing posted by B
        let offered = BoardEntry::sign(&supplier, EntryKind::Register, n, [0xC3; 32], 0, 0);
        let only_a = &records[..1];
        let Lookup::Registered { winner, .. } = lookup(only_a, &n, &pk) else {
            panic!()
        };
        let p = proof_from_offer(&winner, offered, &invoice, sig);
        let r = p.verify().unwrap();
        assert_eq!(r.second_commitment, [0xC3; 32]);
        assert!(verify_proof_on_board(&p, only_a));
        // no proof when the lookup is not a double financing
        assert!(proof_from_lookup(&lookup(only_a, &n, &pk), &invoice, sig).is_none());
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
    fn rate_index_is_the_same_in_any_collection_order() {
        let s = SigningKey::from_bytes(&[1; 32]);
        let mut records: Vec<BoardRecord> = (0..7u8)
            .map(|n| BoardRecord {
                txid: format!("{n}"),
                position: Position {
                    height: 100 + u32::from(n),
                    tx_index: 0,
                    output_index: 0,
                },
                entry: BoardEntry::sign(&s, EntryKind::Register, [n; 32], [2; 32], 3, 2),
            })
            .collect();
        // A later entry for N 0 with other classes: only the first one in board order counts.
        records.push(BoardRecord {
            txid: "late".into(),
            position: Position {
                height: 200,
                tx_index: 0,
                output_index: 0,
            },
            entry: BoardEntry::sign(&s, EntryKind::Register, [0; 32], [3; 32], 7, 5),
        });
        let ordered = rate_index(&records, jitsuin_core::index::K);
        records.reverse();
        assert_eq!(rate_index(&records, jitsuin_core::index::K), ordered);
        let row = ordered.tenors[1].published.as_ref().unwrap();
        assert_eq!(
            (ordered.invoices, row.invoices, row.median_discount),
            (7, 7, 3)
        );
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
