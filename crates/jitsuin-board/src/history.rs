//! Buyer history checked against the board, and the minimum standard (HNK-20.T2, T3).
//!
//! The buyer discloses its certificate chain to the financier it asks for money. Every
//! certificate must be anchored by exactly one register entry with its tag, signed by the
//! supplier key in the certificate; no entry may carry the tag that would follow the last one.
//! The outcome of each invoice comes from the board: a two-signature `settled` entry (on time or
//! late), or none after the due date and the grace period (default).

use std::fmt;

use jitsuin_core::history::{next_tag, verify_certs};
use jitsuin_core::{EntryKind, HistoryCert, SettlementDoc};

use crate::{settled, BoardRecord, SettledRecord};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    PaidOnTime,
    PaidLate,
    /// Not settled after the due date plus the grace period.
    Default,
    /// Not settled, not yet past the due date plus the grace period.
    Open,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryLine {
    pub cert: HistoryCert,
    pub register: BoardRecord,
    pub settled: Option<SettledRecord>,
    pub outcome: Outcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryReport {
    pub identity_pk: [u8; 32],
    pub lines: Vec<HistoryLine>,
    pub on_time: u32,
    pub late: u32,
    pub defaults: u32,
    pub open: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryError {
    Core(jitsuin_core::Error),
    /// No valid register entry carries the certificate's tag for its N.
    NotAnchored {
        index: u32,
    },
    /// More than one valid register entry carries the same tag (the buyer forked the chain).
    Equivocation {
        index: u32,
    },
    /// An entry on the board carries the tag after the last disclosed certificate.
    UndisclosedSuccessor,
    /// The certificate names a financier outside the allowlist.
    FinancierNotAllowed {
        index: u32,
    },
}

impl fmt::Display for HistoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HistoryError::Core(e) => write!(f, "{e}"),
            HistoryError::NotAnchored { index } => {
                write!(f, "certificate {index} is not anchored on the board")
            }
            HistoryError::Equivocation { index } => {
                write!(
                    f,
                    "certificate {index}: the buyer anchored two invoices at one position"
                )
            }
            HistoryError::UndisclosedSuccessor => {
                write!(
                    f,
                    "the board has a later invoice the buyer did not disclose"
                )
            }
            HistoryError::FinancierNotAllowed { index } => {
                write!(
                    f,
                    "certificate {index} names a financier outside the allowlist"
                )
            }
        }
    }
}

impl std::error::Error for HistoryError {}

impl From<jitsuin_core::Error> for HistoryError {
    fn from(e: jitsuin_core::Error) -> Self {
        HistoryError::Core(e)
    }
}

/// Checks a disclosed chain against the board. `today` and the due dates are days since epoch.
pub fn verify_history(
    certs: &[HistoryCert],
    identity_pk: &[u8; 32],
    allowlist: &[[u8; 32]],
    records: &[BoardRecord],
    settled_records: &[SettledRecord],
    today: u32,
    grace_days: u32,
) -> Result<HistoryReport, HistoryError> {
    verify_certs(certs, identity_pk)?;
    let mut report = HistoryReport {
        identity_pk: *identity_pk,
        lines: Vec::new(),
        on_time: 0,
        late: 0,
        defaults: 0,
        open: 0,
    };
    for c in certs {
        if !allowlist.contains(&c.financier_pk) {
            return Err(HistoryError::FinancierNotAllowed { index: c.index });
        }
        // Only entries signed by this invoice's supplier count; forged copies of a tag do not.
        let anchors: Vec<&BoardRecord> = tagged(records, c.tag())
            .filter(|r| r.entry.verify(&c.supplier_pk).is_ok())
            .collect();
        let register = match anchors.as_slice() {
            [] => return Err(HistoryError::NotAnchored { index: c.index }),
            [one] if one.entry.nullifier == c.nullifier => (*one).clone(),
            [_] => return Err(HistoryError::NotAnchored { index: c.index }),
            _ => return Err(HistoryError::Equivocation { index: c.index }),
        };
        let doc = SettlementDoc {
            nullifier: c.nullifier,
            amount_zat: c.amount_zat,
            due_date: c.due_date,
        };
        let s = settled(settled_records, &doc, &c.invoice_pk, &c.financier_pk);
        let outcome = match &s {
            Some(r) if r.entry.on_time() => Outcome::PaidOnTime,
            Some(_) => Outcome::PaidLate,
            None if today > c.due_date.saturating_add(grace_days) => Outcome::Default,
            None => Outcome::Open,
        };
        match outcome {
            Outcome::PaidOnTime => report.on_time += 1,
            Outcome::PaidLate => report.late += 1,
            Outcome::Default => report.defaults += 1,
            Outcome::Open => report.open += 1,
        }
        report.lines.push(HistoryLine {
            cert: c.clone(),
            register,
            settled: s,
            outcome,
        });
    }
    if tagged(records, next_tag(identity_pk, certs.last()))
        .next()
        .is_some()
    {
        return Err(HistoryError::UndisclosedSuccessor);
    }
    Ok(report)
}

/// The buyer's own view of its chain (P-09, HNK-25.T2): which of the certificates it holds are
/// anchored on the board, and so which invoice index `k` comes next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnChain {
    /// Leading certificates anchored by exactly one valid register entry for their invoice.
    pub anchored: usize,
    /// Indices of the trailing certificates no register entry ever anchored (the financier did
    /// not register). They are dropped: disclosing them would fail with `NotAnchored`.
    pub dropped: Vec<u32>,
    /// The next invoice index: the number of anchored certificates.
    pub next_index: u32,
    /// A register entry already carries the tag the next certificate would carry: this device
    /// is missing the newest certificate (lost, or deleted by a relay). Issuing index
    /// `next_index` again would fork the history, so the buyer must not.
    pub successor_on_board: bool,
}

/// Works out the buyer's next invoice index from its own certificates and the board, instead of
/// a typed number. Fails on a chain that does not hold together (gaps, wrong links, another
/// identity), on two anchors for one certificate, and on an anchored certificate after an
/// unanchored one.
pub fn own_chain(
    certs: &[HistoryCert],
    identity_pk: &[u8; 32],
    records: &[BoardRecord],
) -> Result<OwnChain, HistoryError> {
    verify_certs(certs, identity_pk)?;
    let anchored_once = |c: &HistoryCert| -> Result<bool, HistoryError> {
        let anchors: Vec<&BoardRecord> = tagged(records, c.tag())
            .filter(|r| r.entry.verify(&c.supplier_pk).is_ok() && r.entry.nullifier == c.nullifier)
            .collect();
        match anchors.len() {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(HistoryError::Equivocation { index: c.index }),
        }
    };
    let mut anchored = 0;
    while anchored < certs.len() && anchored_once(&certs[anchored])? {
        anchored += 1;
    }
    for c in &certs[anchored..] {
        if anchored_once(c)? {
            return Err(HistoryError::NotAnchored {
                index: certs[anchored].index,
            });
        }
    }
    let head = anchored.checked_sub(1).map(|i| &certs[i]);
    Ok(OwnChain {
        anchored,
        dropped: certs[anchored..].iter().map(|c| c.index).collect(),
        next_index: anchored as u32,
        successor_on_board: tagged(records, next_tag(identity_pk, head))
            .next()
            .is_some(),
    })
}

/// Tagged register entries carrying `tag`.
fn tagged(records: &[BoardRecord], tag: [u8; 32]) -> impl Iterator<Item = &BoardRecord> {
    records.iter().filter(move |r| {
        r.entry.kind == EntryKind::RegisterWithHistory && r.entry.history_tag == Some(tag)
    })
}

/// Minimum standard a financier applies before registering a new invoice of the buyer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MinimumStandard {
    /// Defaults tolerated (usually 0).
    pub max_defaults: u32,
    /// Required share of settled invoices paid on time, in percent.
    pub min_on_time_pct: u32,
    /// Settled invoices needed before the buyer counts as established.
    pub established_after: u32,
    /// Largest amount for a buyer that is not established yet.
    pub new_buyer_limit_zat: u64,
}

impl MinimumStandard {
    pub fn evaluate(&self, report: &HistoryReport, amount_zat: u64) -> Result<(), &'static str> {
        if report.defaults > self.max_defaults {
            return Err("buyer has defaults above the standard");
        }
        let settled = report.on_time + report.late;
        if settled < self.established_after {
            if amount_zat > self.new_buyer_limit_zat {
                return Err("amount above the limit for a new buyer");
            }
            return Ok(());
        }
        if report.on_time * 100 < self.min_on_time_pct * settled {
            return Err("on-time share below the standard");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Position;
    use ed25519_dalek::SigningKey;
    use jitsuin_core::{
        BoardEntry, BuyerIdentity, Invoice, SettledEntry, SETTLED_LATE, SETTLED_ON_TIME,
    };

    const TODAY: u32 = 100;

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    struct World {
        id: BuyerIdentity,
        certs: Vec<HistoryCert>,
        records: Vec<BoardRecord>,
        settled: Vec<SettledRecord>,
        height: u32,
    }

    impl World {
        fn new() -> Self {
            World {
                id: BuyerIdentity::from_master_secret([0x42; 32]),
                certs: Vec::new(),
                records: Vec::new(),
                settled: Vec::new(),
                height: 10,
            }
        }

        fn id_pk(&self) -> [u8; 32] {
            self.id.identity_key().verifying_key().to_bytes()
        }

        fn invoice(&self, index: u32, due: u32) -> Invoice {
            Invoice {
                invoice_id: format!("TES-INV-H{index}"),
                supplier_ephemeral_pk: key(10 + index as u8).verifying_key().to_bytes(),
                buyer_pk: self.id.invoice_key(index).verifying_key().to_bytes(),
                amount_zat: 10_000,
                issue_date: 1,
                due_date: due,
                terms_hash: [9; 32],
            }
        }

        fn at(&mut self) -> Position {
            self.height += 1;
            Position {
                height: self.height,
                tx_index: 0,
                output_index: 0,
            }
        }

        /// Finances the next invoice and settles it with `flag`, or leaves it unpaid (None).
        fn deal(&mut self, due: u32, flag: Option<u8>) {
            let index = self.certs.len() as u32;
            let inv = self.invoice(index, due);
            let cert = HistoryCert::issue(
                &self.id,
                index,
                &inv,
                key(3).verifying_key().to_bytes(),
                self.certs.last(),
            )
            .unwrap();
            let entry = BoardEntry::sign_with_history(
                &key(10 + index as u8),
                cert.nullifier,
                [0xBB; 32],
                0,
                0,
                cert.tag(),
            );
            let position = self.at();
            self.records.push(BoardRecord {
                txid: format!("r{index}"),
                position,
                entry,
            });
            if let Some(flag) = flag {
                let doc = SettlementDoc {
                    nullifier: cert.nullifier,
                    amount_zat: cert.amount_zat,
                    due_date: cert.due_date,
                };
                let buyer = self.id.invoice_key(index);
                let e = SettledEntry::countersign(
                    &doc,
                    &doc.buyer_seal(&buyer),
                    &cert.invoice_pk,
                    &key(3),
                    flag,
                )
                .unwrap();
                let position = self.at();
                self.settled.push(SettledRecord {
                    txid: format!("s{index}"),
                    position,
                    entry: e,
                });
            }
            self.certs.push(cert);
        }

        fn check(&self, certs: &[HistoryCert]) -> Result<HistoryReport, HistoryError> {
            verify_history(
                certs,
                &self.id_pk(),
                &[key(3).verifying_key().to_bytes()],
                &self.records,
                &self.settled,
                TODAY,
                7,
            )
        }
    }

    #[test]
    fn the_next_index_comes_from_the_anchored_chain() {
        let mut w = World::new();
        let own = |w: &World, certs: &[HistoryCert]| own_chain(certs, &w.id_pk(), &w.records);
        // empty history: index 0, nothing on the board yet
        assert_eq!(
            own(&w, &[]).unwrap(),
            OwnChain {
                anchored: 0,
                dropped: vec![],
                next_index: 0,
                successor_on_board: false
            }
        );
        w.deal(50, Some(SETTLED_ON_TIME));
        w.deal(60, None);
        let certs = w.certs.clone();
        let r = own(&w, &certs).unwrap();
        assert_eq!(
            (r.anchored, r.next_index, r.successor_on_board),
            (2, 2, false)
        );

        // a certificate issued but never registered by the financier is dropped, its index reused
        let inv = w.invoice(2, 70);
        let unanchored = HistoryCert::issue(
            &w.id,
            2,
            &inv,
            key(3).verifying_key().to_bytes(),
            certs.last(),
        )
        .unwrap();
        let mut with_tail = certs.clone();
        with_tail.push(unanchored);
        let r = own(&w, &with_tail).unwrap();
        assert_eq!(
            (r.anchored, r.dropped.clone(), r.next_index),
            (2, vec![2], 2)
        );

        // the device lost its newest certificate: the board already holds its successor tag
        let r = own(&w, &certs[..1]).unwrap();
        assert_eq!((r.next_index, r.successor_on_board), (1, true));

        // a chain that skips an index does not hold together
        assert!(own(&w, &[certs[1].clone()]).is_err());
        // another identity's certificates are refused
        assert!(own_chain(&certs, &key(77).verifying_key().to_bytes(), &w.records).is_err());
    }

    fn standard() -> MinimumStandard {
        MinimumStandard {
            max_defaults: 0,
            min_on_time_pct: 80,
            established_after: 2,
            new_buyer_limit_zat: 20_000,
        }
    }

    #[test]
    fn complete_history_with_every_outcome() {
        let mut w = World::new();
        w.deal(50, Some(SETTLED_ON_TIME));
        w.deal(60, Some(SETTLED_LATE));
        w.deal(80, None); // 80 + 7 < 100: default
        w.deal(120, None); // still open
        let r = w.check(&w.certs).unwrap();
        let outcomes: Vec<_> = r.lines.iter().map(|l| l.outcome).collect();
        assert_eq!(
            outcomes,
            vec![
                Outcome::PaidOnTime,
                Outcome::PaidLate,
                Outcome::Default,
                Outcome::Open
            ]
        );
        assert_eq!((r.on_time, r.late, r.defaults, r.open), (1, 1, 1, 1));
        assert_eq!(
            standard().evaluate(&r, 10_000),
            Err("buyer has defaults above the standard")
        );
    }

    #[test]
    fn hiding_a_bad_invoice_is_caught() {
        let mut w = World::new();
        w.deal(50, Some(SETTLED_ON_TIME));
        w.deal(60, None); // default the buyer wants to hide
        w.deal(70, Some(SETTLED_ON_TIME));
        // leaving out the tail
        assert_eq!(
            w.check(&w.certs[..1]),
            Err(HistoryError::UndisclosedSuccessor)
        );
        // claiming to be new
        assert_eq!(w.check(&[]), Err(HistoryError::UndisclosedSuccessor));
        // a hand-built renumbered chain: cert 2 re-linked after cert 0
        let mut fork = w.certs[2].clone();
        fork.index = 1;
        fork.prev = w.certs[0].hash();
        let id = w.id.identity_key();
        fork.signature = ed25519_dalek::Signer::sign(
            &id,
            &fork.to_bytes()[..jitsuin_core::history::HISTORY_SIGNED_LEN],
        )
        .to_bytes();
        assert_eq!(
            w.check(&[w.certs[0].clone(), fork]),
            Err(HistoryError::NotAnchored { index: 1 })
        );
    }

    #[test]
    fn forged_tags_are_ignored_but_two_real_anchors_are_equivocation() {
        let mut w = World::new();
        w.deal(50, Some(SETTLED_ON_TIME));
        // a griefer copies the tag of certificate 0 with its own key: ignored
        let c0 = w.certs[0].clone();
        let fake = BoardEntry::sign_with_history(&key(99), c0.nullifier, [1; 32], 0, 0, c0.tag());
        let position = w.at();
        w.records.push(BoardRecord {
            txid: "fake".into(),
            position,
            entry: fake,
        });
        assert!(w.check(&w.certs).is_ok());
        // the real supplier signing a second entry with the same tag is a fork
        let dup = BoardEntry::sign_with_history(&key(10), c0.nullifier, [2; 32], 0, 0, c0.tag());
        let position = w.at();
        w.records.push(BoardRecord {
            txid: "dup".into(),
            position,
            entry: dup,
        });
        assert_eq!(
            w.check(&w.certs),
            Err(HistoryError::Equivocation { index: 0 })
        );
    }

    #[test]
    fn allowlist_and_minimum_standard() {
        let mut w = World::new();
        w.deal(50, Some(SETTLED_ON_TIME));
        let r = w.check(&w.certs).unwrap();
        // one settled invoice: still new, so the limit applies
        assert_eq!(standard().evaluate(&r, 20_000), Ok(()));
        assert_eq!(
            standard().evaluate(&r, 20_001),
            Err("amount above the limit for a new buyer")
        );
        w.deal(60, Some(SETTLED_LATE));
        w.deal(70, Some(SETTLED_LATE));
        let r = w.check(&w.certs).unwrap();
        assert_eq!(
            standard().evaluate(&r, 1_000_000),
            Err("on-time share below the standard")
        );
        // a financier outside the allowlist
        let other = verify_history(
            &w.certs,
            &w.id_pk(),
            &[key(4).verifying_key().to_bytes()],
            &w.records,
            &w.settled,
            TODAY,
            7,
        );
        assert_eq!(other, Err(HistoryError::FinancierNotAllowed { index: 0 }));
    }
}
