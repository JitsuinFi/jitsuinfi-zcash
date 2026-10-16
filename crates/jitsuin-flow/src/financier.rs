//! Financier flow (HNK-05.T1): check the board, register the entry, wait for confirmation, then
//! pay the advance with a signed receipt.
//!
//! [`Flow`] is a pure state machine fed with [`Event`]s, so its rules are unit tested without a
//! chain. [`Financier`] drives it against a real wallet and board. Every path other than "our
//! entry is the first valid one and confirmed" stops before any money moves.

use std::thread;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use jitsuin_board::{lookup, lwd, scan, BoardRecord, Lookup};
use jitsuin_core::{BoardEntry, EntryKind, Receipt, ReceiptKind, ENTRY_LEN, RECEIPT_LEN};
use jitsuin_wallet::{Devtool, Memo, Payment, PaymentMemo, WalletTx};

use crate::Error;

/// Value sent with each board entry; the board only needs the memo.
pub const ENTRY_POST_ZAT: u64 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deal {
    pub nullifier: [u8; 32],
    /// From the invoice; verifies the supplier signature on board entries.
    pub supplier_ephemeral_pk: [u8; 32],
    /// `financier_commitment(financier_pk, salt)` of this financier.
    pub financier_commitment: [u8; 32],
    /// Shielded address of the supplier that receives the advance.
    pub supplier_address: String,
    pub advance_zat: u64,
    /// Confirmations of the board entry required before paying (at least 1).
    pub min_confirmations: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// Scan the board for the nullifier.
    Check,
    /// The nullifier is free: the supplier must sign the entry for our commitment.
    AwaitSupplierSignature,
    /// Signed entry, ready to post to the board.
    Register { entry: BoardEntry },
    /// Entry posted; wait until it is mined, confirmed, and still the first valid entry.
    AwaitConfirmation { entry_txid: String },
    /// Our entry is the first valid one and confirmed: the advance may be paid.
    Pay { entry: BoardRecord },
    /// Advance paid.
    Done {
        entry: BoardRecord,
        advance_txid: String,
    },
    /// Stopped before the advance was paid.
    Stopped(Stop),
}

impl State {
    pub fn name(&self) -> &'static str {
        match self {
            State::Check => "Check",
            State::AwaitSupplierSignature => "AwaitSupplierSignature",
            State::Register { .. } => "Register",
            State::AwaitConfirmation { .. } => "AwaitConfirmation",
            State::Pay { .. } => "Pay",
            State::Done { .. } => "Done",
            State::Stopped(_) => "Stopped",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// Another financier's entry for this nullifier is already the first valid one.
    AlreadyFinanced { winner: BoardRecord },
    /// The supplier signed entries for more than one financier (evidence for HNK-07).
    DoubleFinanced {
        winner: BoardRecord,
        conflicting: Vec<BoardRecord>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Board lookup for the deal's nullifier, plus the chain tip height at that time.
    BoardChecked {
        lookup: Lookup,
        tip_height: u32,
    },
    SupplierSigned(BoardEntry),
    EntryPosted {
        txid: String,
    },
    AdvanceSent {
        txid: String,
    },
}

impl Event {
    fn name(&self) -> &'static str {
        match self {
            Event::BoardChecked { .. } => "BoardChecked",
            Event::SupplierSigned(_) => "SupplierSigned",
            Event::EntryPosted { .. } => "EntryPosted",
            Event::AdvanceSent { .. } => "AdvanceSent",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Flow {
    deal: Deal,
    state: State,
}

impl Flow {
    pub fn new(deal: Deal) -> Result<Self, Error> {
        if deal.min_confirmations == 0 {
            return Err(Error::InvalidDeal("min_confirmations must be at least 1"));
        }
        if deal.advance_zat == 0 {
            return Err(Error::InvalidDeal("advance must be greater than zero"));
        }
        if deal.supplier_address.is_empty() {
            return Err(Error::InvalidDeal("supplier address is empty"));
        }
        Ok(Flow {
            deal,
            state: State::Check,
        })
    }

    pub fn deal(&self) -> &Deal {
        &self.deal
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    /// Applies one event. On error the state is unchanged.
    pub fn apply(&mut self, event: Event) -> Result<&State, Error> {
        let next = match (&self.state, event) {
            (
                State::Check | State::AwaitConfirmation { .. },
                Event::BoardChecked { lookup, tip_height },
            ) => self.on_board(lookup, tip_height),
            (State::AwaitSupplierSignature, Event::SupplierSigned(entry)) => {
                self.check_entry(&entry)?;
                State::Register { entry }
            }
            (State::Register { .. }, Event::EntryPosted { txid }) => {
                State::AwaitConfirmation { entry_txid: txid }
            }
            (State::Pay { entry }, Event::AdvanceSent { txid }) => State::Done {
                entry: entry.clone(),
                advance_txid: txid,
            },
            (state, event) => {
                return Err(Error::UnexpectedEvent {
                    state: state.name(),
                    event: event.name(),
                })
            }
        };
        self.state = next;
        Ok(&self.state)
    }

    fn on_board(&self, lookup: Lookup, tip_height: u32) -> State {
        match lookup {
            Lookup::DoubleFinanced {
                winner,
                conflicting,
                ..
            } => State::Stopped(Stop::DoubleFinanced {
                winner,
                conflicting,
            }),
            Lookup::Registered { winner, .. }
                if winner.entry.financier_commitment != self.deal.financier_commitment =>
            {
                State::Stopped(Stop::AlreadyFinanced { winner })
            }
            // Ours (posted now or in an earlier attempt).
            Lookup::Registered { winner, .. } => {
                if confirmations(tip_height, winner.position.height) >= self.deal.min_confirmations
                {
                    State::Pay { entry: winner }
                } else {
                    State::AwaitConfirmation {
                        entry_txid: winner.txid,
                    }
                }
            }
            Lookup::NotFound { .. } => match &self.state {
                State::Check => State::AwaitSupplierSignature,
                // Posted but not mined yet.
                other => other.clone(),
            },
        }
    }

    fn check_entry(&self, entry: &BoardEntry) -> Result<(), Error> {
        if entry.kind != EntryKind::Register {
            return Err(Error::EntryMismatch("entry kind is not register"));
        }
        if entry.nullifier != self.deal.nullifier {
            return Err(Error::EntryMismatch("nullifier differs from the deal"));
        }
        if entry.financier_commitment != self.deal.financier_commitment {
            return Err(Error::EntryMismatch("financier commitment differs"));
        }
        entry
            .verify(&self.deal.supplier_ephemeral_pk)
            .map_err(|_| Error::EntryMismatch("supplier signature does not verify"))
    }
}

/// Confirmations of a block at `height` when the tip is `tip_height` (mined in the tip = 1).
pub fn confirmations(tip_height: u32, height: u32) -> u32 {
    if tip_height >= height {
        tip_height - height + 1
    } else {
        0
    }
}

/// Txid of an advance receipt for `nullifier`, signed by `financier_pk`, that this wallet already
/// sent. Lets a retry after a crash record the earlier payment instead of paying twice.
pub fn sent_advance(
    txs: &[WalletTx],
    nullifier: &[u8; 32],
    financier_pk: &[u8; 32],
) -> Option<String> {
    txs.iter()
        .find(|tx| {
            tx.outputs.iter().filter(|o| !o.received).any(|o| {
                let Memo::Arbitrary(bytes) = &o.memo else {
                    return false;
                };
                Receipt::from_memo_bytes(bytes).is_ok_and(|r| {
                    r.kind == ReceiptKind::Advance
                        && &r.nullifier == nullifier
                        && r.verify(financier_pk).is_ok()
                })
            })
        })
        .map(|tx| tx.txid.clone())
}

/// Drives a [`Flow`] against a financier wallet and the board. No `Debug`: it holds a signing key.
#[derive(Clone)]
pub struct Financier {
    /// Spending wallet of the financier (with identity).
    pub wallet: Devtool,
    /// Watch-only wallet of the board.
    pub board_watch: Devtool,
    pub board_address: String,
    pub lightwalletd: String,
    /// Long-term key of the financier; signs advance receipts. Its public key is behind the
    /// financier commitment.
    pub key: SigningKey,
}

impl Financier {
    /// Scans the board and feeds the lookup to the flow (states `Check` and `AwaitConfirmation`).
    pub fn check<'f>(&self, flow: &'f mut Flow) -> Result<&'f State, Error> {
        let report = scan(&self.board_watch, &self.lightwalletd)?;
        let tip_height = lwd::latest_height(&self.lightwalletd)?;
        let lookup = lookup(
            &report.records,
            &flow.deal().nullifier,
            &flow.deal().supplier_ephemeral_pk,
        );
        flow.apply(Event::BoardChecked { lookup, tip_height })
    }

    /// Posts the supplier-signed entry to the board (state `Register`).
    pub fn register<'f>(&self, flow: &'f mut Flow) -> Result<&'f State, Error> {
        let State::Register { entry } = flow.state() else {
            return Err(unexpected(flow, "register"));
        };
        let memo = entry.to_memo_bytes()[..ENTRY_LEN].to_vec();
        self.wallet.sync()?;
        let txid = self.wallet.pay(&[Payment {
            address: self.board_address.clone(),
            amount_zat: ENTRY_POST_ZAT,
            memo: Some(PaymentMemo::Arbitrary(memo)),
        }])?;
        flow.apply(Event::EntryPosted { txid })
    }

    /// Re-checks the board until the entry is confirmed or the flow stops.
    pub fn wait_for_confirmation<'f>(
        &self,
        flow: &'f mut Flow,
        poll: Duration,
        timeout: Duration,
    ) -> Result<&'f State, Error> {
        let started = Instant::now();
        loop {
            if !matches!(self.check(flow)?, State::AwaitConfirmation { .. }) {
                return Ok(flow.state());
            }
            if started.elapsed() >= timeout {
                return Err(Error::Timeout("board entry not confirmed"));
            }
            thread::sleep(poll);
        }
    }

    /// Pays the advance to the supplier with a signed receipt memo (state `Pay`). If this wallet
    /// already sent an advance receipt for the nullifier, records that txid instead.
    pub fn pay_advance<'f>(&self, flow: &'f mut Flow, date: u32) -> Result<&'f State, Error> {
        if !matches!(flow.state(), State::Pay { .. }) {
            return Err(unexpected(flow, "pay_advance"));
        }
        let deal = flow.deal().clone();
        self.wallet.sync()?;
        let financier_pk = self.key.verifying_key().to_bytes();
        if let Some(txid) = sent_advance(&self.wallet.list_tx()?, &deal.nullifier, &financier_pk) {
            return flow.apply(Event::AdvanceSent { txid });
        }
        let receipt = Receipt::sign(
            &self.key,
            ReceiptKind::Advance,
            deal.nullifier,
            deal.advance_zat,
            date,
        )?;
        let txid = self.wallet.pay(&[Payment {
            address: deal.supplier_address,
            amount_zat: deal.advance_zat,
            memo: Some(PaymentMemo::Arbitrary(
                receipt.to_memo_bytes()[..RECEIPT_LEN].to_vec(),
            )),
        }])?;
        flow.apply(Event::AdvanceSent { txid })
    }
}

fn unexpected(flow: &Flow, event: &'static str) -> Error {
    Error::UnexpectedEvent {
        state: flow.state().name(),
        event,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jitsuin_board::Position;
    use jitsuin_core::financier_commitment;
    use jitsuin_wallet::TxOutput;

    const N: [u8; 32] = [7; 32];

    fn supplier() -> SigningKey {
        SigningKey::from_bytes(&[1; 32])
    }

    fn financier() -> SigningKey {
        SigningKey::from_bytes(&[3; 32])
    }

    fn ours() -> [u8; 32] {
        financier_commitment(&financier().verifying_key().to_bytes(), &[4; 32])
    }

    fn deal(min_confirmations: u32) -> Deal {
        Deal {
            nullifier: N,
            supplier_ephemeral_pk: supplier().verifying_key().to_bytes(),
            financier_commitment: ours(),
            supplier_address: "utest1supplier".into(),
            advance_zat: 950_000,
            min_confirmations,
        }
    }

    fn entry(commitment: [u8; 32]) -> BoardEntry {
        BoardEntry::sign(&supplier(), EntryKind::Register, N, commitment, 2, 3)
    }

    fn record(txid: &str, height: u32, entry: BoardEntry) -> BoardRecord {
        BoardRecord {
            txid: txid.into(),
            position: Position {
                height,
                tx_index: 1,
                output_index: 0,
            },
            entry,
        }
    }

    fn board(records: &[BoardRecord], tip_height: u32) -> Event {
        Event::BoardChecked {
            lookup: lookup(records, &N, &supplier().verifying_key().to_bytes()),
            tip_height,
        }
    }

    #[test]
    fn happy_path_waits_for_confirmations_before_paying() {
        let mut flow = Flow::new(deal(2)).unwrap();
        let griefer = SigningKey::from_bytes(&[9; 32]);
        let grief = record(
            "g",
            90,
            BoardEntry::sign(&griefer, EntryKind::Register, N, [0x99; 32], 0, 0),
        );

        // a griefing entry without a valid supplier signature does not block the deal
        assert_eq!(
            flow.apply(board(std::slice::from_ref(&grief), 99)).unwrap(),
            &State::AwaitSupplierSignature
        );
        flow.apply(Event::SupplierSigned(entry(ours()))).unwrap();
        assert!(matches!(flow.state(), State::Register { .. }));
        flow.apply(Event::EntryPosted { txid: "e".into() }).unwrap();

        // not mined yet
        flow.apply(board(std::slice::from_ref(&grief), 100))
            .unwrap();
        assert_eq!(
            flow.state(),
            &State::AwaitConfirmation {
                entry_txid: "e".into()
            }
        );
        // mined in the tip: 1 confirmation, 2 required
        let mine = record("e", 101, entry(ours()));
        flow.apply(board(&[grief.clone(), mine.clone()], 101))
            .unwrap();
        assert!(matches!(flow.state(), State::AwaitConfirmation { .. }));
        // an advance cannot be recorded before confirmation
        assert!(matches!(
            flow.apply(Event::AdvanceSent { txid: "x".into() }),
            Err(Error::UnexpectedEvent { .. })
        ));
        flow.apply(board(&[grief, mine.clone()], 102)).unwrap();
        assert_eq!(
            flow.state(),
            &State::Pay {
                entry: mine.clone()
            }
        );

        flow.apply(Event::AdvanceSent { txid: "a".into() }).unwrap();
        assert_eq!(
            flow.state(),
            &State::Done {
                entry: mine,
                advance_txid: "a".into()
            }
        );
    }

    #[test]
    fn stops_when_another_financier_is_registered() {
        let mut flow = Flow::new(deal(1)).unwrap();
        let other = record("o", 50, entry([0xEE; 32]));
        flow.apply(board(std::slice::from_ref(&other), 60)).unwrap();
        assert_eq!(
            flow.state(),
            &State::Stopped(Stop::AlreadyFinanced { winner: other })
        );
        // nothing moves after a stop
        for event in [
            Event::SupplierSigned(entry(ours())),
            Event::EntryPosted { txid: "e".into() },
            Event::AdvanceSent { txid: "a".into() },
            board(&[], 61),
        ] {
            assert!(flow.apply(event).is_err());
        }
    }

    #[test]
    fn stops_on_double_financing_even_after_posting() {
        let mut flow = Flow::new(deal(1)).unwrap();
        flow.apply(board(&[], 10)).unwrap();
        flow.apply(Event::SupplierSigned(entry(ours()))).unwrap();
        flow.apply(Event::EntryPosted { txid: "e".into() }).unwrap();
        // the supplier also signed for another financier, mined first
        let other = record("o", 11, entry([0xEE; 32]));
        let mine = record("e", 12, entry(ours()));
        flow.apply(board(&[other.clone(), mine.clone()], 12))
            .unwrap();
        assert_eq!(
            flow.state(),
            &State::Stopped(Stop::DoubleFinanced {
                winner: other,
                conflicting: vec![mine],
            })
        );
    }

    #[test]
    fn resumes_from_an_entry_posted_earlier() {
        let mut flow = Flow::new(deal(1)).unwrap();
        let mine = record("e", 20, entry(ours()));
        flow.apply(board(std::slice::from_ref(&mine), 20)).unwrap();
        assert_eq!(flow.state(), &State::Pay { entry: mine });
    }

    #[test]
    fn rejects_entries_that_do_not_match_the_deal() {
        let mut flow = Flow::new(deal(1)).unwrap();
        flow.apply(board(&[], 1)).unwrap();
        let other_signer = SigningKey::from_bytes(&[9; 32]);
        let bad = [
            BoardEntry::sign(&supplier(), EntryKind::Settled, N, ours(), 2, 3),
            BoardEntry::sign(&supplier(), EntryKind::Register, [8; 32], ours(), 2, 3),
            entry([0xEE; 32]),
            BoardEntry::sign(&other_signer, EntryKind::Register, N, ours(), 2, 3),
        ];
        for e in bad {
            assert!(matches!(
                flow.apply(Event::SupplierSigned(e)),
                Err(Error::EntryMismatch(_))
            ));
            assert_eq!(flow.state(), &State::AwaitSupplierSignature);
        }
    }

    #[test]
    fn invalid_deals_are_rejected() {
        assert!(Flow::new(deal(0)).is_err());
        let mut d = deal(1);
        d.advance_zat = 0;
        assert!(Flow::new(d).is_err());
    }

    #[test]
    fn confirmation_count() {
        assert_eq!(confirmations(100, 100), 1);
        assert_eq!(confirmations(105, 100), 6);
        assert_eq!(confirmations(99, 100), 0);
    }

    #[test]
    fn finds_an_advance_already_sent() {
        let pk = financier().verifying_key().to_bytes();
        let receipt = Receipt::sign(&financier(), ReceiptKind::Advance, N, 950_000, 1).unwrap();
        let out = |received, memo: Vec<u8>| TxOutput {
            index: 0,
            pool: "Ironwood".into(),
            value_zat: 950_000,
            is_change: false,
            received,
            memo: Memo::Arbitrary(memo),
        };
        let tx = |txid: &str, o| WalletTx {
            txid: txid.into(),
            mined_height: None,
            fee_zat: None,
            outputs: vec![o],
        };
        let memo = receipt.to_memo_bytes().to_vec();
        let other_n = Receipt::sign(&financier(), ReceiptKind::Advance, [8; 32], 1, 1)
            .unwrap()
            .to_memo_bytes()
            .to_vec();
        let txs = vec![
            tx("received", out(true, memo.clone())),
            tx("other-n", out(false, other_n)),
            tx("sent", out(false, memo)),
        ];
        assert_eq!(sent_advance(&txs, &N, &pk).as_deref(), Some("sent"));
        assert_eq!(sent_advance(&txs[..2], &N, &pk), None);
    }
}
