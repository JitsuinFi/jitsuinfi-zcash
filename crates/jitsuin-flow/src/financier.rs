//! Financier flow (HNK-05.T1, Sign-to-Pay HNK-19.T3): check the board, register the entry, wait
//! for confirmation, wait for the assignment letter sealed by supplier and buyer, then pay the
//! advance. The advance memo carries the receipt and the financier's seal on the letter, so the
//! last signature and the money travel in one shielded transaction.
//!
//! [`Flow`] is a pure state machine fed with [`Event`]s, so its rules are unit tested without a
//! chain. [`Financier`] drives it against a real wallet and board. Every path other than "our
//! entry is the first valid one, confirmed, and the letter is sealed" stops before any money
//! moves.

use std::thread;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, SigningKey};
use jitsuin_board::{lookup, lwd, proof_from_lookup, scan, BoardRecord, Lookup};
use jitsuin_core::index::{classes_for, validate_classes};
use jitsuin_core::memo::{self, MemoItem};
use jitsuin_core::{
    commitment_opening, nullifier, verify_invoice, Assignment, BoardEntry, ChainStatus,
    DoubleSignProof, Invoice, Receipt, ReceiptKind, ReceivableNote, Role, Seal,
};
use jitsuin_wallet::{Devtool, Memo, Payment, PaymentMemo, WalletTx};

use crate::codec::{Reader, Writer};
use crate::Error;

/// Magic and version of a deal snapshot ([`Flow::to_bytes`]).
pub const FLOW_MAGIC: &[u8; 4] = b"JTSF";
pub const FLOW_VERSION: u8 = 1;

/// Value sent with each board entry; the board only needs the memo.
pub const ENTRY_POST_ZAT: u64 = 10_000;

/// Blocks after which an unmined advance counts as expired and may be paid again (K-7): the
/// ZIP-203 default expiry delta of 40 blocks plus a margin of 10.
pub const ADVANCE_EXPIRY_BLOCKS: u32 = 50;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deal {
    /// The buyer-signed invoice; gives N and the supplier and buyer keys.
    pub invoice: Invoice,
    /// Assignment letter of the invoice to this financier (DEV-07).
    pub assignment: Assignment,
    /// `financier_commitment(financier_pk, salt)` of this financier.
    pub financier_commitment: [u8; 32],
    /// Shielded address of the supplier that receives the advance.
    pub supplier_address: String,
    pub advance_zat: u64,
    /// Confirmations of the board entry required before paying (at least 1).
    pub min_confirmations: u32,
    /// Tag of the buyer's new history certificate (HNK-20). When set, the register entry must
    /// carry it, so the invoice joins the buyer's anchored history.
    pub history_tag: Option<[u8; 32]>,
    /// Discount and tenor classes the register entry must carry (HNK-08, HNK-27.T2), normally
    /// from [`deal_classes`]; `0/0` means not disclosed.
    pub discount_bucket: u8,
    pub tenor_bucket: u8,
}

/// Classes of a deal for the public rate index: from the face value, the advance, the advance
/// date and the due date (days since the Unix epoch). A deal that fits no class (advance above
/// face value, due date before the advance or more than a year later) is registered as `0/0`.
pub fn deal_classes(invoice: &Invoice, advance_zat: u64, advance_day: u32) -> (u8, u8) {
    classes_for(
        invoice.amount_zat,
        advance_zat,
        advance_day,
        invoice.due_date,
    )
    .unwrap_or((0, 0))
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
    /// Our entry is the first valid one and confirmed; the assignment letter must be sealed by
    /// the supplier and the buyer before any money moves (signing escrow).
    AwaitAssignment { entry: BoardRecord },
    /// Letter sealed by supplier and buyer: the advance may be paid together with our seal.
    Pay {
        entry: BoardRecord,
        assignment_seals: Vec<Seal>,
        /// Advances sent earlier that expired unmined; never counted as paid again.
        expired_advances: Vec<String>,
    },
    /// Advance broadcast at `sent_tip`; wait until it is mined (K-7).
    AwaitAdvanceConfirmation {
        entry: BoardRecord,
        assignment_seals: Vec<Seal>,
        advance_txid: String,
        sent_tip: u32,
        expired_advances: Vec<String>,
    },
    /// Advance paid and mined.
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
            State::AwaitAssignment { .. } => "AwaitAssignment",
            State::Pay { .. } => "Pay",
            State::AwaitAdvanceConfirmation { .. } => "AwaitAdvanceConfirmation",
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
    /// Seals of the assignment letter collected so far (supplier, then buyer).
    AssignmentSealed(Vec<Seal>),
    /// Advance broadcast (or found already sent), with the chain tip at that time.
    AdvanceSent {
        txid: String,
        tip_height: u32,
    },
    /// Wallet check of the advance: mined or not, and the chain tip.
    AdvanceChecked {
        mined: bool,
        tip_height: u32,
    },
}

impl Event {
    fn name(&self) -> &'static str {
        match self {
            Event::BoardChecked { .. } => "BoardChecked",
            Event::SupplierSigned(_) => "SupplierSigned",
            Event::EntryPosted { .. } => "EntryPosted",
            Event::AssignmentSealed(_) => "AssignmentSealed",
            Event::AdvanceSent { .. } => "AdvanceSent",
            Event::AdvanceChecked { .. } => "AdvanceChecked",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Flow {
    deal: Deal,
    nullifier: [u8; 32],
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
        if validate_classes(deal.discount_bucket, deal.tenor_bucket).is_err() {
            return Err(Error::InvalidDeal("unknown discount or tenor class"));
        }
        let nullifier = nullifier(&deal.invoice)?;
        // The letter must belong to this invoice and must not let one key hold two roles.
        deal.assignment.verify(&deal.invoice, &[])?;
        Ok(Flow {
            deal,
            nullifier,
            state: State::Check,
        })
    }

    pub fn deal(&self) -> &Deal {
        &self.deal
    }

    /// N of the invoice (DEV-04).
    pub fn nullifier(&self) -> &[u8; 32] {
        &self.nullifier
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    /// Double-signature proof of a deal stopped as double financed (HNK-26.T14): the first entry
    /// and the first conflicting one, both with their board positions, so `jitsuin verify` and
    /// the Verify page can check it against the board. `buyer_signature` is the buyer's
    /// signature on the deal's invoice; the deal does not keep it. `None` in any other state.
    pub fn double_sign_proof(
        &self,
        buyer_signature: [u8; 64],
    ) -> Result<Option<DoubleSignProof>, Error> {
        let State::Stopped(Stop::DoubleFinanced {
            winner,
            conflicting,
        }) = &self.state
        else {
            return Ok(None);
        };
        verify_invoice(&self.deal.invoice, &Signature::from_bytes(&buyer_signature))?;
        let lookup = Lookup::DoubleFinanced {
            winner: winner.clone(),
            conflicting: conflicting.clone(),
            ignored_invalid: Vec::new(),
        };
        let proof = proof_from_lookup(&lookup, &self.deal.invoice, buyer_signature).ok_or(
            Error::InvalidDeal("double financing without a conflicting entry"),
        )?;
        proof.verify()?;
        Ok(Some(proof))
    }

    /// Snapshot of the deal and its state for the node's store (HNK-26.T10): a node restarted
    /// from it resumes the deal where it stopped. Format `JTSF` v1, see [`Flow::from_bytes`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut w = Writer::default();
        w.raw(FLOW_MAGIC);
        w.byte(FLOW_VERSION);
        let d = &self.deal;
        w.bytes(&d.invoice.to_canonical_bytes()?)?;
        w.bytes(&d.assignment.to_canonical_bytes()?)?;
        w.raw(&d.financier_commitment);
        w.str(&d.supplier_address)?;
        w.u64(d.advance_zat);
        w.u32(d.min_confirmations);
        match &d.history_tag {
            None => w.byte(0),
            Some(tag) => {
                w.byte(1);
                w.raw(tag);
            }
        }
        w.byte(d.discount_bucket);
        w.byte(d.tenor_bucket);
        match &self.state {
            State::Check => w.byte(0),
            State::AwaitSupplierSignature => w.byte(1),
            State::Register { entry } => {
                w.byte(2);
                w.entry(entry);
            }
            State::AwaitConfirmation { entry_txid } => {
                w.byte(3);
                w.str(entry_txid)?;
            }
            State::AwaitAssignment { entry } => {
                w.byte(4);
                w.record(entry)?;
            }
            State::Pay {
                entry,
                assignment_seals,
                expired_advances,
            } => {
                w.byte(5);
                w.record(entry)?;
                w.seals(assignment_seals)?;
                w.strs(expired_advances)?;
            }
            State::AwaitAdvanceConfirmation {
                entry,
                assignment_seals,
                advance_txid,
                sent_tip,
                expired_advances,
            } => {
                w.byte(6);
                w.record(entry)?;
                w.seals(assignment_seals)?;
                w.str(advance_txid)?;
                w.u32(*sent_tip);
                w.strs(expired_advances)?;
            }
            State::Done {
                entry,
                advance_txid,
            } => {
                w.byte(7);
                w.record(entry)?;
                w.str(advance_txid)?;
            }
            State::Stopped(Stop::AlreadyFinanced { winner }) => {
                w.byte(8);
                w.record(winner)?;
            }
            State::Stopped(Stop::DoubleFinanced {
                winner,
                conflicting,
            }) => {
                w.byte(9);
                w.record(winner)?;
                w.records(conflicting)?;
            }
        }
        Ok(w.out)
    }

    /// Strict decoder of [`Flow::to_bytes`]. The deal is checked again as in [`Flow::new`], our
    /// own entry as when the supplier signed it, and the letter seals as when they arrived, so a
    /// damaged or edited snapshot never resumes a deal that `apply` would not have reached.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.take(4)? != FLOW_MAGIC {
            return Err(Error::Format("not a deal snapshot"));
        }
        let version = r.byte()?;
        if version != FLOW_VERSION {
            return Err(Error::Format("unsupported snapshot version"));
        }
        let deal = Deal {
            invoice: Invoice::from_canonical_bytes(r.bytes()?)?,
            assignment: Assignment::from_canonical_bytes(r.bytes()?)?,
            financier_commitment: r.array()?,
            supplier_address: r.str()?,
            advance_zat: r.u64()?,
            min_confirmations: r.u32()?,
            history_tag: match r.byte()? {
                0 => None,
                1 => Some(r.array()?),
                _ => return Err(Error::Format("malformed deal snapshot")),
            },
            discount_bucket: r.byte()?,
            tenor_bucket: r.byte()?,
        };
        let mut flow = Flow::new(deal)?;
        let state = match r.byte()? {
            0 => State::Check,
            1 => State::AwaitSupplierSignature,
            2 => State::Register { entry: r.entry()? },
            3 => State::AwaitConfirmation {
                entry_txid: r.str()?,
            },
            4 => State::AwaitAssignment { entry: r.record()? },
            5 => State::Pay {
                entry: r.record()?,
                assignment_seals: r.seals()?,
                expired_advances: r.strs()?,
            },
            6 => State::AwaitAdvanceConfirmation {
                entry: r.record()?,
                assignment_seals: r.seals()?,
                advance_txid: r.str()?,
                sent_tip: r.u32()?,
                expired_advances: r.strs()?,
            },
            7 => State::Done {
                entry: r.record()?,
                advance_txid: r.str()?,
            },
            8 => State::Stopped(Stop::AlreadyFinanced {
                winner: r.record()?,
            }),
            9 => State::Stopped(Stop::DoubleFinanced {
                winner: r.record()?,
                conflicting: r.records()?,
            }),
            _ => return Err(Error::Format("unknown state")),
        };
        r.finish()?;
        match &state {
            State::Register { entry } => flow.check_entry(entry)?,
            State::AwaitAssignment { entry } | State::Done { entry, .. } => {
                flow.check_entry(&entry.entry)?
            }
            State::Pay {
                entry,
                assignment_seals,
                ..
            }
            | State::AwaitAdvanceConfirmation {
                entry,
                assignment_seals,
                ..
            } => {
                flow.check_entry(&entry.entry)?;
                if !matches!(
                    flow.deal
                        .assignment
                        .verify(&flow.deal.invoice, assignment_seals)?,
                    ChainStatus::Incomplete {
                        next: Role::Financier
                    }
                ) {
                    return Err(Error::Format(
                        "assignment needs exactly the supplier and buyer seals",
                    ));
                }
            }
            _ => {}
        }
        flow.state = state;
        Ok(flow)
    }

    /// Applies one event. On error the state is unchanged.
    pub fn apply(&mut self, event: Event) -> Result<&State, Error> {
        let next = match (&self.state, event) {
            // `Register` accepts a board check too (K-4): right before posting, a conflict that
            // appeared since the first check stops the deal, and an entry of ours that is
            // already on chain (an earlier attempt) is followed instead of posted again.
            (
                State::Check
                | State::Register { .. }
                | State::AwaitConfirmation { .. }
                | State::AwaitAssignment { .. }
                | State::Pay { .. },
                Event::BoardChecked { lookup, tip_height },
            ) => self.on_board(lookup, tip_height),
            (State::AwaitSupplierSignature, Event::SupplierSigned(entry)) => {
                self.check_entry(&entry)?;
                State::Register { entry }
            }
            (State::Register { .. }, Event::EntryPosted { txid }) => {
                State::AwaitConfirmation { entry_txid: txid }
            }
            (State::AwaitAssignment { entry }, Event::AssignmentSealed(seals)) => {
                match self.deal.assignment.verify(&self.deal.invoice, &seals)? {
                    ChainStatus::Incomplete {
                        next: Role::Financier,
                    } => State::Pay {
                        entry: entry.clone(),
                        assignment_seals: seals,
                        expired_advances: Vec::new(),
                    },
                    _ => {
                        return Err(Error::InvalidDeal(
                            "assignment needs exactly the supplier and buyer seals",
                        ))
                    }
                }
            }
            (
                State::Pay {
                    entry,
                    assignment_seals,
                    expired_advances,
                },
                Event::AdvanceSent { txid, tip_height },
            ) => State::AwaitAdvanceConfirmation {
                entry: entry.clone(),
                assignment_seals: assignment_seals.clone(),
                advance_txid: txid,
                sent_tip: tip_height,
                expired_advances: expired_advances.clone(),
            },
            (
                State::AwaitAdvanceConfirmation {
                    entry,
                    assignment_seals,
                    advance_txid,
                    sent_tip,
                    expired_advances,
                },
                Event::AdvanceChecked { mined, tip_height },
            ) => {
                if mined {
                    State::Done {
                        entry: entry.clone(),
                        advance_txid: advance_txid.clone(),
                    }
                } else if tip_height > sent_tip.saturating_add(ADVANCE_EXPIRY_BLOCKS) {
                    // Expired unmined: back to `Pay`; this txid never counts as paid again.
                    let mut expired = expired_advances.clone();
                    expired.push(advance_txid.clone());
                    State::Pay {
                        entry: entry.clone(),
                        assignment_seals: assignment_seals.clone(),
                        expired_advances: expired,
                    }
                } else {
                    self.state.clone()
                }
            }
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
            // Ours (posted now or in an earlier attempt). A re-check after confirmation keeps
            // the state while the entry stays where it was; an entry re-mined at another height
            // is counted again from there (K-7).
            Lookup::Registered { winner, .. } => match &self.state {
                State::AwaitAssignment { entry } | State::Pay { entry, .. }
                    if entry.position == winner.position =>
                {
                    self.state.clone()
                }
                State::AwaitAssignment { .. } | State::Pay { .. }
                    if confirmations(tip_height, winner.position.height)
                        < self.deal.min_confirmations =>
                {
                    State::AwaitConfirmation {
                        entry_txid: winner.txid,
                    }
                }
                State::AwaitAssignment { .. } => State::AwaitAssignment { entry: winner },
                State::Pay {
                    assignment_seals,
                    expired_advances,
                    ..
                } => State::Pay {
                    entry: winner,
                    assignment_seals: assignment_seals.clone(),
                    expired_advances: expired_advances.clone(),
                },
                _ if confirmations(tip_height, winner.position.height)
                    >= self.deal.min_confirmations =>
                {
                    State::AwaitAssignment { entry: winner }
                }
                _ => State::AwaitConfirmation {
                    entry_txid: winner.txid,
                },
            },
            Lookup::NotFound { .. } => match &self.state {
                State::Check => State::AwaitSupplierSignature,
                // Entry gone after a reorg: wait for it again before paying.
                State::AwaitAssignment { entry } | State::Pay { entry, .. } => {
                    State::AwaitConfirmation {
                        entry_txid: entry.txid.clone(),
                    }
                }
                // Posted but not mined yet.
                other => other.clone(),
            },
        }
    }

    fn check_entry(&self, entry: &BoardEntry) -> Result<(), Error> {
        if !entry.kind.is_register() {
            return Err(Error::EntryMismatch("entry kind is not register"));
        }
        if entry.nullifier != self.nullifier {
            return Err(Error::EntryMismatch("nullifier differs from the deal"));
        }
        if entry.financier_commitment != self.deal.financier_commitment {
            return Err(Error::EntryMismatch("financier commitment differs"));
        }
        if self.deal.history_tag.is_some() && entry.history_tag != self.deal.history_tag {
            return Err(Error::EntryMismatch("history tag missing or wrong"));
        }
        if (entry.discount_bucket, entry.tenor_bucket)
            != (self.deal.discount_bucket, self.deal.tenor_bucket)
        {
            return Err(Error::EntryMismatch(
                "discount or tenor class differs from the deal",
            ));
        }
        entry
            .verify(&self.deal.invoice.supplier_ephemeral_pk)
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

/// Txid of a register entry for `nullifier` and `financier_commitment` that this wallet already
/// sent, mined or not (K-4). Lets `register` after a crash record the earlier post instead of
/// posting a second entry (two tagged entries for one invoice read as equivocation, Spec #2).
pub fn sent_entry(
    txs: &[WalletTx],
    nullifier: &[u8; 32],
    financier_commitment: &[u8; 32],
) -> Option<String> {
    txs.iter()
        .find(|tx| {
            tx.outputs.iter().filter(|o| !o.received).any(|o| {
                let Memo::Arbitrary(bytes) = &o.memo else {
                    return false;
                };
                BoardEntry::from_memo_bytes(bytes).is_ok_and(|e| {
                    e.kind.is_register()
                        && &e.nullifier == nullifier
                        && &e.financier_commitment == financier_commitment
                })
            })
        })
        .map(|tx| tx.txid.clone())
}

/// Txid of an advance receipt for `nullifier`, signed by `financier_pk`, that this wallet already
/// sent. Lets a retry after a crash record the earlier payment instead of paying twice.
pub fn sent_advance(
    txs: &[WalletTx],
    nullifier: &[u8; 32],
    financier_pk: &[u8; 32],
    expired: &[String],
) -> Option<String> {
    txs.iter()
        .filter(|tx| !expired.contains(&tx.txid))
        .find(|tx| {
            tx.outputs.iter().filter(|o| !o.received).any(|o| {
                let Memo::Arbitrary(bytes) = &o.memo else {
                    return false;
                };
                memo::decode(bytes).is_ok_and(|items| {
                    items.iter().any(|item| {
                        matches!(item, MemoItem::Receipt(r) if r.kind == ReceiptKind::Advance
                            && &r.nullifier == nullifier
                            && r.verify(financier_pk).is_ok())
                    })
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
    /// Long-term key of the financier; signs advance receipts and the assignment letter. Its
    /// public key is behind the financier commitment and in the letter.
    pub key: SigningKey,
}

impl Financier {
    /// Salt and commitment for a deal on `invoice` (P-08): derived from this financier's key and
    /// N, so a retry after a crash reuses the same commitment. Send the salt with
    /// `financier_pk` to the supplier; put the commitment in [`Deal::financier_commitment`].
    pub fn commitment_opening(&self, invoice: &Invoice) -> Result<([u8; 32], [u8; 32]), Error> {
        Ok(commitment_opening(&self.key, &nullifier(invoice)?))
    }

    /// Scans the board and feeds the lookup to the flow (states `Check` and `AwaitConfirmation`).
    pub fn check<'f>(&self, flow: &'f mut Flow) -> Result<&'f State, Error> {
        let report = scan(&self.board_watch, &self.lightwalletd)?;
        let tip_height = lwd::latest_height(&self.lightwalletd)?;
        let lookup = lookup(
            &report.records,
            flow.nullifier(),
            &flow.deal().invoice.supplier_ephemeral_pk,
        );
        flow.apply(Event::BoardChecked { lookup, tip_height })
    }

    /// Posts the supplier-signed entry to the board (state `Register`). Checks the board once more
    /// first (a new conflict stops the deal; our own entry already on chain is followed), and
    /// records an entry this wallet already sent instead of posting it again (K-4).
    pub fn register<'f>(&self, flow: &'f mut Flow) -> Result<&'f State, Error> {
        if !matches!(flow.state(), State::Register { .. }) {
            return Err(unexpected(flow, "register"));
        }
        let State::Register { entry } = self.check(flow)?.clone() else {
            return Ok(flow.state());
        };
        self.wallet.sync()?;
        if let Some(txid) = sent_entry(
            &self.wallet.list_tx()?,
            flow.nullifier(),
            &flow.deal().financier_commitment,
        ) {
            return flow.apply(Event::EntryPosted { txid });
        }
        let memo = entry.to_memo_bytes()[..entry.encoded_len()].to_vec();
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

    /// Pays the advance to the supplier (state `Pay`) after a last board check. The memo carries
    /// the advance receipt, this financier's seal on the assignment letter (Sign-to-Pay) and a
    /// receivable note for the fund's members (HNK-15). If
    /// this wallet already sent an advance receipt for the nullifier, records that txid instead.
    pub fn pay_advance<'f>(&self, flow: &'f mut Flow, date: u32) -> Result<&'f State, Error> {
        if !matches!(flow.state(), State::Pay { .. }) {
            return Err(unexpected(flow, "pay_advance"));
        }
        let financier_pk = self.key.verifying_key().to_bytes();
        if flow.deal().assignment.financier_pk != financier_pk {
            return Err(Error::InvalidDeal(
                "financier key differs from the assignment letter",
            ));
        }
        // Last look: a late double financing or a reorg moves the flow out of `Pay`.
        let State::Pay {
            assignment_seals,
            expired_advances,
            ..
        } = self.check(flow)?.clone()
        else {
            return Ok(flow.state());
        };
        let deal = flow.deal().clone();
        let n = *flow.nullifier();
        self.wallet.sync()?;
        if let Some(txid) = sent_advance(
            &self.wallet.list_tx()?,
            &n,
            &financier_pk,
            &expired_advances,
        ) {
            let tip_height = lwd::latest_height(&self.lightwalletd)?;
            return flow.apply(Event::AdvanceSent { txid, tip_height });
        }
        let receipt = Receipt::sign(&self.key, ReceiptKind::Advance, n, deal.advance_zat, date)?;
        let seal = deal.assignment.seal_next(&self.key, &assignment_seals)?;
        // The receivable note lets holders of the fund's viewing key value the invoice (HNK-15).
        let note = ReceivableNote {
            nullifier: n,
            face_zat: deal.invoice.amount_zat,
            due_date: deal.invoice.due_date,
        };
        let memo = memo::encode(&[
            MemoItem::Receipt(receipt),
            MemoItem::Seal(seal),
            MemoItem::Note(note),
        ])?;
        let txid = self.wallet.pay(&[Payment {
            address: deal.supplier_address,
            amount_zat: deal.advance_zat,
            memo: Some(PaymentMemo::Arbitrary(memo)),
        }])?;
        let tip_height = lwd::latest_height(&self.lightwalletd)?;
        flow.apply(Event::AdvanceSent { txid, tip_height })
    }

    /// Checks the advance in this wallet until it is mined (`Done`), or it expires unmined and
    /// the flow goes back to `Pay` for one new payment (state `AwaitAdvanceConfirmation`, K-7).
    pub fn wait_for_advance<'f>(
        &self,
        flow: &'f mut Flow,
        poll: Duration,
        timeout: Duration,
    ) -> Result<&'f State, Error> {
        let started = Instant::now();
        loop {
            let State::AwaitAdvanceConfirmation { advance_txid, .. } = flow.state().clone() else {
                return Err(unexpected(flow, "wait_for_advance"));
            };
            self.wallet.sync()?;
            let mined = self
                .wallet
                .list_tx()?
                .iter()
                .any(|tx| tx.txid == advance_txid && tx.mined_height.is_some());
            let tip_height = lwd::latest_height(&self.lightwalletd)?;
            if !matches!(
                flow.apply(Event::AdvanceChecked { mined, tip_height })?,
                State::AwaitAdvanceConfirmation { .. }
            ) {
                return Ok(flow.state());
            }
            if started.elapsed() >= timeout {
                return Err(Error::Timeout("advance not mined"));
            }
            thread::sleep(poll);
        }
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
    use jitsuin_board::{verify_proof_on_board, Position};
    use jitsuin_core::{financier_commitment, sign_invoice, EntryKind, SEAL_LEN};
    use jitsuin_wallet::TxOutput;

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    fn supplier() -> SigningKey {
        key(1)
    }

    fn buyer() -> SigningKey {
        key(2)
    }

    fn financier() -> SigningKey {
        key(3)
    }

    fn invoice() -> Invoice {
        Invoice {
            invoice_id: "TES-INV-0003".into(),
            supplier_ephemeral_pk: supplier().verifying_key().to_bytes(),
            buyer_pk: buyer().verifying_key().to_bytes(),
            amount_zat: 1_000_000,
            issue_date: 20_377,
            due_date: 20_437,
            terms_hash: [9; 32],
        }
    }

    fn n() -> [u8; 32] {
        nullifier(&invoice()).unwrap()
    }

    fn letter() -> Assignment {
        Assignment::for_invoice(
            &invoice(),
            financier().verifying_key().to_bytes(),
            "utest1financier",
            [5; 32],
        )
        .unwrap()
    }

    /// Supplier and buyer seals on the letter.
    fn seals() -> Vec<Seal> {
        let a = letter();
        let s0 = a.seal_next(&supplier(), &[]).unwrap();
        let s1 = a.seal_next(&buyer(), std::slice::from_ref(&s0)).unwrap();
        vec![s0, s1]
    }

    fn ours() -> [u8; 32] {
        financier_commitment(&financier().verifying_key().to_bytes(), &[4; 32])
    }

    fn deal(min_confirmations: u32) -> Deal {
        Deal {
            invoice: invoice(),
            assignment: letter(),
            financier_commitment: ours(),
            supplier_address: "utest1supplier".into(),
            advance_zat: 950_000,
            min_confirmations,
            history_tag: None,
            discount_bucket: 2,
            tenor_bucket: 3,
        }
    }

    fn entry(commitment: [u8; 32]) -> BoardEntry {
        BoardEntry::sign(&supplier(), EntryKind::Register, n(), commitment, 2, 3)
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
            lookup: lookup(records, &n(), &supplier().verifying_key().to_bytes()),
            tip_height,
        }
    }

    #[test]
    fn happy_path_waits_for_confirmations_and_the_sealed_letter() {
        let mut flow = Flow::new(deal(2)).unwrap();
        let griefer = key(9);
        let grief = record(
            "g",
            90,
            BoardEntry::sign(&griefer, EntryKind::Register, n(), [0x99; 32], 0, 0),
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
            flow.apply(Event::AdvanceSent {
                txid: "x".into(),
                tip_height: 101
            }),
            Err(Error::UnexpectedEvent { .. })
        ));
        flow.apply(board(&[grief.clone(), mine.clone()], 102))
            .unwrap();
        assert_eq!(
            flow.state(),
            &State::AwaitAssignment {
                entry: mine.clone()
            }
        );
        // confirmed is not enough: no advance without the sealed letter
        assert!(matches!(
            flow.apply(Event::AdvanceSent {
                txid: "x".into(),
                tip_height: 102
            }),
            Err(Error::UnexpectedEvent { .. })
        ));
        flow.apply(Event::AssignmentSealed(seals())).unwrap();
        assert_eq!(
            flow.state(),
            &State::Pay {
                entry: mine.clone(),
                assignment_seals: seals(),
                expired_advances: vec![],
            }
        );
        // the last look before paying keeps the state
        flow.apply(board(&[grief, mine.clone()], 103)).unwrap();
        assert!(matches!(flow.state(), State::Pay { .. }));

        flow.apply(Event::AdvanceSent {
            txid: "a".into(),
            tip_height: 103,
        })
        .unwrap();
        // broadcast is not paid: wait until the advance is mined
        assert!(matches!(
            flow.state(),
            State::AwaitAdvanceConfirmation { .. }
        ));
        flow.apply(Event::AdvanceChecked {
            mined: false,
            tip_height: 104,
        })
        .unwrap();
        assert!(matches!(
            flow.state(),
            State::AwaitAdvanceConfirmation { .. }
        ));
        flow.apply(Event::AdvanceChecked {
            mined: true,
            tip_height: 105,
        })
        .unwrap();
        assert_eq!(
            flow.state(),
            &State::Done {
                entry: mine,
                advance_txid: "a".into()
            }
        );
    }

    #[test]
    fn an_expired_advance_is_paid_again_once() {
        let mine = record("e", 20, entry(ours()));
        let mut flow = Flow::new(deal(1)).unwrap();
        flow.apply(board(std::slice::from_ref(&mine), 20)).unwrap();
        flow.apply(Event::AssignmentSealed(seals())).unwrap();
        flow.apply(Event::AdvanceSent {
            txid: "a1".into(),
            tip_height: 30,
        })
        .unwrap();
        // still within the expiry window
        flow.apply(Event::AdvanceChecked {
            mined: false,
            tip_height: 30 + ADVANCE_EXPIRY_BLOCKS,
        })
        .unwrap();
        assert!(matches!(
            flow.state(),
            State::AwaitAdvanceConfirmation { .. }
        ));
        // expired unmined: back to Pay, and a1 never counts as paid again
        flow.apply(Event::AdvanceChecked {
            mined: false,
            tip_height: 31 + ADVANCE_EXPIRY_BLOCKS,
        })
        .unwrap();
        assert_eq!(
            flow.state(),
            &State::Pay {
                entry: mine,
                assignment_seals: seals(),
                expired_advances: vec!["a1".into()],
            }
        );
    }

    #[test]
    fn a_re_mined_entry_is_counted_again() {
        let mut d = deal(3);
        d.min_confirmations = 3;
        let mut flow = Flow::new(d).unwrap();
        let mine = record("e", 20, entry(ours()));
        flow.apply(board(std::slice::from_ref(&mine), 22)).unwrap();
        flow.apply(Event::AssignmentSealed(seals())).unwrap();
        assert!(matches!(flow.state(), State::Pay { .. }));
        // a reorg re-mines our entry at 24: only 1 confirmation at tip 24, 3 required
        let moved = record("e", 24, entry(ours()));
        flow.apply(board(std::slice::from_ref(&moved), 24)).unwrap();
        assert_eq!(
            flow.state(),
            &State::AwaitConfirmation {
                entry_txid: "e".into()
            }
        );
        // re-mined but already deep enough: stay in AwaitAssignment with the new position
        let mut flow = Flow::new(deal(1)).unwrap();
        flow.apply(board(std::slice::from_ref(&mine), 22)).unwrap();
        flow.apply(board(std::slice::from_ref(&moved), 30)).unwrap();
        assert_eq!(flow.state(), &State::AwaitAssignment { entry: moved });
    }

    #[test]
    fn incomplete_or_forged_letters_keep_the_money() {
        let mut flow = Flow::new(deal(1)).unwrap();
        let mine = record("e", 20, entry(ours()));
        flow.apply(board(std::slice::from_ref(&mine), 20)).unwrap();
        assert!(matches!(flow.state(), State::AwaitAssignment { .. }));

        let s = seals();
        // supplier only
        assert!(flow
            .apply(Event::AssignmentSealed(s[..1].to_vec()))
            .is_err());
        // buyer seal forged by the supplier
        let forged = letter().seal_next(&supplier(), &s[..1]).unwrap();
        assert!(matches!(
            flow.apply(Event::AssignmentSealed(vec![s[0].clone(), forged])),
            Err(Error::Core(jitsuin_core::Error::UnexpectedSigner))
        ));
        // already sealed by the financier: the financier seal must go with the money
        let s2 = letter().seal_next(&financier(), &s).unwrap();
        let mut all = s.clone();
        all.push(s2);
        assert!(flow.apply(Event::AssignmentSealed(all)).is_err());
        assert!(matches!(flow.state(), State::AwaitAssignment { .. }));
    }

    #[test]
    fn late_double_financing_or_reorg_before_paying() {
        let mine = record("e", 20, entry(ours()));
        let mut flow = Flow::new(deal(1)).unwrap();
        flow.apply(board(std::slice::from_ref(&mine), 20)).unwrap();
        flow.apply(Event::AssignmentSealed(seals())).unwrap();
        let mut reorged = flow.clone();
        // the supplier signs for a second financier later: stop before paying
        let other = record("o", 25, entry([0xEE; 32]));
        flow.apply(board(&[mine.clone(), other], 25)).unwrap();
        assert!(matches!(
            flow.state(),
            State::Stopped(Stop::DoubleFinanced { .. })
        ));
        // our entry disappears in a reorg: wait for it again
        reorged.apply(board(&[], 26)).unwrap();
        assert_eq!(
            reorged.state(),
            &State::AwaitConfirmation {
                entry_txid: "e".into()
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
            Event::AssignmentSealed(seals()),
            Event::AdvanceSent {
                txid: "a".into(),
                tip_height: 61,
            },
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
    fn a_double_financed_deal_gives_a_proof_that_holds_on_the_board() {
        let mut flow = Flow::new(deal(1)).unwrap();
        let buyer_signature = sign_invoice(&buyer(), &invoice()).unwrap().to_bytes();
        flow.apply(board(&[], 10)).unwrap();
        assert_eq!(flow.double_sign_proof(buyer_signature).unwrap(), None);

        flow.apply(Event::SupplierSigned(entry(ours()))).unwrap();
        let (o, e) = ("0f".repeat(32), "0e".repeat(32));
        flow.apply(Event::EntryPosted { txid: e.clone() }).unwrap();
        let other = record(&o, 11, entry([0xEE; 32]));
        let mine = record(&e, 12, entry(ours()));
        let records = [other.clone(), mine.clone()];
        flow.apply(board(&records, 12)).unwrap();

        let proof = flow.double_sign_proof(buyer_signature).unwrap().unwrap();
        assert_eq!(proof.first, other.entry);
        assert_eq!(proof.second, mine.entry);
        assert_eq!(proof.second_at.as_ref().unwrap().txid, e);
        assert!(verify_proof_on_board(&proof, &records));
        let bytes = proof.to_bytes().unwrap();
        assert_eq!(DoubleSignProof::from_bytes(&bytes).unwrap(), proof);

        // only the buyer's signature on this invoice is accepted
        let mut forged = buyer_signature;
        forged[0] ^= 1;
        assert!(flow.double_sign_proof(forged).is_err());
    }

    #[test]
    fn already_financed_gives_no_proof() {
        let mut flow = Flow::new(deal(1)).unwrap();
        let other = record("o", 11, entry([0xEE; 32]));
        flow.apply(board(std::slice::from_ref(&other), 11)).unwrap();
        assert!(matches!(
            flow.state(),
            State::Stopped(Stop::AlreadyFinanced { .. })
        ));
        let buyer_signature = sign_invoice(&buyer(), &invoice()).unwrap().to_bytes();
        assert_eq!(flow.double_sign_proof(buyer_signature).unwrap(), None);
    }

    /// Snapshot and restore; the restored flow must equal the original byte for byte.
    fn restored(flow: &Flow) -> Flow {
        let bytes = flow.to_bytes().unwrap();
        let back = Flow::from_bytes(&bytes).unwrap();
        assert_eq!(back.state(), flow.state());
        assert_eq!(back.deal(), flow.deal());
        assert_eq!(back.nullifier(), flow.nullifier());
        assert_eq!(back.to_bytes().unwrap(), bytes);
        back
    }

    #[test]
    fn a_restored_snapshot_resumes_the_deal_in_every_state() {
        let mut flow = restored(&Flow::new(deal(1)).unwrap());
        flow.apply(board(&[], 10)).unwrap();
        let mut flow = restored(&flow);
        assert_eq!(flow.state(), &State::AwaitSupplierSignature);
        flow.apply(Event::SupplierSigned(entry(ours()))).unwrap();
        let mut flow = restored(&flow);
        flow.apply(Event::EntryPosted { txid: "e".into() }).unwrap();
        let mut flow = restored(&flow);
        let mine = record("e", 11, entry(ours()));
        flow.apply(board(std::slice::from_ref(&mine), 11)).unwrap();
        let mut flow = restored(&flow);
        assert!(matches!(flow.state(), State::AwaitAssignment { .. }));
        flow.apply(Event::AssignmentSealed(seals())).unwrap();
        let mut flow = restored(&flow);
        assert!(matches!(flow.state(), State::Pay { .. }));
        flow.apply(Event::AdvanceSent {
            txid: "a".into(),
            tip_height: 12,
        })
        .unwrap();
        let mut flow = restored(&flow);
        // the advance expires unmined: the restored flow remembers it and pays again
        flow.apply(Event::AdvanceChecked {
            mined: false,
            tip_height: 12 + ADVANCE_EXPIRY_BLOCKS + 1,
        })
        .unwrap();
        let mut flow = restored(&flow);
        assert!(matches!(
            flow.state(),
            State::Pay { expired_advances, .. } if expired_advances == &["a".to_string()]
        ));
        flow.apply(Event::AdvanceSent {
            txid: "b".into(),
            tip_height: 70,
        })
        .unwrap();
        let mut flow = restored(&flow);
        flow.apply(Event::AdvanceChecked {
            mined: true,
            tip_height: 71,
        })
        .unwrap();
        let flow = restored(&flow);
        assert_eq!(
            flow.state(),
            &State::Done {
                entry: mine,
                advance_txid: "b".into()
            }
        );

        let other = record("o", 11, entry([0xEE; 32]));
        let mut stopped = Flow::new(deal(1)).unwrap();
        stopped
            .apply(board(std::slice::from_ref(&other), 11))
            .unwrap();
        assert!(matches!(
            restored(&stopped).state(),
            State::Stopped(Stop::AlreadyFinanced { .. })
        ));
        let mut double = Flow::new(deal(1)).unwrap();
        double.apply(board(&[], 10)).unwrap();
        double.apply(Event::SupplierSigned(entry(ours()))).unwrap();
        double
            .apply(Event::EntryPosted { txid: "e".into() })
            .unwrap();
        double
            .apply(board(&[other, record("e", 12, entry(ours()))], 12))
            .unwrap();
        assert!(matches!(
            restored(&double).state(),
            State::Stopped(Stop::DoubleFinanced { .. })
        ));

        let mut tagged = deal(1);
        tagged.history_tag = Some([7; 32]);
        restored(&Flow::new(tagged).unwrap());
    }

    #[test]
    fn a_damaged_or_edited_snapshot_is_refused() {
        let mut flow = Flow::new(deal(1)).unwrap();
        flow.apply(board(&[], 10)).unwrap();
        flow.apply(Event::SupplierSigned(entry(ours()))).unwrap();
        flow.apply(Event::EntryPosted { txid: "e".into() }).unwrap();
        flow.apply(board(&[record("e", 11, entry(ours()))], 11))
            .unwrap();
        flow.apply(Event::AssignmentSealed(seals())).unwrap();
        let good = flow.to_bytes().unwrap();

        let mut bad = good.clone();
        bad[0] = b'X';
        assert!(matches!(Flow::from_bytes(&bad), Err(Error::Format(_))));
        let mut bad = good.clone();
        bad[4] = 2;
        assert!(matches!(Flow::from_bytes(&bad), Err(Error::Format(_))));
        let mut bad = good.clone();
        bad.push(0);
        assert!(matches!(Flow::from_bytes(&bad), Err(Error::Format(_))));
        assert!(Flow::from_bytes(&good[..good.len() - 1]).is_err());
        // the Pay state with only the supplier's seal: apply would never have reached it
        let mut one_seal = flow.clone();
        if let State::Pay {
            assignment_seals, ..
        } = &mut one_seal.state
        {
            assignment_seals.truncate(1);
        }
        assert!(Flow::from_bytes(&one_seal.to_bytes().unwrap()).is_err());
        // the buyer's seal with a broken signature
        let mut broken = flow.clone();
        if let State::Pay {
            assignment_seals, ..
        } = &mut broken.state
        {
            let mut b = assignment_seals[1].to_bytes();
            b[SEAL_LEN - 1] ^= 1;
            assignment_seals[1] = Seal::from_bytes(&b).unwrap();
        }
        assert!(Flow::from_bytes(&broken.to_bytes().unwrap()).is_err());
        // an entry for another financier in our Register state
        let mut foreign = Flow::new(deal(1)).unwrap();
        foreign.state = State::Register {
            entry: entry([0xEE; 32]),
        };
        assert!(matches!(
            Flow::from_bytes(&foreign.to_bytes().unwrap()),
            Err(Error::EntryMismatch(_))
        ));
    }

    #[test]
    fn resumes_from_an_entry_posted_earlier() {
        let mut flow = Flow::new(deal(1)).unwrap();
        let mine = record("e", 20, entry(ours()));
        flow.apply(board(std::slice::from_ref(&mine), 20)).unwrap();
        assert_eq!(flow.state(), &State::AwaitAssignment { entry: mine });
    }

    #[test]
    fn rejects_entries_that_do_not_match_the_deal() {
        let mut flow = Flow::new(deal(1)).unwrap();
        flow.apply(board(&[], 1)).unwrap();
        let bad = [
            BoardEntry::sign(&supplier(), EntryKind::Settled, n(), ours(), 2, 3),
            BoardEntry::sign(&supplier(), EntryKind::Register, [8; 32], ours(), 2, 3),
            entry([0xEE; 32]),
            BoardEntry::sign(&key(9), EntryKind::Register, n(), ours(), 2, 3),
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
    fn entry_classes_must_match_the_deal() {
        let mut flow = Flow::new(deal(1)).unwrap();
        flow.apply(board(&[], 1)).unwrap();
        // 0/0 (or any other class) when the deal says 2/3 is refused, state unchanged
        for (d, t) in [(0, 0), (3, 3), (2, 4)] {
            let e = BoardEntry::sign(&supplier(), EntryKind::Register, n(), ours(), d, t);
            assert!(matches!(
                flow.apply(Event::SupplierSigned(e)),
                Err(Error::EntryMismatch(
                    "discount or tenor class differs from the deal"
                ))
            ));
            assert_eq!(flow.state(), &State::AwaitSupplierSignature);
        }
        flow.apply(Event::SupplierSigned(entry(ours()))).unwrap();
        assert!(matches!(flow.state(), State::Register { .. }));
    }

    #[test]
    fn deal_classes_come_from_face_advance_and_dates() {
        // 1 000 000 zat face, 975 000 advance (2.5% discount), 45 days: same vector as index.rs
        let mut inv = invoice();
        inv.amount_zat = 1_000_000;
        inv.due_date = 20_790;
        assert_eq!(deal_classes(&inv, 975_000, 20_745), (3, 2));
        // a deal that fits no class is registered as 0/0
        assert_eq!(deal_classes(&inv, 1_000_001, 20_745), (0, 0));
        assert_eq!(deal_classes(&inv, 975_000, 20_791), (0, 0));
        // an unknown class makes the deal invalid
        let mut d = deal(1);
        d.discount_bucket = 99;
        assert!(matches!(Flow::new(d), Err(Error::InvalidDeal(_))));
    }

    #[test]
    fn history_tag_is_required_when_the_deal_has_one() {
        let mut d = deal(1);
        d.history_tag = Some([0x77; 32]);
        let mut flow = Flow::new(d).unwrap();
        flow.apply(board(&[], 1)).unwrap();
        // an untagged entry, or one with another tag, is refused
        for e in [
            entry(ours()),
            BoardEntry::sign_with_history(&supplier(), n(), ours(), 2, 3, [0x78; 32]),
        ] {
            assert!(matches!(
                flow.apply(Event::SupplierSigned(e)),
                Err(Error::EntryMismatch("history tag missing or wrong"))
            ));
        }
        let tagged = BoardEntry::sign_with_history(&supplier(), n(), ours(), 2, 3, [0x77; 32]);
        flow.apply(Event::SupplierSigned(tagged)).unwrap();
        assert!(matches!(flow.state(), State::Register { .. }));
    }

    #[test]
    fn invalid_deals_are_rejected() {
        assert!(Flow::new(deal(0)).is_err());
        let mut d = deal(1);
        d.advance_zat = 0;
        assert!(Flow::new(d).is_err());
        // a letter for another invoice
        let mut d = deal(1);
        d.assignment.amount_zat += 1;
        assert!(Flow::new(d).is_err());
        // the financier is the buyer
        let mut d = deal(1);
        d.assignment.financier_pk = d.invoice.buyer_pk;
        assert!(matches!(
            Flow::new(d),
            Err(Error::Core(jitsuin_core::Error::SelfApproval))
        ));
    }

    #[test]
    fn confirmation_count() {
        assert_eq!(confirmations(100, 100), 1);
        assert_eq!(confirmations(105, 100), 6);
        assert_eq!(confirmations(99, 100), 0);
    }

    #[test]
    fn a_board_check_right_before_posting_stops_or_follows() {
        let to_register = || {
            let mut flow = Flow::new(deal(2)).unwrap();
            flow.apply(board(&[], 1)).unwrap();
            flow.apply(Event::SupplierSigned(entry(ours()))).unwrap();
            assert!(matches!(flow.state(), State::Register { .. }));
            flow
        };
        // nothing new on the board: still ready to post
        let mut flow = to_register();
        flow.apply(board(&[], 2)).unwrap();
        assert!(matches!(flow.state(), State::Register { .. }));
        // another financier registered meanwhile: stop, nothing is posted
        let mut flow = to_register();
        let theirs = record("t", 2, entry([0xEE; 32]));
        flow.apply(board(std::slice::from_ref(&theirs), 2)).unwrap();
        assert!(matches!(
            flow.state(),
            State::Stopped(Stop::AlreadyFinanced { .. })
        ));
        // our entry from an earlier attempt is already mined: follow it, do not post again
        let mut flow = to_register();
        let mine = record("e0", 2, entry(ours()));
        flow.apply(board(std::slice::from_ref(&mine), 2)).unwrap();
        assert_eq!(
            flow.state(),
            &State::AwaitConfirmation {
                entry_txid: "e0".into()
            }
        );
    }

    #[test]
    fn finds_an_entry_already_sent() {
        let out = |received, memo: Vec<u8>| TxOutput {
            index: 0,
            pool: "Ironwood".into(),
            value_zat: ENTRY_POST_ZAT,
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
        let mine = entry(ours()).to_memo_bytes().to_vec();
        let other_n = BoardEntry::sign(&supplier(), EntryKind::Register, [8; 32], ours(), 2, 3)
            .to_memo_bytes()
            .to_vec();
        let other_commitment = entry([0xEE; 32]).to_memo_bytes().to_vec();
        let txs = vec![
            tx("received", out(true, mine.clone())),
            tx("other-n", out(false, other_n)),
            tx("other-commitment", out(false, other_commitment)),
            tx("pending", out(false, mine)),
        ];
        assert_eq!(sent_entry(&txs, &n(), &ours()).as_deref(), Some("pending"));
        assert_eq!(sent_entry(&txs[..3], &n(), &ours()), None);
    }

    #[test]
    fn finds_an_advance_already_sent() {
        let pk = financier().verifying_key().to_bytes();
        let receipt = Receipt::sign(&financier(), ReceiptKind::Advance, n(), 950_000, 1).unwrap();
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
        let seal = letter().seal_next(&financier(), &seals()).unwrap();
        let memo =
            memo::encode(&[MemoItem::Receipt(receipt.clone()), MemoItem::Seal(seal)]).unwrap();
        let other_n = Receipt::sign(&financier(), ReceiptKind::Advance, [8; 32], 1, 1)
            .unwrap()
            .to_memo_bytes()
            .to_vec();
        let txs = vec![
            tx("received", out(true, memo.clone())),
            tx("other-n", out(false, other_n)),
            tx("sent", out(false, memo)),
            tx("legacy", out(false, receipt.to_memo_bytes().to_vec())),
        ];
        assert_eq!(sent_advance(&txs, &n(), &pk, &[]).as_deref(), Some("sent"));
        assert_eq!(sent_advance(&txs[..2], &n(), &pk, &[]), None);
        assert_eq!(
            sent_advance(&txs[3..], &n(), &pk, &[]).as_deref(),
            Some("legacy")
        );
        // an advance that expired unmined is not counted as sent
        assert_eq!(
            sent_advance(&txs, &n(), &pk, &["sent".into()]).as_deref(),
            Some("legacy")
        );
    }
}
