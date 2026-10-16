//! Settlement sealed by buyer and financier, and its public board entry (HNK-19.T4, D-19,
//! DEV-08).
//!
//! The settlement document is private: N, the amount due and the due date, all known to the
//! parties from the invoice and the assignment letter. The buyer seals it ("I paid"), the
//! financier seals it after the payment is received (flag: on time or late). The public board
//! entry carries `settled_tag(N)` instead of N and only the two signatures, so outsiders cannot
//! link it to the register entry; holders of N rebuild both seals and verify them.
//!
//! Settlement document (integers little-endian): magic `JTSS` (4), version (1), N (32),
//! amount_zat (8), due_date (4).
//!
//! Settled entry (memo, 167 bytes, zero padded to 512):
//!
//! | offset | field                                   | size |
//! |--------|-----------------------------------------|------|
//! | 0      | memo marker `0xFF`                      | 1    |
//! | 1      | magic `JTS1`                            | 4    |
//! | 5      | kind `0x02` (settled)                   | 1    |
//! | 6      | `settled_tag(N)`                        | 32   |
//! | 38     | financier flag (1 on time, 2 late)      | 1    |
//! | 39     | buyer seal signature                    | 64   |
//! | 103    | financier seal signature                | 64   |

use ed25519_dalek::SigningKey;

use crate::assignment::Assignment;
use crate::entry::{settled_tag, EntryKind, ENTRY_MAGIC, MEMO_ARBITRARY_DATA, MEMO_LEN};
use crate::error::Error;
use crate::invoice::Reader;
use crate::seal::{
    next_content, sealed_document_hash, verify_chain, ChainStatus, DocKind, Role, Seal,
    SealContent, Signers,
};

pub const SETTLEMENT_MAGIC: &[u8; 4] = b"JTSS";
pub const SETTLEMENT_VERSION: u8 = 1;
pub const SETTLED_LEN: usize = 1 + 4 + 1 + 32 + 1 + 64 + 64;
pub const SETTLED_ON_TIME: u8 = 0x01;
pub const SETTLED_LATE: u8 = 0x02;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettlementDoc {
    pub nullifier: [u8; 32],
    pub amount_zat: u64,
    pub due_date: u32,
}

impl SettlementDoc {
    pub fn for_assignment(a: &Assignment) -> Self {
        SettlementDoc {
            nullifier: a.nullifier,
            amount_zat: a.amount_zat,
            due_date: a.due_date,
        }
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(49);
        out.extend_from_slice(SETTLEMENT_MAGIC);
        out.push(SETTLEMENT_VERSION);
        out.extend_from_slice(&self.nullifier);
        out.extend_from_slice(&self.amount_zat.to_le_bytes());
        out.extend_from_slice(&self.due_date.to_le_bytes());
        out
    }

    pub fn doc_hash(&self) -> [u8; 32] {
        sealed_document_hash(&self.to_canonical_bytes())
    }

    /// The buyer's claim "I paid": step 0 of the settlement policy.
    pub fn buyer_seal(&self, buyer: &SigningKey) -> Seal {
        let c = next_content(DocKind::Settlement, self.nullifier, self.doc_hash(), &[], 0)
            .expect("settlement policy has a first role");
        Seal::sign(buyer, c)
    }

    /// Checks a buyer seal (claim) against the document and the buyer key.
    pub fn verify_claim(&self, buyer_seal: &Seal, buyer_pk: &[u8; 32]) -> Result<(), Error> {
        let signers = Signers {
            buyer: Some(*buyer_pk),
            ..Signers::default()
        };
        match verify_chain(
            DocKind::Settlement,
            &self.nullifier,
            &self.doc_hash(),
            std::slice::from_ref(buyer_seal),
            &signers,
        )? {
            ChainStatus::Incomplete {
                next: Role::Financier,
            } if buyer_seal.flag == 0 => Ok(()),
            _ => Err(Error::SealOrder),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettledEntry {
    pub tag: [u8; 32],
    pub flag: u8,
    pub buyer_sig: [u8; 64],
    pub financier_sig: [u8; 64],
}

impl SettledEntry {
    /// Countersigns a verified buyer claim. `flag` is [`SETTLED_ON_TIME`] or [`SETTLED_LATE`].
    pub fn countersign(
        doc: &SettlementDoc,
        buyer_seal: &Seal,
        buyer_pk: &[u8; 32],
        financier: &SigningKey,
        flag: u8,
    ) -> Result<Self, Error> {
        doc.verify_claim(buyer_seal, buyer_pk)?;
        check_flag(flag)?;
        let c = next_content(
            DocKind::Settlement,
            doc.nullifier,
            doc.doc_hash(),
            std::slice::from_ref(buyer_seal),
            flag,
        )?;
        let fin = Seal::sign(financier, c);
        Ok(SettledEntry {
            tag: settled_tag(&doc.nullifier),
            flag,
            buyer_sig: buyer_seal.signature,
            financier_sig: fin.signature,
        })
    }

    /// Rebuilds both seals for holders of the document and the two public keys.
    pub fn seals(
        &self,
        doc: &SettlementDoc,
        buyer_pk: &[u8; 32],
        financier_pk: &[u8; 32],
    ) -> [Seal; 2] {
        let content = |step: u8, role, flag, prev| SealContent {
            doc_kind: DocKind::Settlement,
            doc_id: doc.nullifier,
            doc_hash: doc.doc_hash(),
            step,
            role,
            flag,
            prev,
        };
        let buyer = seal_from(
            content(0, Role::Buyer, 0, [0; 32]),
            buyer_pk,
            self.buyer_sig,
        );
        let prev = buyer.hash();
        let fin = seal_from(
            content(1, Role::Financier, self.flag, prev),
            financier_pk,
            self.financier_sig,
        );
        [buyer, fin]
    }

    /// Valid when the tag matches N and both seals verify in order (`Sealed`).
    pub fn verify(
        &self,
        doc: &SettlementDoc,
        buyer_pk: &[u8; 32],
        financier_pk: &[u8; 32],
    ) -> Result<(), Error> {
        if self.tag != settled_tag(&doc.nullifier) {
            return Err(Error::SealMismatch);
        }
        check_flag(self.flag)?;
        let signers = Signers {
            buyer: Some(*buyer_pk),
            financier: Some(*financier_pk),
            ..Signers::default()
        };
        match verify_chain(
            DocKind::Settlement,
            &doc.nullifier,
            &doc.doc_hash(),
            &self.seals(doc, buyer_pk, financier_pk),
            &signers,
        )? {
            ChainStatus::Sealed => Ok(()),
            ChainStatus::Incomplete { .. } => Err(Error::SealOrder),
        }
    }

    pub fn on_time(&self) -> bool {
        self.flag == SETTLED_ON_TIME
    }

    pub fn to_memo_bytes(&self) -> [u8; MEMO_LEN] {
        let mut m = [0u8; MEMO_LEN];
        m[0] = MEMO_ARBITRARY_DATA;
        m[1..5].copy_from_slice(ENTRY_MAGIC);
        m[5] = EntryKind::Settled as u8;
        m[6..38].copy_from_slice(&self.tag);
        m[38] = self.flag;
        m[39..103].copy_from_slice(&self.buyer_sig);
        m[103..SETTLED_LEN].copy_from_slice(&self.financier_sig);
        m
    }

    /// Strict decoder. Accepts the 167-byte entry alone or a padded memo; padding must be zero.
    pub fn from_memo_bytes(memo: &[u8]) -> Result<Self, Error> {
        if memo.len() > MEMO_LEN {
            return Err(Error::TrailingBytes);
        }
        let mut r = Reader::new(memo);
        if r.byte()? != MEMO_ARBITRARY_DATA {
            return Err(Error::NotArbitraryDataMemo);
        }
        if r.take(4)? != ENTRY_MAGIC {
            return Err(Error::BadMagic);
        }
        let kind = r.byte()?;
        if kind != EntryKind::Settled as u8 {
            return Err(Error::UnknownEntryKind(kind));
        }
        let entry = SettledEntry {
            tag: r.array()?,
            flag: r.byte()?,
            buyer_sig: r.array()?,
            financier_sig: r.array()?,
        };
        check_flag(entry.flag)?;
        if r.rest().iter().any(|b| *b != 0) {
            return Err(Error::NonZeroPadding);
        }
        Ok(entry)
    }
}

fn check_flag(flag: u8) -> Result<(), Error> {
    if flag == SETTLED_ON_TIME || flag == SETTLED_LATE {
        Ok(())
    } else {
        Err(Error::InvalidFlag(flag))
    }
}

fn seal_from(c: SealContent, signer_pk: &[u8; 32], signature: [u8; 64]) -> Seal {
    Seal {
        doc_kind: c.doc_kind,
        doc_id: c.doc_id,
        doc_hash: c.doc_hash,
        step: c.step,
        role: c.role,
        flag: c.flag,
        prev: c.prev,
        signer_pk: *signer_pk,
        signature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    fn doc() -> SettlementDoc {
        SettlementDoc {
            nullifier: [7; 32],
            amount_zat: 50_000,
            due_date: 20_437,
        }
    }

    fn pks() -> ([u8; 32], [u8; 32]) {
        (
            key(2).verifying_key().to_bytes(),
            key(3).verifying_key().to_bytes(),
        )
    }

    #[test]
    fn buyer_claim_plus_financier_countersign_verifies() {
        let (buyer_pk, fin_pk) = pks();
        let claim = doc().buyer_seal(&key(2));
        doc().verify_claim(&claim, &buyer_pk).unwrap();
        let e =
            SettledEntry::countersign(&doc(), &claim, &buyer_pk, &key(3), SETTLED_ON_TIME).unwrap();
        e.verify(&doc(), &buyer_pk, &fin_pk).unwrap();
        assert!(e.on_time());
        assert_eq!(e.tag, settled_tag(&doc().nullifier));

        let memo = e.to_memo_bytes();
        assert_eq!(SETTLED_LEN, 167);
        assert_eq!(&memo[1..6], b"JTS1\x02");
        assert_eq!(SettledEntry::from_memo_bytes(&memo).unwrap(), e);
        assert_eq!(
            SettledEntry::from_memo_bytes(&memo[..SETTLED_LEN]).unwrap(),
            e
        );
    }

    #[test]
    fn one_sided_or_forged_settlements_fail() {
        let (buyer_pk, fin_pk) = pks();
        let claim = doc().buyer_seal(&key(2));
        // a claim signed by someone else is not the buyer's claim
        let fake = doc().buyer_seal(&key(9));
        assert_eq!(
            doc().verify_claim(&fake, &buyer_pk),
            Err(Error::UnexpectedSigner)
        );
        assert!(
            SettledEntry::countersign(&doc(), &fake, &buyer_pk, &key(3), SETTLED_ON_TIME).is_err()
        );
        let e =
            SettledEntry::countersign(&doc(), &claim, &buyer_pk, &key(3), SETTLED_LATE).unwrap();
        // wrong financier, wrong amount, flag flipped from late to on time
        assert!(e.verify(&doc(), &buyer_pk, &buyer_pk).is_err());
        let mut other = doc();
        other.amount_zat += 1;
        assert!(e.verify(&other, &buyer_pk, &fin_pk).is_err());
        let mut flipped = e.clone();
        flipped.flag = SETTLED_ON_TIME;
        assert_eq!(
            flipped.verify(&doc(), &buyer_pk, &fin_pk),
            Err(Error::BadSignature)
        );
        assert_eq!(
            SettledEntry::countersign(&doc(), &claim, &buyer_pk, &key(3), 0),
            Err(Error::InvalidFlag(0))
        );
    }

    #[test]
    fn strict_decoder_rejects_the_old_single_signature_layout() {
        let (buyer_pk, _) = pks();
        let claim = doc().buyer_seal(&key(2));
        let e =
            SettledEntry::countersign(&doc(), &claim, &buyer_pk, &key(3), SETTLED_ON_TIME).unwrap();
        let mut m = e.to_memo_bytes();
        m[38] = 0;
        assert_eq!(
            SettledEntry::from_memo_bytes(&m),
            Err(Error::InvalidFlag(0))
        );
        let mut m = e.to_memo_bytes();
        m[SETTLED_LEN] = 1;
        assert_eq!(
            SettledEntry::from_memo_bytes(&m),
            Err(Error::NonZeroPadding)
        );
        let mut m = e.to_memo_bytes();
        m[5] = 1;
        assert_eq!(
            SettledEntry::from_memo_bytes(&m),
            Err(Error::UnknownEntryKind(1))
        );
        // DEV-08: the earlier layout (zero commitment at offset 38) no longer decodes
        let old = crate::entry::BoardEntry::sign(
            &key(3),
            EntryKind::Settled,
            settled_tag(&doc().nullifier),
            [0; 32],
            2,
            3,
        );
        assert_eq!(
            SettledEntry::from_memo_bytes(&old.to_memo_bytes()),
            Err(Error::InvalidFlag(0))
        );
    }
}
