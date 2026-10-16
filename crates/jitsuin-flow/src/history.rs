//! Minimum standard before registration (HNK-20.T3): the financier checks the buyer's disclosed
//! history against the board and the buyer's certificate for the new invoice, then requires the
//! register entry to carry that certificate's tag (`Deal::history_tag`).

use jitsuin_board::history::{verify_history, HistoryReport, MinimumStandard};
use jitsuin_board::{scan, BoardRecord, SettledRecord};
use jitsuin_core::history::verify_certs;
use jitsuin_core::{nullifier, HistoryCert, Invoice};

use crate::financier::Financier;
use crate::Error;

/// Rules for the history check, set by the financier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryPolicy {
    /// Financier keys whose settlements count (registered, licensed financiers).
    pub allowlist: Vec<[u8; 32]>,
    pub standard: MinimumStandard,
    pub grace_days: u32,
}

/// Checks `history` (certificates 0..k) and `new_cert` (k+1) for `invoice` financed by
/// `financier_pk`. Returns the history report and the tag the register entry must carry.
#[allow(clippy::too_many_arguments)]
pub fn check_buyer(
    history: &[HistoryCert],
    new_cert: &HistoryCert,
    invoice: &Invoice,
    financier_pk: &[u8; 32],
    policy: &HistoryPolicy,
    records: &[BoardRecord],
    settled: &[SettledRecord],
    today: u32,
) -> Result<(HistoryReport, [u8; 32]), Error> {
    let report = verify_history(
        history,
        &new_cert.identity_pk,
        &policy.allowlist,
        records,
        settled,
        today,
        policy.grace_days,
    )
    .map_err(Error::History)?;
    let mut chain = history.to_vec();
    chain.push(new_cert.clone());
    verify_certs(&chain, &new_cert.identity_pk)?;
    if new_cert.invoice_pk != invoice.buyer_pk
        || new_cert.supplier_pk != invoice.supplier_ephemeral_pk
        || new_cert.nullifier != nullifier(invoice)?
        || new_cert.amount_zat != invoice.amount_zat
        || new_cert.due_date != invoice.due_date
        || &new_cert.financier_pk != financier_pk
    {
        return Err(Error::InvalidDeal(
            "history certificate does not match the invoice",
        ));
    }
    policy
        .standard
        .evaluate(&report, invoice.amount_zat)
        .map_err(Error::BelowStandard)?;
    Ok((report, new_cert.tag()))
}

impl Financier {
    /// [`check_buyer`] against the current board.
    pub fn check_buyer(
        &self,
        history: &[HistoryCert],
        new_cert: &HistoryCert,
        invoice: &Invoice,
        policy: &HistoryPolicy,
        today: u32,
    ) -> Result<(HistoryReport, [u8; 32]), Error> {
        let report = scan(&self.board_watch, &self.lightwalletd)?;
        check_buyer(
            history,
            new_cert,
            invoice,
            &self.key.verifying_key().to_bytes(),
            policy,
            &report.records,
            &report.settled,
            today,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use jitsuin_board::history::HistoryError;
    use jitsuin_board::Position;
    use jitsuin_core::{BoardEntry, BuyerIdentity};

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    fn fin_pk() -> [u8; 32] {
        key(3).verifying_key().to_bytes()
    }

    fn policy() -> HistoryPolicy {
        HistoryPolicy {
            allowlist: vec![fin_pk()],
            standard: MinimumStandard {
                max_defaults: 0,
                min_on_time_pct: 80,
                established_after: 2,
                new_buyer_limit_zat: 20_000,
            },
            grace_days: 7,
        }
    }

    fn id() -> BuyerIdentity {
        BuyerIdentity::from_master_secret([0x42; 32])
    }

    fn invoice(index: u32, amount: u64, due: u32) -> Invoice {
        Invoice {
            invoice_id: format!("TES-INV-N{index}"),
            supplier_ephemeral_pk: key(10).verifying_key().to_bytes(),
            buyer_pk: id().invoice_key(index).verifying_key().to_bytes(),
            amount_zat: amount,
            issue_date: 1,
            due_date: due,
            terms_hash: [9; 32],
        }
    }

    #[test]
    fn new_buyer_within_the_limit_then_a_default_blocks_the_next_deal() {
        let inv0 = invoice(0, 10_000, 50);
        let c0 = HistoryCert::issue(&id(), 0, &inv0, fin_pk(), None).unwrap();
        let (r, tag) = check_buyer(&[], &c0, &inv0, &fin_pk(), &policy(), &[], &[], 10).unwrap();
        assert_eq!((r.on_time, r.defaults), (0, 0));
        assert_eq!(tag, c0.tag());

        // above the new-buyer limit
        let big = invoice(0, 50_000, 50);
        let cb = HistoryCert::issue(&id(), 0, &big, fin_pk(), None).unwrap();
        assert!(matches!(
            check_buyer(&[], &cb, &big, &fin_pk(), &policy(), &[], &[], 10),
            Err(Error::BelowStandard(_))
        ));

        // invoice 0 is registered with its tag but never settled; later the buyer asks again
        let entry = BoardEntry::sign_with_history(&key(10), c0.nullifier, [1; 32], 0, 0, tag);
        let records = vec![BoardRecord {
            txid: "r0".into(),
            position: Position {
                height: 5,
                tx_index: 0,
                output_index: 0,
            },
            entry,
        }];
        let inv1 = invoice(1, 10_000, 200);
        let c1 = HistoryCert::issue(&id(), 1, &inv1, fin_pk(), Some(&c0)).unwrap();
        assert!(matches!(
            check_buyer(
                std::slice::from_ref(&c0),
                &c1,
                &inv1,
                &fin_pk(),
                &policy(),
                &records,
                &[],
                100
            ),
            Err(Error::BelowStandard(
                "buyer has defaults above the standard"
            ))
        ));
        // hiding invoice 0 by posing as a new buyer does not work either
        let fresh = HistoryCert::issue(&id(), 0, &invoice(0, 10_000, 200), fin_pk(), None).unwrap();
        assert!(matches!(
            check_buyer(
                &[],
                &fresh,
                &invoice(0, 10_000, 200),
                &fin_pk(),
                &policy(),
                &records,
                &[],
                100
            ),
            Err(Error::History(HistoryError::UndisclosedSuccessor))
        ));
    }

    #[test]
    fn the_new_certificate_must_match_the_invoice_and_this_financier() {
        let inv0 = invoice(0, 10_000, 50);
        let c0 = HistoryCert::issue(&id(), 0, &inv0, fin_pk(), None).unwrap();
        let other_invoice = invoice(0, 9_000, 50);
        assert!(matches!(
            check_buyer(&[], &c0, &other_invoice, &fin_pk(), &policy(), &[], &[], 10),
            Err(Error::InvalidDeal(_))
        ));
        let stranger = key(4).verifying_key().to_bytes();
        assert!(matches!(
            check_buyer(&[], &c0, &inv0, &stranger, &policy(), &[], &[], 10),
            Err(Error::InvalidDeal(_))
        ));
        // a new certificate that skips an index
        let c2 =
            HistoryCert::issue(&id(), 1, &invoice(1, 10_000, 50), fin_pk(), Some(&c0)).unwrap();
        assert!(check_buyer(
            &[],
            &c2,
            &invoice(1, 10_000, 50),
            &fin_pk(),
            &policy(),
            &[],
            &[],
            10
        )
        .is_err());
    }
}
