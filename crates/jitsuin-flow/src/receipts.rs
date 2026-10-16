//! Signed receipts found in a wallet: advances for the supplier, repayments for the financier.
//! A memo may carry seals next to the receipt (Sign-to-Pay); they are returned with it.

use jitsuin_core::memo::{self, MemoItem};
use jitsuin_core::{Receipt, ReceiptKind, Seal};
use jitsuin_wallet::{Memo, WalletTx};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Valid,
    /// Not signed by the expected key, or the signature does not verify.
    BadSignature(jitsuin_core::Error),
    /// The receipt states a different amount than the output that carries it.
    AmountMismatch {
        receipt_zat: u64,
        received_zat: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedReceipt {
    pub txid: String,
    pub mined_height: Option<u32>,
    pub output_index: u32,
    pub received_zat: u64,
    pub receipt: Receipt,
    pub verdict: Verdict,
    /// Seals carried in the same memo, in memo order.
    pub seals: Vec<Seal>,
}

impl ReceivedReceipt {
    pub fn is_valid(&self) -> bool {
        self.verdict == Verdict::Valid
    }
}

/// Every receipt of `kind` for `nullifier` received by the wallet, with its verdict against
/// `signer_pk`. Memos that are not receipts, other kinds, other nullifiers and outgoing outputs
/// are skipped.
pub fn received(
    txs: &[WalletTx],
    kind: ReceiptKind,
    nullifier: &[u8; 32],
    signer_pk: &[u8; 32],
) -> Vec<ReceivedReceipt> {
    let mut found = Vec::new();
    for tx in txs {
        for out in tx.outputs.iter().filter(|o| o.received) {
            let Memo::Arbitrary(bytes) = &out.memo else {
                continue;
            };
            let Ok(items) = memo::decode(bytes) else {
                continue;
            };
            let mut receipts = Vec::new();
            let mut seals = Vec::new();
            for item in items {
                match item {
                    MemoItem::Receipt(r) => receipts.push(r),
                    MemoItem::Seal(s) => seals.push(s),
                }
            }
            // Exactly one receipt per output; anything else is not a receipt memo.
            let Ok([receipt]) = <[Receipt; 1]>::try_from(receipts) else {
                continue;
            };
            if receipt.kind != kind || &receipt.nullifier != nullifier {
                continue;
            }
            let verdict = match receipt.verify(signer_pk) {
                Err(e) => Verdict::BadSignature(e),
                Ok(()) if receipt.amount_zat != out.value_zat => Verdict::AmountMismatch {
                    receipt_zat: receipt.amount_zat,
                    received_zat: out.value_zat,
                },
                Ok(()) => Verdict::Valid,
            };
            found.push(ReceivedReceipt {
                txid: tx.txid.clone(),
                mined_height: tx.mined_height,
                output_index: out.index,
                received_zat: out.value_zat,
                receipt,
                verdict,
                seals,
            });
        }
    }
    found
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use jitsuin_wallet::TxOutput;

    pub(crate) fn receipt_memo(
        signer: &SigningKey,
        kind: ReceiptKind,
        n: [u8; 32],
        amount: u64,
    ) -> Vec<u8> {
        Receipt::sign(signer, kind, n, amount, 20_378)
            .unwrap()
            .to_memo_bytes()
            .to_vec()
    }

    pub(crate) fn tx(
        txid: &str,
        mined_height: Option<u32>,
        value_zat: u64,
        received: bool,
        memo: Memo,
    ) -> WalletTx {
        WalletTx {
            txid: txid.into(),
            mined_height,
            fee_zat: None,
            outputs: vec![TxOutput {
                index: 0,
                pool: "Ironwood".into(),
                value_zat,
                is_change: false,
                received,
                memo,
            }],
        }
    }

    #[test]
    fn verifies_signer_kind_and_amount() {
        const N: [u8; 32] = [7; 32];
        let signer = SigningKey::from_bytes(&[3; 32]);
        let pk = signer.verifying_key().to_bytes();
        let forger = SigningKey::from_bytes(&[5; 32]);
        let adv = |k: &SigningKey, n, amount| {
            Memo::Arbitrary(receipt_memo(k, ReceiptKind::Advance, n, amount))
        };
        let h = Some(10);
        let txs = vec![
            tx("ok", h, 950_000, true, adv(&signer, N, 950_000)),
            tx("short", h, 900_000, true, adv(&signer, N, 950_000)),
            tx("forged", h, 950_000, true, adv(&forger, N, 950_000)),
            tx("other-n", h, 950_000, true, adv(&signer, [8; 32], 950_000)),
            tx("sent", h, 950_000, false, adv(&signer, N, 950_000)),
            tx(
                "other-kind",
                h,
                950_000,
                true,
                Memo::Arbitrary(receipt_memo(&signer, ReceiptKind::Repayment, N, 950_000)),
            ),
            tx("text", h, 950_000, true, Memo::Text("hello".into())),
            tx(
                "junk",
                h,
                950_000,
                true,
                Memo::Arbitrary(vec![0xFF, 1, 2, 3]),
            ),
        ];
        let found = received(&txs, ReceiptKind::Advance, &N, &pk);
        let verdicts: Vec<_> = found
            .iter()
            .map(|a| (a.txid.as_str(), a.verdict.clone()))
            .collect();
        assert_eq!(
            verdicts,
            vec![
                ("ok", Verdict::Valid),
                (
                    "short",
                    Verdict::AmountMismatch {
                        receipt_zat: 950_000,
                        received_zat: 900_000
                    }
                ),
                (
                    "forged",
                    Verdict::BadSignature(jitsuin_core::Error::UnexpectedSigner)
                ),
            ]
        );
        assert!(found[0].is_valid());
    }
}
