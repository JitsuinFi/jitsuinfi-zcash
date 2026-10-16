//! Supplier side of the advance (HNK-05.T2): sign the register entry for the agreed financier and
//! verify the advance receipt that arrives with the money.

use ed25519_dalek::SigningKey;
use jitsuin_core::{financier_commitment, BoardEntry, EntryKind, Receipt, ReceiptKind};
use jitsuin_wallet::{Memo, WalletTx};

/// Signs the register entry for the financier whose commitment opening (public key and salt) was
/// shared off-chain, so the supplier signs exactly that financier's commitment.
pub fn sign_register_entry(
    supplier_ephemeral: &SigningKey,
    nullifier: [u8; 32],
    financier_pk: &[u8; 32],
    salt: &[u8; 32],
    discount_bucket: u8,
    tenor_bucket: u8,
) -> BoardEntry {
    BoardEntry::sign(
        supplier_ephemeral,
        EntryKind::Register,
        nullifier,
        financier_commitment(financier_pk, salt),
        discount_bucket,
        tenor_bucket,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Valid,
    /// Not signed by the expected financier, or the signature does not verify.
    BadSignature(jitsuin_core::Error),
    /// The receipt states a different amount than the output that carries it.
    AmountMismatch {
        receipt_zat: u64,
        received_zat: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedAdvance {
    pub txid: String,
    pub mined_height: Option<u32>,
    pub output_index: u32,
    pub received_zat: u64,
    pub receipt: Receipt,
    pub verdict: Verdict,
}

impl ReceivedAdvance {
    pub fn is_valid(&self) -> bool {
        self.verdict == Verdict::Valid
    }
}

/// Every advance receipt for `nullifier` received by the supplier wallet, with its verdict.
/// Memos that are not receipts, other nullifiers and outgoing outputs are skipped.
pub fn received_advances(
    txs: &[WalletTx],
    nullifier: &[u8; 32],
    financier_pk: &[u8; 32],
) -> Vec<ReceivedAdvance> {
    let mut found = Vec::new();
    for tx in txs {
        for out in tx.outputs.iter().filter(|o| o.received) {
            let Memo::Arbitrary(bytes) = &out.memo else {
                continue;
            };
            let Ok(receipt) = Receipt::from_memo_bytes(bytes) else {
                continue;
            };
            if receipt.kind != ReceiptKind::Advance || &receipt.nullifier != nullifier {
                continue;
            }
            let verdict = match receipt.verify(financier_pk) {
                Err(e) => Verdict::BadSignature(e),
                Ok(()) if receipt.amount_zat != out.value_zat => Verdict::AmountMismatch {
                    receipt_zat: receipt.amount_zat,
                    received_zat: out.value_zat,
                },
                Ok(()) => Verdict::Valid,
            };
            found.push(ReceivedAdvance {
                txid: tx.txid.clone(),
                mined_height: tx.mined_height,
                output_index: out.index,
                received_zat: out.value_zat,
                receipt,
                verdict,
            });
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use jitsuin_wallet::TxOutput;

    const N: [u8; 32] = [7; 32];

    fn financier() -> SigningKey {
        SigningKey::from_bytes(&[3; 32])
    }

    fn receipt_memo(signer: &SigningKey, n: [u8; 32], amount: u64) -> Vec<u8> {
        Receipt::sign(signer, ReceiptKind::Advance, n, amount, 20_378)
            .unwrap()
            .to_memo_bytes()
            .to_vec()
    }

    fn tx(txid: &str, value_zat: u64, received: bool, memo: Memo) -> WalletTx {
        WalletTx {
            txid: txid.into(),
            mined_height: Some(10),
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
    fn verifies_signer_and_amount() {
        let pk = financier().verifying_key().to_bytes();
        let forger = SigningKey::from_bytes(&[5; 32]);
        let txs = vec![
            tx(
                "ok",
                950_000,
                true,
                Memo::Arbitrary(receipt_memo(&financier(), N, 950_000)),
            ),
            tx(
                "short",
                900_000,
                true,
                Memo::Arbitrary(receipt_memo(&financier(), N, 950_000)),
            ),
            tx(
                "forged",
                950_000,
                true,
                Memo::Arbitrary(receipt_memo(&forger, N, 950_000)),
            ),
            tx(
                "other-n",
                950_000,
                true,
                Memo::Arbitrary(receipt_memo(&financier(), [8; 32], 950_000)),
            ),
            tx(
                "sent",
                950_000,
                false,
                Memo::Arbitrary(receipt_memo(&financier(), N, 950_000)),
            ),
            tx("text", 950_000, true, Memo::Text("hello".into())),
            tx("junk", 950_000, true, Memo::Arbitrary(vec![0xFF, 1, 2, 3])),
        ];
        let found = received_advances(&txs, &N, &pk);
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

    #[test]
    fn signed_entry_carries_the_financier_commitment() {
        let supplier = SigningKey::from_bytes(&[1; 32]);
        let pk = financier().verifying_key().to_bytes();
        let e = sign_register_entry(&supplier, N, &pk, &[4; 32], 2, 3);
        assert_eq!(e.financier_commitment, financier_commitment(&pk, &[4; 32]));
        e.verify(&supplier.verifying_key().to_bytes()).unwrap();
    }
}
