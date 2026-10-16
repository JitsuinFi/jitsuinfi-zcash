//! Signed payment receipts carried in a Zcash memo (HNK-05.T2).
//!
//! An advance receipt goes with the financier's advance to the supplier; a repayment receipt goes
//! with the buyer's payment to the financier at maturity (HNK-06). Both live in the memo of the
//! shielded output that carries the money, so only the recipient can read them.
//!
//! Memo layout (512 bytes, ZIP-302 arbitrary data), see vault `07-Architecture/Format Data`:
//!
//! | offset | field                                  | size |
//! |--------|----------------------------------------|------|
//! | 0      | memo marker `0xFF`                     | 1    |
//! | 1      | magic `JTR1`                           | 4    |
//! | 5      | kind                                   | 1    |
//! | 6      | nullifier                              | 32   |
//! | 38     | amount in zatoshi (u64 LE)             | 8    |
//! | 46     | date, days since Unix epoch (u32 LE)   | 4    |
//! | 50     | signer public key (Ed25519)            | 32   |
//! | 82     | signer signature over bytes 1..82      | 64   |
//! | 146    | zero padding                           | 366  |

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::entry::{MEMO_ARBITRARY_DATA, MEMO_LEN};
use crate::error::Error;
use crate::invoice::Reader;

pub const RECEIPT_MAGIC: &[u8; 4] = b"JTR1";
/// Bytes covered by the signer signature (memo offsets 1..82).
pub const RECEIPT_SIGNED_LEN: usize = 4 + 1 + 32 + 8 + 4 + 32;
/// Encoded receipt length including the memo marker.
pub const RECEIPT_LEN: usize = 1 + RECEIPT_SIGNED_LEN + 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReceiptKind {
    /// Financier → supplier, signed by the financier.
    Advance = 0x01,
    /// Buyer → financier at maturity, signed by the buyer.
    Repayment = 0x02,
}

impl TryFrom<u8> for ReceiptKind {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Error> {
        match value {
            0x01 => Ok(ReceiptKind::Advance),
            0x02 => Ok(ReceiptKind::Repayment),
            other => Err(Error::UnknownReceiptKind(other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub kind: ReceiptKind,
    pub nullifier: [u8; 32],
    pub amount_zat: u64,
    pub date: u32,
    pub signer_pk: [u8; 32],
    pub signature: [u8; 64],
}

impl Receipt {
    pub fn sign(
        signer: &SigningKey,
        kind: ReceiptKind,
        nullifier: [u8; 32],
        amount_zat: u64,
        date: u32,
    ) -> Result<Self, Error> {
        if amount_zat == 0 {
            return Err(Error::InvalidAmount);
        }
        let signer_pk = signer.verifying_key().to_bytes();
        let msg = signed_part(kind, &nullifier, amount_zat, date, &signer_pk);
        Ok(Receipt {
            kind,
            nullifier,
            amount_zat,
            date,
            signer_pk,
            signature: signer.sign(&msg).to_bytes(),
        })
    }

    /// Checks that the receipt is signed by `expected_signer_pk` (agreed off-chain) and that the
    /// signature is valid (`verify_strict`).
    pub fn verify(&self, expected_signer_pk: &[u8; 32]) -> Result<(), Error> {
        if &self.signer_pk != expected_signer_pk {
            return Err(Error::UnexpectedSigner);
        }
        let vk = VerifyingKey::from_bytes(&self.signer_pk).map_err(|_| Error::InvalidPublicKey)?;
        let msg = signed_part(
            self.kind,
            &self.nullifier,
            self.amount_zat,
            self.date,
            &self.signer_pk,
        );
        vk.verify_strict(&msg, &Signature::from_bytes(&self.signature))
            .map_err(|_| Error::BadSignature)
    }

    /// Full 512-byte memo, zero padded after the receipt.
    pub fn to_memo_bytes(&self) -> [u8; MEMO_LEN] {
        let mut memo = [0u8; MEMO_LEN];
        memo[0] = MEMO_ARBITRARY_DATA;
        let msg = signed_part(
            self.kind,
            &self.nullifier,
            self.amount_zat,
            self.date,
            &self.signer_pk,
        );
        memo[1..1 + RECEIPT_SIGNED_LEN].copy_from_slice(&msg);
        memo[1 + RECEIPT_SIGNED_LEN..RECEIPT_LEN].copy_from_slice(&self.signature);
        memo
    }

    /// Strict decoder. Accepts the 146-byte receipt alone or a padded memo; padding must be zero.
    /// Does not verify the signature (see [`Receipt::verify`]).
    pub fn from_memo_bytes(memo: &[u8]) -> Result<Self, Error> {
        if memo.len() > MEMO_LEN {
            return Err(Error::TrailingBytes);
        }
        let mut r = Reader::new(memo);
        if r.byte()? != MEMO_ARBITRARY_DATA {
            return Err(Error::NotArbitraryDataMemo);
        }
        if r.take(4)? != RECEIPT_MAGIC {
            return Err(Error::BadMagic);
        }
        let kind = ReceiptKind::try_from(r.byte()?)?;
        let nullifier = r.array()?;
        let amount_zat = u64::from_le_bytes(r.array()?);
        if amount_zat == 0 {
            return Err(Error::InvalidAmount);
        }
        let receipt = Receipt {
            kind,
            nullifier,
            amount_zat,
            date: u32::from_le_bytes(r.array()?),
            signer_pk: r.array()?,
            signature: r.array()?,
        };
        if r.rest().iter().any(|b| *b != 0) {
            return Err(Error::NonZeroPadding);
        }
        Ok(receipt)
    }
}

fn signed_part(
    kind: ReceiptKind,
    nullifier: &[u8; 32],
    amount_zat: u64,
    date: u32,
    signer_pk: &[u8; 32],
) -> [u8; RECEIPT_SIGNED_LEN] {
    let mut out = [0u8; RECEIPT_SIGNED_LEN];
    out[..4].copy_from_slice(RECEIPT_MAGIC);
    out[4] = kind as u8;
    out[5..37].copy_from_slice(nullifier);
    out[37..45].copy_from_slice(&amount_zat.to_le_bytes());
    out[45..49].copy_from_slice(&date.to_le_bytes());
    out[49..81].copy_from_slice(signer_pk);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{financier_commitment, BoardEntry, EntryKind};

    fn financier() -> SigningKey {
        SigningKey::from_bytes(&[3; 32])
    }

    fn advance() -> Receipt {
        Receipt::sign(&financier(), ReceiptKind::Advance, [7; 32], 950_000, 20_378).unwrap()
    }

    #[test]
    fn roundtrip_and_verify() {
        let r = advance();
        let memo = r.to_memo_bytes();
        assert_eq!(&memo[1..5], b"JTR1");
        assert!(memo[RECEIPT_LEN..].iter().all(|b| *b == 0));
        let back = Receipt::from_memo_bytes(&memo).unwrap();
        assert_eq!(back, r);
        back.verify(&financier().verifying_key().to_bytes())
            .unwrap();
        // the unpadded 146-byte form decodes too (what is put into the ZIP-321 URI)
        assert_eq!(Receipt::from_memo_bytes(&memo[..RECEIPT_LEN]).unwrap(), r);
    }

    #[test]
    fn layout_is_stable() {
        let memo = advance().to_memo_bytes();
        assert_eq!(RECEIPT_LEN, 146);
        assert_eq!(memo[0], 0xFF);
        assert_eq!(memo[5], 0x01);
        assert_eq!(&memo[6..38], &[7; 32]);
        assert_eq!(&memo[38..46], &950_000u64.to_le_bytes());
        assert_eq!(&memo[46..50], &20_378u32.to_le_bytes());
        assert_eq!(&memo[50..82], &financier().verifying_key().to_bytes());
    }

    #[test]
    fn rejects_wrong_signer_and_tampering() {
        let r = advance();
        let other = SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes();
        assert_eq!(r.verify(&other), Err(Error::UnexpectedSigner));

        let pk = financier().verifying_key().to_bytes();
        let mut tampered = r.clone();
        tampered.amount_zat += 1;
        assert_eq!(tampered.verify(&pk), Err(Error::BadSignature));

        // a forger who swaps in its own key must also match the expected signer
        let forger = SigningKey::from_bytes(&[5; 32]);
        let forged =
            Receipt::sign(&forger, ReceiptKind::Advance, [7; 32], 950_000, 20_378).unwrap();
        assert_eq!(forged.verify(&pk), Err(Error::UnexpectedSigner));
    }

    #[test]
    fn strict_decoder() {
        let memo = advance().to_memo_bytes();

        let mut m = memo;
        m[0] = 0xF6;
        assert_eq!(
            Receipt::from_memo_bytes(&m),
            Err(Error::NotArbitraryDataMemo)
        );

        let mut m = memo;
        m[4] = b'2';
        assert_eq!(Receipt::from_memo_bytes(&m), Err(Error::BadMagic));

        let mut m = memo;
        m[5] = 0x03;
        assert_eq!(
            Receipt::from_memo_bytes(&m),
            Err(Error::UnknownReceiptKind(0x03))
        );

        let mut m = memo;
        m[38..46].copy_from_slice(&[0; 8]);
        assert_eq!(Receipt::from_memo_bytes(&m), Err(Error::InvalidAmount));

        let mut m = memo;
        m[RECEIPT_LEN] = 1;
        assert_eq!(Receipt::from_memo_bytes(&m), Err(Error::NonZeroPadding));

        assert_eq!(
            Receipt::from_memo_bytes(&memo[..RECEIPT_LEN - 1]),
            Err(Error::Truncated)
        );

        // a board entry is not a receipt
        let entry = BoardEntry::sign(&financier(), EntryKind::Register, [7; 32], [1; 32], 0, 0);
        assert_eq!(
            Receipt::from_memo_bytes(&entry.to_memo_bytes()),
            Err(Error::BadMagic)
        );
    }

    #[test]
    fn zero_amount_is_rejected() {
        assert_eq!(
            Receipt::sign(&financier(), ReceiptKind::Advance, [7; 32], 0, 1),
            Err(Error::InvalidAmount)
        );
    }

    #[test]
    fn financier_commitment_vector() {
        // Cross-checked with Python: hashlib.blake2b(b"\x03"*32 + b"\x04"*32, digest_size=32)
        assert_eq!(
            hex(&financier_commitment(&[3; 32], &[4; 32])),
            "c72255e7b3f5bd4f2e652cf71eceb37d0b35074f2bb11c4a788ce2282d982b3a"
        );
        assert_ne!(
            financier_commitment(&[3; 32], &[4; 32]),
            financier_commitment(&[3; 32], &[5; 32])
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
