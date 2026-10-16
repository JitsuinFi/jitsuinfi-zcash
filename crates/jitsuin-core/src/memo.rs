//! Several items in one 512-byte memo, so a signature and the money that depends on it travel in
//! the same shielded transaction (Sign-to-Pay, HNK-19.T3).
//!
//! Layout: ZIP-302 marker `0xFF`, then items back to back, then zero padding. Each item starts
//! with its magic and has a fixed length:
//!
//! | item    | magic  | length (without marker) |
//! |---------|--------|-------------------------|
//! | receipt | `JTR1` | 145                     |
//! | seal    | `JTL1` | 200                     |
//!
//! A memo with one receipt is byte-identical to [`Receipt::to_memo_bytes`].

use crate::entry::{MEMO_ARBITRARY_DATA, MEMO_LEN};
use crate::error::Error;
use crate::receipt::{Receipt, RECEIPT_LEN, RECEIPT_MAGIC};
use crate::seal::{Seal, SEAL_LEN, SEAL_MAGIC};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoItem {
    Receipt(Receipt),
    Seal(Seal),
}

/// Marker plus items, without padding (what goes into a ZIP-321 URI). At most 512 bytes.
pub fn encode(items: &[MemoItem]) -> Result<Vec<u8>, Error> {
    let mut out = vec![MEMO_ARBITRARY_DATA];
    for item in items {
        match item {
            MemoItem::Receipt(r) => out.extend_from_slice(&r.to_memo_bytes()[1..RECEIPT_LEN]),
            MemoItem::Seal(s) => out.extend_from_slice(&s.to_bytes()),
        }
    }
    if out.len() > MEMO_LEN {
        return Err(Error::TrailingBytes);
    }
    Ok(out)
}

/// Strict decoder: every item must be complete and known, and the rest must be zero.
pub fn decode(memo: &[u8]) -> Result<Vec<MemoItem>, Error> {
    if memo.len() > MEMO_LEN {
        return Err(Error::TrailingBytes);
    }
    if memo.first() != Some(&MEMO_ARBITRARY_DATA) {
        return Err(Error::NotArbitraryDataMemo);
    }
    let mut items = Vec::new();
    let mut rest = &memo[1..];
    while rest.iter().any(|b| *b != 0) {
        let magic = rest.get(..4).ok_or(Error::Truncated)?;
        if magic == RECEIPT_MAGIC {
            let body = rest.get(..RECEIPT_LEN - 1).ok_or(Error::Truncated)?;
            let mut one = Vec::with_capacity(RECEIPT_LEN);
            one.push(MEMO_ARBITRARY_DATA);
            one.extend_from_slice(body);
            items.push(MemoItem::Receipt(Receipt::from_memo_bytes(&one)?));
            rest = &rest[RECEIPT_LEN - 1..];
        } else if magic == SEAL_MAGIC {
            let body = rest.get(..SEAL_LEN).ok_or(Error::Truncated)?;
            items.push(MemoItem::Seal(Seal::from_bytes(body)?));
            rest = &rest[SEAL_LEN..];
        } else {
            return Err(Error::BadMagic);
        }
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::ReceiptKind;
    use crate::seal::{next_content, sealed_document_hash, DocKind};
    use ed25519_dalek::SigningKey;

    fn items() -> (Receipt, Seal) {
        let k = SigningKey::from_bytes(&[3; 32]);
        let r = Receipt::sign(&k, ReceiptKind::Advance, [7; 32], 950_000, 20_378).unwrap();
        let c = next_content(
            DocKind::Assignment,
            [7; 32],
            sealed_document_hash(b"x"),
            &[],
            0,
        )
        .unwrap();
        (r, Seal::sign(&k, c))
    }

    #[test]
    fn receipt_and_seal_fit_one_memo() {
        let (r, s) = items();
        let memo = encode(&[MemoItem::Receipt(r.clone()), MemoItem::Seal(s.clone())]).unwrap();
        assert_eq!(memo.len(), 1 + 145 + 200);
        let mut padded = memo.clone();
        padded.resize(MEMO_LEN, 0);
        assert_eq!(
            decode(&padded).unwrap(),
            vec![MemoItem::Receipt(r.clone()), MemoItem::Seal(s)]
        );
        // one receipt alone is the classic receipt memo
        let single = encode(&[MemoItem::Receipt(r.clone())]).unwrap();
        assert_eq!(single, r.to_memo_bytes()[..RECEIPT_LEN].to_vec());
        assert_eq!(
            decode(&r.to_memo_bytes()).unwrap(),
            vec![MemoItem::Receipt(r)]
        );
    }

    #[test]
    fn strict_decoding() {
        let (r, s) = items();
        let memo = encode(&[MemoItem::Receipt(r), MemoItem::Seal(s)]).unwrap();
        assert_eq!(decode(&memo[..memo.len() - 1]), Err(Error::Truncated));
        let mut junk = memo.clone();
        junk.extend_from_slice(b"XXXX");
        assert_eq!(decode(&junk), Err(Error::BadMagic));
        let mut stray = memo.clone();
        stray.push(1);
        assert_eq!(decode(&stray), Err(Error::Truncated));
        assert_eq!(decode(&memo[1..]), Err(Error::NotArbitraryDataMemo));
        assert_eq!(decode(&[0xFF]).unwrap(), vec![]);
        let (r, s) = items();
        let too_many = [
            MemoItem::Seal(s.clone()),
            MemoItem::Seal(s.clone()),
            MemoItem::Receipt(r),
        ];
        assert_eq!(encode(&too_many), Err(Error::TrailingBytes));
    }
}
