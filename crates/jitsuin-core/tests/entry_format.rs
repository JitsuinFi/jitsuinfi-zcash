//! HNK-02.T4: board register entries round-trip, fit a 512-byte memo, and every malformed memo is
//! refused with its own error before anyone checks a signature.

use ed25519_dalek::SigningKey;
use jitsuin_core::{BoardEntry, EntryKind, Error, MEMO_LEN};

fn supplier() -> SigningKey {
    SigningKey::from_bytes(&[1; 32])
}

fn entries() -> Vec<BoardEntry> {
    vec![
        BoardEntry::sign(&supplier(), EntryKind::Register, [7; 32], [8; 32], 0, 0),
        BoardEntry::sign(&supplier(), EntryKind::Register, [7; 32], [8; 32], 3, 2),
        BoardEntry::sign_with_history(&supplier(), [7; 32], [8; 32], 1, 1, [9; 32]),
    ]
}

#[test]
fn every_register_entry_round_trips_inside_one_memo() {
    let pk = supplier().verifying_key().to_bytes();
    for e in entries() {
        let memo = e.to_memo_bytes();
        assert_eq!(memo.len(), MEMO_LEN);
        assert!(e.encoded_len() <= MEMO_LEN && e.encoded_len() < 200);
        // the padded memo and the bare entry decode to the same entry
        assert_eq!(BoardEntry::from_memo_bytes(&memo).unwrap(), e);
        assert_eq!(
            BoardEntry::from_memo_bytes(&memo[..e.encoded_len()]).unwrap(),
            e
        );
        e.verify(&pk).unwrap();
    }
}

#[test]
fn malformed_memos_are_refused_each_with_its_reason() {
    let e = &entries()[0];
    let good = e.to_memo_bytes();
    let n = e.encoded_len();

    let mut not_arbitrary = good;
    not_arbitrary[0] = 0xF6; // a text memo
    assert_eq!(
        BoardEntry::from_memo_bytes(&not_arbitrary),
        Err(Error::NotArbitraryDataMemo)
    );

    let mut magic = good;
    magic[1] ^= 0xFF;
    assert_eq!(BoardEntry::from_memo_bytes(&magic), Err(Error::BadMagic));

    let mut kind = good;
    kind[5] = 0x09;
    assert_eq!(
        BoardEntry::from_memo_bytes(&kind),
        Err(Error::UnknownEntryKind(0x09))
    );

    assert_eq!(
        BoardEntry::from_memo_bytes(&good[..n - 1]),
        Err(Error::Truncated)
    );

    let mut padding = good;
    padding[n + 5] = 1;
    assert_eq!(
        BoardEntry::from_memo_bytes(&padding),
        Err(Error::NonZeroPadding)
    );

    let mut long = good.to_vec();
    long.push(0);
    assert_eq!(
        BoardEntry::from_memo_bytes(&long),
        Err(Error::TrailingBytes)
    );
}

#[test]
fn a_changed_field_or_another_supplier_breaks_the_signature() {
    let e = &entries()[2];
    let pk = supplier().verifying_key().to_bytes();
    let mut changed = e.clone();
    changed.financier_commitment[0] ^= 1;
    assert_eq!(changed.verify(&pk), Err(Error::BadSignature));
    let other = SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes();
    assert_eq!(e.verify(&other), Err(Error::BadSignature));
}
