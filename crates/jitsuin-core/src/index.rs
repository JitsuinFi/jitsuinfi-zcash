//! Public rate index (HNK-08): "price public, participants private".
//!
//! A register entry carries two one-byte classes, `discount_bucket` and `tenor_bucket` (memo
//! offsets 70 and 71), never an amount or a party. Anyone holding the board's viewing key can
//! recompute the index from the board; a class is shown only when at least `k` invoices fall in
//! it, so the index never singles out one deal. The class of each entry stays readable on the
//! board itself (Threat Model); the threshold applies to the published aggregate.
//!
//! Classes (vault `07-Architecture/Format Data`, "Bucket indeks"):
//!
//! | code | discount (face − advance) / face | tenor (advance → due date) |
//! |------|----------------------------------|----------------------------|
//! | 0    | not disclosed                    | not disclosed              |
//! | 1    | < 1%                             | ≤ 30 days                  |
//! | 2    | 1–2%                             | 31–60 days                 |
//! | 3    | 2–3%                             | 61–90 days                 |
//! | 4    | 3–5%                             | 91–180 days                |
//! | 5    | 5–8%                             | 181–365 days               |
//! | 6    | 8–12%                            | —                          |
//! | 7    | ≥ 12%                            | —                          |
//!
//! Both classes are disclosed or neither is (`0/0`, the value of entries posted before HNK-08).
//! Any other code, or a single `0`, is invalid: such entries are counted but kept out of the index.

use std::collections::HashSet;

use crate::entry::BoardEntry;
use crate::error::Error;

/// Code of "not disclosed" in both classes.
pub const UNDISCLOSED: u8 = 0;

/// Smallest number of invoices a class needs before the index shows it (AC-HNK-08.3).
pub const K: usize = 5;

/// One class: codes `min..=max` of a measure (basis points or days).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Class {
    pub code: u8,
    pub min: u32,
    pub max: u32,
    pub label: &'static str,
}

const fn class(code: u8, min: u32, max: u32, label: &'static str) -> Class {
    Class {
        code,
        min,
        max,
        label,
    }
}

/// Discount classes in basis points of the face value.
pub const DISCOUNT_CLASSES: [Class; 7] = [
    class(1, 0, 99, "< 1%"),
    class(2, 100, 199, "1-2%"),
    class(3, 200, 299, "2-3%"),
    class(4, 300, 499, "3-5%"),
    class(5, 500, 799, "5-8%"),
    class(6, 800, 1_199, "8-12%"),
    class(7, 1_200, 9_999, ">= 12%"),
];

/// Tenor classes in days from the advance to the due date.
pub const TENOR_CLASSES: [Class; 5] = [
    class(1, 0, 30, "<= 30 days"),
    class(2, 31, 60, "31-60 days"),
    class(3, 61, 90, "61-90 days"),
    class(4, 91, 180, "91-180 days"),
    class(5, 181, 365, "181-365 days"),
];

fn find(classes: &[Class], value: u32) -> Option<&Class> {
    classes.iter().find(|c| (c.min..=c.max).contains(&value))
}

fn by_code(classes: &'static [Class], code: u8) -> Option<&'static Class> {
    classes.iter().find(|c| c.code == code)
}

pub fn discount_class(code: u8) -> Option<&'static Class> {
    by_code(&DISCOUNT_CLASSES, code)
}

pub fn tenor_class(code: u8) -> Option<&'static Class> {
    by_code(&TENOR_CLASSES, code)
}

/// `(face − advance) / face` in basis points, rounded down. The advance must be 1..=face.
pub fn discount_bps(face_zat: u64, advance_zat: u64) -> Result<u32, Error> {
    if face_zat == 0 || advance_zat == 0 || advance_zat > face_zat {
        return Err(Error::InvalidBucket);
    }
    Ok(((u128::from(face_zat - advance_zat) * 10_000) / u128::from(face_zat)) as u32)
}

/// The two classes the supplier signs into the register entry for a deal: face value and advance
/// in zatoshi, advance and due dates in days since the Unix epoch. Errors when the deal fits no
/// class (advance of zero or above the face value, due date before the advance or more than
/// 365 days after it); such a deal can still be registered as `0/0`.
pub fn classes_for(
    face_zat: u64,
    advance_zat: u64,
    advance_day: u32,
    due_day: u32,
) -> Result<(u8, u8), Error> {
    let discount = find(&DISCOUNT_CLASSES, discount_bps(face_zat, advance_zat)?);
    let tenor = due_day
        .checked_sub(advance_day)
        .and_then(|days| find(&TENOR_CLASSES, days));
    match (discount, tenor) {
        (Some(d), Some(t)) => Ok((d.code, t.code)),
        _ => Err(Error::InvalidBucket),
    }
}

/// `Ok(true)` for two defined classes, `Ok(false)` for `0/0` (not disclosed), else
/// [`Error::InvalidBucket`].
pub fn validate_classes(discount: u8, tenor: u8) -> Result<bool, Error> {
    match (discount, tenor) {
        (UNDISCLOSED, UNDISCLOSED) => Ok(false),
        (d, t) if discount_class(d).is_some() && tenor_class(t).is_some() => Ok(true),
        _ => Err(Error::InvalidBucket),
    }
}

impl BoardEntry {
    /// The entry's `(discount, tenor)` classes: `Some` when disclosed, `None` for `0/0`.
    pub fn classes(&self) -> Result<Option<(u8, u8)>, Error> {
        Ok(validate_classes(self.discount_bucket, self.tenor_bucket)?
            .then_some((self.discount_bucket, self.tenor_bucket)))
    }
}

/// Invoices in one discount class of a published tenor class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscountCount {
    pub discount: u8,
    pub invoices: usize,
}

/// A tenor class with at least `k` invoices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    pub invoices: usize,
    /// Lower median of the discount classes of the tenor's invoices.
    pub median_discount: u8,
    /// Discount classes with at least `k` invoices, in class order.
    pub discounts: Vec<DiscountCount>,
    /// Invoices of this tenor in discount classes below `k`, shown only as a total.
    pub other: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenorRow {
    pub tenor: u8,
    /// `None` while the tenor class has fewer than `k` invoices.
    pub published: Option<Published>,
}

/// The public rate index. Holds only aggregates that pass the threshold and board-wide totals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateIndex {
    pub k: usize,
    /// Register entries read, both kinds, before counting each invoice once.
    pub entries: usize,
    /// Distinct invoices (N); each counts with the classes of its first entry in board order.
    pub invoices: usize,
    /// Invoices whose first entry is `0/0`.
    pub undisclosed: usize,
    /// Invoices whose first entry has invalid class codes.
    pub invalid: usize,
    /// Every tenor class, in class order.
    pub tenors: Vec<TenorRow>,
}

impl RateIndex {
    /// Computes the index from register entries **in board order** (height, tx index, output
    /// index). Settled entries carry no classes and are not passed here. Each N counts once,
    /// with its first entry: re-posts and double-financing attempts do not count twice. Outsiders
    /// cannot check supplier signatures, so a griefing entry posted before the real one sets the
    /// classes of that N; posting costs a fee per entry. `k` below [`K`] is raised to [`K`].
    pub fn compute<'a>(entries: impl IntoIterator<Item = &'a BoardEntry>, k: usize) -> Self {
        let k = k.max(K);
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut index = RateIndex {
            k,
            entries: 0,
            invoices: 0,
            undisclosed: 0,
            invalid: 0,
            tenors: Vec::new(),
        };
        // (discount, tenor) of each counted invoice.
        let mut classes: Vec<(u8, u8)> = Vec::new();
        for e in entries.into_iter().filter(|e| e.kind.is_register()) {
            index.entries += 1;
            if !seen.insert(e.nullifier) {
                continue;
            }
            index.invoices += 1;
            match e.classes() {
                Ok(Some(c)) => classes.push(c),
                Ok(None) => index.undisclosed += 1,
                Err(_) => index.invalid += 1,
            }
        }
        index.tenors = TENOR_CLASSES
            .iter()
            .map(|t| {
                let mut discounts: Vec<u8> = classes
                    .iter()
                    .filter(|(_, tenor)| *tenor == t.code)
                    .map(|(d, _)| *d)
                    .collect();
                discounts.sort_unstable();
                let published = (discounts.len() >= k).then(|| {
                    let shown: Vec<DiscountCount> = DISCOUNT_CLASSES
                        .iter()
                        .map(|d| DiscountCount {
                            discount: d.code,
                            invoices: discounts.iter().filter(|x| **x == d.code).count(),
                        })
                        .filter(|c| c.invoices >= k)
                        .collect();
                    Published {
                        invoices: discounts.len(),
                        median_discount: discounts[(discounts.len() - 1) / 2],
                        other: discounts.len() - shown.iter().map(|c| c.invoices).sum::<usize>(),
                        discounts: shown,
                    }
                });
                TenorRow {
                    tenor: t.code,
                    published,
                }
            })
            .collect();
        index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::EntryKind;
    use ed25519_dalek::SigningKey;

    fn entry(n: u8, discount: u8, tenor: u8) -> BoardEntry {
        BoardEntry::sign(
            &SigningKey::from_bytes(&[1; 32]),
            EntryKind::Register,
            [n; 32],
            [2; 32],
            discount,
            tenor,
        )
    }

    #[test]
    fn classes_cover_their_ranges_without_gaps() {
        for classes in [&DISCOUNT_CLASSES[..], &TENOR_CLASSES[..]] {
            for (i, c) in classes.iter().enumerate() {
                assert_eq!(c.code as usize, i + 1);
                assert!(c.min <= c.max);
                if i > 0 {
                    assert_eq!(c.min, classes[i - 1].max + 1);
                }
            }
        }
        assert_eq!(DISCOUNT_CLASSES[0].min, 0);
        assert_eq!(TENOR_CLASSES[0].min, 0);
    }

    #[test]
    fn deal_classes_from_amounts_and_dates() {
        // 1 000 000 zat invoice, 975 000 advance (2.5%), due 45 days after the advance.
        assert_eq!(discount_bps(1_000_000, 975_000), Ok(250));
        assert_eq!(classes_for(1_000_000, 975_000, 20_745, 20_790), Ok((3, 2)));
        // Boundaries: exactly 1% is class 2, 30 days is class 1, 31 days class 2.
        assert_eq!(classes_for(10_000, 9_900, 0, 30), Ok((2, 1)));
        assert_eq!(classes_for(10_000, 9_901, 0, 31), Ok((1, 2)));
        assert_eq!(classes_for(10_000, 1, 0, 365), Ok((7, 5)));
        assert_eq!(classes_for(10_000, 10_000, 5, 5), Ok((1, 1)));
        for bad in [
            classes_for(10_000, 0, 0, 30),      // no advance
            classes_for(10_000, 10_001, 0, 30), // advance above face
            classes_for(0, 0, 0, 30),
            classes_for(10_000, 9_000, 30, 29), // due before advance
            classes_for(10_000, 9_000, 0, 366), // longer than a year
        ] {
            assert_eq!(bad, Err(Error::InvalidBucket));
        }
    }

    #[test]
    fn entry_classes_are_validated() {
        assert_eq!(entry(1, 3, 2).classes(), Ok(Some((3, 2))));
        assert_eq!(entry(1, 0, 0).classes(), Ok(None));
        for (d, t) in [(0, 2), (3, 0), (8, 2), (3, 6), (255, 255)] {
            assert_eq!(
                entry(1, d, t).classes(),
                Err(Error::InvalidBucket),
                "{d}/{t}"
            );
        }
        // Values the existing flows and tests sign stay valid.
        assert_eq!(validate_classes(2, 3), Ok(true));
    }

    #[test]
    fn aggregation_counts_each_invoice_once_with_its_first_entry() {
        let mut board = Vec::new();
        for n in 0..6 {
            board.push(entry(n, 3, 2)); // 6 invoices, 2-3%, 31-60 days
        }
        board.push(entry(0, 7, 5)); // re-post or second financier of N 0: ignored
        for n in 10..13 {
            board.push(entry(n, 2, 2)); // 3 more in 31-60 days at 1-2%
        }
        board.push(entry(20, 0, 0)); // not disclosed
        board.push(entry(21, 9, 9)); // invalid
        let i = RateIndex::compute(&board, K);
        assert_eq!(
            (i.entries, i.invoices, i.undisclosed, i.invalid),
            (12, 11, 1, 1)
        );
        let row = &i.tenors[1];
        assert_eq!(row.tenor, 2);
        let p = row.published.as_ref().unwrap();
        assert_eq!(p.invoices, 9);
        // sorted classes [2,2,2,3,3,3,3,3,3] → lower median 3
        assert_eq!(p.median_discount, 3);
        assert_eq!(
            p.discounts,
            vec![DiscountCount {
                discount: 3,
                invoices: 6
            }]
        );
        assert_eq!(p.other, 3);
        // N 0's later 7/5 entry did not create a 181-365 day row
        assert!(i
            .tenors
            .iter()
            .filter(|r| r.tenor != 2)
            .all(|r| r.published.is_none()));
    }

    #[test]
    fn classes_below_k_are_not_shown_and_k_cannot_be_lowered() {
        let board: Vec<_> = (0..4).map(|n| entry(n, 3, 2)).collect();
        let i = RateIndex::compute(&board, 1);
        assert_eq!(i.k, K);
        assert!(i.tenors.iter().all(|r| r.published.is_none()));
        assert_eq!(i.invoices, 4);

        let board: Vec<_> = (0..5).map(|n| entry(n, 3, 2)).collect();
        assert!(RateIndex::compute(&board, K).tenors[1].published.is_some());
        // A higher k hides it again.
        let i = RateIndex::compute(&board, 6);
        assert_eq!(i.k, 6);
        assert!(i.tenors[1].published.is_none());
    }

    #[test]
    fn settled_entries_do_not_count() {
        let mut settled = entry(1, 3, 2);
        settled.kind = EntryKind::Settled;
        let i = RateIndex::compute([&settled], K);
        assert_eq!((i.entries, i.invoices), (0, 0));
    }
}
