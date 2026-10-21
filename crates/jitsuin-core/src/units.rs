//! The Merkle sum tree of fund units (HNK-15.T1, HNK-30.T23, D-49): each leaf holds a member's
//! units, not a ZEC balance, under an id only the member's withdraw token opens. The root and its
//! sum are what the manager signs into `JTLR` each period; a member checks their own leaf against
//! it with the path the fund sends them (`fund.merkle_path`).
//!
//! - Leaf id: `SHA-256("jitsuin-fund-leaf-v1" ‖ withdraw_token)`.
//! - Leaf: `SHA-256("jitsuin-fund-leaf-v1" ‖ leaf_id ‖ units_le8)`, sum = units.
//! - Node: `SHA-256("jitsuin-fund-node-v1" ‖ left ‖ left_sum_le8 ‖ right ‖ right_sum_le8)`, sum =
//!   both sums (checked, never wraps).
//! - Leaves sorted by id; a level with an odd count is padded with the empty node (zero hash,
//!   sum 0). The empty tree has the empty node as its root.
//! - Path step (41 bytes): sibling hash (32), sibling sum (8, LE), side (1: 0 = sibling on the
//!   left, 1 = sibling on the right).

use sha2::{Digest, Sha256};

use crate::error::Error;

pub const LEAF_DOMAIN: &[u8] = b"jitsuin-fund-leaf-v1";
pub const NODE_DOMAIN: &[u8] = b"jitsuin-fund-node-v1";
pub const STEP_LEN: usize = 32 + 8 + 1;
/// Enough for 2^40 leaves.
pub const MAX_DEPTH: usize = 40;

/// A tree node: hash and the sum of the units under it.
pub type Node = ([u8; 32], u64);

const EMPTY: Node = ([0; 32], 0);

pub fn leaf_id(withdraw_token: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(LEAF_DOMAIN)
        .chain_update(withdraw_token)
        .finalize()
        .into()
}

pub fn leaf(id: &[u8; 32], units: u64) -> Node {
    let h = Sha256::new()
        .chain_update(LEAF_DOMAIN)
        .chain_update(id)
        .chain_update(units.to_le_bytes())
        .finalize()
        .into();
    (h, units)
}

fn parent(l: &Node, r: &Node) -> Option<Node> {
    let h = Sha256::new()
        .chain_update(NODE_DOMAIN)
        .chain_update(l.0)
        .chain_update(l.1.to_le_bytes())
        .chain_update(r.0)
        .chain_update(r.1.to_le_bytes())
        .finalize()
        .into();
    Some((h, l.1.checked_add(r.1)?))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step {
    pub sibling: Node,
    /// True when the sibling is on the right.
    pub right: bool,
}

/// One period's tree, built from `(leaf_id, units)`.
#[derive(Debug, Clone)]
pub struct UnitTree {
    levels: Vec<Vec<Node>>,
    ids: Vec<[u8; 32]>,
}

impl UnitTree {
    /// Ids must be distinct; the units must not add up past `u64::MAX`.
    pub fn build(leaves: &[([u8; 32], u64)]) -> Result<Self, Error> {
        let mut sorted = leaves.to_vec();
        sorted.sort_by_key(|x| x.0);
        if sorted.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(Error::UnitTree);
        }
        let mut levels = vec![sorted
            .iter()
            .map(|(id, u)| leaf(id, *u))
            .collect::<Vec<_>>()];
        while levels.last().map_or(0, Vec::len) > 1 {
            let lv = levels.last().unwrap();
            let next = lv
                .chunks(2)
                .map(|c| parent(&c[0], c.get(1).unwrap_or(&EMPTY)))
                .collect::<Option<Vec<_>>>()
                .ok_or(Error::UnitOverflow)?;
            levels.push(next);
        }
        if levels.len() > MAX_DEPTH + 1 {
            return Err(Error::UnitTree);
        }
        Ok(Self {
            levels,
            ids: sorted.into_iter().map(|(id, _)| id).collect(),
        })
    }

    /// The root and the total units.
    pub fn root(&self) -> Node {
        self.levels
            .last()
            .and_then(|l| l.first())
            .copied()
            .unwrap_or(EMPTY)
    }

    /// The path from the leaf with this id up to the root.
    pub fn path(&self, id: &[u8; 32]) -> Option<Vec<Step>> {
        let mut i = self.ids.binary_search(id).ok()?;
        let mut steps = vec![];
        for lv in &self.levels[..self.levels.len() - 1] {
            let right = i % 2 == 0;
            let j = if right { i + 1 } else { i - 1 };
            steps.push(Step {
                sibling: *lv.get(j).unwrap_or(&EMPTY),
                right,
            });
            i /= 2;
        }
        Some(steps)
    }
}

/// True when a leaf with `units` under `id` is in the tree with this root and total.
pub fn verify(id: &[u8; 32], units: u64, path: &[Step], root: &[u8; 32], total: u64) -> bool {
    if path.len() > MAX_DEPTH {
        return false;
    }
    let mut n = leaf(id, units);
    for s in path {
        let next = if s.right {
            parent(&n, &s.sibling)
        } else {
            parent(&s.sibling, &n)
        };
        match next {
            Some(p) => n = p,
            None => return false,
        }
    }
    n == (*root, total)
}

pub fn path_to_bytes(path: &[Step]) -> Vec<u8> {
    let mut out = Vec::with_capacity(path.len() * STEP_LEN);
    for s in path {
        out.extend_from_slice(&s.sibling.0);
        out.extend_from_slice(&s.sibling.1.to_le_bytes());
        out.push(s.right as u8);
    }
    out
}

pub fn path_from_bytes(bytes: &[u8]) -> Result<Vec<Step>, Error> {
    if !bytes.len().is_multiple_of(STEP_LEN) || bytes.len() / STEP_LEN > MAX_DEPTH {
        return Err(Error::BadPath);
    }
    bytes
        .chunks(STEP_LEN)
        .map(|c| {
            let right = match c[40] {
                0 => false,
                1 => true,
                _ => return Err(Error::BadPath),
            };
            Ok(Step {
                sibling: (
                    c[..32].try_into().unwrap(),
                    u64::from_le_bytes(c[32..40].try_into().unwrap()),
                ),
                right,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn members(n: u8) -> Vec<([u8; 32], u64)> {
        (0..n)
            .map(|i| (leaf_id(&[i; 32]), 1_000 * (i as u64 + 1)))
            .collect()
    }

    #[test]
    fn every_member_finds_their_units_under_the_root() {
        for n in [1u8, 2, 3, 5, 8, 13] {
            let m = members(n);
            let t = UnitTree::build(&m).unwrap();
            let (root, total) = t.root();
            assert_eq!(total, m.iter().map(|x| x.1).sum::<u64>());
            for (id, u) in &m {
                let p = t.path(id).unwrap();
                assert!(verify(id, *u, &p, &root, total));
                let back = path_from_bytes(&path_to_bytes(&p)).unwrap();
                assert_eq!(back, p);
                // a claim of more units, or a smaller total, does not hold
                assert!(!verify(id, u + 1, &p, &root, total));
                assert!(!verify(id, *u, &p, &root, total - 1));
            }
        }
    }

    #[test]
    fn the_manager_cannot_hide_units_behind_a_wrapping_sum() {
        let id = leaf_id(&[1; 32]);
        let bogus = Step {
            sibling: ([7; 32], u64::MAX),
            right: true,
        };
        assert!(!verify(&id, 5, &[bogus], &[0; 32], 4));
        assert!(UnitTree::build(&[(id, u64::MAX), (leaf_id(&[2; 32]), 1)]).is_err());
    }

    #[test]
    fn ids_are_unique_and_the_empty_tree_is_zero() {
        let id = leaf_id(&[1; 32]);
        assert!(UnitTree::build(&[(id, 1), (id, 2)]).is_err());
        let t = UnitTree::build(&[]).unwrap();
        assert_eq!(t.root(), ([0; 32], 0));
        assert!(t.path(&id).is_none());
    }

    /// The same tree as jitsuinfi-frontend `tests/units.test.ts` checks.
    #[test]
    fn vector_for_the_web_app() {
        let m = members(3);
        let t = UnitTree::build(&m).unwrap();
        let (root, total) = t.root();
        let p = t.path(&m[1].0).unwrap();
        let got = format!(
            "{{\"token\":\"{}\",\"units\":{},\"root\":\"{}\",\"total\":{},\"path\":\"{}\"}}",
            hex(&[1; 32]),
            m[1].1,
            hex(&root),
            total,
            hex(&path_to_bytes(&p))
        );
        if std::env::var_os("WRITE_VECTORS").is_some() {
            std::fs::write("tests/vectors/units.json", &got).unwrap();
        }
        assert_eq!(got, include_str!("../tests/vectors/units.json").trim());
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
