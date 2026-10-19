//! Where the board comes from: a live scan with the board's viewing key (the `jitsuin-board`
//! scanner over a watch-only `zcash-devtool` wallet) or a snapshot file.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jitsuin_board::{Collected, Position};
use jitsuin_wallet::Devtool;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::args::{LiveArgs, Network, Source};

/// Account name of the watch-only wallet created from the board's UFVK.
pub const WATCH_ACCOUNT: &str = "jitsuin-board";

#[derive(Debug, Clone)]
pub enum Origin {
    Snapshot {
        path: PathBuf,
    },
    Live {
        network: Network,
        wallet_dir: PathBuf,
        lightwalletd: String,
        /// The watch-only wallet was created by this run.
        created: bool,
        transactions: usize,
        pending: usize,
        elapsed: Duration,
    },
}

impl Origin {
    /// Header lines of a text report.
    pub fn describe(&self) -> String {
        match self {
            Origin::Snapshot { path } => format!("Board    snapshot {}
", path.display()),
            Origin::Live {
                network,
                wallet_dir,
                lightwalletd,
                created,
                transactions,
                pending,
                elapsed,
            } => format!(
                "Board    {} live scan, watch-only wallet {} ({})
         {transactions} mined                  tx, {pending} pending, order from {lightwalletd}, {:.1} s
",
                network.name(),
                wallet_dir.display(),
                if *created { "created now" } else { "existing" },
                elapsed.as_secs_f64()
            ),
        }
    }

    pub fn to_json(&self) -> Value {
        match self {
            Origin::Snapshot { path } => {
                json!({ "source": "snapshot", "path": path.display().to_string() })
            }
            Origin::Live {
                network,
                wallet_dir,
                lightwalletd,
                created,
                transactions,
                pending,
                elapsed,
            } => json!({
                "source": "live",
                "network": network.name(),
                "wallet_dir": wallet_dir.display().to_string(),
                "wallet_created": created,
                "lightwalletd": lightwalletd,
                "transactions": transactions,
                "pending": pending,
                "elapsed_ms": elapsed.as_millis() as u64,
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Board {
    pub origin: Origin,
    pub collected: Collected,
}

/// One board output in a snapshot, the same shape the web app gets from its backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotItem {
    pub txid: String,
    pub height: u32,
    pub tx_index: u32,
    pub output_index: u32,
    /// Full 512-byte memo, base64url without padding.
    pub memo: String,
}

pub fn load(source: &Source) -> Result<Board, String> {
    match source {
        Source::Snapshot(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            let collected = from_snapshot(&text).map_err(|e| format!("{}: {e}", path.display()))?;
            Ok(Board {
                origin: Origin::Snapshot { path: path.clone() },
                collected,
            })
        }
        Source::Live(live) => scan(live),
    }
}

/// Decodes a snapshot. Memos that are not valid entries end up in `rejected`, as in a live scan.
pub fn from_snapshot(json: &str) -> Result<Collected, String> {
    let items: Vec<SnapshotItem> =
        serde_json::from_str(json).map_err(|e| format!("not a board snapshot: {e}"))?;
    let mut c = Collected::default();
    for i in items {
        let memo = URL_SAFE_NO_PAD
            .decode(i.memo.trim())
            .map_err(|_| format!("memo of {} is not base64url", i.txid))?;
        let position = Position {
            height: i.height,
            tx_index: i.tx_index,
            output_index: i.output_index,
        };
        c.add(&i.txid, position, &memo);
    }
    c.sort();
    Ok(c)
}

/// Snapshot of the decoded entries in board order. Rejected memos are not entries and are left
/// out. Re-encoding is exact: the decoders are strict, so a decoded entry has one encoding.
pub fn to_snapshot(c: &Collected) -> String {
    let item = |txid: &str, p: Position, memo: &[u8]| SnapshotItem {
        txid: txid.to_string(),
        height: p.height,
        tx_index: p.tx_index,
        output_index: p.output_index,
        memo: URL_SAFE_NO_PAD.encode(memo),
    };
    let mut items: Vec<(Position, SnapshotItem)> = c
        .records
        .iter()
        .map(|r| {
            (
                r.position,
                item(&r.txid, r.position, &r.entry.to_memo_bytes()),
            )
        })
        .chain(c.settled.iter().map(|s| {
            (
                s.position,
                item(&s.txid, s.position, &s.entry.to_memo_bytes()),
            )
        }))
        .collect();
    items.sort_by_key(|(p, _)| *p);
    let items: Vec<SnapshotItem> = items.into_iter().map(|(_, i)| i).collect();
    serde_json::to_string_pretty(&items).expect("snapshot serializes")
}

/// True when `dir` already holds a devtool wallet (devtool writes `keys.toml` on init).
pub fn wallet_exists(dir: &Path) -> bool {
    dir.join("keys.toml").is_file()
}

fn scan(a: &LiveArgs) -> Result<Board, String> {
    let watch = Devtool::new(&a.devtool, &a.wallet_dir);
    let created = !wallet_exists(&a.wallet_dir);
    if created {
        let birthday = a.birthday.ok_or_else(|| {
            format!(
                "{} has no wallet yet: pass --birthday <first block of the board> so the scan \
                 does not start at the chain tip and miss entries",
                a.wallet_dir.display()
            )
        })?;
        watch
            .init_fvk(WATCH_ACCOUNT, &a.ufvk, birthday)
            .map_err(|e| devtool_error(a, e))?;
    }
    let report = jitsuin_board::scan(&watch, &a.lightwalletd).map_err(|e| match e {
        jitsuin_board::Error::Wallet(w) => devtool_error(a, w),
        other => other.to_string(),
    })?;
    let collected = Collected {
        records: report.records,
        settled: report.settled,
        rejected: report.rejected,
    };
    if let Some(path) = &a.save_board {
        std::fs::write(path, to_snapshot(&collected))
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    }
    Ok(Board {
        origin: Origin::Live {
            network: a.network,
            wallet_dir: a.wallet_dir.clone(),
            lightwalletd: a.lightwalletd.clone(),
            created,
            transactions: report.transactions,
            pending: report.pending,
            elapsed: report.elapsed,
        },
        collected,
    })
}

fn devtool_error(a: &LiveArgs, e: jitsuin_wallet::Error) -> String {
    match e {
        jitsuin_wallet::Error::Io(io) if io.kind() == ErrorKind::NotFound => format!(
            "zcash-devtool not found at `{}`: install it (README, \"Verify the board\") or pass \
             --devtool <path>",
            a.devtool.display()
        ),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use jitsuin_core::{BoardEntry, EntryKind};

    #[test]
    fn snapshot_roundtrip_keeps_entries_and_order() {
        let s = SigningKey::from_bytes(&[1; 32]);
        let e = |n: u8| BoardEntry::sign(&s, EntryKind::Register, [n; 32], [2; 32], 1, 2);
        let item = |txid: &str, height, memo: &[u8]| SnapshotItem {
            txid: txid.into(),
            height,
            tx_index: 0,
            output_index: 0,
            memo: URL_SAFE_NO_PAD.encode(memo),
        };
        let json = serde_json::to_string(&vec![
            item("bb", 11, &e(2).to_memo_bytes()),
            item("aa", 10, &e(1).to_memo_bytes()),
            item("cc", 12, b"\xffnot an entry"),
        ])
        .unwrap();
        let c = from_snapshot(&json).unwrap();
        assert_eq!(
            c.records
                .iter()
                .map(|r| r.txid.as_str())
                .collect::<Vec<_>>(),
            ["aa", "bb"]
        );
        assert_eq!(c.rejected.len(), 1);

        let again = from_snapshot(&to_snapshot(&c)).unwrap();
        assert_eq!(again.records, c.records);
        assert!(again.rejected.is_empty());
    }

    #[test]
    fn bad_snapshots_are_errors() {
        assert!(from_snapshot("{}")
            .unwrap_err()
            .contains("not a board snapshot"));
        let bad = r#"[{"txid":"aa","height":1,"tx_index":0,"output_index":0,"memo":"***"}]"#;
        assert!(from_snapshot(bad).unwrap_err().contains("base64url"));
    }

    #[test]
    fn a_live_scan_without_a_wallet_needs_the_birthday() {
        let dir = std::env::temp_dir().join("jitsuin-cli-test-no-wallet");
        let a = LiveArgs {
            ufvk: "uviewtest1qqqq".into(),
            network: Network::Test,
            birthday: None,
            wallet_dir: dir,
            devtool: "zcash-devtool-that-does-not-exist".into(),
            lightwalletd: Network::Test.lightwalletd().into(),
            save_board: None,
        };
        assert!(scan(&a).unwrap_err().contains("--birthday"));
        let a = LiveArgs {
            birthday: Some(1),
            ..a
        };
        assert!(scan(&a).unwrap_err().contains("zcash-devtool not found"));
    }
}
