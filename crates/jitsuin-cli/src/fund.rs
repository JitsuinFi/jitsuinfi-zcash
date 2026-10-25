//! `jitsuin fund` (HNK-27.T10): a JitsuinFi Vault member checks the fund's solvency on its own
//! machine. The operational account's full viewing key goes into a local watch-only
//! `zcash-devtool` wallet and is never sent anywhere (P-10); `jitsuin_flow::fund` builds the view
//! (cash, receivables from the manager-signed advance receipts and notes, the latest liability
//! root) and compares assets with liabilities.
//!
//! Limits, printed with every report: the receivables are what the manager declared in its notes
//! (face value and due date are not tied to the advance or to a real invoice), so a breach only
//! shows once a receivable is overdue. With `--path`, the member's units are checked against the
//! latest manager-signed root on chain: the period's path the fund sent them (`fund.merkle_path`,
//! saved from the member page) must end in that root and add up to its total (HNK-29.T2, D-49).
//! Since D-49 the root's total counts units at par (1 zat each), so SOLVENT means "not below par".
//!
//! Since 2026-10-25 (user decision) the fund is valued on its books, not on the whole wallet it
//! shares with the manager: the path file carries the fund's deposit and payout txids (`books`),
//! `jitsuin_flow::fund::fund_books` reads their values from the chain and replays the advances
//! the fund paid and their repayments. SOLVENT then means the books' assets are not below par
//! AND the wallet holds at least the books' cash. A path from a close made before the books
//! (no `books` field) still checks inclusion, but gives no solvency verdict.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use jitsuin_core::units;
use jitsuin_flow::fund::{
    book_solvency, member_books, BookSolvency, Books, FundBooks, FundView, ReceivableStatus,
    SolvencyPolicy,
};
use jitsuin_wallet::Devtool;
use serde_json::{json, Value};

use crate::args::Network;
use crate::board::wallet_exists;

/// Account name of the watch-only wallet created from the operational account's UFVK.
pub const WATCH_ACCOUNT: &str = "jitsuin-fund";

pub const USAGE: &str = "\
jitsuin fund: solvency of a JitsuinFi Vault fund, checked by a member (HNK-15, P-10)

USAGE:
    jitsuin fund --ufvk <UFVK> --manager-pk <HEX> [OPTIONS]

    --ufvk <UFVK>           Full viewing key of the fund's operational account (from the
                            manager, private channel). Stays in the local wallet.
    --manager-pk <HEX>      Manager's public key (64 hex); only its receipts and roots count.
    --birthday <HEIGHT>     First block of the account. Required when the wallet is created.
    --grace-days <DAYS>     Days after the due date before a receivable is overdue [default 7]
    --haircut <PERCENT>     Share of an overdue receivable written off [default 100, as the
                            fund's node values it; the member page refuses another value]
    --today <DAYS>          Date as days since 1970-01-01 [default: today]
    --path <FILE>           The fund.merkle_path you saved from the member page: checks that
                            your units are under the latest root on chain, and carries the
                            fund's books (its deposit and payout txids). Without it, or with a
                            path from before the books, there is no solvency verdict.
    --wallet-dir <DIR>      Watch-only wallet [default: wallet-fund-<network>]
    --devtool <PATH>        zcash-devtool binary [default: $JITSUIN_DEVTOOL or zcash-devtool]
    --json                  Machine-readable report.

EXIT STATUS:
    0 solvent (and, with --path, your units included), 1 not solvent, no liability root yet, or
    not included, 2 usage, input or network error.
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundArgs {
    pub ufvk: String,
    pub network: Network,
    pub manager_pk: [u8; 32],
    pub birthday: Option<u32>,
    pub grace_days: u32,
    pub haircut_pct: u64,
    pub today: u32,
    pub wallet_dir: PathBuf,
    pub devtool: PathBuf,
    pub json: bool,
    pub path: Option<PathBuf>,
}

fn unhex32(s: &str) -> Result<[u8; 32], String> {
    let b = s.trim().as_bytes();
    if b.len() != 64 {
        return Err("--manager-pk must be 64 hex characters".into());
    }
    let mut out = [0u8; 32];
    for (i, pair) in b.chunks(2).enumerate() {
        let s = std::str::from_utf8(pair).map_err(|_| "--manager-pk is not hex".to_string())?;
        out[i] = u8::from_str_radix(s, 16).map_err(|_| "--manager-pk is not hex".to_string())?;
    }
    Ok(out)
}

fn today() -> u32 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (secs / 86_400) as u32
}

/// Parses the arguments after `fund`. `devtool_env` is `$JITSUIN_DEVTOOL`.
pub fn parse(args: &[String], devtool_env: Option<&str>) -> Result<Option<FundArgs>, String> {
    let mut it = args.iter();
    let (mut ufvk, mut manager_pk, mut birthday, mut grace, mut haircut, mut day) =
        (None, None, None, None, None, None);
    let (mut wallet_dir, mut devtool, mut json, mut path) = (None, None, false, None);
    while let Some(arg) = it.next() {
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n, Some(v.to_string())),
            _ => (arg.as_str(), None),
        };
        if matches!(name, "-h" | "--help") {
            return Ok(None);
        }
        if name == "--json" {
            json = true;
            continue;
        }
        let mut value = || -> Result<String, String> {
            match inline.clone().or_else(|| it.next().cloned()) {
                Some(v) if !v.is_empty() => Ok(v),
                _ => Err(format!("{name} needs a value")),
            }
        };
        let number = |v: String| {
            v.parse::<u64>()
                .map_err(|_| format!("{name} must be a whole number, got `{v}`"))
        };
        match name {
            "--ufvk" => set(&mut ufvk, name, value()?)?,
            "--manager-pk" => set(&mut manager_pk, name, unhex32(&value()?)?)?,
            "--birthday" => set(&mut birthday, name, number(value()?)? as u32)?,
            "--grace-days" => set(&mut grace, name, number(value()?)? as u32)?,
            "--haircut" => {
                let p = number(value()?)?;
                if p > 100 {
                    return Err("--haircut is a percentage from 0 to 100".into());
                }
                set(&mut haircut, name, p)?
            }
            "--today" => set(&mut day, name, number(value()?)? as u32)?,
            "--wallet-dir" => set(&mut wallet_dir, name, PathBuf::from(value()?))?,
            "--devtool" => set(&mut devtool, name, PathBuf::from(value()?))?,
            "--path" => set(&mut path, name, PathBuf::from(value()?))?,
            _ => {
                return Err(format!(
                    "unknown option `{arg}` (try `jitsuin fund --help`)"
                ))
            }
        }
    }
    let ufvk = ufvk.ok_or("give the operational account's key: --ufvk <UFVK>")?;
    let network = Network::of_ufvk(&ufvk)?;
    Ok(Some(FundArgs {
        manager_pk: manager_pk.ok_or("give the manager's key: --manager-pk <HEX>")?,
        birthday,
        grace_days: grace.unwrap_or(7),
        haircut_pct: haircut.unwrap_or(100),
        today: day.unwrap_or_else(today),
        wallet_dir: wallet_dir
            .unwrap_or_else(|| PathBuf::from(format!("wallet-fund-{}", network.name()))),
        devtool: devtool.unwrap_or_else(|| {
            PathBuf::from(
                devtool_env
                    .filter(|v| !v.is_empty())
                    .unwrap_or("zcash-devtool"),
            )
        }),
        json,
        path,
        ufvk,
        network,
    }))
}

fn set<T>(slot: &mut Option<T>, name: &str, value: T) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("{name} given twice"));
    }
    *slot = Some(value);
    Ok(())
}

/// The fund's books from a saved `fund.merkle_path` (the node adds them since 2026-10-25), or
/// `None` for a path without them. Txids only; their values come from the chain.
pub fn path_books(path_json: &str) -> Option<FundBooks> {
    let b: Value = serde_json::from_str(path_json).ok()?;
    let b = if b["type"] == "fund.merkle_path" {
        &b["body"]["books"]
    } else {
        &b["books"]
    };
    let ids = |k: &str| -> Option<Vec<String>> {
        b[k].as_array()?
            .iter()
            .map(|t| {
                t.as_str()
                    .filter(|t| t.len() == 64 && t.bytes().all(|c| c.is_ascii_hexdigit()))
                    .map(str::to_string)
            })
            .collect()
    };
    Some(FundBooks {
        deposits: ids("deposits")?,
        payouts: ids("payouts")?,
    })
}

/// Why there is no verdict when the books are missing.
pub const NO_BOOKS: &str = "no fund books: the fund's assets are its books (deposits and their \
flows), which come with your path; run with --path and a path saved from a close made after \
the books (2026-10-25)";

/// Syncs the local watch-only wallet (created on first run), values the fund on `books` and
/// computes the verdict; no verdict without books.
pub fn run(
    a: &FundArgs,
    books: Option<&FundBooks>,
) -> Result<(Books, Option<BookSolvency>), String> {
    let watch = Devtool::new(&a.devtool, &a.wallet_dir);
    if !wallet_exists(&a.wallet_dir) {
        let birthday = a.birthday.ok_or_else(|| {
            format!(
                "{} has no wallet yet: pass --birthday <first block of the account>",
                a.wallet_dir.display()
            )
        })?;
        watch
            .init_fvk(WATCH_ACCOUNT, &a.ufvk, birthday)
            .map_err(|e| format!("zcash-devtool: {e}"))?;
    }
    let b = member_books(
        &watch,
        &a.manager_pk,
        a.today,
        a.grace_days,
        books.unwrap_or(&FundBooks::default()),
    )
    .map_err(|e| e.to_string())?;
    let verdict = books.and_then(|_| {
        book_solvency(
            &b,
            &SolvencyPolicy {
                overdue_haircut_pct: a.haircut_pct,
            },
        )
    });
    Ok((b, verdict))
}

/// The member's units against the latest root on chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inclusion {
    pub period: u32,
    pub units: u64,
    pub included: bool,
    pub why: String,
}

/// Checks a saved `fund.merkle_path` body against the latest manager-signed root in `view`.
pub fn inclusion(path_json: &str, view: &FundView) -> Result<Inclusion, String> {
    let b: Value =
        serde_json::from_str(path_json).map_err(|_| "the path file is not JSON".to_string())?;
    let b = if b["type"] == "fund.merkle_path" {
        &b["body"]
    } else {
        &b
    };
    let field = |k: &str| b[k].as_u64().ok_or(format!("the path file has no {k}"));
    let hex32 = |k: &str| -> Result<[u8; 32], String> {
        let s = b[k].as_str().ok_or(format!("the path file has no {k}"))?;
        let v = unhex(s)
            .filter(|v| v.len() == 32)
            .ok_or(format!("{k} is not 32 bytes of hex"))?;
        Ok(v.try_into().expect("32 bytes"))
    };
    let (period, units, total) = (field("period")? as u32, field("units")?, field("total")?);
    let (leaf, root) = (hex32("leaf_id")?, hex32("root")?);
    let steps = b["path"]
        .as_str()
        .and_then(unhex)
        .ok_or("the path file has no path")
        .and_then(|p| units::path_from_bytes(&p).map_err(|_| "not a fund path"))?;
    let out = |included: bool, why: String| Inclusion {
        period,
        units,
        included,
        why,
    };
    if !units::verify(&leaf, units, &steps, &root, total) {
        return Ok(out(
            false,
            "the path does not add up to the root it names".into(),
        ));
    }
    Ok(match &view.root {
        None => out(false, "no liability root on chain yet".into()),
        Some((r, _)) if r.period != period => out(
            false,
            format!(
                "the path is for period {period}; the latest root on chain is period {}",
                r.period
            ),
        ),
        Some((r, _)) if r.root != root || r.total_zat != total => out(
            false,
            "the root the fund sent you is not the one it signed on chain".into(),
        ),
        Some(_) => out(
            true,
            format!("your {units} units are in the period {period} root on chain"),
        ),
    })
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// 0 solvent (and included, when a path was checked), 1 otherwise.
pub fn passed(verdict: &Option<BookSolvency>, inc: Option<&Inclusion>) -> bool {
    verdict.is_some_and(|s| s.solvent) && inc.is_none_or(|i| i.included)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn status(s: ReceivableStatus) -> &'static str {
    match s {
        ReceivableStatus::Open => "open",
        ReceivableStatus::Repaid => "repaid",
        ReceivableStatus::Overdue => "overdue",
    }
}

const LIMITS: &str =
    "Assets are the fund's books: the deposits the manager lists (check that yours is there) \
and their flows read from the chain, not the whole wallet, which the fund shares with the \
manager. The wallet check shows it holds at least the books' cash now, not that this cash is set \
apart: the manager can spend from the same wallet later. Receivables are the manager's own notes \
(face value and due date); a breach shows only once a receivable is overdue. Network fees are \
not on the books. Liabilities count units at par (1 zat each). Inclusion of your units needs \
your Merkle path (--path).";

pub fn render_text(
    a: &FundArgs,
    b: &Books,
    verdict: &Option<BookSolvency>,
    inc: Option<&Inclusion>,
) -> String {
    let view = &b.view;
    let mut out = format!(
        "Fund     {} watch-only wallet {}, day {}, grace {} days, haircut {}%\n",
        a.network.name(),
        a.wallet_dir.display(),
        a.today,
        a.grace_days,
        a.haircut_pct
    );
    let deposited: u64 = b.deposits.iter().map(|l| l.amount_zat).sum();
    let paid: u64 = b.payouts.iter().map(|l| l.amount_zat).sum();
    out += &format!(
        "Books    deposits {} zat ({}), advanced {}, repaid {}, paid out {} zat ({})\n",
        deposited,
        b.deposits.len(),
        b.advanced_zat,
        b.repaid_zat,
        paid,
        b.payouts.len()
    );
    if !b.missing.is_empty() {
        out += &format!(
            "Missing  {} listed transactions are not mined in the wallet: {}\n",
            b.missing.len(),
            b.missing.join(", ")
        );
    }
    out += &format!(
        "Cash     {} zat on the books; the wallet holds {} zat\n",
        view.cash_zat, b.wallet_zat
    );
    for r in &view.receivables {
        out += &format!(
            "Note     N {}… face {} repaid {} due {} {}\n",
            &hex(&r.nullifier)[..16],
            r.face_zat,
            r.repaid_zat,
            r.due_date,
            status(r.status)
        );
    }
    if view.ignored_roots > 0 {
        out += &format!(
            "Ignored  {} roots not signed by the manager\n",
            view.ignored_roots
        );
    }
    out += &match (verdict, &view.root) {
        (None, None) => {
            "Verdict  NO ROOT: the manager has not posted a liability root yet\n".to_string()
        }
        (None, Some(_)) => format!("Verdict  NONE: {NO_BOOKS}\n"),
        (Some(v), _) => {
            let s = &v.solvency;
            format!(
                "Root     period {}, liabilities {} zat\nAssets   {} zat (cash {} + open {} + overdue after haircut {})\nWallet   {} zat: {}\nVerdict  {}\n",
                s.period,
                s.liabilities_zat,
                s.assets_zat,
                s.cash_zat,
                s.open_zat,
                s.overdue_zat,
                v.wallet_zat,
                if v.wallet_covers {
                    "holds at least the books' cash"
                } else {
                    "LESS than the books' cash"
                },
                if v.solvent { "SOLVENT" } else { "NOT SOLVENT" }
            )
        }
    };
    if let Some(i) = inc {
        out += &format!(
            "Units    {}: {}\n",
            if i.included {
                "INCLUDED"
            } else {
                "NOT INCLUDED"
            },
            i.why
        );
    }
    out += &format!("Limits   {LIMITS}\n");
    out
}

pub fn render_json(
    a: &FundArgs,
    b: &Books,
    verdict: &Option<BookSolvency>,
    inc: Option<&Inclusion>,
) -> Value {
    let view = &b.view;
    let lines = |ls: &[jitsuin_flow::fund::BookLine]| -> Vec<Value> {
        ls.iter()
            .map(|l| json!({ "txid": l.txid, "amount_zat": l.amount_zat }))
            .collect()
    };
    json!({
        "network": a.network.name(),
        "today": a.today,
        "grace_days": a.grace_days,
        "haircut_pct": a.haircut_pct,
        // since 2026-10-25: the fund's cash on its books, not the wallet's balance
        "basis": "books",
        "cash_zat": view.cash_zat,
        "wallet_zat": b.wallet_zat,
        "books": {
            "deposits": lines(&b.deposits),
            "payouts": lines(&b.payouts),
            "missing": b.missing,
            "advanced_zat": b.advanced_zat,
            "repaid_zat": b.repaid_zat,
        },
        "receivables": view.receivables.iter().map(|r| json!({
            "nullifier": hex(&r.nullifier),
            "face_zat": r.face_zat,
            "advance_zat": r.advance_zat,
            "repaid_zat": r.repaid_zat,
            "due_date": r.due_date,
            "status": status(r.status),
            "advance_txid": r.advance_txid,
        })).collect::<Vec<_>>(),
        "ignored_roots": view.ignored_roots,
        "verdict": verdict.map(|v| json!({
            "period": v.solvency.period,
            "liabilities_zat": v.solvency.liabilities_zat,
            "assets_zat": v.solvency.assets_zat,
            "cash_zat": v.solvency.cash_zat,
            "open_zat": v.solvency.open_zat,
            "overdue_zat": v.solvency.overdue_zat,
            "wallet_zat": v.wallet_zat,
            "wallet_covers": v.wallet_covers,
            "solvent": v.solvent,
        })),
        "no_verdict": match (verdict, &view.root) {
            (Some(_), _) => Value::Null,
            (None, None) => "no liability root on chain yet".into(),
            (None, Some(_)) => NO_BOOKS.into(),
        },
        "inclusion": inc.map(|i| json!({
            "period": i.period,
            "units": i.units,
            "included": i.included,
            "why": i.why,
        })),
        "limits": LIMITS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use jitsuin_flow::fund::{Receivable, Solvency};

    fn books(view: FundView, wallet_zat: u64) -> Books {
        Books {
            view,
            wallet_zat,
            deposits: vec![],
            payouts: vec![],
            missing: vec![],
            advanced_zat: 0,
            repaid_zat: 0,
        }
    }

    fn verdict(s: Solvency, wallet_zat: u64) -> Option<BookSolvency> {
        let wallet_covers = wallet_zat >= s.cash_zat;
        Some(BookSolvency {
            solvency: s,
            wallet_zat,
            wallet_covers,
            solvent: s.solvent && wallet_covers,
        })
    }

    fn p(args: &[&str]) -> Result<Option<FundArgs>, String> {
        let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        parse(&owned, None)
    }

    #[test]
    fn parses_the_member_check() {
        let pk = "ab".repeat(32);
        let a = p(&[
            "--ufvk",
            "uviewtest1qqqq",
            "--manager-pk",
            &pk,
            "--today",
            "20500",
        ])
        .unwrap()
        .unwrap();
        assert_eq!(a.network, Network::Test);
        assert_eq!(a.manager_pk, [0xab; 32]);
        assert_eq!((a.grace_days, a.haircut_pct, a.today), (7, 100, 20_500));
        assert_eq!(a.wallet_dir, PathBuf::from("wallet-fund-testnet"));
        assert!(p(&["--ufvk", "uviewtest1qqqq"]).is_err()); // no manager key
        assert!(p(&["--manager-pk", &pk]).is_err()); // no UFVK
        assert!(p(&["--ufvk", "uviewtest1qqqq", "--manager-pk", "12"]).is_err());
        assert!(p(&[
            "--ufvk",
            "uviewtest1qqqq",
            "--manager-pk",
            &pk,
            "--haircut",
            "101"
        ])
        .is_err());
        assert!(p(&["--ufvk", "uviewtest1qqqq", "--manager-pk", &pk, "--bogus"]).is_err());
        assert!(p(&["--help"]).unwrap().is_none());
    }

    #[test]
    fn renders_a_verdict_and_its_limits() {
        let a = p(&[
            "--ufvk",
            "uviewtest1qqqq",
            "--manager-pk",
            &"ab".repeat(32),
            "--today",
            "40",
        ])
        .unwrap()
        .unwrap();
        let view = FundView {
            cash_zat: 100_000,
            receivables: vec![Receivable {
                nullifier: [7; 32],
                face_zat: 40_000,
                due_date: 50,
                advance_zat: 38_000,
                advance_txid: "a1".into(),
                repaid_zat: 0,
                status: ReceivableStatus::Open,
            }],
            root: None,
            ignored_roots: 0,
        };
        let b = books(view, 300_000_000);
        let none = book_solvency(
            &b,
            &SolvencyPolicy {
                overdue_haircut_pct: 100,
            },
        );
        assert!(!passed(&none, None));
        assert!(render_text(&a, &b, &none, None).contains("NO ROOT"));
        let s = Solvency {
            cash_zat: 100_000,
            open_zat: 40_000,
            overdue_zat: 0,
            assets_zat: 140_000,
            liabilities_zat: 120_000,
            period: 3,
            solvent: true,
        };
        let v = verdict(s, 300_000_000);
        assert!(passed(&v, None));
        let text = render_text(&a, &b, &v, None);
        assert!(text.contains("SOLVENT") && text.contains("Limits"));
        let j = render_json(&a, &b, &v, None);
        assert_eq!(j["verdict"]["solvent"], true);
        assert_eq!(j["basis"], "books");
        assert_eq!(
            (j["cash_zat"].as_u64(), j["wallet_zat"].as_u64()),
            (Some(100_000), Some(300_000_000))
        );
        assert_eq!(j["receivables"][0]["status"], "open");
        // assets cover the units, but the wallet holds less than the books' cash: not solvent
        let short = verdict(s, 99_999);
        assert!(!passed(&short, None));
        assert!(render_text(&a, &b, &short, None).contains("NOT SOLVENT"));
    }

    #[test]
    fn a_saved_path_is_checked_against_the_root_on_chain() {
        use ed25519_dalek::SigningKey;
        use jitsuin_core::LiabilityRoot;
        let leaves: Vec<([u8; 32], u64)> = (1..=3u8)
            .map(|i| (units::leaf_id(&[i; 32]), 1_000 * i as u64))
            .collect();
        let t = units::UnitTree::build(&leaves).unwrap();
        let (root, total) = t.root();
        let body = json!({
            "period": 4,
            "leaf_id": hex(&leaves[1].0),
            "units": 2_000,
            "root": hex(&root),
            "total": total,
            "path": hex(&units::path_to_bytes(&t.path(&leaves[1].0).unwrap())),
        })
        .to_string();
        let key = SigningKey::from_bytes(&[9; 32]);
        let mut view = FundView {
            cash_zat: 0,
            receivables: vec![],
            root: None,
            ignored_roots: 0,
        };
        assert!(!inclusion(&body, &view).unwrap().included);
        view.root = Some((LiabilityRoot::sign(&key, 4, root, total), "t".into()));
        let ok = inclusion(&body, &view).unwrap();
        assert!(ok.included, "{}", ok.why);
        view.root = Some((LiabilityRoot::sign(&key, 5, root, total), "t".into()));
        assert!(inclusion(&body, &view).unwrap().why.contains("period 5"));
        view.root = Some((LiabilityRoot::sign(&key, 4, [1; 32], total), "t".into()));
        assert!(!inclusion(&body, &view).unwrap().included);
        let lied = body.replace("\"units\":2000", "\"units\":2001");
        assert!(!inclusion(&lied, &view).unwrap().included);
        let s = verdict(
            Solvency {
                cash_zat: 1,
                open_zat: 0,
                overdue_zat: 0,
                assets_zat: 9_000,
                liabilities_zat: 6_000,
                period: 4,
                solvent: true,
            },
            1,
        );
        let not = inclusion(&lied, &view).unwrap();
        assert!(!passed(&s, Some(&not)));
    }

    #[test]
    fn the_books_come_with_the_path() {
        let d = "d1".repeat(32);
        let w = "e2".repeat(32);
        let body = json!({ "period": 2, "books": { "deposits": [d], "payouts": [w] } });
        assert_eq!(
            path_books(&body.to_string()),
            Some(FundBooks {
                deposits: vec![d.clone()],
                payouts: vec![w.clone()]
            })
        );
        let message = json!({ "type": "fund.merkle_path", "body": body });
        assert!(path_books(&message.to_string()).is_some());
        // a path from a close made before the books: inclusion only, no verdict
        assert_eq!(path_books(&json!({ "period": 1 }).to_string()), None);
        assert_eq!(
            path_books(&json!({ "books": { "deposits": ["nothex"], "payouts": [] } }).to_string()),
            None
        );
        let a = p(&["--ufvk", "uviewtest1qqqq", "--manager-pk", &"ab".repeat(32)])
            .unwrap()
            .unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let mut view = FundView {
            cash_zat: 0,
            receivables: vec![],
            root: None,
            ignored_roots: 0,
        };
        view.root = Some((
            jitsuin_core::LiabilityRoot::sign(&key, 1, [1; 32], 50_000),
            "t".into(),
        ));
        let b = books(view, 300_000_000);
        let j = render_json(&a, &b, &None, None);
        assert!(j["verdict"].is_null());
        assert!(j["no_verdict"]
            .as_str()
            .unwrap()
            .starts_with("no fund books"));
        assert!(render_text(&a, &b, &None, None).contains("Verdict  NONE"));
    }
}
