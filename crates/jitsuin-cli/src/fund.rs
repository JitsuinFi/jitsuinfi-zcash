//! `jitsuin fund` (HNK-27.T10): a JitsuinFi Vault member checks the fund's solvency on its own
//! machine. The operational account's full viewing key goes into a local watch-only
//! `zcash-devtool` wallet and is never sent anywhere (P-10); `jitsuin_flow::fund` builds the view
//! (cash, receivables from the manager-signed advance receipts and notes, the latest liability
//! root) and compares assets with liabilities.
//!
//! Limits, printed with every report: the receivables are what the manager declared in its notes
//! (face value and due date are not tied to the advance or to a real invoice), so a breach only
//! shows once a receivable is overdue; inclusion of the member's own deposit in the root needs the
//! Merkle path (HNK-15.T1).

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use jitsuin_flow::fund::{
    member_view, solvency, FundView, ReceivableStatus, Solvency, SolvencyPolicy,
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
    --haircut <PERCENT>     Share of an overdue receivable written off [default 100]
    --today <DAYS>          Date as days since 1970-01-01 [default: today]
    --wallet-dir <DIR>      Watch-only wallet [default: wallet-fund-<network>]
    --devtool <PATH>        zcash-devtool binary [default: $JITSUIN_DEVTOOL or zcash-devtool]
    --json                  Machine-readable report.

EXIT STATUS:
    0 solvent, 1 not solvent or no liability root yet, 2 usage, input or network error.
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
    let (mut wallet_dir, mut devtool, mut json) = (None, None, false);
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

/// Syncs the local watch-only wallet (created on first run) and computes the verdict.
pub fn run(a: &FundArgs) -> Result<(FundView, Option<Solvency>), String> {
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
    let view =
        member_view(&watch, &a.manager_pk, a.today, a.grace_days).map_err(|e| e.to_string())?;
    let verdict = solvency(
        &view,
        &SolvencyPolicy {
            overdue_haircut_pct: a.haircut_pct,
        },
    );
    Ok((view, verdict))
}

/// 0 solvent, 1 not solvent or no root yet.
pub fn passed(verdict: &Option<Solvency>) -> bool {
    verdict.is_some_and(|s| s.solvent)
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
    "Receivables are the manager's own notes (face value and due date); a breach shows \
only once a receivable is overdue. Inclusion of your deposit in the root needs your Merkle path.";

pub fn render_text(a: &FundArgs, view: &FundView, verdict: &Option<Solvency>) -> String {
    let mut out = format!(
        "Fund     {} watch-only wallet {}, day {}, grace {} days, haircut {}%\n",
        a.network.name(),
        a.wallet_dir.display(),
        a.today,
        a.grace_days,
        a.haircut_pct
    );
    out += &format!("Cash     {} zat\n", view.cash_zat);
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
    out += &match verdict {
        None => "Verdict  NO ROOT: the manager has not posted a liability root yet\n".to_string(),
        Some(s) => format!(
            "Root     period {}, liabilities {} zat\nAssets   {} zat (cash {} + open {} + overdue after haircut {})\nVerdict  {}\n",
            s.period,
            s.liabilities_zat,
            s.assets_zat,
            s.cash_zat,
            s.open_zat,
            s.overdue_zat,
            if s.solvent { "SOLVENT" } else { "NOT SOLVENT" }
        ),
    };
    out += &format!("Limits   {LIMITS}\n");
    out
}

pub fn render_json(a: &FundArgs, view: &FundView, verdict: &Option<Solvency>) -> Value {
    json!({
        "network": a.network.name(),
        "today": a.today,
        "grace_days": a.grace_days,
        "haircut_pct": a.haircut_pct,
        "cash_zat": view.cash_zat,
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
        "verdict": verdict.map(|s| json!({
            "period": s.period,
            "liabilities_zat": s.liabilities_zat,
            "assets_zat": s.assets_zat,
            "open_zat": s.open_zat,
            "overdue_zat": s.overdue_zat,
            "solvent": s.solvent,
        })),
        "limits": LIMITS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use jitsuin_flow::fund::Receivable;

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
        let none = solvency(
            &view,
            &SolvencyPolicy {
                overdue_haircut_pct: 100,
            },
        );
        assert!(!passed(&none));
        assert!(render_text(&a, &view, &none).contains("NO ROOT"));
        let s = Some(Solvency {
            cash_zat: 100_000,
            open_zat: 40_000,
            overdue_zat: 0,
            assets_zat: 140_000,
            liabilities_zat: 120_000,
            period: 3,
            solvent: true,
        });
        assert!(passed(&s));
        let text = render_text(&a, &view, &s);
        assert!(text.contains("SOLVENT") && text.contains("Limits"));
        let j = render_json(&a, &view, &s);
        assert_eq!(j["verdict"]["solvent"], true);
        assert_eq!(j["receivables"][0]["status"], "open");
    }
}
