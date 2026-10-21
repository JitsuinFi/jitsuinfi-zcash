//! Command line parsing, hand-written to keep the dependency tree small (U-HNK-09.1).

use std::path::PathBuf;

use jitsuin_board::lwd;
use jitsuin_core::index::K;

pub const USAGE: &str = "\
jitsuin: JitsuinFi registry board verifier (no spending key, no ZEC needed)

USAGE:
    jitsuin verify (--ufvk <UFVK> | --board <FILE>) [CHECKS] [OPTIONS]
    jitsuin index  (--ufvk <UFVK> | --board <FILE>) [--k <K>] [OPTIONS]
    jitsuin fund   --ufvk <UFVK> --manager-pk <HEX> [OPTIONS]   (see `jitsuin fund --help`)

    verify   List the board's entries and check proofs and bundles against it.
    index    Public rate index: discount by tenor class, from the board (HNK-08).
    fund     A fund member's solvency check with its own watch-only wallet (HNK-15).

BOARD SOURCE (exactly one):
    --ufvk <UFVK>           Board's unified full viewing key (uview1... or uviewtest1...).
                            Scans the chain with a watch-only zcash-devtool wallet.
    --board <FILE>          Board snapshot, JSON [{txid, height, tx_index, output_index, memo}]
                            (memo = full 512-byte memo, base64url). Offline.

CHECKS (verify, repeatable):
    --proof <FILE>          Double-signature proof (JTSP), binary or base64url text.
    --exhibit <FILE>        Exhibit A (JTSX): the double signature without the invoice.
    --bundle <FILE>         Verification bundle (JTSB), binary or base64url text.

INDEX:
    --k <K>                 Smallest number of invoices a class needs to be shown
                            [default and minimum: 5]

LIVE SCAN OPTIONS (with --ufvk):
    --birthday <HEIGHT>     First block of the board. Required when the wallet is created.
    --wallet-dir <DIR>      Watch-only wallet [default: wallet-board-<network>]
    --devtool <PATH>        zcash-devtool binary [default: $JITSUIN_DEVTOOL or zcash-devtool]
    --lightwalletd <URL>    Server for transaction order [default: zec.rocks for the network]
    --save-board <FILE>     Also write the scanned board as a snapshot.

OUTPUT:
    --json                  Machine-readable report.

EXIT STATUS:
    0 every check holds, 1 a check failed, 2 usage, input or network error.
";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Main,
    Test,
}

impl Network {
    /// Network of a unified full viewing key, from its human-readable part.
    pub fn of_ufvk(ufvk: &str) -> Result<Self, String> {
        if ufvk.starts_with("uviewtest1") {
            Ok(Network::Test)
        } else if ufvk.starts_with("uview1") {
            Ok(Network::Main)
        } else {
            Err("--ufvk must be a unified full viewing key (uview1... or uviewtest1...)".into())
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Network::Main => "mainnet",
            Network::Test => "testnet",
        }
    }

    pub fn lightwalletd(self) -> &'static str {
        match self {
            Network::Main => lwd::MAINNET,
            Network::Test => lwd::TESTNET,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveArgs {
    pub ufvk: String,
    pub network: Network,
    pub birthday: Option<u32>,
    pub wallet_dir: PathBuf,
    pub devtool: PathBuf,
    pub lightwalletd: String,
    pub save_board: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Live(LiveArgs),
    Snapshot(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyArgs {
    pub source: Source,
    pub proofs: Vec<PathBuf>,
    pub exhibits: Vec<PathBuf>,
    pub bundles: Vec<PathBuf>,
    pub json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexArgs {
    pub source: Source,
    pub k: usize,
    pub json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Verify(Box<VerifyArgs>),
    Index(Box<IndexArgs>),
    Help,
    Version,
}

/// Parses the arguments after the program name. `devtool_env` is `$JITSUIN_DEVTOOL`.
pub fn parse(args: &[String], devtool_env: Option<&str>) -> Result<Command, String> {
    let mut it = args.iter();
    let command = match it.next().map(String::as_str) {
        None | Some("help" | "-h" | "--help") => return Ok(Command::Help),
        Some("-V" | "--version") => return Ok(Command::Version),
        Some(c @ ("verify" | "index")) => c,
        Some(other) => return Err(format!("unknown command `{other}` (try `jitsuin --help`)")),
    };

    let mut ufvk = None;
    let mut board = None;
    let mut birthday = None;
    let mut wallet_dir = None;
    let mut devtool = None;
    let mut lightwalletd = None;
    let mut save_board = None;
    let mut proofs = Vec::new();
    let mut exhibits = Vec::new();
    let mut bundles = Vec::new();
    let mut k = None;
    let mut json = false;

    while let Some(arg) = it.next() {
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n, Some(v.to_string())),
            _ => (arg.as_str(), None),
        };
        if matches!(name, "-h" | "--help") {
            return Ok(Command::Help);
        }
        if name == "--json" {
            if inline.is_some() {
                return Err("--json takes no value".into());
            }
            json = true;
            continue;
        }
        let mut value = || -> Result<String, String> {
            match inline.clone().or_else(|| it.next().cloned()) {
                Some(v) if !v.is_empty() => Ok(v),
                _ => Err(format!("{name} needs a value")),
            }
        };
        match name {
            "--ufvk" => set(&mut ufvk, name, value()?)?,
            "--board" => set(&mut board, name, PathBuf::from(value()?))?,
            "--birthday" => {
                let v = value()?;
                let h = v
                    .parse::<u32>()
                    .map_err(|_| format!("--birthday must be a block height, got `{v}`"))?;
                set(&mut birthday, name, h)?
            }
            "--wallet-dir" => set(&mut wallet_dir, name, PathBuf::from(value()?))?,
            "--devtool" => set(&mut devtool, name, PathBuf::from(value()?))?,
            "--lightwalletd" => set(&mut lightwalletd, name, value()?)?,
            "--save-board" => set(&mut save_board, name, PathBuf::from(value()?))?,
            "--proof" | "--exhibit" | "--bundle" if command != "verify" => {
                return Err(format!("{name} only applies to `jitsuin verify`"))
            }
            "--proof" => proofs.push(PathBuf::from(value()?)),
            "--exhibit" => exhibits.push(PathBuf::from(value()?)),
            "--bundle" => bundles.push(PathBuf::from(value()?)),
            "--k" if command != "index" => return Err("--k only applies to `jitsuin index`".into()),
            "--k" => {
                let v = value()?;
                let n = v.parse::<usize>().ok().filter(|n| *n >= K).ok_or_else(|| {
                    format!("--k must be a whole number of at least {K}, got `{v}`")
                })?;
                set(&mut k, name, n)?
            }
            _ => return Err(format!("unknown option `{arg}` (try `jitsuin --help`)")),
        }
    }

    let live_only = [
        ("--birthday", birthday.is_some()),
        ("--wallet-dir", wallet_dir.is_some()),
        ("--devtool", devtool.is_some()),
        ("--lightwalletd", lightwalletd.is_some()),
        ("--save-board", save_board.is_some()),
    ];
    let source = match (ufvk, board) {
        (Some(_), Some(_)) => return Err("use either --ufvk or --board, not both".into()),
        (None, None) => return Err("give the board: --ufvk <UFVK> or --board <FILE>".into()),
        (None, Some(path)) => {
            if let Some((opt, _)) = live_only.iter().find(|(_, given)| *given) {
                return Err(format!("{opt} only applies to a live scan (--ufvk)"));
            }
            Source::Snapshot(path)
        }
        (Some(ufvk), None) => {
            let network = Network::of_ufvk(&ufvk)?;
            Source::Live(LiveArgs {
                wallet_dir: wallet_dir
                    .unwrap_or_else(|| PathBuf::from(format!("wallet-board-{}", network.name()))),
                devtool: devtool.unwrap_or_else(|| {
                    PathBuf::from(
                        devtool_env
                            .filter(|v| !v.is_empty())
                            .unwrap_or("zcash-devtool"),
                    )
                }),
                lightwalletd: lightwalletd.unwrap_or_else(|| network.lightwalletd().to_string()),
                ufvk,
                network,
                birthday,
                save_board,
            })
        }
    };
    Ok(match command {
        "index" => Command::Index(Box::new(IndexArgs {
            source,
            k: k.unwrap_or(K),
            json,
        })),
        _ => Command::Verify(Box::new(VerifyArgs {
            source,
            proofs,
            exhibits,
            bundles,
            json,
        })),
    })
}

fn set<T>(slot: &mut Option<T>, name: &str, value: T) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("{name} given twice"));
    }
    *slot = Some(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_UFVK: &str = "uviewtest1qqqq";

    fn p(args: &[&str]) -> Result<Command, String> {
        let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        parse(&owned, None)
    }

    fn verify(args: &[&str]) -> VerifyArgs {
        match p(args) {
            Ok(Command::Verify(v)) => *v,
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn help_and_version() {
        assert_eq!(p(&[]), Ok(Command::Help));
        assert_eq!(p(&["--help"]), Ok(Command::Help));
        assert_eq!(p(&["verify", "--board", "b.json", "-h"]), Ok(Command::Help));
        assert_eq!(p(&["--version"]), Ok(Command::Version));
        assert!(p(&["scan"]).unwrap_err().contains("unknown command"));
    }

    #[test]
    fn snapshot_with_checks() {
        let v = verify(&[
            "verify",
            "--board",
            "board.json",
            "--proof",
            "a.txt",
            "--proof=b.txt",
            "--bundle",
            "c.txt",
            "--json",
        ]);
        assert_eq!(v.source, Source::Snapshot("board.json".into()));
        assert_eq!(
            v.proofs,
            vec![PathBuf::from("a.txt"), PathBuf::from("b.txt")]
        );
        assert_eq!(v.bundles, vec![PathBuf::from("c.txt")]);
        let x = verify(&["verify", "--board", "b", "--exhibit", "x.txt"]);
        assert_eq!(x.exhibits, vec![PathBuf::from("x.txt")]);
        assert!(v.json);
    }

    #[test]
    fn live_defaults_follow_the_network() {
        let v = verify(&["verify", "--ufvk", TEST_UFVK, "--birthday", "4508000"]);
        let Source::Live(l) = v.source else { panic!() };
        assert_eq!(l.network, Network::Test);
        assert_eq!(l.birthday, Some(4_508_000));
        assert_eq!(l.wallet_dir, PathBuf::from("wallet-board-testnet"));
        assert_eq!(l.devtool, PathBuf::from("zcash-devtool"));
        assert_eq!(l.lightwalletd, lwd::TESTNET);

        let v = verify(&["verify", "--ufvk", "uview1abc"]);
        let Source::Live(l) = v.source else { panic!() };
        assert_eq!(
            (l.network, l.lightwalletd.as_str()),
            (Network::Main, lwd::MAINNET)
        );
        assert_eq!(l.birthday, None);
    }

    #[test]
    fn live_overrides_and_env() {
        let args: Vec<String> = [
            "verify",
            "--ufvk",
            TEST_UFVK,
            "--wallet-dir",
            "/data/w",
            "--lightwalletd",
            "https://lwd.example:443",
            "--save-board",
            "out.json",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let Ok(Command::Verify(v)) = parse(&args, Some("/opt/zcash-devtool")) else {
            panic!()
        };
        let Source::Live(l) = v.source else { panic!() };
        assert_eq!(l.wallet_dir, PathBuf::from("/data/w"));
        assert_eq!(l.devtool, PathBuf::from("/opt/zcash-devtool"));
        assert_eq!(l.lightwalletd, "https://lwd.example:443");
        assert_eq!(l.save_board, Some(PathBuf::from("out.json")));
        // --devtool wins over the environment
        let mut args = args.clone();
        args.extend(["--devtool".into(), "./dt".into()]);
        let Ok(Command::Verify(v)) = parse(&args, Some("/opt/zcash-devtool")) else {
            panic!()
        };
        let Source::Live(l) = v.source else { panic!() };
        assert_eq!(l.devtool, PathBuf::from("./dt"));
    }

    #[test]
    fn index_takes_the_same_board_options_and_k() {
        let Ok(Command::Index(i)) = p(&["index", "--board", "b.json", "--json"]) else {
            panic!()
        };
        assert_eq!(
            (i.source, i.k, i.json),
            (Source::Snapshot("b.json".into()), K, true)
        );
        let Ok(Command::Index(i)) = p(&["index", "--ufvk", TEST_UFVK, "--k=8"]) else {
            panic!()
        };
        assert_eq!(i.k, 8);
        assert!(matches!(i.source, Source::Live(_)));
        let err = |a: &[&str]| p(a).unwrap_err();
        assert!(err(&["index", "--board", "b", "--k", "4"]).contains("at least 5"));
        assert!(err(&["index", "--board", "b", "--k", "x"]).contains("at least 5"));
        assert!(err(&["index", "--board", "b", "--proof", "p"])
            .contains("only applies to `jitsuin verify`"));
        assert!(err(&["verify", "--board", "b", "--k", "5"])
            .contains("only applies to `jitsuin index`"));
        assert!(err(&["index"]).contains("give the board"));
    }

    #[test]
    fn invalid_combinations_are_rejected() {
        let err = |a: &[&str]| p(a).unwrap_err();
        assert!(err(&["verify"]).contains("give the board"));
        assert!(err(&["verify", "--board", "b", "--ufvk", TEST_UFVK]).contains("not both"));
        assert!(err(&["verify", "--board", "b", "--birthday", "1"]).contains("live scan"));
        assert!(err(&["verify", "--board", "b", "--save-board", "x"]).contains("live scan"));
        assert!(err(&["verify", "--ufvk", "zxviewtestsapling1q"]).contains("unified full"));
        assert!(err(&["verify", "--ufvk", TEST_UFVK, "--birthday", "x"]).contains("block height"));
        assert!(err(&["verify", "--board"]).contains("needs a value"));
        assert!(err(&["verify", "--board="]).contains("needs a value"));
        assert!(err(&["verify", "--board", "a", "--board", "b"]).contains("twice"));
        assert!(err(&["verify", "--board", "a", "--json=yes"]).contains("no value"));
        assert!(err(&["verify", "--board", "a", "--frobnicate"]).contains("unknown option"));
    }
}
