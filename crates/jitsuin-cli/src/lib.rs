//! `jitsuin` command line (HNK-09). `jitsuin verify` reads the registry board, either live with
//! the board's published viewing key (a watch-only `zcash-devtool` wallet, no spending key, no
//! ZEC) or from a snapshot file, and checks double-signature proofs and verification bundles on
//! it. `jitsuin index` prints the public rate index of the same board (HNK-08). `jitsuin fund`
//! lets a fund member check the fund's solvency with its own watch-only wallet (HNK-27.T10).

pub mod args;
pub mod board;
pub mod fund;
pub mod index;
pub mod verify;

use args::{Command, IndexArgs, VerifyArgs, USAGE};

/// Exit status: every check holds.
pub const EXIT_OK: i32 = 0;
/// Exit status: a proof or bundle does not hold on the board.
pub const EXIT_FAILED: i32 = 1;
/// Exit status: usage, input or network error.
pub const EXIT_ERROR: i32 = 2;

/// Runs one command line and returns (exit status, stdout, stderr).
pub fn main_with(args: &[String], devtool_env: Option<&str>) -> (i32, String, String) {
    if args.first().map(String::as_str) == Some("fund") {
        return fund_main(&args[1..], devtool_env);
    }
    match args::parse(args, devtool_env) {
        Err(e) => (EXIT_ERROR, String::new(), format!("error: {e}\n")),
        Ok(Command::Help) => (EXIT_OK, USAGE.to_string(), String::new()),
        Ok(Command::Version) => (
            EXIT_OK,
            format!("jitsuin {}\n", env!("CARGO_PKG_VERSION")),
            String::new(),
        ),
        Ok(Command::Index(i)) => match index(&i) {
            Err(e) => (
                EXIT_ERROR,
                String::new(),
                format!(
                    "error: {e}
"
                ),
            ),
            Ok(out) => (EXIT_OK, out, String::new()),
        },
        Ok(Command::Verify(v)) => match verify(&v) {
            Err(e) => (EXIT_ERROR, String::new(), format!("error: {e}\n")),
            Ok((passed, out)) => (
                if passed { EXIT_OK } else { EXIT_FAILED },
                out,
                String::new(),
            ),
        },
    }
}

fn fund_main(args: &[String], devtool_env: Option<&str>) -> (i32, String, String) {
    let a = match fund::parse(args, devtool_env) {
        Err(e) => return (EXIT_ERROR, String::new(), format!("error: {e}\n")),
        Ok(None) => return (EXIT_OK, fund::USAGE.to_string(), String::new()),
        Ok(Some(a)) => a,
    };
    match fund::run(&a) {
        Err(e) => (EXIT_ERROR, String::new(), format!("error: {e}\n")),
        Ok((view, verdict)) => {
            let out = if a.json {
                let mut s = serde_json::to_string_pretty(&fund::render_json(&a, &view, &verdict))
                    .expect("report serializes");
                s.push('\n');
                s
            } else {
                fund::render_text(&a, &view, &verdict)
            };
            let code = if fund::passed(&verdict) {
                EXIT_OK
            } else {
                EXIT_FAILED
            };
            (code, out, String::new())
        }
    }
}

fn verify(v: &VerifyArgs) -> Result<(bool, String), String> {
    let board = board::load(&v.source)?;
    let report = verify::run(board, &v.proofs, &v.exhibits, &v.bundles)?;
    let out = if v.json {
        let mut s =
            serde_json::to_string_pretty(&verify::render_json(&report)).expect("report serializes");
        s.push('\n');
        s
    } else {
        verify::render_text(&report)
    };
    Ok((report.passed(), out))
}

fn index(a: &IndexArgs) -> Result<String, String> {
    let board = board::load(&a.source)?;
    let i = index::run(&board, a.k);
    Ok(if a.json {
        let mut s = serde_json::to_string_pretty(&index::render_json(&board, &i))
            .expect("index serializes");
        s.push('\n');
        s
    } else {
        index::render_text(&board, &i)
    })
}
