//! `jitsuin` command line (HNK-09). `jitsuin verify` reads the registry board, either live with
//! the board's published viewing key (a watch-only `zcash-devtool` wallet, no spending key, no
//! ZEC) or from a snapshot file, and checks double-signature proofs and verification bundles on
//! it.

pub mod args;
pub mod board;
pub mod verify;

use args::{Command, VerifyArgs, USAGE};

/// Exit status: every check holds.
pub const EXIT_OK: i32 = 0;
/// Exit status: a proof or bundle does not hold on the board.
pub const EXIT_FAILED: i32 = 1;
/// Exit status: usage, input or network error.
pub const EXIT_ERROR: i32 = 2;

/// Runs one command line and returns (exit status, stdout, stderr).
pub fn main_with(args: &[String], devtool_env: Option<&str>) -> (i32, String, String) {
    match args::parse(args, devtool_env) {
        Err(e) => (EXIT_ERROR, String::new(), format!("error: {e}\n")),
        Ok(Command::Help) => (EXIT_OK, USAGE.to_string(), String::new()),
        Ok(Command::Version) => (
            EXIT_OK,
            format!("jitsuin {}\n", env!("CARGO_PKG_VERSION")),
            String::new(),
        ),
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

fn verify(v: &VerifyArgs) -> Result<(bool, String), String> {
    let board = board::load(&v.source)?;
    let report = verify::run(board, &v.proofs, &v.bundles)?;
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
