use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let devtool = std::env::var("JITSUIN_DEVTOOL").ok();
    let (code, out, err) = jitsuin_cli::main_with(&args, devtool.as_deref());
    // Ignore a closed pipe (for example `jitsuin verify ... | head`).
    let _ = std::io::stdout().write_all(out.as_bytes());
    let _ = std::io::stderr().write_all(err.as_bytes());
    std::process::exit(code);
}
