//! JitsuinFi wallet backend (HNK-03).
//!
//! Wraps the `zcash-devtool` CLI (spike SPK-03/SPK-19: works on testnet NU7 and mainnet with the
//! pinned pre-release crates). Spending keys never leave the devtool wallet directory; this crate
//! only passes paths and reads command output.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

pub const ZATOSHI_PER_COIN: u64 = 100_000_000;
pub const MEMO_LEN: usize = 512;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// devtool exited with an error; carries the last error line only (never key material).
    Devtool(String),
    Parse(String),
    InvalidPayment(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Devtool(m) => write!(f, "zcash-devtool: {m}"),
            Error::Parse(m) => write!(f, "parse: {m}"),
            Error::InvalidPayment(m) => write!(f, "invalid payment: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Memo content as seen by the wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Memo {
    Empty,
    Text(String),
    /// Full 512-byte memo, including the leading ZIP-302 `0xFF` marker.
    Arbitrary(Vec<u8>),
    Other(String),
}

/// One payment inside a ZIP-321 request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payment {
    pub address: String,
    pub amount_zat: u64,
    pub memo: Option<PaymentMemo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentMemo {
    Text(String),
    /// Raw memo bytes starting with `0xFF` (for example `BoardEntry::to_memo_bytes()[..ENTRY_LEN]`).
    Arbitrary(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutput {
    pub index: u32,
    pub pool: String,
    pub value_zat: u64,
    pub is_change: bool,
    pub received: bool,
    pub memo: Memo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletTx {
    pub txid: String,
    pub mined_height: Option<u32>,
    pub fee_zat: Option<u64>,
    pub outputs: Vec<TxOutput>,
}

impl WalletTx {
    /// True when any output of this transaction is in the transparent pool (AC-HNK-03.4: flag it).
    pub fn touches_transparent(&self) -> bool {
        self.outputs
            .iter()
            .any(|o| o.pool.eq_ignore_ascii_case("transparent"))
    }
}

/// Handle to one devtool wallet directory.
#[derive(Debug, Clone)]
pub struct Devtool {
    bin: PathBuf,
    wallet_dir: PathBuf,
    identity: Option<PathBuf>,
}

impl Devtool {
    pub fn new(bin: impl Into<PathBuf>, wallet_dir: impl Into<PathBuf>) -> Self {
        Devtool {
            bin: bin.into(),
            wallet_dir: wallet_dir.into(),
            identity: None,
        }
    }

    /// age identity file that decrypts the wallet mnemonic; required for spending.
    pub fn with_identity(mut self, identity: impl Into<PathBuf>) -> Self {
        self.identity = Some(identity.into());
        self
    }

    pub fn wallet_dir(&self) -> &Path {
        &self.wallet_dir
    }

    fn run(&self, args: &[&str]) -> Result<String, Error> {
        let out = Command::new(&self.bin)
            .arg("wallet")
            .arg("-w")
            .arg(&self.wallet_dir)
            .args(args)
            .output()?;
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let last = stderr
                .lines()
                .chain(stdout.lines())
                .rfind(|l| l.contains("Error"))
                .unwrap_or("non-zero exit")
                .trim()
                .to_string();
            return Err(Error::Devtool(last));
        }
        Ok(stdout)
    }

    pub fn sync(&self) -> Result<(), Error> {
        self.run(&["sync"]).map(|_| ())
    }

    /// Fetches full transactions so memos become readable (compact blocks carry no memos, SPK-05).
    pub fn enhance(&self) -> Result<(), Error> {
        self.run(&["enhance"]).map(|_| ())
    }

    pub fn default_address(&self) -> Result<String, Error> {
        let out = self.run(&["list-addresses"])?;
        out.lines()
            .find_map(|l| {
                l.trim()
                    .strip_prefix("Default Address:")
                    .map(|a| a.trim().to_string())
            })
            .ok_or_else(|| Error::Parse("no default address".into()))
    }

    pub fn list_tx(&self) -> Result<Vec<WalletTx>, Error> {
        parse_list_tx(&self.run(&["list-tx"])?)
    }

    /// Builds one shielded transaction for all payments and broadcasts it. Returns the txid.
    /// Uses `--target-note-count 1` so change is not split (fewer outputs, lower fee; SPK-03).
    pub fn pay(&self, payments: &[Payment]) -> Result<String, Error> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| Error::InvalidPayment("identity file required for spending".into()))?;
        let uri = zip321_uri(payments)?;
        let identity = identity.to_string_lossy().into_owned();
        let out = self.run(&[
            "pay",
            "--identity",
            &identity,
            "--payment-uri",
            &uri,
            "--disable-confirmation",
            "--target-note-count",
            "1",
        ])?;
        out.lines()
            .rev()
            .map(str::trim)
            .find(|l| is_txid(l))
            .map(str::to_string)
            .ok_or_else(|| Error::Parse("txid not found in pay output".into()))
    }
}

/// ZIP-321 payment request. Memos are base64url (no padding) of the raw memo bytes.
pub fn zip321_uri(payments: &[Payment]) -> Result<String, Error> {
    if payments.is_empty() {
        return Err(Error::InvalidPayment("no payments".into()));
    }
    let mut params = Vec::new();
    for (i, p) in payments.iter().enumerate() {
        if p.address.is_empty() || !p.address.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(Error::InvalidPayment(format!("bad address at index {i}")));
        }
        if p.amount_zat == 0 {
            return Err(Error::InvalidPayment(format!("zero amount at index {i}")));
        }
        let suffix = if i == 0 {
            String::new()
        } else {
            format!(".{i}")
        };
        params.push(format!("address{suffix}={}", p.address));
        params.push(format!("amount{suffix}={}", format_amount(p.amount_zat)));
        if let Some(memo) = &p.memo {
            let bytes = match memo {
                PaymentMemo::Text(t) => t.as_bytes().to_vec(),
                PaymentMemo::Arbitrary(b) => b.clone(),
            };
            if bytes.len() > MEMO_LEN {
                return Err(Error::InvalidPayment(format!(
                    "memo longer than 512 bytes at index {i}"
                )));
            }
            params.push(format!("memo{suffix}={}", URL_SAFE_NO_PAD.encode(bytes)));
        }
    }
    Ok(format!("zcash:?{}", params.join("&")))
}

/// Zatoshi to a ZIP-321 decimal amount without trailing zeros.
pub fn format_amount(zat: u64) -> String {
    let whole = zat / ZATOSHI_PER_COIN;
    let frac = zat % ZATOSHI_PER_COIN;
    if frac == 0 {
        return whole.to_string();
    }
    let frac = format!("{frac:08}");
    format!("{whole}.{}", frac.trim_end_matches('0'))
}

fn is_txid(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn parse_value_zat(s: &str) -> Result<u64, Error> {
    // e.g. "0.24991250 TAZ (Change)" or "1.00000000 ZEC"
    let num = s
        .split_whitespace()
        .next()
        .ok_or_else(|| Error::Parse(format!("value: {s}")))?;
    let (whole, frac) = num.split_once('.').unwrap_or((num, "0"));
    if frac.len() > 8 {
        return Err(Error::Parse(format!("value precision: {s}")));
    }
    let whole: u64 = whole
        .parse()
        .map_err(|_| Error::Parse(format!("value: {s}")))?;
    let frac: u64 = format!("{frac:0<8}")
        .parse()
        .map_err(|_| Error::Parse(format!("value: {s}")))?;
    Ok(whole * ZATOSHI_PER_COIN + frac)
}

fn parse_memo(s: &str) -> Memo {
    if s == "Memo::Empty" {
        return Memo::Empty;
    }
    if let Some(hex) = s
        .strip_prefix("Memo::Arbitrary(")
        .and_then(|r| r.strip_suffix(')'))
    {
        let mut bytes = vec![0xFF];
        for part in hex.split(':') {
            match u8::from_str_radix(part, 16) {
                Ok(b) => bytes.push(b),
                Err(_) => return Memo::Other(s.to_string()),
            }
        }
        return Memo::Arbitrary(bytes);
    }
    if let Some(t) = s
        .strip_prefix("Memo::Text(\"")
        .and_then(|r| r.strip_suffix("\")"))
    {
        return Memo::Text(t.to_string());
    }
    Memo::Other(s.to_string())
}

/// Parses `zcash-devtool wallet list-tx` output.
pub fn parse_list_tx(out: &str) -> Result<Vec<WalletTx>, Error> {
    let mut txs: Vec<WalletTx> = Vec::new();
    for raw in out.lines() {
        let line = raw.trim();
        if is_txid(line) {
            txs.push(WalletTx {
                txid: line.to_string(),
                mined_height: None,
                fee_zat: None,
                outputs: Vec::new(),
            });
            continue;
        }
        let Some(tx) = txs.last_mut() else { continue };
        if let Some(rest) = line.strip_prefix("Mined:") {
            tx.mined_height = rest.split_whitespace().next().and_then(|h| h.parse().ok());
        } else if let Some(rest) = line.strip_prefix("Fee paid:") {
            let rest = rest.trim();
            tx.fee_zat = if rest == "Unknown" {
                None
            } else {
                Some(parse_value_zat(rest)?)
            };
        } else if let Some(rest) = line.strip_prefix("Output ") {
            // "Output 3 (Ironwood)"
            let (idx, pool) = rest
                .split_once(' ')
                .ok_or_else(|| Error::Parse(format!("output: {line}")))?;
            tx.outputs.push(TxOutput {
                index: idx
                    .parse()
                    .map_err(|_| Error::Parse(format!("output: {line}")))?,
                pool: pool.trim_matches(|c| c == '(' || c == ')').to_string(),
                value_zat: 0,
                is_change: false,
                received: false,
                memo: Memo::Empty,
            });
        } else if let Some(o) = tx.outputs.last_mut() {
            if let Some(rest) = line.strip_prefix("Value:") {
                o.value_zat = parse_value_zat(rest.trim())?;
                o.is_change = rest.contains("(Change)");
            } else if line.starts_with("Received by account:") {
                o.received = true;
            } else if let Some(rest) = line.strip_prefix("Memo:") {
                o.memo = parse_memo(rest.trim());
            }
        }
    }
    Ok(txs)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "Transactions:
64795b2ba61d7998940277b246180a4bf03206d78b81086bcec7c0e28be54932
     Mined: 4508848 (2026-10-16 16:28:36.0 +00:00:00)
    Amount:   1.00000000 TAZ
  Fee paid: Unknown
  Output 0 (Ironwood)
    Value:   1.00000000 TAZ
    Received by account: 2113 (TES-wallet-a)
d759bbf2605a9cc9a220dbc0383645133c01bb722a38fc22a0f13b36355d2ac0
     Mined: 4508918 (2026-10-16 16:56:12.0 +00:00:00)
  Fee paid:   0.00020000 TAZ
  Output 1 (Ironwood)
    Value:   0.00020000 TAZ
    Memo: Memo::Text(\"TES-SPK07 memo teks untuk wallet-b\")
  Output 2 (Ironwood)
    Value:   0.00010000 TAZ
    Memo: Memo::Arbitrary(4a:54:53:31:01)
  Output 3 (Ironwood)
    Value:   0.24931250 TAZ (Change)
    Memo: Memo::Empty
";

    #[test]
    fn parses_list_tx() {
        let txs = parse_list_tx(SAMPLE).unwrap();
        assert_eq!(txs.len(), 2);
        assert_eq!(txs[0].mined_height, Some(4_508_848));
        assert_eq!(txs[0].fee_zat, None);
        assert!(txs[0].outputs[0].received);
        assert_eq!(txs[0].outputs[0].value_zat, 100_000_000);
        assert_eq!(txs[1].fee_zat, Some(20_000));
        assert_eq!(
            txs[1].outputs[0].memo,
            Memo::Text("TES-SPK07 memo teks untuk wallet-b".into())
        );
        assert_eq!(
            txs[1].outputs[1].memo,
            Memo::Arbitrary(vec![0xFF, 0x4a, 0x54, 0x53, 0x31, 0x01])
        );
        assert!(txs[1].outputs[2].is_change);
        assert_eq!(txs[1].outputs[2].value_zat, 24_931_250);
        assert!(!txs[1].touches_transparent());
    }

    #[test]
    fn builds_zip321_uri() {
        let uri = zip321_uri(&[
            Payment {
                address: "utest1abc".into(),
                amount_zat: 10_000,
                memo: Some(PaymentMemo::Arbitrary(vec![0xFF, 1, 2])),
            },
            Payment {
                address: "utest1def".into(),
                amount_zat: 150_000_000,
                memo: Some(PaymentMemo::Text("hi".into())),
            },
        ])
        .unwrap();
        assert_eq!(uri, "zcash:?address=utest1abc&amount=0.0001&memo=_wEC&address.1=utest1def&amount.1=1.5&memo.1=aGk");
    }

    #[test]
    fn rejects_bad_payments() {
        assert!(zip321_uri(&[]).is_err());
        assert!(zip321_uri(&[Payment {
            address: "a&b".into(),
            amount_zat: 1,
            memo: None
        }])
        .is_err());
        assert!(zip321_uri(&[Payment {
            address: "utest1".into(),
            amount_zat: 0,
            memo: None
        }])
        .is_err());
        let long = PaymentMemo::Arbitrary(vec![0u8; 513]);
        assert!(zip321_uri(&[Payment {
            address: "utest1".into(),
            amount_zat: 1,
            memo: Some(long)
        }])
        .is_err());
    }

    #[test]
    fn formats_amounts() {
        assert_eq!(format_amount(100_000_000), "1");
        assert_eq!(format_amount(10_000), "0.0001");
        assert_eq!(format_amount(1), "0.00000001");
    }
}
