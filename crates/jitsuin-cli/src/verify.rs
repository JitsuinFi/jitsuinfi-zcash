//! `jitsuin verify` (HNK-09.T1): what the board shows an outsider, and whether each given
//! double-signature proof and verification bundle holds on it. All checks reuse `jitsuin-core`
//! and the `jitsuin-board` scanner functions; nothing here re-implements a rule.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jitsuin_board::{
    bundle_on_board, exhibit_on_board, proof_on_board, BoardRecord, Lookup, Position,
};
use jitsuin_core::bundle::BUNDLE_MAGIC;
use jitsuin_core::exhibit::{Exhibit, EXHIBIT_MAGIC};
use jitsuin_core::proof::PROOF_MAGIC;
use jitsuin_core::{Bundle, ChainStatus, DoubleSignProof, EntryAt, EntryKind};
use serde_json::{json, Value};

use crate::board::Board;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    /// Context only; never fails the run.
    Info,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Info => "INFO",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub status: Status,
    pub name: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocKind {
    Proof,
    Exhibit,
    Bundle,
}

/// Checks for one proof or bundle file.
#[derive(Debug, Clone)]
pub struct DocReport {
    pub kind: DocKind,
    pub path: PathBuf,
    pub checks: Vec<Check>,
}

impl DocReport {
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|c| c.status != Status::Fail)
    }

    fn conclusion(&self) -> &'static str {
        match (self.kind, self.passed()) {
            (DocKind::Proof, true) => "DOUBLE FINANCING PROVEN",
            (DocKind::Proof, false) => "PROOF DOES NOT HOLD",
            (DocKind::Exhibit, true) => "DOUBLE SIGNATURE ON THE BOARD (exhibit)",
            (DocKind::Exhibit, false) => "EXHIBIT DOES NOT HOLD",
            (DocKind::Bundle, true) => "DEAL VERIFIED",
            (DocKind::Bundle, false) => "DEAL DOES NOT HOLD",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Report {
    pub board: Board,
    pub docs: Vec<DocReport>,
}

impl Report {
    pub fn passed(&self) -> bool {
        self.docs.iter().all(DocReport::passed)
    }

    fn counted(&self) -> (usize, usize) {
        let checks = self.docs.iter().flat_map(|d| &d.checks);
        let (mut total, mut failed) = (0, 0);
        for c in checks.filter(|c| c.status != Status::Info) {
            total += 1;
            failed += usize::from(c.status == Status::Fail);
        }
        (total, failed)
    }
}

pub fn run(
    board: Board,
    proofs: &[PathBuf],
    exhibits: &[PathBuf],
    bundles: &[PathBuf],
) -> Result<Report, String> {
    let mut docs = Vec::new();
    for path in exhibits {
        let exhibit = Exhibit::from_bytes(&read_doc(path, EXHIBIT_MAGIC)?)
            .map_err(|e| format!("{}: not an exhibit: {e}", path.display()))?;
        docs.push(DocReport {
            kind: DocKind::Exhibit,
            path: path.clone(),
            checks: check_exhibit(&exhibit, &board.collected.records),
        });
    }
    for path in proofs {
        let proof = DoubleSignProof::from_bytes(&read_doc(path, PROOF_MAGIC)?)
            .map_err(|e| format!("{}: not a double-signature proof: {e}", path.display()))?;
        docs.push(DocReport {
            kind: DocKind::Proof,
            path: path.clone(),
            checks: check_proof(&proof, &board.collected.records),
        });
    }
    for path in bundles {
        let bundle = Bundle::from_bytes(&read_doc(path, BUNDLE_MAGIC)?)
            .map_err(|e| format!("{}: not a verification bundle: {e}", path.display()))?;
        docs.push(DocReport {
            kind: DocKind::Bundle,
            path: path.clone(),
            checks: check_bundle(&bundle, &board),
        });
    }
    Ok(Report { board, docs })
}

/// A proof or bundle file: raw bytes starting with `magic`, or base64url text (the form the web
/// app downloads and links carry).
pub fn read_doc(path: &Path, magic: &[u8; 4]) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if bytes.starts_with(magic) {
        return Ok(bytes);
    }
    let text = String::from_utf8_lossy(&bytes);
    URL_SAFE_NO_PAD
        .decode(text.trim().trim_end_matches('='))
        .map_err(|_| format!("{}: neither binary nor base64url", path.display()))
}

pub fn check_proof(proof: &DoubleSignProof, records: &[BoardRecord]) -> Vec<Check> {
    let mut out = Vec::new();
    let report = match proof.verify() {
        Ok(r) => r,
        Err(e) => {
            out.push(fail("signatures", e.to_string()));
            return out;
        }
    };
    out.push(pass(
        "signatures",
        format!(
            "buyer signed invoice {}; supplier signed N {} for 2 different financiers ({} and {})",
            proof.invoice.invoice_id,
            short(&report.nullifier),
            short(&report.first_commitment),
            short(&report.second_commitment),
        ),
    ));
    // One line per claim, from the same rule the web Verify page uses (`proof_on_board`).
    let claims = proof_on_board(proof, records);
    match (&proof.first_at, claims.first) {
        (Some(at), Some(ok)) => out.push(check(
            ok,
            "first entry",
            format!("on the board at {}", where_(at)),
            format!("not on the board at {}", where_(at)),
        )),
        _ => out.push(fail(
            "first entry",
            "the proof gives no board position for the first entry".into(),
        )),
    }
    match (&proof.second_at, claims.second) {
        (Some(at), Some(ok)) => out.push(check(
            ok,
            "second entry",
            format!("on the board at {}", where_(at)),
            format!("not on the board at {}", where_(at)),
        )),
        _ => out.push(info(
            "second entry",
            "offered off-chain to the financier that caught it, never posted".into(),
        )),
    }
    if let Some(ok) = claims.ordered {
        out.push(check(
            ok,
            "order",
            "the first entry came before the second".into(),
            "the \"first\" entry is not before the second".into(),
        ));
    }
    debug_assert_eq!(out.iter().all(|c| c.status != Status::Fail), claims.holds());
    out
}

/// Exhibit A (HNK-30.T5): the same board claims as a proof, without the invoice. It cannot say
/// which invoice it is about; that line is context, not a failure.
pub fn check_exhibit(exhibit: &Exhibit, records: &[BoardRecord]) -> Vec<Check> {
    let mut out = Vec::new();
    let report = match exhibit.verify() {
        Ok(r) => r,
        Err(e) => {
            out.push(fail("signatures", e.to_string()));
            return out;
        }
    };
    out.push(pass(
        "signatures",
        format!(
            "key {} signed N {} for 2 different financiers ({} and {})",
            short(&report.supplier_pk),
            short(&report.nullifier),
            short(&report.first_commitment),
            short(&report.second_commitment),
        ),
    ));
    out.push(info(
        "invoice",
        "not in the exhibit; a holder of the invoice checks that N and the key are its own".into(),
    ));
    let claims = exhibit_on_board(exhibit, records);
    match (&exhibit.first_at, claims.first) {
        (Some(at), Some(ok)) => out.push(check(
            ok,
            "first entry",
            format!("on the board at {}", where_(at)),
            format!("not on the board at {}", where_(at)),
        )),
        _ => out.push(fail(
            "first entry",
            "the exhibit gives no board position for the first entry".into(),
        )),
    }
    match (&exhibit.second_at, claims.second) {
        (Some(at), Some(ok)) => out.push(check(
            ok,
            "second entry",
            format!("on the board at {}", where_(at)),
            format!("not on the board at {}", where_(at)),
        )),
        _ => out.push(info(
            "second entry",
            "offered off-chain to the financier that caught it, never posted".into(),
        )),
    }
    if let Some(ok) = claims.ordered {
        out.push(check(
            ok,
            "order",
            "the first entry came before the second".into(),
            "the \"first\" entry is not before the second".into(),
        ));
    }
    out
}

pub fn check_bundle(bundle: &Bundle, board: &Board) -> Vec<Check> {
    let mut out = Vec::new();
    let report = match bundle.verify() {
        Ok(r) => r,
        Err(e) => {
            out.push(fail("signatures", e.to_string()));
            return out;
        }
    };
    let letter = match report.assignment {
        None => "no assignment letter".to_string(),
        Some(ChainStatus::Sealed) => {
            "assignment letter sealed by supplier, buyer, financier".into()
        }
        Some(ChainStatus::Incomplete { next }) => {
            format!("assignment letter waiting for the {next:?} seal")
        }
    };
    out.push(pass(
        "signatures",
        format!(
            "buyer signed invoice {} (N {}); {letter}",
            bundle.invoice.invoice_id,
            short(&report.nullifier)
        ),
    ));
    if let Some(ChainStatus::Incomplete { next }) = report.assignment {
        out.push(info(
            "letter",
            format!("not fully sealed yet: next is the {next:?}"),
        ));
    }
    let on = match bundle_on_board(bundle, &board.collected.records, &board.collected.settled) {
        Ok(on) => on,
        Err(e) => {
            out.push(fail("board", e.to_string()));
            return out;
        }
    };
    let ignored = match &on.register {
        Lookup::NotFound { ignored_invalid } => {
            out.push(fail(
                "registration",
                "no entry for N signed by the invoice's supplier key on this board".into(),
            ));
            ignored_invalid.len()
        }
        Lookup::Registered {
            winner,
            ignored_invalid,
        } => {
            out.push(pass(
                "registration",
                format!(
                    "registered once: first valid entry at {}",
                    record_at(winner)
                ),
            ));
            ignored_invalid.len()
        }
        Lookup::DoubleFinanced {
            winner,
            conflicting,
            ignored_invalid,
        } => {
            out.push(fail(
                "registration",
                format!(
                    "double financed: first valid entry at {}, then {} more for other financiers \
                     (first at {})",
                    record_at(winner),
                    conflicting.len(),
                    record_at(&conflicting[0]),
                ),
            ));
            ignored_invalid.len()
        }
    };
    if ignored > 0 {
        out.push(info(
            "ignored",
            format!(
                "{ignored} {} for N ignored: the supplier signature does not verify",
                if ignored == 1 { "entry" } else { "entries" }
            ),
        ));
    }
    match (&bundle.settlement, &on.settled) {
        (None, _) => out.push(info(
            "settlement",
            "the bundle has no settlement document (deal still open)".into(),
        )),
        (Some(_), Some(s)) => out.push(pass(
            "settlement",
            format!(
                "settled entry signed by buyer and financier at {}, {}",
                where_pos(&s.txid, s.position),
                if s.entry.on_time() { "on time" } else { "late" }
            ),
        )),
        (Some(_), None) => out.push(fail(
            "settlement",
            "the bundle has a settlement document but no settled entry signed by buyer and \
             financier is on the board"
                .into(),
        )),
    }
    out
}

/// Text report for people.
pub fn render_text(r: &Report) -> String {
    let mut s = String::new();
    let c = &r.board.collected;
    s += &r.board.origin.describe();
    let tagged = c
        .records
        .iter()
        .filter(|r| r.entry.kind == EntryKind::RegisterWithHistory)
        .count();
    s += &format!(
        "Entries  {} register ({} with history tag), {} settled, {} rejected memo(s)\n",
        c.records.len(),
        tagged,
        c.settled.len(),
        c.rejected.len()
    );
    if !c.records.is_empty() || !c.settled.is_empty() {
        s += "\n  height      tx  out  kind      N / tag       commitment    d/t  txid\n";
        let mut rows: Vec<(Position, String)> = c
            .records
            .iter()
            .map(|r| {
                let kind = match r.entry.kind {
                    EntryKind::RegisterWithHistory => "history",
                    _ => "register",
                };
                (
                    r.position,
                    row(
                        r.position,
                        kind,
                        &short(&r.entry.nullifier),
                        &short(&r.entry.financier_commitment),
                        &format!("{}/{}", r.entry.discount_bucket, r.entry.tenor_bucket),
                        &r.txid,
                    ),
                )
            })
            .chain(c.settled.iter().map(|x| {
                (
                    x.position,
                    row(
                        x.position,
                        "settled",
                        &short(&x.entry.tag),
                        "-",
                        "-",
                        &x.txid,
                    ),
                )
            }))
            .collect();
        rows.sort_by_key(|(p, _)| *p);
        for (_, line) in rows {
            s += &line;
        }
    }
    for x in &c.rejected {
        s += &format!("  rejected  {}:{}  {}\n", x.txid, x.output_index, x.reason);
    }
    for d in &r.docs {
        let what = match d.kind {
            DocKind::Proof => "Proof",
            DocKind::Exhibit => "Exhibit",
            DocKind::Bundle => "Bundle",
        };
        s += &format!("\n{what}  {}\n", d.path.display());
        for c in &d.checks {
            s += &format!("  {}  {}: {}\n", c.status.label(), c.name, c.detail);
        }
        s += &format!("  => {}\n", d.conclusion());
    }
    let (total, failed) = r.counted();
    s += &format!(
        "\nResult   {} ({total} check(s), {failed} failed)\n",
        if r.passed() { "PASS" } else { "FAIL" }
    );
    s
}

/// JSON report for scripts (`--json`).
pub fn render_json(r: &Report) -> Value {
    let c = &r.board.collected;
    let pos = |p: Position| json!({ "height": p.height, "tx_index": p.tx_index, "output_index": p.output_index });
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "board": r.board.origin.to_json(),
        "entries": c.records.iter().map(|x| json!({
            "kind": match x.entry.kind { EntryKind::RegisterWithHistory => "history", _ => "register" },
            "txid": x.txid,
            "position": pos(x.position),
            "nullifier": hex(&x.entry.nullifier),
            "commitment": hex(&x.entry.financier_commitment),
            "discount_bucket": x.entry.discount_bucket,
            "tenor_bucket": x.entry.tenor_bucket,
            "history_tag": x.entry.history_tag.map(|t| hex(&t)),
        })).collect::<Vec<_>>(),
        "settled": c.settled.iter().map(|x| json!({
            "txid": x.txid,
            "position": pos(x.position),
            "tag": hex(&x.entry.tag),
            "on_time": x.entry.on_time(),
        })).collect::<Vec<_>>(),
        "rejected": c.rejected.iter().map(|x| json!({
            "txid": x.txid, "output_index": x.output_index, "reason": x.reason,
        })).collect::<Vec<_>>(),
        "documents": r.docs.iter().map(|d| json!({
            "kind": match d.kind { DocKind::Proof => "proof", DocKind::Exhibit => "exhibit", DocKind::Bundle => "bundle" },
            "path": d.path.display().to_string(),
            "pass": d.passed(),
            "conclusion": d.conclusion(),
            "checks": d.checks.iter().map(|c| json!({
                "status": c.status.label(), "name": c.name, "detail": c.detail,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "pass": r.passed(),
    })
}

fn row(p: Position, kind: &str, id: &str, commitment: &str, buckets: &str, txid: &str) -> String {
    format!(
        "  {:<10} {:>3} {:>4}  {:<8}  {:<12}  {:<12}  {:<3}  {}\n",
        p.height, p.tx_index, p.output_index, kind, id, commitment, buckets, txid
    )
}

fn position(at: &EntryAt) -> Position {
    Position {
        height: at.height,
        tx_index: at.tx_index,
        output_index: at.output_index,
    }
}

fn where_(at: &EntryAt) -> String {
    where_pos(&at.txid, position(at))
}

fn record_at(r: &BoardRecord) -> String {
    where_pos(&r.txid, r.position)
}

fn where_pos(txid: &str, p: Position) -> String {
    format!(
        "{}/{}/{} (txid {txid})",
        p.height, p.tx_index, p.output_index
    )
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// First 6 bytes as hex: enough to tell entries apart in a table.
fn short(bytes: &[u8]) -> String {
    hex(&bytes[..6])
}

fn check(ok: bool, name: &'static str, yes: String, no: String) -> Check {
    if ok {
        pass(name, yes)
    } else {
        fail(name, no)
    }
}

fn pass(name: &'static str, detail: String) -> Check {
    Check {
        status: Status::Pass,
        name,
        detail,
    }
}

fn fail(name: &'static str, detail: String) -> Check {
    Check {
        status: Status::Fail,
        name,
        detail,
    }
}

fn info(name: &'static str, detail: String) -> Check {
    Check {
        status: Status::Info,
        name,
        detail,
    }
}
