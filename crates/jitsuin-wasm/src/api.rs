//! Plain Rust implementation of the browser API. Inputs and outputs are strings: keys and hashes
//! as hex, documents as base64url without padding, structured data as JSON. `lib.rs` wraps each
//! function for JavaScript.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use jitsuin_board::history::{verify_history as board_verify_history, Outcome};
use jitsuin_board::{bundle_on_board as board_bundle_on_board, Collected, Lookup, Position};
use jitsuin_core::memo::{self, MemoItem};
use jitsuin_core::{
    nullifier, Assignment, Bundle, BuyerIdentity, ChainStatus, DoubleSignProof, HistoryCert,
    Invoice, Receipt, ReceiptKind, Role, Seal, SettlementDoc,
};
use jitsuin_wallet::{zip321_uri, Payment, PaymentMemo};
use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};
use serde::Deserialize;
use serde_json::{json, Value};

pub type ApiResult<T> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex<const N: usize>(s: &str) -> ApiResult<[u8; N]> {
    let b = s.trim().as_bytes();
    if b.len() != 2 * N {
        return Err(format!("expected {} hex characters", 2 * N));
    }
    let mut out = [0u8; N];
    for (i, pair) in b.chunks(2).enumerate() {
        let s = std::str::from_utf8(pair).map_err(err)?;
        out[i] = u8::from_str_radix(s, 16).map_err(|_| "invalid hex".to_string())?;
    }
    Ok(out)
}

pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(s: &str) -> ApiResult<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s.trim())
        .map_err(|_| "invalid base64url".to_string())
}

fn identity(master_hex: &str) -> ApiResult<BuyerIdentity> {
    Ok(BuyerIdentity::from_master_secret(unhex::<32>(master_hex)?))
}

fn invoice(b: &str) -> ApiResult<Invoice> {
    Invoice::from_canonical_bytes(&unb64(b)?).map_err(err)
}

fn assignment(b: &str) -> ApiResult<Assignment> {
    Assignment::from_canonical_bytes(&unb64(b)?).map_err(err)
}

/// Invoice key for `index`, checked against the invoice's `buyer_pk`.
fn buyer_key(master_hex: &str, index: u32, inv: &Invoice) -> ApiResult<SigningKey> {
    let key = identity(master_hex)?.invoice_key(index);
    if key.verifying_key().to_bytes() != inv.buyer_pk {
        return Err("this invoice is not addressed to the buyer key at this index".into());
    }
    Ok(key)
}

#[derive(Deserialize)]
struct InvoiceJson {
    invoice_id: String,
    supplier_pk: String,
    buyer_pk: String,
    amount_zat: u64,
    issue_date: u32,
    due_date: u32,
    terms_hash: String,
}

/// Canonical invoice (base64url) from JSON fields; keys and hash as hex.
pub fn invoice_encode(json_text: &str) -> ApiResult<String> {
    let j: InvoiceJson = serde_json::from_str(json_text).map_err(err)?;
    let inv = Invoice {
        invoice_id: j.invoice_id,
        supplier_ephemeral_pk: unhex(&j.supplier_pk)?,
        buyer_pk: unhex(&j.buyer_pk)?,
        amount_zat: j.amount_zat,
        issue_date: j.issue_date,
        due_date: j.due_date,
        terms_hash: unhex(&j.terms_hash)?,
    };
    Ok(b64(&inv.to_canonical_bytes().map_err(err)?))
}

/// N of an invoice (hex).
pub fn invoice_nullifier(invoice_b64: &str) -> ApiResult<String> {
    Ok(hex(&nullifier(&invoice(invoice_b64)?).map_err(err)?))
}

/// SHA-256 of a file read in the browser (`terms_hash`); the file never leaves the device.
pub fn document_hash(file: &[u8]) -> String {
    hex(&jitsuin_core::document_hash(file))
}

/// Public keys derived from the buyer's master secret (a passkey PRF output).
pub fn buyer_keys(master_hex: &str, index: u32) -> ApiResult<String> {
    let id = identity(master_hex)?;
    Ok(json!({
        "identity_pk": hex(&id.identity_key().verifying_key().to_bytes()),
        "invoice_pk": hex(&id.invoice_key(index).verifying_key().to_bytes()),
    })
    .to_string())
}

/// Buyer signature on the canonical invoice (hex).
pub fn buyer_sign_invoice(master_hex: &str, index: u32, invoice_b64: &str) -> ApiResult<String> {
    let inv = invoice(invoice_b64)?;
    let key = buyer_key(master_hex, index, &inv)?;
    Ok(hex(&jitsuin_core::sign_invoice(&key, &inv)
        .map_err(err)?
        .to_bytes()))
}

/// Buyer seal on the assignment letter, after checking the supplier's seal (base64url).
pub fn buyer_seal_assignment(
    master_hex: &str,
    index: u32,
    invoice_b64: &str,
    assignment_b64: &str,
    supplier_seal_b64: &str,
) -> ApiResult<String> {
    let inv = invoice(invoice_b64)?;
    let a = assignment(assignment_b64)?;
    let supplier_seal = Seal::from_bytes(&unb64(supplier_seal_b64)?).map_err(err)?;
    let prior = [supplier_seal];
    match a.verify(&inv, &prior).map_err(err)? {
        ChainStatus::Incomplete { next: Role::Buyer } => {}
        _ => return Err("the letter is not waiting for the buyer's seal".into()),
    }
    let key = buyer_key(master_hex, index, &inv)?;
    Ok(b64(&a.seal_next(&key, &prior).map_err(err)?.to_bytes()))
}

/// Repayment request from the sealed letter: ZIP-321 URI and its QR code (SVG).
pub fn buyer_repayment(
    master_hex: &str,
    index: u32,
    invoice_b64: &str,
    assignment_b64: &str,
    date: u32,
) -> ApiResult<String> {
    let inv = invoice(invoice_b64)?;
    let a = assignment(assignment_b64)?;
    if a.nullifier != nullifier(&inv).map_err(err)? {
        return Err("the letter belongs to another invoice".into());
    }
    let key = buyer_key(master_hex, index, &inv)?;
    let receipt = Receipt::sign(
        &key,
        ReceiptKind::Repayment,
        a.nullifier,
        a.amount_zat,
        date,
    )
    .map_err(err)?;
    let claim = SettlementDoc::for_assignment(&a).buyer_seal(&key);
    let memo = memo::encode(&[MemoItem::Receipt(receipt), MemoItem::Seal(claim)]).map_err(err)?;
    let uri = zip321_uri(&[Payment {
        address: a.financier_address.clone(),
        amount_zat: a.amount_zat,
        memo: Some(PaymentMemo::Arbitrary(memo)),
    }])
    .map_err(err)?;
    let svg = QrCode::with_error_correction_level(uri.as_bytes(), EcLevel::M)
        .map_err(err)?
        .render::<svg::Color<'_>>()
        .min_dimensions(320, 320)
        .build();
    Ok(json!({ "uri": uri, "qr_svg": svg }).to_string())
}

/// History certificate for the invoice at `index`, chained after `prev_b64` ("" for index 0).
pub fn buyer_history_cert(
    master_hex: &str,
    index: u32,
    invoice_b64: &str,
    financier_pk_hex: &str,
    prev_b64: &str,
) -> ApiResult<String> {
    let inv = invoice(invoice_b64)?;
    let prev = if prev_b64.trim().is_empty() {
        None
    } else {
        Some(HistoryCert::from_bytes(&unb64(prev_b64)?).map_err(err)?)
    };
    let cert = HistoryCert::issue(
        &identity(master_hex)?,
        index,
        &inv,
        unhex(financier_pk_hex)?,
        prev.as_ref(),
    )
    .map_err(err)?;
    Ok(b64(&cert.to_bytes()))
}

fn chain_status(s: Option<ChainStatus>) -> Value {
    match s {
        None => Value::Null,
        Some(ChainStatus::Sealed) => json!("Sealed"),
        Some(ChainStatus::Incomplete { next }) => json!(format!("AwaitingSeal:{next:?}")),
    }
}

/// Offline check of a verification bundle (HNK-19.T6).
pub fn verify_bundle(bundle_b64: &str) -> ApiResult<String> {
    let b = Bundle::from_bytes(&unb64(bundle_b64)?).map_err(err)?;
    let r = b.verify().map_err(err)?;
    Ok(json!({
        "nullifier": hex(&r.nullifier),
        "invoice_id": b.invoice.invoice_id,
        "amount_zat": b.invoice.amount_zat,
        "due_date": b.invoice.due_date,
        "assignment": chain_status(r.assignment),
    })
    .to_string())
}

/// Offline check of a double-signature proof (HNK-07).
pub fn verify_proof(proof_b64: &str) -> ApiResult<String> {
    let p = DoubleSignProof::from_bytes(&unb64(proof_b64)?).map_err(err)?;
    let r = p.verify().map_err(err)?;
    let at = |a: &Option<jitsuin_core::EntryAt>| {
        a.as_ref()
            .map(|a| json!({ "txid": a.txid, "height": a.height }))
            .unwrap_or(Value::Null)
    };
    Ok(json!({
        "nullifier": hex(&r.nullifier),
        "supplier_pk": hex(&r.supplier_pk),
        "first_commitment": hex(&r.first_commitment),
        "second_commitment": hex(&r.second_commitment),
        "first_at": at(&p.first_at),
        "second_at": at(&p.second_at),
    })
    .to_string())
}

#[derive(Deserialize)]
struct BoardItem {
    txid: String,
    height: u32,
    tx_index: u32,
    output_index: u32,
    /// Full memo, base64url.
    memo: String,
}

/// Board memos as served by the backend: `[{txid, height, tx_index, output_index, memo}]`.
fn board(board_json: &str) -> ApiResult<Collected> {
    let items: Vec<BoardItem> = serde_json::from_str(board_json).map_err(err)?;
    let mut c = Collected::default();
    for i in items {
        let position = Position {
            height: i.height,
            tx_index: i.tx_index,
            output_index: i.output_index,
        };
        c.add(&i.txid, position, &unb64(&i.memo)?);
    }
    c.sort();
    Ok(c)
}

/// Bundle checked against board data in the browser, without trusting the server's verdict.
pub fn bundle_on_board(bundle_b64: &str, board_json: &str) -> ApiResult<String> {
    let b = Bundle::from_bytes(&unb64(bundle_b64)?).map_err(err)?;
    b.verify().map_err(err)?;
    let c = board(board_json)?;
    let on = board_bundle_on_board(&b, &c.records, &c.settled).map_err(err)?;
    let register = match &on.register {
        Lookup::NotFound { .. } => json!({ "status": "NotFound" }),
        Lookup::Registered { winner, .. } => {
            json!({ "status": "Registered", "txid": winner.txid, "height": winner.position.height })
        }
        Lookup::DoubleFinanced {
            winner,
            conflicting,
            ..
        } => json!({
            "status": "DoubleFinanced",
            "txid": winner.txid,
            "conflicting": conflicting.iter().map(|r| r.txid.clone()).collect::<Vec<_>>(),
        }),
    };
    let settled = on
        .settled
        .map(|s| json!({ "txid": s.txid, "height": s.position.height, "on_time": s.entry.on_time() }))
        .unwrap_or(Value::Null);
    Ok(json!({ "register": register, "settled": settled }).to_string())
}

/// Buyer history checked against board data in the browser (HNK-20).
pub fn verify_history(
    certs_json: &str,
    identity_pk_hex: &str,
    allowlist_json: &str,
    board_json: &str,
    today: u32,
    grace_days: u32,
) -> ApiResult<String> {
    let certs: Vec<String> = serde_json::from_str(certs_json).map_err(err)?;
    let certs: Vec<HistoryCert> = certs
        .iter()
        .map(|c| HistoryCert::from_bytes(&unb64(c)?).map_err(err))
        .collect::<ApiResult<_>>()?;
    let allow: Vec<String> = serde_json::from_str(allowlist_json).map_err(err)?;
    let allow: Vec<[u8; 32]> = allow.iter().map(|k| unhex(k)).collect::<ApiResult<_>>()?;
    let c = board(board_json)?;
    let r = board_verify_history(
        &certs,
        &unhex(identity_pk_hex)?,
        &allow,
        &c.records,
        &c.settled,
        today,
        grace_days,
    )
    .map_err(err)?;
    let name = |o: Outcome| format!("{o:?}");
    Ok(json!({
        "on_time": r.on_time,
        "late": r.late,
        "defaults": r.defaults,
        "open": r.open,
        "lines": r.lines.iter().map(|l| json!({
            "index": l.cert.index,
            "nullifier": hex(&l.cert.nullifier),
            "due_date": l.cert.due_date,
            "outcome": name(l.outcome),
        })).collect::<Vec<_>>(),
    })
    .to_string())
}

/// Supplier signature helper for tests and the supplier screen: seals the letter as supplier.
pub fn supplier_seal_assignment(
    supplier_secret_hex: &str,
    invoice_b64: &str,
    assignment_b64: &str,
) -> ApiResult<String> {
    let inv = invoice(invoice_b64)?;
    let a = assignment(assignment_b64)?;
    let key = SigningKey::from_bytes(&unhex::<32>(supplier_secret_hex)?);
    if key.verifying_key().to_bytes() != inv.supplier_ephemeral_pk {
        return Err("key is not the supplier key of this invoice".into());
    }
    a.verify(&inv, &[]).map_err(err)?;
    Ok(b64(&a.seal_next(&key, &[]).map_err(err)?.to_bytes()))
}
