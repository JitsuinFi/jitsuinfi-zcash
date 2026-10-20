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

/// Overwrites `bytes` with zeros in a way the compiler does not remove.
fn wipe(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        // SAFETY: `b` is a valid, aligned `&mut u8`.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Runs `f` with a 32-byte secret given as bytes (P-07, HNK-27.T9): the secret is turned into the
/// hex form the API takes, `secret` is zeroed at once, and the hex copy is zeroed after `f`. In the
/// browser `secret` is the page's `Uint8Array` passed as `&mut [u8]`; wasm-bindgen copies it back,
/// so the page's array is all zeros when the call returns. Best effort: keys derived inside `f`
/// are dropped (and `SigningKey`, `BuyerIdentity` zero themselves on drop).
pub fn with_secret<T>(secret: &mut [u8], f: impl FnOnce(&str) -> ApiResult<T>) -> ApiResult<T> {
    if secret.len() != 32 {
        wipe(secret);
        return Err("expected a 32-byte secret".into());
    }
    let mut h = hex(secret);
    wipe(secret);
    let r = f(&h);
    // SAFETY: zero bytes are valid UTF-8, so the string stays valid.
    wipe(unsafe { h.as_bytes_mut() });
    r
}

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
        memo: Some(PaymentMemo::Arbitrary(memo.clone())),
    }])
    .map_err(err)?;
    let svg = QrCode::with_error_correction_level(uri.as_bytes(), EcLevel::M)
        .map_err(err)?
        .render::<svg::Color<'_>>()
        .min_dimensions(320, 320)
        .build();
    Ok(json!({ "uri": uri, "qr_svg": svg, "memo": b64(&memo) }).to_string())
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

/// A double-signature proof checked against board data in the browser (HNK-28.T2, BL-D27-05):
/// the signatures, then every board position the proof claims, by the same rule as
/// `jitsuin verify` (`jitsuin_board::proof_on_board`). A position the proof only claims is
/// reported as claimed, never as a fact; a proof without the first entry's position fails.
pub fn verify_proof_on_board(proof_b64: &str, board_json: &str) -> ApiResult<String> {
    let p = DoubleSignProof::from_bytes(&unb64(proof_b64)?).map_err(err)?;
    let c = board(board_json)?;
    let at = |a: &Option<jitsuin_core::EntryAt>| {
        a.as_ref()
            .map(|a| json!({ "txid": a.txid, "height": a.height, "tx_index": a.tx_index, "output_index": a.output_index }))
            .unwrap_or(Value::Null)
    };
    let signatures = match p.verify() {
        Ok(r) => json!({
            "ok": true,
            "nullifier": hex(&r.nullifier),
            "supplier_pk": hex(&r.supplier_pk),
            "first_commitment": hex(&r.first_commitment),
            "second_commitment": hex(&r.second_commitment),
            "invoice_id": p.invoice.invoice_id,
        }),
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    };
    let claims = jitsuin_board::proof_on_board(&p, &c.records);
    let holds = signatures["ok"] == true && claims.holds();
    Ok(json!({
        "holds": holds,
        "signatures": signatures,
        "first": { "claimed_at": at(&p.first_at), "on_board": claims.first },
        "second": { "claimed_at": at(&p.second_at), "on_board": claims.second },
        "ordered": claims.ordered,
        "board_entries": c.records.len(),
    })
    .to_string())
}

/// The public rate index of board data (HNK-28.T3, BL-D28-05): the same numbers and JSON shape
/// as `jitsuin index --json`, without its version and board origin.
pub fn rate_index(board_json: &str, k: u32) -> ApiResult<String> {
    let c = board(board_json)?;
    Ok(
        jitsuin_board::rate_index_json(&jitsuin_board::rate_index(&c.records, k as usize))
            .to_string(),
    )
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

fn seals_of(json_text: &str) -> ApiResult<Vec<Seal>> {
    let list: Vec<String> = serde_json::from_str(json_text).map_err(err)?;
    list.iter()
        .map(|s| Seal::from_bytes(&unb64(s)?).map_err(err))
        .collect()
}

/// Financier seal on the assignment letter, the last of the chain, after checking the supplier's
/// and the buyer's seals (`seals_json`: their seals as a JSON array of base64url). Sign-to-Pay:
/// the advance goes out only once this seal exists.
/// Commitment opening of this financier for the invoice (P-08): `{salt, commitment}`, both hex.
/// Derived from the financier key and N, so asking again gives the same values.
pub fn financier_commitment(financier_secret_hex: &str, invoice_b64: &str) -> ApiResult<String> {
    let inv = invoice(invoice_b64)?;
    let key = SigningKey::from_bytes(&unhex::<32>(financier_secret_hex)?);
    let (salt, commitment) = jitsuin_core::commitment_opening(&key, &nullifier(&inv).map_err(err)?);
    Ok(json!({ "salt": hex(&salt), "commitment": hex(&commitment) }).to_string())
}

pub fn financier_seal_assignment(
    financier_secret_hex: &str,
    invoice_b64: &str,
    assignment_b64: &str,
    seals_json: &str,
) -> ApiResult<String> {
    let inv = invoice(invoice_b64)?;
    let a = assignment(assignment_b64)?;
    let key = SigningKey::from_bytes(&unhex::<32>(financier_secret_hex)?);
    if key.verifying_key().to_bytes() != a.financier_pk {
        return Err("key is not the financier key of this letter".into());
    }
    let prior = seals_of(seals_json)?;
    match a.verify(&inv, &prior).map_err(err)? {
        ChainStatus::Incomplete {
            next: Role::Financier,
        } => {}
        _ => return Err("the letter is not waiting for the financier's seal".into()),
    }
    Ok(b64(&a.seal_next(&key, &prior).map_err(err)?.to_bytes()))
}

/// Where the letter's seal chain stands: "Sealed", "AwaitingSeal:<Role>", or an error when the
/// letter no longer matches the invoice or a seal does not verify (a changed amount, for one).
pub fn assignment_status(
    invoice_b64: &str,
    assignment_b64: &str,
    seals_json: &str,
) -> ApiResult<String> {
    let inv = invoice(invoice_b64)?;
    let a = assignment(assignment_b64)?;
    let st = a.verify(&inv, &seals_of(seals_json)?).map_err(err)?;
    Ok(chain_status(Some(st))
        .as_str()
        .unwrap_or_default()
        .to_string())
}

/// Discount and tenor classes for an entry: both given and valid, or both absent (`0/0`, not
/// disclosed).
fn entry_classes(discount: Option<u8>, tenor: Option<u8>) -> ApiResult<(u8, u8)> {
    let (d, t) = match (discount, tenor) {
        (None, None) => (0, 0),
        (Some(d), Some(t)) => (d, t),
        _ => return Err("give both the discount and the tenor class, or neither".into()),
    };
    jitsuin_core::index::validate_classes(d, t).map_err(err)?;
    Ok((d, t))
}

/// Register entry for the board (memo, base64url), signed with the supplier's key of this invoice,
/// committing to one financier: `BLAKE2b-256(financier_pk ‖ salt)`. Also returns the commitment.
/// `discount` and `tenor` are the deal's classes from the financier (both or neither).
pub fn supplier_register_entry(
    supplier_secret_hex: &str,
    invoice_b64: &str,
    financier_pk_hex: &str,
    salt_hex: &str,
    discount: Option<u8>,
    tenor: Option<u8>,
) -> ApiResult<String> {
    let (d, t) = entry_classes(discount, tenor)?;
    let inv = invoice(invoice_b64)?;
    let key = SigningKey::from_bytes(&unhex::<32>(supplier_secret_hex)?);
    if key.verifying_key().to_bytes() != inv.supplier_ephemeral_pk {
        return Err("key is not the supplier key of this invoice".into());
    }
    let commitment =
        jitsuin_core::financier_commitment(&unhex(financier_pk_hex)?, &unhex(salt_hex)?);
    let e = jitsuin_core::BoardEntry::sign(
        &key,
        jitsuin_core::EntryKind::Register,
        nullifier(&inv).map_err(err)?,
        commitment,
        d,
        t,
    );
    Ok(json!({ "memo": b64(&e.to_memo_bytes()), "commitment": hex(&commitment) }).to_string())
}

/// Double-signature proof (base64url) from two register memos for the same invoice, signed by its
/// supplier for two different financiers, with the buyer's invoice signature. Neither entry needs
/// to be on chain: the second one may only have been offered.
#[derive(Deserialize)]
struct EntryAtJson {
    txid: String,
    height: u32,
    tx_index: u32,
    output_index: u32,
}

/// Board position `{txid, height, tx_index, output_index}` as JSON, or `None` / `""` for an entry
/// that is not on chain.
fn entry_at(json_text: Option<&str>) -> ApiResult<Option<jitsuin_core::EntryAt>> {
    let Some(text) = json_text.map(str::trim).filter(|t| !t.is_empty()) else {
        return Ok(None);
    };
    let j: EntryAtJson = serde_json::from_str(text).map_err(err)?;
    unhex::<32>(&j.txid)?;
    Ok(Some(jitsuin_core::EntryAt {
        txid: j.txid.trim().to_lowercase(),
        height: j.height,
        tx_index: j.tx_index,
        output_index: j.output_index,
    }))
}

/// `first_at_json` and `second_at_json` are the board positions of the two entries (K-3,
/// HNK-27.T4). `jitsuin verify` needs the first entry's position; the second may be omitted when
/// it was only offered.
pub fn double_sign_proof(
    invoice_b64: &str,
    buyer_signature_hex: &str,
    first_memo_b64: &str,
    second_memo_b64: &str,
    first_at_json: Option<&str>,
    second_at_json: Option<&str>,
) -> ApiResult<String> {
    let entry = |m: &str| jitsuin_core::BoardEntry::from_memo_bytes(&unb64(m)?).map_err(err);
    let p = DoubleSignProof {
        invoice: invoice(invoice_b64)?,
        buyer_signature: unhex(buyer_signature_hex)?,
        first: entry(first_memo_b64)?,
        second: entry(second_memo_b64)?,
        first_at: entry_at(first_at_json)?,
        second_at: entry_at(second_at_json)?,
    };
    p.verify().map_err(err)?;
    if let (Some(a), Some(b)) = (&p.first_at, &p.second_at) {
        if (a.height, a.tx_index, a.output_index) >= (b.height, b.tx_index, b.output_index) {
            return Err("the first entry must come before the second on the board".into());
        }
    }
    Ok(b64(&p.to_bytes().map_err(err)?))
}

fn supplier_key(master_hex: &str, invoice_id: &str, buyer_pk_hex: &str) -> ApiResult<SigningKey> {
    jitsuin_core::SupplierMaster::from_master_secret(unhex::<32>(master_hex)?)
        .invoice_key(invoice_id, &unhex::<32>(buyer_pk_hex)?)
        .ok_or_else(|| "invoice_id is too long".to_string())
}

/// Public key (hex) of the supplier's per-invoice key from the supplier master (P-03,
/// HNK-24.T1), for `invoice_id` and the buyer's `invoice_pk(k)`.
pub fn supplier_invoice_public_key(
    master_hex: &str,
    invoice_id: &str,
    buyer_pk_hex: &str,
) -> ApiResult<String> {
    Ok(hex(&supplier_key(master_hex, invoice_id, buyer_pk_hex)?
        .verifying_key()
        .to_bytes()))
}

/// The per-invoice secret as 32 bytes, for a supplier `*Bytes` function (which wipes it).
pub fn supplier_invoice_secret(
    master_hex: &str,
    invoice_id: &str,
    buyer_pk_hex: &str,
) -> ApiResult<Vec<u8>> {
    Ok(supplier_key(master_hex, invoice_id, buyer_pk_hex)?
        .to_bytes()
        .to_vec())
}

/// Local storage keys (HNK-24.T3) from a role master: 64 bytes, AES-256-GCM key then HMAC key.
pub fn storage_keys(master_hex: &str) -> ApiResult<Vec<u8>> {
    let k = jitsuin_core::storage_keys(&unhex::<32>(master_hex)?);
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&k.encryption);
    out.extend_from_slice(&k.index);
    Ok(out)
}

/// Public key (hex) of a 32-byte secret, for the supplier's per-invoice key made in the browser.
pub fn public_key(secret_hex: &str) -> ApiResult<String> {
    Ok(hex(&SigningKey::from_bytes(&unhex::<32>(secret_hex)?)
        .verifying_key()
        .to_bytes()))
}

/// Invoice fields as JSON (keys and hashes hex), for showing what is being signed.
pub fn invoice_decode(invoice_b64: &str) -> ApiResult<String> {
    let inv = invoice(invoice_b64)?;
    Ok(json!({
        "invoice_id": inv.invoice_id,
        "supplier_pk": hex(&inv.supplier_ephemeral_pk),
        "buyer_pk": hex(&inv.buyer_pk),
        "amount_zat": inv.amount_zat,
        "issue_date": inv.issue_date,
        "due_date": inv.due_date,
        "terms_hash": hex(&inv.terms_hash),
        "nullifier": hex(&nullifier(&inv).map_err(err)?),
    })
    .to_string())
}

/// Fields of an assignment letter (P-13, HNK-27.T3), so the supplier and the buyer read what they
/// seal: N, amount, due date, financier key, pay address and the hash of the letter PDF. With an
/// invoice, `matches_invoice` says whether N, amount and due date are the invoice's.
pub fn assignment_decode(assignment_b64: &str, invoice_b64: &str) -> ApiResult<String> {
    let a = assignment(assignment_b64)?;
    let matches = if invoice_b64.trim().is_empty() {
        Value::Null
    } else {
        let inv = invoice(invoice_b64)?;
        Value::Bool(
            a.nullifier == nullifier(&inv).map_err(err)?
                && a.amount_zat == inv.amount_zat
                && a.due_date == inv.due_date,
        )
    };
    Ok(json!({
        "nullifier": hex(&a.nullifier),
        "amount_zat": a.amount_zat,
        "due_date": a.due_date,
        "financier_pk": hex(&a.financier_pk),
        "financier_address": a.financier_address,
        "terms_hash": hex(&a.terms_hash),
        "matches_invoice": matches,
    })
    .to_string())
}

/// Assignment letter (base64url) of `invoice_b64` to the financier key and pay address.
pub fn assignment_encode(
    invoice_b64: &str,
    financier_pk_hex: &str,
    financier_address: &str,
    terms_hash_hex: &str,
) -> ApiResult<String> {
    let a = Assignment::for_invoice(
        &invoice(invoice_b64)?,
        unhex(financier_pk_hex)?,
        financier_address,
        unhex(terms_hash_hex)?,
    )
    .map_err(err)?;
    Ok(b64(&a.to_canonical_bytes().map_err(err)?))
}

#[derive(Deserialize)]
struct BundleJson {
    invoice: String,
    buyer_signature: String,
    #[serde(default)]
    assignment: Option<String>,
    #[serde(default)]
    seals: Vec<String>,
    #[serde(default)]
    with_settlement: bool,
}

/// Verification bundle (base64url) from its parts; verified before it is returned.
pub fn bundle_build(json_text: &str) -> ApiResult<String> {
    let j: BundleJson = serde_json::from_str(json_text).map_err(err)?;
    let assignment = j.assignment.as_deref().map(assignment).transpose()?;
    let settlement = match (&assignment, j.with_settlement) {
        (Some(a), true) => Some(SettlementDoc::for_assignment(a)),
        _ => None,
    };
    let b = Bundle {
        invoice: invoice(&j.invoice)?,
        buyer_signature: unhex(&j.buyer_signature)?,
        assignment,
        assignment_seals: j
            .seals
            .iter()
            .map(|s| Seal::from_bytes(&unb64(s)?).map_err(err))
            .collect::<ApiResult<_>>()?,
        settlement,
    };
    b.verify().map_err(err)?;
    Ok(b64(&b.to_bytes().map_err(err)?))
}

/// What anyone can read from one board memo: only hashes and opaque signatures. Nothing in it
/// names the parties, the amount or the invoice; signatures cannot be checked without the invoice.
pub fn board_memo_describe(memo_b64: &str) -> ApiResult<String> {
    let memo = unb64(memo_b64)?;
    let mut c = Collected::default();
    c.add(
        "",
        Position {
            height: 0,
            tx_index: 0,
            output_index: 0,
        },
        &memo,
    );
    if let Some(r) = c.records.first() {
        let e = &r.entry;
        return Ok(json!({
            "kind": format!("{:?}", e.kind),
            "nullifier": hex(&e.nullifier),
            "financier_commitment": hex(&e.financier_commitment),
            "discount_bucket": e.discount_bucket,
            "tenor_bucket": e.tenor_bucket,
            "history_tag": e.history_tag.map(|t| hex(&t)),
            "signature": hex(&e.supplier_sig),
        })
        .to_string());
    }
    if let Some(s) = c.settled.first() {
        let e = &s.entry;
        return Ok(json!({
            "kind": "Settled",
            "settled_tag": hex(&e.tag),
            "on_time": e.on_time(),
            "buyer_signature": hex(&e.buyer_sig),
            "financier_signature": hex(&e.financier_sig),
        })
        .to_string());
    }
    Err(c
        .rejected
        .first()
        .map(|r| r.reason.clone())
        .unwrap_or_else(|| "not a JitsuinFi board memo".into()))
}

/// Register memo (base64url) for an invoice the buyer listed in its history: the entry carries the
/// certificate's tag, so a verifier finds it from the certificate alone.
pub fn supplier_register_history_entry(
    supplier_secret_hex: &str,
    invoice_b64: &str,
    financier_pk_hex: &str,
    salt_hex: &str,
    cert_b64: &str,
    discount: Option<u8>,
    tenor: Option<u8>,
) -> ApiResult<String> {
    let (d, t) = entry_classes(discount, tenor)?;
    let inv = invoice(invoice_b64)?;
    let key = SigningKey::from_bytes(&unhex::<32>(supplier_secret_hex)?);
    if key.verifying_key().to_bytes() != inv.supplier_ephemeral_pk {
        return Err("key is not the supplier key of this invoice".into());
    }
    let cert = HistoryCert::from_bytes(&unb64(cert_b64)?).map_err(err)?;
    let n = nullifier(&inv).map_err(err)?;
    if cert.nullifier != n {
        return Err("the certificate belongs to another invoice".into());
    }
    let commitment =
        jitsuin_core::financier_commitment(&unhex(financier_pk_hex)?, &unhex(salt_hex)?);
    let e = jitsuin_core::BoardEntry::sign_with_history(&key, n, commitment, d, t, cert.tag());
    Ok(json!({ "memo": b64(&e.to_memo_bytes()), "commitment": hex(&commitment) }).to_string())
}

/// Register memo with a history tag given directly (K-10, HNK-27.T8): the financier checks the
/// buyer's certificate and passes only its 32-byte tag, so the supplier never holds certificate k
/// (whose holder can follow the buyer's next invoices, TM #6). The financier's `check_entry`
/// refuses the entry when the tag is not the one of the checked certificate.
pub fn supplier_register_tagged_entry(
    supplier_secret_hex: &str,
    invoice_b64: &str,
    financier_pk_hex: &str,
    salt_hex: &str,
    history_tag_hex: &str,
    discount: Option<u8>,
    tenor: Option<u8>,
) -> ApiResult<String> {
    let (d, t) = entry_classes(discount, tenor)?;
    let inv = invoice(invoice_b64)?;
    let key = SigningKey::from_bytes(&unhex::<32>(supplier_secret_hex)?);
    if key.verifying_key().to_bytes() != inv.supplier_ephemeral_pk {
        return Err("key is not the supplier key of this invoice".into());
    }
    let n = nullifier(&inv).map_err(err)?;
    let commitment =
        jitsuin_core::financier_commitment(&unhex(financier_pk_hex)?, &unhex(salt_hex)?);
    let e = jitsuin_core::BoardEntry::sign_with_history(
        &key,
        n,
        commitment,
        d,
        t,
        unhex(history_tag_hex)?,
    );
    Ok(json!({ "memo": b64(&e.to_memo_bytes()), "commitment": hex(&commitment) }).to_string())
}

/// Settled memo (base64url): the financier countersigns the buyer's repayment memo (from
/// `buyer_repayment`). On time when the buyer's receipt is dated on or before the due date.
pub fn financier_settle(
    financier_secret_hex: &str,
    invoice_b64: &str,
    assignment_b64: &str,
    repayment_memo_b64: &str,
) -> ApiResult<String> {
    let inv = invoice(invoice_b64)?;
    let a = assignment(assignment_b64)?;
    if a.nullifier != nullifier(&inv).map_err(err)? {
        return Err("the letter belongs to another invoice".into());
    }
    let key = SigningKey::from_bytes(&unhex::<32>(financier_secret_hex)?);
    if key.verifying_key().to_bytes() != a.financier_pk {
        return Err("key is not the financier of this letter".into());
    }
    let mut receipt = None;
    let mut claim = None;
    for item in memo::decode(&unb64(repayment_memo_b64)?).map_err(err)? {
        match item {
            MemoItem::Receipt(r) => receipt = Some(r),
            MemoItem::Seal(s) => claim = Some(s),
            _ => {}
        }
    }
    let (receipt, claim) = receipt.zip(claim).ok_or("the memo is not a repayment")?;
    receipt.verify(&inv.buyer_pk).map_err(err)?;
    if receipt.kind != ReceiptKind::Repayment || receipt.nullifier != a.nullifier {
        return Err("the receipt is not a repayment of this invoice".into());
    }
    let on_time = receipt.date <= a.due_date;
    let flag = if on_time {
        jitsuin_core::SETTLED_ON_TIME
    } else {
        jitsuin_core::SETTLED_LATE
    };
    let doc = SettlementDoc::for_assignment(&a);
    let e = jitsuin_core::SettledEntry::countersign(&doc, &claim, &inv.buyer_pk, &key, flag)
        .map_err(err)?;
    Ok(json!({ "memo": b64(&e.to_memo_bytes()), "on_time": on_time }).to_string())
}
