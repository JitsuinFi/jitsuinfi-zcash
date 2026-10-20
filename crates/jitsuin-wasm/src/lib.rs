//! JitsuinFi in the browser (FE crucial parts, Hans): buyer keys derived from a passkey PRF
//! output, invoice and assignment signing, the repayment QR, and client-side verification of
//! bundles, proofs and buyer histories, so the browser does not have to trust the server.
//!
//! Secrets (the master secret, the supplier key) stay in the page that calls these functions;
//! nothing here does network I/O. Keys and hashes are hex, documents base64url (no padding),
//! structured results JSON strings. Errors are thrown as JavaScript `Error`s.

use wasm_bindgen::prelude::*;

pub mod api;

fn js<T>(r: api::ApiResult<T>) -> Result<T, JsError> {
    r.map_err(|e| JsError::new(&e))
}

#[wasm_bindgen(js_name = invoiceEncode)]
pub fn invoice_encode(json: &str) -> Result<String, JsError> {
    js(api::invoice_encode(json))
}

#[wasm_bindgen(js_name = invoiceNullifier)]
pub fn invoice_nullifier(invoice_b64: &str) -> Result<String, JsError> {
    js(api::invoice_nullifier(invoice_b64))
}

#[wasm_bindgen(js_name = documentHash)]
pub fn document_hash(file: &[u8]) -> String {
    api::document_hash(file)
}

/// Fields of an assignment letter; pass the invoice (or "") to check that the letter is for it.
#[wasm_bindgen(js_name = assignmentDecode)]
pub fn assignment_decode(assignment_b64: &str, invoice_b64: &str) -> Result<String, JsError> {
    js(api::assignment_decode(assignment_b64, invoice_b64))
}

#[wasm_bindgen(js_name = financierCommitment)]
pub fn financier_commitment(
    financier_secret_hex: &str,
    invoice_b64: &str,
) -> Result<String, JsError> {
    js(api::financier_commitment(financier_secret_hex, invoice_b64))
}

#[wasm_bindgen(js_name = buyerKeys)]
pub fn buyer_keys(master_hex: &str, index: u32) -> Result<String, JsError> {
    js(api::buyer_keys(master_hex, index))
}

#[wasm_bindgen(js_name = buyerSignInvoice)]
pub fn buyer_sign_invoice(
    master_hex: &str,
    index: u32,
    invoice_b64: &str,
) -> Result<String, JsError> {
    js(api::buyer_sign_invoice(master_hex, index, invoice_b64))
}

#[wasm_bindgen(js_name = buyerSealAssignment)]
pub fn buyer_seal_assignment(
    master_hex: &str,
    index: u32,
    invoice_b64: &str,
    assignment_b64: &str,
    supplier_seal_b64: &str,
) -> Result<String, JsError> {
    js(api::buyer_seal_assignment(
        master_hex,
        index,
        invoice_b64,
        assignment_b64,
        supplier_seal_b64,
    ))
}

#[wasm_bindgen(js_name = buyerRepayment)]
pub fn buyer_repayment(
    master_hex: &str,
    index: u32,
    invoice_b64: &str,
    assignment_b64: &str,
    date: u32,
) -> Result<String, JsError> {
    js(api::buyer_repayment(
        master_hex,
        index,
        invoice_b64,
        assignment_b64,
        date,
    ))
}

#[wasm_bindgen(js_name = buyerHistoryCert)]
pub fn buyer_history_cert(
    master_hex: &str,
    index: u32,
    invoice_b64: &str,
    financier_pk_hex: &str,
    prev_b64: &str,
) -> Result<String, JsError> {
    js(api::buyer_history_cert(
        master_hex,
        index,
        invoice_b64,
        financier_pk_hex,
        prev_b64,
    ))
}

#[wasm_bindgen(js_name = supplierRegisterEntry)]
/// `discount` and `tenor` are the classes from the financier (both or neither; omitted = `0/0`).
pub fn supplier_register_entry(
    supplier_secret_hex: &str,
    invoice_b64: &str,
    financier_pk_hex: &str,
    salt_hex: &str,
    discount: Option<u8>,
    tenor: Option<u8>,
) -> Result<String, JsError> {
    js(api::supplier_register_entry(
        supplier_secret_hex,
        invoice_b64,
        financier_pk_hex,
        salt_hex,
        discount,
        tenor,
    ))
}

#[wasm_bindgen(js_name = doubleSignProof)]
/// `first_at` and `second_at`: board positions as JSON `{txid, height, tx_index, output_index}`
/// (omit for an entry that is not on chain; `jitsuin verify` needs the first one).
pub fn double_sign_proof(
    invoice_b64: &str,
    buyer_signature_hex: &str,
    first_memo_b64: &str,
    second_memo_b64: &str,
    first_at: Option<String>,
    second_at: Option<String>,
) -> Result<String, JsError> {
    js(api::double_sign_proof(
        invoice_b64,
        buyer_signature_hex,
        first_memo_b64,
        second_memo_b64,
        first_at.as_deref(),
        second_at.as_deref(),
    ))
}

#[wasm_bindgen(js_name = financierSealAssignment)]
pub fn financier_seal_assignment(
    financier_secret_hex: &str,
    invoice_b64: &str,
    assignment_b64: &str,
    seals_json: &str,
) -> Result<String, JsError> {
    js(api::financier_seal_assignment(
        financier_secret_hex,
        invoice_b64,
        assignment_b64,
        seals_json,
    ))
}

#[wasm_bindgen(js_name = assignmentStatus)]
pub fn assignment_status(
    invoice_b64: &str,
    assignment_b64: &str,
    seals_json: &str,
) -> Result<String, JsError> {
    js(api::assignment_status(
        invoice_b64,
        assignment_b64,
        seals_json,
    ))
}

#[wasm_bindgen(js_name = supplierSealAssignment)]
pub fn supplier_seal_assignment(
    supplier_secret_hex: &str,
    invoice_b64: &str,
    assignment_b64: &str,
) -> Result<String, JsError> {
    js(api::supplier_seal_assignment(
        supplier_secret_hex,
        invoice_b64,
        assignment_b64,
    ))
}

#[wasm_bindgen(js_name = verifyBundle)]
pub fn verify_bundle(bundle_b64: &str) -> Result<String, JsError> {
    js(api::verify_bundle(bundle_b64))
}

#[wasm_bindgen(js_name = verifyProof)]
pub fn verify_proof(proof_b64: &str) -> Result<String, JsError> {
    js(api::verify_proof(proof_b64))
}

#[wasm_bindgen(js_name = bundleOnBoard)]
pub fn bundle_on_board(bundle_b64: &str, board_json: &str) -> Result<String, JsError> {
    js(api::bundle_on_board(bundle_b64, board_json))
}

#[wasm_bindgen(js_name = verifyHistory)]
pub fn verify_history(
    certs_json: &str,
    identity_pk_hex: &str,
    allowlist_json: &str,
    board_json: &str,
    today: u32,
    grace_days: u32,
) -> Result<String, JsError> {
    js(api::verify_history(
        certs_json,
        identity_pk_hex,
        allowlist_json,
        board_json,
        today,
        grace_days,
    ))
}

#[wasm_bindgen(js_name = publicKey)]
pub fn public_key(secret_hex: &str) -> Result<String, JsError> {
    js(api::public_key(secret_hex))
}

#[wasm_bindgen(js_name = invoiceDecode)]
pub fn invoice_decode(invoice_b64: &str) -> Result<String, JsError> {
    js(api::invoice_decode(invoice_b64))
}

#[wasm_bindgen(js_name = assignmentEncode)]
pub fn assignment_encode(
    invoice_b64: &str,
    financier_pk_hex: &str,
    financier_address: &str,
    terms_hash_hex: &str,
) -> Result<String, JsError> {
    js(api::assignment_encode(
        invoice_b64,
        financier_pk_hex,
        financier_address,
        terms_hash_hex,
    ))
}

#[wasm_bindgen(js_name = bundleBuild)]
pub fn bundle_build(json: &str) -> Result<String, JsError> {
    js(api::bundle_build(json))
}

#[wasm_bindgen(js_name = boardMemoDescribe)]
pub fn board_memo_describe(memo_b64: &str) -> Result<String, JsError> {
    js(api::board_memo_describe(memo_b64))
}

#[cfg(test)]
mod tests;

#[wasm_bindgen(js_name = supplierRegisterHistoryEntry)]
pub fn supplier_register_history_entry(
    supplier_secret_hex: &str,
    invoice_b64: &str,
    financier_pk_hex: &str,
    salt_hex: &str,
    cert_b64: &str,
    discount: Option<u8>,
    tenor: Option<u8>,
) -> Result<String, JsError> {
    js(api::supplier_register_history_entry(
        supplier_secret_hex,
        invoice_b64,
        financier_pk_hex,
        salt_hex,
        cert_b64,
        discount,
        tenor,
    ))
}

/// Register memo carrying a history tag (hex) from the financier, without certificate k.
#[wasm_bindgen(js_name = supplierRegisterTaggedEntry)]
pub fn supplier_register_tagged_entry(
    supplier_secret_hex: &str,
    invoice_b64: &str,
    financier_pk_hex: &str,
    salt_hex: &str,
    history_tag_hex: &str,
    discount: Option<u8>,
    tenor: Option<u8>,
) -> Result<String, JsError> {
    js(api::supplier_register_tagged_entry(
        supplier_secret_hex,
        invoice_b64,
        financier_pk_hex,
        salt_hex,
        history_tag_hex,
        discount,
        tenor,
    ))
}

#[wasm_bindgen(js_name = financierSettle)]
pub fn financier_settle(
    financier_secret_hex: &str,
    invoice_b64: &str,
    assignment_b64: &str,
    repayment_memo_b64: &str,
) -> Result<String, JsError> {
    js(api::financier_settle(
        financier_secret_hex,
        invoice_b64,
        assignment_b64,
        repayment_memo_b64,
    ))
}
