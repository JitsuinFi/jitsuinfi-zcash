//! Buyer side (HNK-06.T2, HNK-19.T4): seal the assignment letter, and pay at maturity with a
//! ZIP-321 request built from the sealed letter. The memo carries the repayment receipt and the
//! buyer's settlement claim ("I paid"), both signed by the buyer key from the invoice, so every
//! holder of the invoice can verify them. Any ZIP-321 wallet can pay the request; the memo
//! travels unchanged.

use ed25519_dalek::SigningKey;
use jitsuin_core::memo::{self, MemoItem};
use jitsuin_core::{Assignment, Receipt, ReceiptKind, Seal, SettlementDoc};
use jitsuin_wallet::{zip321_uri, Payment, PaymentMemo};
use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};

use crate::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepaymentRequest {
    /// `zcash:<financier address>?amount=…&memo=…` (memo = base64url of the receipt and the
    /// claim seal, 346 bytes).
    pub uri: String,
    pub receipt: Receipt,
    /// Buyer seal on the settlement document; the financier countersigns it once paid.
    pub claim: Seal,
}

/// Builds the repayment request from the assignment letter: pay the amount due to the
/// financier's address, with the receipt and the settlement claim in the memo.
pub fn repayment_request(
    buyer: &SigningKey,
    assignment: &Assignment,
    date: u32,
) -> Result<RepaymentRequest, Error> {
    assignment.validate()?;
    let receipt = Receipt::sign(
        buyer,
        ReceiptKind::Repayment,
        assignment.nullifier,
        assignment.amount_zat,
        date,
    )?;
    let claim = SettlementDoc::for_assignment(assignment).buyer_seal(buyer);
    let memo = memo::encode(&[
        MemoItem::Receipt(receipt.clone()),
        MemoItem::Seal(claim.clone()),
    ])?;
    let uri = zip321_uri(&[Payment {
        address: assignment.financier_address.clone(),
        amount_zat: assignment.amount_zat,
        memo: Some(PaymentMemo::Arbitrary(memo)),
    }])?;
    Ok(RepaymentRequest {
        uri,
        receipt,
        claim,
    })
}

/// The buyer's seal on the assignment letter (written acknowledgment of the assignment).
pub fn seal_assignment(
    buyer: &SigningKey,
    assignment: &Assignment,
    supplier_seal: &Seal,
) -> Result<Seal, Error> {
    Ok(assignment.seal_next(buyer, std::slice::from_ref(supplier_seal))?)
}

/// QR code of a payment URI as an SVG document (error correction M, quiet zone included).
pub fn qr_svg(uri: &str) -> Result<String, Error> {
    let code = qr(uri)?;
    Ok(code
        .render::<svg::Color<'_>>()
        .min_dimensions(320, 320)
        .build())
}

fn qr(uri: &str) -> Result<QrCode, Error> {
    QrCode::with_error_correction_level(uri.as_bytes(), EcLevel::M)
        .map_err(|e| Error::Qr(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use qrcode::Color;

    const ADDRESS: &str = "utest1s2gsurwfaat8ehuz3a3v2egu75qj6fgmenjf6y2l2q5m9dttvrhzhqaz3ggdgfq3nn36f2lt2vz9ecqq8emsmptf5c2ztte2n7sw2km4sxh0mdsvy06rkzxkekn48jl9cad5hj4hv74kd7gd8rrds3tl65gzard2tmnrkmtzj2ll8dfac6xq7kudfmqyxk8093349cfhpa8r23eqa2s";

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    fn letter() -> Assignment {
        Assignment {
            nullifier: [7; 32],
            amount_zat: 50_000,
            due_date: 20_437,
            financier_pk: key(3).verifying_key().to_bytes(),
            terms_hash: [5; 32],
            financier_address: ADDRESS.into(),
        }
    }

    #[test]
    fn request_carries_a_receipt_and_a_claim_signed_by_the_buyer() {
        let req = repayment_request(&key(2), &letter(), 20_437).unwrap();
        assert!(req
            .uri
            .starts_with(&format!("zcash:{ADDRESS}?amount=0.0005&memo=")));
        let buyer_pk = key(2).verifying_key().to_bytes();
        req.receipt.verify(&buyer_pk).unwrap();
        SettlementDoc::for_assignment(&letter())
            .verify_claim(&req.claim, &buyer_pk)
            .unwrap();
        // memo = base64url (no padding) of 346 bytes = 462 characters
        let memo = req.uri.rsplit("memo=").next().unwrap();
        assert_eq!(memo.len(), 462);
        let mut bad = letter();
        bad.amount_zat = 0;
        assert!(repayment_request(&key(2), &bad, 1).is_err());
    }

    #[test]
    fn qr_decodes_back_to_the_uri() {
        let req = repayment_request(&key(2), &letter(), 20_437).unwrap();
        let code = qr(&req.uri).unwrap();
        // render modules as a bitmap (4 px per module, 4-module quiet zone) and decode it
        let (w, scale, quiet) = (code.width(), 4usize, 4usize);
        let size = (w + 2 * quiet) * scale;
        let colors = code.to_colors();
        let mut img = rqrr::PreparedImage::prepare_from_bitmap(size, size, |x, y| {
            let (mx, my) = (x / scale, y / scale);
            mx >= quiet
                && my >= quiet
                && mx < quiet + w
                && my < quiet + w
                && colors[(my - quiet) * w + (mx - quiet)] == Color::Dark
        });
        let grids = img.detect_grids();
        assert_eq!(grids.len(), 1);
        let (_, content) = grids[0].decode().unwrap();
        assert_eq!(content, req.uri);

        let svg = qr_svg(&req.uri).unwrap();
        assert!(svg.contains("<svg"));
    }
}
