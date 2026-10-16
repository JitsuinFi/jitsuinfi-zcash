//! Buyer side of the repayment (HNK-06.T2): a ZIP-321 payment request to the financier, with a
//! repayment receipt signed by the buyer in the memo, and its QR code.
//!
//! The buyer key is the one that signed the invoice, so every holder of the invoice can verify
//! the receipt. Any ZIP-321 wallet can pay the request; the memo travels unchanged.

use ed25519_dalek::SigningKey;
use jitsuin_core::{Receipt, ReceiptKind, RECEIPT_LEN};
use jitsuin_wallet::{zip321_uri, Payment, PaymentMemo};
use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};

use crate::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepaymentRequest {
    /// `zcash:<financier address>?amount=…&memo=…` (memo = base64url of the 146-byte receipt).
    pub uri: String,
    pub receipt: Receipt,
}

/// Builds the repayment request for the invoice behind `nullifier`. `financier_address` comes
/// from the assignment letter; `amount_zat` is the amount due.
pub fn repayment_request(
    buyer: &SigningKey,
    nullifier: [u8; 32],
    financier_address: &str,
    amount_zat: u64,
    date: u32,
) -> Result<RepaymentRequest, Error> {
    let receipt = Receipt::sign(buyer, ReceiptKind::Repayment, nullifier, amount_zat, date)?;
    let uri = zip321_uri(&[Payment {
        address: financier_address.to_string(),
        amount_zat,
        memo: Some(PaymentMemo::Arbitrary(
            receipt.to_memo_bytes()[..RECEIPT_LEN].to_vec(),
        )),
    }])?;
    Ok(RepaymentRequest { uri, receipt })
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

    fn buyer() -> SigningKey {
        SigningKey::from_bytes(&[2; 32])
    }

    #[test]
    fn request_carries_a_buyer_signed_receipt() {
        let req = repayment_request(&buyer(), [7; 32], ADDRESS, 50_000, 20_437).unwrap();
        assert!(req
            .uri
            .starts_with(&format!("zcash:{ADDRESS}?amount=0.0005&memo=")));
        assert_eq!(req.receipt.kind, ReceiptKind::Repayment);
        req.receipt
            .verify(&buyer().verifying_key().to_bytes())
            .unwrap();
        // memo = base64url (no padding) of the 146-byte receipt = 195 characters
        let memo = req.uri.rsplit("memo=").next().unwrap();
        assert_eq!(memo.len(), 195);
        assert!(repayment_request(&buyer(), [7; 32], ADDRESS, 0, 1).is_err());
        assert!(repayment_request(&buyer(), [7; 32], "bad&addr", 1, 1).is_err());
    }

    #[test]
    fn qr_decodes_back_to_the_uri() {
        let req = repayment_request(&buyer(), [7; 32], ADDRESS, 50_000, 20_437).unwrap();
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
