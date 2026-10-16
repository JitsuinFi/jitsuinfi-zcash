//! Minimal lightwalletd gRPC client: only what the scanner and the flows need (block transaction
//! order, chain tip).
//!
//! gRPC over HTTP/2 with hand-written protobuf, so no protoc or generated code is required
//! (spike SPK-08 proved `GetBlock` returns the transaction index of every transaction).

use crate::Error;

pub const TESTNET: &str = "https://testnet.zec.rocks:443";
pub const MAINNET: &str = "https://zec.rocks:443";

const GET_BLOCK: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlock";
const GET_LATEST_BLOCK: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock";

/// Txids (display hex, as shown by wallets and explorers) of one block, in block order.
pub fn block_txids(endpoint: &str, height: u32) -> Result<Vec<String>, Error> {
    let mut msg = vec![0x08];
    put_varint(&mut msg, u64::from(height));
    let block = unary(endpoint, GET_BLOCK, &msg)?;
    if block.is_empty() {
        return Err(Error::Lightwalletd(format!(
            "empty GetBlock response for height {height}"
        )));
    }
    parse_compact_block_txids(&block)
}

/// Block time (Unix seconds) of the block at `height` (`CompactBlock.time`, field 5).
pub fn block_time(endpoint: &str, height: u32) -> Result<u32, Error> {
    let mut msg = vec![0x08];
    put_varint(&mut msg, u64::from(height));
    parse_compact_block_time(&unary(endpoint, GET_BLOCK, &msg)?)
}

pub fn parse_compact_block_time(block: &[u8]) -> Result<u32, Error> {
    fields(block)?
        .into_iter()
        .find_map(|(f, v)| match (f, v) {
            (5, Value::Varint(t)) => u32::try_from(t).ok(),
            _ => None,
        })
        .ok_or_else(|| Error::Lightwalletd("CompactBlock without time".into()))
}

/// Height of the chain tip seen by lightwalletd (`GetLatestBlock`), used to count confirmations.
pub fn latest_height(endpoint: &str) -> Result<u32, Error> {
    parse_block_id_height(&unary(endpoint, GET_LATEST_BLOCK, &[])?)
}

/// `BlockID { height (1), hash (2) }` → height.
pub fn parse_block_id_height(block_id: &[u8]) -> Result<u32, Error> {
    fields(block_id)?
        .into_iter()
        .find_map(|(f, v)| match (f, v) {
            (1, Value::Varint(h)) => u32::try_from(h).ok(),
            _ => None,
        })
        .ok_or_else(|| Error::Lightwalletd("BlockID without height".into()))
}

/// One unary gRPC call; returns the response message without the 5-byte gRPC frame header.
fn unary(endpoint: &str, method: &str, msg: &[u8]) -> Result<Vec<u8>, Error> {
    let mut body = vec![0u8];
    body.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    body.extend_from_slice(msg);

    let client = reqwest::blocking::Client::builder()
        .http2_prior_knowledge()
        .build()
        .map_err(|e| Error::Lightwalletd(e.to_string()))?;
    let resp = client
        .post(format!("{}{}", endpoint.trim_end_matches('/'), method))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(body)
        .send()
        .map_err(|e| Error::Lightwalletd(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(Error::Lightwalletd(format!("HTTP {}", resp.status())));
    }
    let bytes = resp
        .bytes()
        .map_err(|e| Error::Lightwalletd(e.to_string()))?;
    if bytes.len() < 5 {
        return Err(Error::Lightwalletd(format!("empty response from {method}")));
    }
    Ok(bytes[5..].to_vec())
}

/// Extracts `vtx` (field 7) → `CompactTx { index (1), txid (2) }` from a CompactBlock message.
pub fn parse_compact_block_txids(block: &[u8]) -> Result<Vec<String>, Error> {
    let mut txs: Vec<(u64, String)> = Vec::new();
    for (field, value) in fields(block)? {
        if let (7, Value::Bytes(tx)) = (field, value) {
            let mut index = 0u64;
            let mut txid = String::new();
            for (f, v) in fields(tx)? {
                match (f, v) {
                    (1, Value::Varint(i)) => index = i,
                    (2, Value::Bytes(h)) => {
                        txid = h.iter().rev().map(|b| format!("{b:02x}")).collect()
                    }
                    _ => {}
                }
            }
            txs.push((index, txid));
        }
    }
    txs.sort_by_key(|(i, _)| *i);
    Ok(txs.into_iter().map(|(_, t)| t).collect())
}

enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Other,
}

fn fields(buf: &[u8]) -> Result<Vec<(u64, Value<'_>)>, Error> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        let key = varint(buf, &mut i)?;
        let (field, wire) = (key >> 3, key & 7);
        let value = match wire {
            0 => Value::Varint(varint(buf, &mut i)?),
            2 => {
                let len = varint(buf, &mut i)? as usize;
                let end = i
                    .checked_add(len)
                    .filter(|e| *e <= buf.len())
                    .ok_or_else(truncated)?;
                let v = Value::Bytes(&buf[i..end]);
                i = end;
                v
            }
            1 => {
                i = i
                    .checked_add(8)
                    .filter(|e| *e <= buf.len())
                    .ok_or_else(truncated)?;
                Value::Other
            }
            5 => {
                i = i
                    .checked_add(4)
                    .filter(|e| *e <= buf.len())
                    .ok_or_else(truncated)?;
                Value::Other
            }
            w => {
                return Err(Error::Lightwalletd(format!(
                    "unsupported protobuf wire type {w}"
                )))
            }
        };
        out.push((field, value));
    }
    Ok(out)
}

fn varint(buf: &[u8], i: &mut usize) -> Result<u64, Error> {
    let mut result = 0u64;
    for shift in (0..64).step_by(7) {
        let b = *buf.get(*i).ok_or_else(truncated)?;
        *i += 1;
        result |= u64::from(b & 0x7f) << shift;
        if b < 0x80 {
            return Ok(result);
        }
    }
    Err(Error::Lightwalletd("varint too long".into()))
}

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn truncated() -> Error {
    Error::Lightwalletd("truncated protobuf".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vtx_order_and_reverses_txid() {
        // vtx: index 1 txid [0x02;32], index 0 txid [0x01, 0x00 x31]
        let mut block = vec![0x10, 0x05]; // height = 5 (field 2), ignored
        for (idx, txid) in [
            (1u8, [0x02u8; 32]),
            (0u8, {
                let mut t = [0u8; 32];
                t[0] = 0x01;
                t
            }),
        ] {
            let mut tx = vec![0x08, idx, 0x12, 32];
            tx.extend_from_slice(&txid);
            block.push(0x3a);
            block.push(tx.len() as u8);
            block.extend_from_slice(&tx);
        }
        let txids = parse_compact_block_txids(&block).unwrap();
        assert_eq!(txids.len(), 2);
        assert_eq!(txids[0], format!("{}01", "00".repeat(31)));
        assert_eq!(txids[1], "02".repeat(32));
    }

    #[test]
    fn parses_block_id_height() {
        // height 4_509_045 (varint), hash 2 bytes
        let mut id = vec![0x08];
        put_varint(&mut id, 4_509_045);
        id.extend_from_slice(&[0x12, 0x02, 0xab, 0xcd]);
        assert_eq!(parse_block_id_height(&id).unwrap(), 4_509_045);
        assert!(parse_block_id_height(&[0x12, 0x00]).is_err());
    }

    #[test]
    fn parses_block_time() {
        let mut block = vec![0x10, 0x05, 0x28];
        put_varint(&mut block, 1_792_174_167);
        assert_eq!(parse_compact_block_time(&block).unwrap(), 1_792_174_167);
        assert!(parse_compact_block_time(&[0x10, 0x05]).is_err());
    }

    #[test]
    fn rejects_truncated() {
        assert!(parse_compact_block_txids(&[0x3a, 0x10, 0x08]).is_err());
    }
}
