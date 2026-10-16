# jitsuinfi-zcash

Zcash protocol and integration layer for **JitsuinFi**, private invoice financing without double financing.

> Zcash stops double-spending. JitsuinFi stops double-financing.

Crates:
- `crates/jitsuin-core`: canonical invoices, buyer signatures, shielded registry entries (ZIP-302 memo).
- `crates/jitsuin-wallet`: wallet backend wrapping `zcash-devtool` (sync, ZIP-321 payments with memos, transaction listing).

Status: in development for ZECATHON 2026. Development runs on Zcash testnet (NU7).
