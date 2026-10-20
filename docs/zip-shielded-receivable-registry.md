# Shielded Receivable Registry

```
Title: Shielded Receivable Registry: double-financing prevention for invoices over Zcash memos
Status: Draft (ZECATHON 2026)
Category: Application
Reference implementation: jitsuinfi-zcash (crates jitsuin-core, jitsuin-board, jitsuin-flow, jitsuin-wasm)
```

## Abstract

This document specifies a registry that lets financiers check, without learning anything about other deals, whether an invoice has already been financed. Each invoice has a nullifier `N` derived from its canonical encoding. Financiers register `N` on a public *board*: a Zcash shielded account whose full viewing key is published, receiving entries as ZIP 302 arbitrary-data memos. A supplier who registers the same invoice for two financiers produces two entries for one `N`, both signed with the supplier's per-invoice key, which is a cryptographic proof of double signing. Money moves only in shielded pools. The specification also covers chained multi-party signatures over the deal documents (seals), a payment flow in which the last signature and the money travel in one transaction, two-party settlement, an anchored buyer payment history, and solvency checks for a pooled fund.

## Motivation

Invoice financing lets a supplier sell an unpaid invoice to a financier. Its oldest fraud is double financing: the same invoice is sold to several financiers. Existing registries are either central databases that see every deal, or public ledgers that expose trading relationships, amounts and parties. Zcash already solves the same problem for money: a note's nullifier prevents double spending without revealing which note was spent. This registry applies the same idea to receivables: *Zcash stops double-spending; the registry stops double-financing.*

Goals:
1. A financier can tell whether an invoice is already registered, and prove double signing, before paying.
2. Outsiders learn no parties, amounts or documents.
3. Griefers cannot block an invoice by registering it first.
4. No smart contract or new consensus rule: only shielded transactions and memos.

## Conventions

All integers are little-endian. `BLAKE2b-256(p, x)` is BLAKE2b with 32-byte output and 16-byte personalization `p`; without `p`, no personalization. `‖` is concatenation. Signatures are Ed25519 (RFC 8032), verified with *strict* verification (non-canonical signatures and small-order keys are rejected). Dates are days since the Unix epoch (UTC). Amounts are in zatoshi. Every memo starts with the ZIP 302 arbitrary-data marker `0xFF` and is zero padded to 512 bytes; decoders MUST reject non-zero padding.

## Specification

### 1. Canonical invoice

| Field | Size |
|---|---|
| magic `JTSI` | 4 |
| version `0x01` | 1 |
| `invoice_id` length | 1 (1–32) |
| `invoice_id` | printable ASCII `0x21`–`0x7E` |
| `supplier_ephemeral_pk` | 32 — a fresh Ed25519 key for this invoice only |
| `buyer_pk` | 32 |
| `amount_zat` | 8, > 0 |
| `issue_date` | 4 |
| `due_date` | 4, ≥ `issue_date` |
| `terms_hash` | 32 — SHA-256 of the off-chain document, computed by the client |

The buyer signs the canonical bytes: `sig_buyer = Ed25519.sign(buyer_sk, bytes)`. Decoders MUST reject unknown magic or version, truncated input, trailing bytes, and invalid keys.

### 2. Nullifier

```
N = BLAKE2b-256("JitsuinNullifier", canonical_invoice_bytes)
```

`N` MUST NOT depend on any signature: Ed25519 is deterministic only by convention, and a signer with random nonces could otherwise give one invoice two nullifiers. `N` cannot be guessed without the invoice because the canonical bytes include the random `supplier_ephemeral_pk`.

### 3. Board and register entries

The board is a shielded Zcash account; its UFVK is published so anyone can scan it with a watch-only wallet. Memos are only readable after fetching full transactions (compact blocks carry no memos).

Register entry, kind `0x01` (136 bytes) or `0x03` (168 bytes, with a buyer history tag):

| Offset | Field | Size |
|---|---|---|
| 0 | `0xFF` | 1 |
| 1 | magic `JTS1` | 4 |
| 5 | kind | 1 |
| 6 | `N` | 32 |
| 38 | `financier_commitment = BLAKE2b-256(financier_pk ‖ salt)` | 32 |
| 70 | `discount_bucket` | 1 |
| 71 | `tenor_bucket` | 1 |
| 72 | `history_tag` (kind `0x03` only) | 32 |
| 72 / 104 | `sig_supplier` over bytes 1 up to this offset, by `supplier_ephemeral_pk` | 64 |

**Classes.** `discount_bucket` and `tenor_bucket` feed the public rate index. They are `0/0` (not disclosed) unless the supplier opts in: a holder of the invoice can find the entry by `N` and read them. A financier MUST accept an entry whose classes are either the deal's classes or `0/0`, and MUST refuse any other pair.

**Ordering.** Entries are totally ordered by (block height, transaction index in the block, output index). The transaction index is taken from lightwalletd `GetBlock`.

**Lookup.** A holder of the invoice computes `N` and considers the register entries (kinds `0x01` and `0x03`) with that `N` whose `sig_supplier` verifies under `supplier_ephemeral_pk`; all others are ignored (anti-griefing). The first such entry is the registration. A later entry with the *same* `financier_commitment` is a re-post. A later entry with a *different* commitment is double financing.

**Financier rule.** A financier MUST NOT pay before its own entry is the first valid entry for `N` with at least one confirmation, and MUST re-check the board immediately before paying (a later double financing stops the payment; a missing entry after a reorganization returns to waiting).

### 4. Memo container and receipts

A memo may carry several items back to back after `0xFF`:

| Item | Magic | Length without marker |
|---|---|---|
| Receipt | `JTR1` | 145 |
| Seal | `JTL1` | 200 |
| Receivable note | `JTN1` | 48 |
| Liability root | `JTLR` | 144 |

Receipt: magic, kind (`0x01` advance, `0x02` repayment), `N`, `amount_zat` (8, > 0), date (4), `signer_pk` (32), signature over the preceding bytes (64). A receipt is valid when signed by the expected key and its amount equals the value of the output that carries it.

### 5. Seals

A seal is a signature by one role in a fixed order over one document:

| Offset | Field | Size |
|---|---|---|
| 0 | magic `JTL1` | 4 |
| 4 | document kind (`0x01` invoice, `0x02` assignment, `0x03` settlement) | 1 |
| 5 | document id = `N` | 32 |
| 37 | `BLAKE2b-256("JitsuinDocument_", canonical_document)` | 32 |
| 69 | step | 1 |
| 70 | role (`0x01` supplier, `0x02` buyer, `0x03` financier) | 1 |
| 71 | flag | 1 |
| 72 | `BLAKE2b-256("JitsuinSealHash_", previous seal)`, zero at step 0 | 32 |
| 104 | `signer_pk` | 32 |
| 136 | signature over bytes 0–135 | 64 |

Policies: invoice = (buyer); assignment = (supplier, buyer, financier); settlement = (buyer, financier). Verifiers MUST reject skipped or reordered steps, broken links, seals for another document, signers other than the role's key, and one key holding two roles.

### 6. Assignment letter and Sign-to-Pay

Assignment letter: magic `JTSA`, version, `N`, `amount_zat`, `due_date`, `financier_pk`, `terms_hash`, address length (2), financier shielded address (1–512 ASCII alphanumeric). `N`, amount and due date MUST match the invoice. The buyer's seal is the written acknowledgment of the assignment.

The financier MUST NOT pay the advance before the supplier and buyer seals verify. The advance output's memo carries the advance receipt, the financier's seal (which completes the letter) and a receivable note, so the last signature and the money arrive in one shielded transaction.

### 7. Settlement

Settlement document (private): magic `JTSS`, version, `N`, `amount_zat`, `due_date`. The buyer's repayment memo carries a repayment receipt and the buyer's settlement seal (the claim). Once mined payments matching `N` cover the amount, the financier countersigns with flag `0x01` (paid on or before `due_date`) or `0x02` (late) and posts a settled entry:

| Offset | Field | Size |
|---|---|---|
| 0 | `0xFF` | 1 |
| 1 | `JTS1` | 4 |
| 5 | kind `0x02` | 1 |
| 6 | `settled_tag = BLAKE2b-256(N ‖ "settled")` | 32 |
| 38 | flag | 1 |
| 39 | buyer seal signature | 64 |
| 103 | financier seal signature | 64 |

The entry carries no `N`, commitment or bucket, so it cannot be linked to its register entry without `N`. Holders of `N` rebuild both seals and verify them. A buyer claim without a covering mined payment MUST NOT be countersigned.

### 8. Buyer history chain

The buyer derives keys from a 32-byte master secret (for example a WebAuthn PRF output): `seed = BLAKE2b-256(key = master, "JitsuinBuyerKey_", input)` with `input = "identity"` or `"invoice" ‖ index (4)`. Invoice `i` uses the key for index `i` as `buyer_pk`.

History certificate (277 bytes): magic `JTSH`, version, index, invoice key, supplier key, `N`, amount, due date, financier key, previous certificate hash (`BLAKE2b-256("JitsuinHistory__", previous)`, zero for index 0), identity key, identity signature. The register entry of invoice `i` is kind `0x03` with `history_tag = BLAKE2b-256("JitsuinHistTag__", identity_pk ‖ previous_hash)`.

A verifier given certificates `0..k` MUST check: a gap-free chain from index 0 under one identity; exactly one register entry carrying each certificate's tag, for its `N`, signed by its supplier key (two such entries are equivocation); and **no** entry carrying the tag that would follow certificate `k`. Each invoice's outcome is read from the board: a valid settled entry (on time or late), or none after the due date plus grace (default).

### 9. Pooled fund (optional)

Members holding the UFVK of a fund's operational account compute solvency themselves: cash (account balance) plus, for every advance carrying a manager-signed receipt and a receivable note (`JTN1`: `N`, face amount, due date), the face amount minus repayments received for `N`, overdue amounts after a haircut, compared with the total of the latest manager-signed liability root (`JTLR`: period, Merkle sum root of member deposits, total, manager key, signature).

### 10. Verification bundle and double-signature proof

Bundle `JTSB`: typed items (invoice, buyer signature, assignment letter, assignment seals, settlement document). Proof `JTSP`: invoice, buyer signature, two register entries with optional board positions. A proof is valid when the buyer signed the invoice and both entries are register entries for its `N`, signed by its `supplier_ephemeral_pk`, with different commitments. Both verify offline.

## Security considerations

- **Double financing** is detected by any holder of the invoice and proven by two supplier-signed entries; the proof needs no transaction when the second entry was only offered.
- **Griefing**: entries not signed by the supplier key from the invoice are ignored; the board is append-only, so griefers only add noise.
- **No smart contract**: payment ordering is enforced by the financier's software and by signed documents, not by consensus. Collusion between supplier and buyer (fictitious invoices) is outside what a registry can detect.
- **Repayment disputes**: a payment is never counted unless mined; a false buyer claim is signed evidence. A financier denying a real payment cannot yet be disproven to third parties without payment disclosure.
- **History**: anchoring makes trimming, forking and posing as a new buyer detectable; a fresh identity is limited by KYC binding and new-buyer limits.

## Privacy considerations

Outsiders see shielded transactions, their timing, and board entries containing hashes and opaque signatures. They can see that some invoice was registered or settled, and that an `N` appears twice, but not which invoice, which parties or which amounts. The first history tag of a buyer can be computed by anyone who knows the buyer's identity key. Viewing keys cannot be revoked; separate accounts per role and period limit exposure.

## Test vectors

Canonical invoice (supplier secret key 32×`0x01`, buyer secret key 32×`0x02`, `invoice_id` `TES-INV-0001`, amount 1 000 000 000, issue 20 377, due 20 437, `terms_hash` 32×`0x09`):

```
canonical = 4a545349010c5445532d494e562d303030318a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39400ca9a3b00000000994f0000d54f00000909090909090909090909090909090909090909090909090909090909090909
sig_buyer = 11b59c4dbce361601b4ba66f246b4ca17469722f506e23fa8d63de28b6acc142b091392510709c67fedd800bc93b8e7a7321c362363c8d04ca164d2a1e76cb0b
N         = 3513c284b075c8efbd27da2de1ad9eb673bcbb8c45ae087a9a594c35c8064a6e
```

Other vectors:

| Input | Output |
|---|---|
| `SHA-256("TES-terms")` | `00082d1119307d17036738bf382daab1bfe963280b44b7dc050f5ad30542b229` |
| `financier_commitment(32×0x03, salt 32×0x04)` | `c72255e7b3f5bd4f2e652cf71eceb37d0b35074f2bb11c4a788ce2282d982b3a` |
| `settled_tag(32×0x07)` | `745dd5c7a8c41316f9c712e9aef7e458ece60e0a3ef1914ad47bee144c13a494` |
| buyer invoice seed, master 32×`0x42`, index 0 | `b467d39acc924edc21c631f77e1f1a6781dbd254efa0cc344ab1c7beaf34ac98` |

Every vector is asserted by the reference implementation's unit tests (`cargo test --workspace`) and was cross-checked with Python's `hashlib`.

## Reference implementation

`jitsuinfi-zcash`: `jitsuin-core` (formats), `jitsuin-board` (scanner, lookup, history checks), `jitsuin-flow` (financier state machine, settlement watchdog, fund solvency), `jitsuin-wasm` (browser package). All flows were exercised end to end on Zcash testnet (NU7, Ironwood pool) with test data prefixed `TES-`.
