"""Independent generator for the HNK-01 invoice test vector.

Pure-Python Ed25519 (RFC 8032 §5.1, reference algorithm) and the canonical invoice layout from
jitsuin-core/src/invoice.rs + vault Format Data. Self-checks against RFC 8032 test 1 first.
"""
import datetime
import hashlib
import sys

p = 2**255 - 19
q = 2**252 + 27742317777372353535851937790883648493
d = (-121665 * pow(121666, p - 2, p)) % p
I = pow(2, (p - 1) // 4, p)


def H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def recover_x(y: int, sign: int):
    if y >= p:
        return None
    x2 = (y * y - 1) * pow(d * y * y + 1, p - 2, p) % p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * I % p
    if (x * x - x2) % p != 0:
        return None
    if x & 1 != sign:
        x = p - x
    return x


Gy = 4 * pow(5, p - 2, p) % p
G = (recover_x(Gy, 0), Gy, 1, recover_x(Gy, 0) * Gy % p)


def add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C = 2 * P[3] * Q[3] * d % p
    D = 2 * P[2] * Q[2] % p
    E, F, Gg, Hh = B - A, D - C, D + C, B + A
    return (E * F % p, Gg * Hh % p, F * Gg % p, E * Hh % p)


def mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = add(Q, P)
        P = add(P, P)
        s >>= 1
    return Q


def compress(P) -> bytes:
    zinv = pow(P[2], p - 2, p)
    x = P[0] * zinv % p
    y = P[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def decompresses(b: bytes) -> bool:
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    return recover_x(y, sign) is not None


def expand(secret: bytes):
    h = H(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def pubkey(secret: bytes) -> bytes:
    a, _ = expand(secret)
    return compress(mul(a, G))


def sign(secret: bytes, msg: bytes) -> bytes:
    a, prefix = expand(secret)
    A = compress(mul(a, G))
    r = int.from_bytes(H(prefix + msg), "little") % q
    R = compress(mul(r, G))
    h = int.from_bytes(H(R + A + msg), "little") % q
    s = (r + h * a) % q
    return R + int.to_bytes(s, 32, "little")


# RFC 8032 §7.1 test 1
sk1 = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
assert pubkey(sk1).hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
assert sign(sk1, b"").hex() == ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")

buyer_seed = hashlib.sha256(b"jitsuinfi HNK-01 test vector v1 / buyer").digest()
supplier_seed = hashlib.sha256(b"jitsuinfi HNK-01 test vector v1 / supplier ephemeral").digest()
buyer_pk = pubkey(buyer_seed)
supplier_pk = pubkey(supplier_seed)
invoice_id = b"TES-INV-0001"
amount = 125_000_000  # 1.25 ZEC
issue = (datetime.date(2026, 10, 19) - datetime.date(1970, 1, 1)).days
due = issue + 30
terms = hashlib.sha256(b"TES terms v1: net 30").digest()

canon = (b"JTSI" + bytes([1, len(invoice_id)]) + invoice_id + supplier_pk + buyer_pk
         + amount.to_bytes(8, "little") + issue.to_bytes(4, "little") + due.to_bytes(4, "little") + terms)
sig = sign(buyer_seed, canon)

# a 32-byte string that is NOT a valid compressed Ed25519 point (for the invalid-key test)
bad = None
for y in range(2, 1000):
    cand = y.to_bytes(32, "little")
    if not decompresses(cand):
        bad = cand
        break
assert bad is not None

lines = [
    "# HNK-01 canonical invoice test vector v1 (generated independently in pure Python, RFC 8032 Ed25519).",
    "# Regenerate: python gen_invoice_vector.py > invoice_v1.txt: every value must match jitsuin-core.",
    f"buyer_seed={buyer_seed.hex()}",
    f"supplier_seed={supplier_seed.hex()}",
    f"buyer_pk={buyer_pk.hex()}",
    f"supplier_ephemeral_pk={supplier_pk.hex()}",
    f"invoice_id={invoice_id.decode()}",
    f"amount_zat={amount}",
    f"issue_date={issue}",
    f"due_date={due}",
    f"terms_hash={terms.hex()}",
    f"canonical={canon.hex()}",
    f"signature={sig.hex()}",
    f"invalid_point={bad.hex()}",
]
sys.stdout.write("\n".join(lines) + "\n")
