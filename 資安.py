import os
import hashlib
import hmac
from dataclasses import dataclass

# -----------------------------
# Utilities
# -----------------------------


def int_to_bytes(x: int) -> bytes:
    if x == 0:
        return b"\x00"
    return x.to_bytes((x.bit_length() + 7) // 8, "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def modinv(a: int, m: int) -> int:
    # a^{-1} mod m
    return pow(a, -1, m)


def kdf_split(k_int: int, k1_len=32, k2_len=32) -> tuple[bytes, bytes]:
    """
    論文說可以先 hash/fold 再 split k 成 k1,k2。
    這裡用 SHA-512(k_bytes) 當作 KDF，再切成 k1,k2。
    """
    kb = int_to_bytes(k_int)
    digest = hashlib.sha512(kb).digest()
    k1 = digest[:k1_len]
    k2 = digest[k1_len:k1_len + k2_len]
    return k1, k2


def KH(k2: bytes, m: bytes, out_bits: int, q: int) -> int:
    """
    Keyed-hash: r = KH_{k2}(m)
    實作：HMAC-SHA256(k2, m) -> 截位 -> 映射到 [0, q-1]
    out_bits 建議約等於 |q|/2（論文 4.1 提到用來減少 overhead 的選擇）:contentReference[oaicite:3]{index=3}
    """
    mac = hmac.new(k2, m, hashlib.sha256).digest()
    r_int = bytes_to_int(mac)
    if out_bits is not None:
        r_int = r_int >> max(0, (len(mac)*8 - out_bits))
    return r_int % q

# -----------------------------
# Symmetric encryption (AES-GCM preferred)
# -----------------------------


def aesgcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        return xor_stream_encrypt(key, plaintext)  # fallback (demo only)

    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, associated_data=None)
    return nonce + ct  # pack


def aesgcm_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        return xor_stream_decrypt(key, ciphertext)  # fallback (demo only)

    nonce, ct = ciphertext[:12], ciphertext[12:]
    return AESGCM(key).decrypt(nonce, ct, associated_data=None)


def xor_stream_encrypt(key: bytes, plaintext: bytes) -> bytes:
    # Demo-only fallback: keystream = SHA256(key||counter)
    out = bytearray()
    counter = 0
    i = 0
    while i < len(plaintext):
        counter_bytes = counter.to_bytes(4, "big")
        ks = hashlib.sha256(key + counter_bytes).digest()
        chunk = plaintext[i:i+len(ks)]
        out.extend(bytes(a ^ b for a, b in zip(chunk, ks)))
        i += len(ks)
        counter += 1
    return bytes(out)


def xor_stream_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    return xor_stream_encrypt(key, ciphertext)

# -----------------------------
# Parameters & Keys
# -----------------------------


@dataclass
class GroupParams:
    p: int  # large prime
    q: int  # large prime factor of p-1
    g: int  # generator of subgroup order q mod p


@dataclass
class KeyPair:
    x: int  # secret
    y: int  # public = g^x mod p


def keygen(params: GroupParams) -> KeyPair:
    # secret in [1, q-1]
    x = int.from_bytes(os.urandom(64), "big") % (params.q - 1) + 1
    y = pow(params.g, x, params.p)
    return KeyPair(x=x, y=y)

# -----------------------------
# Signcryption (SCS1 / SCS2) per paper section 3.2 :contentReference[oaicite:4]{index=4}
# -----------------------------


def signcrypt_SCS1(params: GroupParams, alice: KeyPair, bob_pub: int, m: bytes,
                   r_bits: int | None = None) -> tuple[bytes, int, int]:
    """
    SCS1 (from SDSS1):
    1) pick x, k = yb^x mod p, split -> k1,k2
    2) r = KH_{k2}(m)
    3) s = x / (r + xa) mod q
    4) c = E_{k1}(m)
    output (c,r,s)
    """
    x = int.from_bytes(os.urandom(64), "big") % (params.q - 1) + 1
    k = pow(bob_pub, x, params.p)
    k1, k2 = kdf_split(k)
    r = KH(k2, m, out_bits=r_bits, q=params.q)
    denom = (r + alice.x) % params.q
    s = (x * modinv(denom, params.q)) % params.q
    c = aesgcm_encrypt(k1, m)
    return c, r, s


def unsigncrypt_SCS1(params: GroupParams, alice_pub: int, bob: KeyPair,
                     c: bytes, r: int, s: int,
                     r_bits: int | None = None) -> bytes:
    """
    Bob recovers k:
    k = (ya * g^r)^(s*xb) mod p
    then split -> k1,k2; m = D_{k1}(c); verify KH_{k2}(m) == r
    """
    base = (alice_pub * pow(params.g, r, params.p)) % params.p
    # exponent reduced mod q (subgroup)
    k = pow(base, (s * bob.x) % params.q, params.p)
    k1, k2 = kdf_split(k)
    m = aesgcm_decrypt(k1, c)
    r_check = KH(k2, m, out_bits=r_bits, q=params.q)
    if r_check != r:
        raise ValueError("Verification failed: r != KH_{k2}(m)")
    return m


def signcrypt_SCS2(params: GroupParams, alice: KeyPair, bob_pub: int, m: bytes,
                   r_bits: int | None = None) -> tuple[bytes, int, int]:
    """
    SCS2 (from SDSS2):
    r = KH_{k2}(m)
    s = x / (1 + xa*r) mod q
    """
    x = int.from_bytes(os.urandom(64), "big") % (params.q - 1) + 1
    k = pow(bob_pub, x, params.p)
    k1, k2 = kdf_split(k)
    r = KH(k2, m, out_bits=r_bits, q=params.q)
    denom = (1 + (alice.x * r) % params.q) % params.q
    s = (x * modinv(denom, params.q)) % params.q
    c = aesgcm_encrypt(k1, m)
    return c, r, s


def unsigncrypt_SCS2(params: GroupParams, alice_pub: int, bob: KeyPair,
                     c: bytes, r: int, s: int,
                     r_bits: int | None = None) -> bytes:
    """
    k = (g * ya^r)^(s*xb) mod p
    """
    base = (params.g * pow(alice_pub, r, params.p)) % params.p
    k = pow(base, (s * bob.x) % params.q, params.p)
    k1, k2 = kdf_split(k)
    m = aesgcm_decrypt(k1, c)
    r_check = KH(k2, m, out_bits=r_bits, q=params.q)
    if r_check != r:
        raise ValueError("Verification failed: r != KH_{k2}(m)")
    return m

# -----------------------------
# Demo runner
# -----------------------------


def demo():
    """
    注意：這裡 params 需要是一個安全的 (p,q,g) 子群設定。
    報告展示可用現成安全參數（例如 RFC/標準的 DSA subgroup）。
    你也可以先用小參數做概念展示，但不要宣稱安全。
    """
    # 這裡故意不內建 p,q,g，避免你誤用不安全的玩具參數上交實作。
    raise NotImplementedError(
        "Provide secure DSA-like subgroup params (p,q,g) to run demo.")


if __name__ == "__main__":
    demo()
