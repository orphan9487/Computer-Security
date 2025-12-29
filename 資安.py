import os
import hashlib
import hmac
from dataclasses import dataclass

# -----------------------------
# Pretty-print helpers
# -----------------------------


def hr(title: str = ""):
    line = "=" * 70
    print("\n" + line)
    if title:
        print(title)
        print("-" * 70)


def fmt_int(x: int) -> str:
    return f"{x} (0x{x:x}, bits={x.bit_length()})"


def fmt_bytes(b: bytes, maxlen: int = 80) -> str:
    hx = b.hex()
    if len(hx) > maxlen:
        hx = hx[:maxlen] + "..."
    return f"len={len(b)} bytes, hex={hx}"

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
    return pow(a, -1, m)


def kdf_split(k_int: int, k1_len=32, k2_len=32) -> tuple[bytes, bytes]:
    kb = int_to_bytes(k_int)
    digest = hashlib.sha512(kb).digest()
    k1 = digest[:k1_len]
    k2 = digest[k1_len:k1_len + k2_len]
    return k1, k2


def KH(k2: bytes, m: bytes, out_bits: int | None, q: int) -> int:
    mac = hmac.new(k2, m, hashlib.sha256).digest()
    r_int = bytes_to_int(mac)
    if out_bits is not None:
        r_int = r_int >> max(0, (len(mac) * 8 - out_bits))
    return r_int % q

# -----------------------------
# Symmetric encryption (AES-GCM preferred)
# -----------------------------


def aesgcm_encrypt(key: bytes, plaintext: bytes, verbose: bool = False) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        if verbose:
            print("[AES] 使用 AES-GCM")
    except ImportError:
        if verbose:
            print("[AES] cryptography 未安裝，改用 XOR demo fallback（不安全）")
        return xor_stream_encrypt(key, plaintext)

    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, associated_data=None)
    packed = nonce + ct
    if verbose:
        print("[AES] nonce:", fmt_bytes(nonce))
        print("[AES] packed(ciphertext+tag):", fmt_bytes(packed))
    return packed


def aesgcm_decrypt(key: bytes, ciphertext: bytes, verbose: bool = False) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        if verbose:
            print("[AES] 使用 AES-GCM")
    except ImportError:
        if verbose:
            print("[AES] cryptography 未安裝，改用 XOR demo fallback（不安全）")
        return xor_stream_decrypt(key, ciphertext)

    nonce, ct = ciphertext[:12], ciphertext[12:]
    if verbose:
        print("[AES] nonce:", fmt_bytes(nonce))
        print("[AES] ct+tag:", fmt_bytes(ct))
    return AESGCM(key).decrypt(nonce, ct, associated_data=None)


def xor_stream_encrypt(key: bytes, plaintext: bytes) -> bytes:
    out = bytearray()
    counter = 0
    i = 0
    while i < len(plaintext):
        counter_bytes = counter.to_bytes(4, "big")
        ks = hashlib.sha256(key + counter_bytes).digest()
        chunk = plaintext[i:i + len(ks)]
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
    p: int
    q: int
    g: int


@dataclass
class KeyPair:
    x: int
    y: int


def keygen(params: GroupParams) -> KeyPair:
    x = int.from_bytes(os.urandom(64), "big") % (params.q - 1) + 1
    y = pow(params.g, x, params.p)
    return KeyPair(x=x, y=y)

# -----------------------------
# Verbose Signcryption / Unsigncryption
# -----------------------------


def signcrypt_SCS1_verbose(params: GroupParams, alice: KeyPair, bob_pub: int, m: bytes,
                           r_bits: int | None = None) -> tuple[bytes, int, int]:
    hr("SCS1 Signcrypt（Alice -> Bob）")
    print("[Input] m:", m)
    print("[Input] r_bits:", r_bits)

    x = int.from_bytes(os.urandom(64), "big") % (params.q - 1) + 1
    print("[1] 選一次性 x:", fmt_int(x))

    k = pow(bob_pub, x, params.p)
    print("[2] k = yb^x mod p:", fmt_int(k))

    k1, k2 = kdf_split(k)
    print("[3] KDF split k -> (k1,k2)")
    print("    k1:", fmt_bytes(k1))
    print("    k2:", fmt_bytes(k2))

    r = KH(k2, m, out_bits=r_bits, q=params.q)
    print("[4] r = KH_{k2}(m) mod q:", fmt_int(r))

    denom = (r + alice.x) % params.q
    print("[5] denom = (r + xa) mod q:", fmt_int(denom))
    s = (x * modinv(denom, params.q)) % params.q
    print("[6] s = x * inv(denom) mod q:", fmt_int(s))

    c = aesgcm_encrypt(k1, m, verbose=True)
    print("[7] c = E_{k1}(m):", fmt_bytes(c))

    print("[Output] (c, r, s) 完成")
    return c, r, s


def unsigncrypt_SCS1_verbose(params: GroupParams, alice_pub: int, bob: KeyPair,
                             c: bytes, r: int, s: int,
                             r_bits: int | None = None) -> bytes:
    hr("SCS1 Unsigncrypt（Bob）")
    print("[Input] c:", fmt_bytes(c))
    print("[Input] r:", fmt_int(r))
    print("[Input] s:", fmt_int(s))
    print("[Input] r_bits:", r_bits)

    g_r = pow(params.g, r, params.p)
    base = (alice_pub * g_r) % params.p
    print("[1] g^r mod p:", fmt_int(g_r))
    print("[2] base = (ya * g^r) mod p:", fmt_int(base))

    exp = (s * bob.x) % params.q
    print("[3] exp = (s * xb) mod q:", fmt_int(exp))

    k = pow(base, exp, params.p)
    print("[4] k = base^exp mod p:", fmt_int(k))

    k1, k2 = kdf_split(k)
    print("[5] KDF split k -> (k1,k2)")
    print("    k1:", fmt_bytes(k1))
    print("    k2:", fmt_bytes(k2))

    m = aesgcm_decrypt(k1, c, verbose=True)
    print("[6] m = D_{k1}(c):", m)

    r_check = KH(k2, m, out_bits=r_bits, q=params.q)
    print("[7] r_check = KH_{k2}(m) mod q:", fmt_int(r_check))

    if r_check != r:
        raise ValueError("Verification failed: r != KH_{k2}(m)")
    print("[8] 驗證成功：r_check == r")
    return m


def signcrypt_SCS2_verbose(params: GroupParams, alice: KeyPair, bob_pub: int, m: bytes,
                           r_bits: int | None = None) -> tuple[bytes, int, int]:
    hr("SCS2 Signcrypt（Alice -> Bob）")
    print("[Input] m:", m)
    print("[Input] r_bits:", r_bits)

    x = int.from_bytes(os.urandom(64), "big") % (params.q - 1) + 1
    print("[1] 選一次性 x:", fmt_int(x))

    k = pow(bob_pub, x, params.p)
    print("[2] k = yb^x mod p:", fmt_int(k))

    k1, k2 = kdf_split(k)
    print("[3] KDF split k -> (k1,k2)")
    print("    k1:", fmt_bytes(k1))
    print("    k2:", fmt_bytes(k2))

    r = KH(k2, m, out_bits=r_bits, q=params.q)
    print("[4] r = KH_{k2}(m) mod q:", fmt_int(r))

    denom = (1 + (alice.x * r) % params.q) % params.q
    print("[5] denom = (1 + xa*r) mod q:", fmt_int(denom))
    s = (x * modinv(denom, params.q)) % params.q
    print("[6] s = x * inv(denom) mod q:", fmt_int(s))

    c = aesgcm_encrypt(k1, m, verbose=True)
    print("[7] c = E_{k1}(m):", fmt_bytes(c))

    print("[Output] (c, r, s) 完成")
    return c, r, s


def unsigncrypt_SCS2_verbose(params: GroupParams, alice_pub: int, bob: KeyPair,
                             c: bytes, r: int, s: int,
                             r_bits: int | None = None) -> bytes:
    hr("SCS2 Unsigncrypt（Bob）")
    print("[Input] c:", fmt_bytes(c))
    print("[Input] r:", fmt_int(r))
    print("[Input] s:", fmt_int(s))
    print("[Input] r_bits:", r_bits)

    ya_r = pow(alice_pub, r, params.p)
    base = (params.g * ya_r) % params.p
    print("[1] ya^r mod p:", fmt_int(ya_r))
    print("[2] base = (g * ya^r) mod p:", fmt_int(base))

    exp = (s * bob.x) % params.q
    print("[3] exp = (s * xb) mod q:", fmt_int(exp))

    k = pow(base, exp, params.p)
    print("[4] k = base^exp mod p:", fmt_int(k))

    k1, k2 = kdf_split(k)
    print("[5] KDF split k -> (k1,k2)")
    print("    k1:", fmt_bytes(k1))
    print("    k2:", fmt_bytes(k2))

    m = aesgcm_decrypt(k1, c, verbose=True)
    print("[6] m = D_{k1}(c):", m)

    r_check = KH(k2, m, out_bits=r_bits, q=params.q)
    print("[7] r_check = KH_{k2}(m) mod q:", fmt_int(r_check))

    if r_check != r:
        raise ValueError("Verification failed: r != KH_{k2}(m)")
    print("[8] 驗證成功：r_check == r")
    return m

# -----------------------------
# Toy params (demo only)
# -----------------------------


def find_toy_params() -> GroupParams:
    p = 467
    q = 233
    for h in range(2, p - 1):
        g = pow(h, (p - 1) // q, p)  # h^2 mod p
        if g != 1 and pow(g, q, p) == 1:
            return GroupParams(p=p, q=q, g=g)
    raise RuntimeError("Failed to find toy params.")

# -----------------------------
# Demo runner (prints everything)
# -----------------------------


def demo(verbose_bits: int | None = 80):
    hr("初始化參數（玩具參數，僅示範流程）")
    params = find_toy_params()
    print("p:", fmt_int(params.p))
    print("q:", fmt_int(params.q))
    print("g:", fmt_int(params.g))
    print("Check (p-1) % q == 0:", (params.p - 1) % params.q == 0)
    print("Check g^q mod p == 1:", pow(params.g, params.q, params.p) == 1)

    hr("KeyGen")
    alice = keygen(params)
    bob = keygen(params)
    print("Alice xa:", fmt_int(alice.x))
    print("Alice ya:", fmt_int(alice.y))
    print("Bob   xb:", fmt_int(bob.x))
    print("Bob   yb:", fmt_int(bob.y))

    m = b"Hello, signcryption!"
    print("\n[Message] m:", m)

    # --- SCS1 ---
    c1, r1, s1 = signcrypt_SCS1_verbose(
        params, alice, bob.y, m, r_bits=verbose_bits)
    m1 = unsigncrypt_SCS1_verbose(
        params, alice.y, bob, c1, r1, s1, r_bits=verbose_bits)
    hr("SCS1 結果")
    print("Recovered m1:", m1)

    # --- SCS2 ---
    c2, r2, s2 = signcrypt_SCS2_verbose(
        params, alice, bob.y, m, r_bits=verbose_bits)
    m2 = unsigncrypt_SCS2_verbose(
        params, alice.y, bob, c2, r2, s2, r_bits=verbose_bits)
    hr("SCS2 結果")
    print("Recovered m2:", m2)

    # --- Tamper tests ---
    hr("竄改測試（Tamper tests）")
    try:
        from cryptography.exceptions import InvalidTag
    except ImportError:
        InvalidTag = Exception  # fallback

    print("\n[Tamper A] 改 r（通常會先觸發 AES-GCM InvalidTag）")
    try:
        _ = unsigncrypt_SCS1_verbose(
            params, alice.y, bob, c1, (r1 + 1) % params.q, s1, r_bits=verbose_bits)
        print("Tamper A FAILED（不應該發生）")
    except (ValueError, InvalidTag) as e:
        print("Tamper A OK:", type(e).__name__, "-", str(e))

    print("\n[Tamper B] 改密文 c 的 1 bit（必定 InvalidTag）")
    c1_bad = bytearray(c1)
    c1_bad[-1] ^= 1
    c1_bad = bytes(c1_bad)
    try:
        _ = unsigncrypt_SCS1_verbose(
            params, alice.y, bob, c1_bad, r1, s1, r_bits=verbose_bits)
        print("Tamper B FAILED（不應該發生）")
    except (ValueError, InvalidTag) as e:
        print("Tamper B OK:", type(e).__name__, "-", str(e))


if __name__ == "__main__":
    demo(verbose_bits=80)
