"""Pure-Python X25519 (RFC 7748), used only as a last-resort fallback.

After pycryptodome's compiled Ed25519 code crashed the whole process on a
real Android device (see wire_ed25519_pure.py), its compiled X25519 code
was replaced here too rather than assumed safe - same toolchain, same risk,
no reason to trust one elliptic-curve native module over its sibling.

This is the reference Montgomery-ladder implementation from RFC 7748
Section 5 itself. Slower than compiled code, but wire.py only does a
handful of ECDH exchanges per login or connection, never in a hot loop, and
it cannot segfault. Checked byte-for-byte against `cryptography`'s X25519
output in tests/test_crypto_backend_compat.py.
"""
from __future__ import annotations

_P = 2 ** 255 - 19
_A24 = 121665
_BITS = 255


def _decode_little_endian(b: bytes) -> int:
    return int.from_bytes(b, "little")


def _decode_u_coordinate(u: bytes) -> int:
    masked = bytearray(u)
    masked[-1] &= (1 << (_BITS % 8)) - 1  # 255 % 8 == 7
    return _decode_little_endian(bytes(masked))


def _encode_u_coordinate(u: int) -> bytes:
    return (u % _P).to_bytes(32, "little")


def _decode_scalar(k: bytes) -> int:
    clamped = bytearray(k)
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    return _decode_little_endian(bytes(clamped))


def _cswap(swap: int, x2: int, x3: int) -> tuple[int, int]:
    dummy = swap * ((x2 - x3) % _P)
    return (x2 - dummy) % _P, (x3 + dummy) % _P


def _scalarmult(k: int, u: int) -> int:
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in reversed(range(_BITS)):
        k_t = (k >> t) & 1
        swap ^= k_t
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        swap = k_t
        A = (x2 + z2) % _P
        AA = (A * A) % _P
        B = (x2 - z2) % _P
        BB = (B * B) % _P
        E = (AA - BB) % _P
        C = (x3 + z3) % _P
        D = (x3 - z3) % _P
        DA = (D * A) % _P
        CB = (C * B) % _P
        x3 = pow(DA + CB, 2, _P)
        z3 = (x1 * pow(DA - CB, 2, _P)) % _P
        x2 = (AA * BB) % _P
        z2 = (E * (AA + _A24 * E)) % _P
    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)
    return (x2 * pow(z2, _P - 2, _P)) % _P


_BASE_U = 9


def public_from_private(raw_private: bytes) -> bytes:
    if len(raw_private) != 32:
        raise ValueError("an X25519 private key is 32 bytes")
    k = _decode_scalar(raw_private)
    return _encode_u_coordinate(_scalarmult(k, _BASE_U))


def exchange(raw_private: bytes, raw_peer_public: bytes) -> bytes:
    if len(raw_private) != 32:
        raise ValueError("an X25519 private key is 32 bytes")
    if len(raw_peer_public) != 32:
        raise ValueError("an X25519 public key is 32 bytes")
    k = _decode_scalar(raw_private)
    u = _decode_u_coordinate(raw_peer_public)
    shared = _scalarmult(k, u)
    if shared == 0:
        # RFC 7748 Section 6.1: reject an all-zero output (low-order point).
        raise ValueError("X25519 produced a degenerate (all-zero) shared secret")
    return _encode_u_coordinate(shared)
