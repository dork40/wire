"""Pure-Python Ed25519 (RFC 8032), used only as a last-resort fallback.

pycryptodome's compiled `_ed25519.abi3.so` crashes the process on first use
on at least one real Android device tested against this build (NDK 28c,
Python 3.14, arm64-v8a) - no catchable Python exception, no tombstone, the
process simply dies a few milliseconds after that .so loads. X25519 from the
same pycryptodome build works fine, so only Ed25519 is replaced here.

This is the reference implementation from the original Ed25519 paper
(Bernstein, Duif, Lange, Schwabe, Yang), long published as the canonical
"definitely correct, not fast" fallback. It is slow (milliseconds, not
microseconds) but wire.py only signs/verifies a handful of times per login
or connection, never in a hot loop, so that cost is not noticeable in this
project's actual usage - and it cannot segfault, unlike the native module it
replaces. Checked byte-for-byte against `cryptography`'s Ed25519 output in
tests/test_crypto_backend_compat.py.
"""
from __future__ import annotations

import hashlib

_b = 256
_q = 2 ** 255 - 19
_l = 2 ** 252 + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _expmod(base: int, e: int, m: int) -> int:
    if e == 0:
        return 1
    t = _expmod(base, e // 2, m) ** 2 % m
    if e & 1:
        t = (t * base) % m
    return t


def _inv(x: int) -> int:
    return _expmod(x, _q - 2, _q)


_d = -121665 * _inv(121666) % _q
_I = _expmod(2, (_q - 1) // 4, _q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = _expmod(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = 4 * _inv(5)
_Bx = _xrecover(_By)
_BASE = (_Bx % _q, _By % _q)


def _edwards(P: tuple[int, int], Q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2)
    return (x3 % _q, y3 % _q)


def _scalarmult(P: tuple[int, int], e: int) -> tuple[int, int]:
    if e == 0:
        return (0, 1)
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q


def _encodeint(y: int) -> bytes:
    return y.to_bytes(_b // 8, "little")


def _encodepoint(P: tuple[int, int]) -> bytes:
    x, y = P
    out = bytearray(y.to_bytes(_b // 8, "little"))
    out[-1] = (out[-1] & 0x7F) | ((x & 1) << 7)
    return bytes(out)


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _clamped_scalar(h: bytes) -> int:
    a = 2 ** (_b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, _b - 2))
    return a


def _hint(m: bytes) -> int:
    h = _H(m)
    return int.from_bytes(h, "little")


def public_from_seed(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("an Ed25519 seed is 32 bytes")
    h = _H(seed)
    a = _clamped_scalar(h)
    A = _scalarmult(_BASE, a)
    return _encodepoint(A)


def sign(message: bytes, seed: bytes, public_key: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("an Ed25519 seed is 32 bytes")
    h = _H(seed)
    a = _clamped_scalar(h)
    r = _hint(h[_b // 8:_b // 4] + message)
    R = _scalarmult(_BASE, r)
    encoded_r = _encodepoint(R)
    s = (r + _hint(encoded_r + public_key + message) * a) % _l
    return encoded_r + _encodeint(s)


def _isoncurve(P: tuple[int, int]) -> bool:
    x, y = P
    return (-x * x + y * y - 1 - _d * x * x * y * y) % _q == 0


def _decodeint(s: bytes) -> int:
    return int.from_bytes(s, "little")


def _decodepoint(s: bytes) -> tuple[int, int]:
    y = int.from_bytes(s, "little") & ((1 << (_b - 1)) - 1)
    x = _xrecover(y)
    if (x & 1) != _bit(s, _b - 1):
        x = _q - x
    P = (x, y)
    if not _isoncurve(P):
        raise ValueError("decoding point that is not on the curve")
    return P


def verify(signature: bytes, message: bytes, public_key: bytes) -> None:
    """Raise ValueError when the signature does not verify."""
    if len(signature) != _b // 4:
        raise ValueError("signature length is wrong")
    if len(public_key) != _b // 8:
        raise ValueError("public key length is wrong")
    R = _decodepoint(signature[: _b // 8])
    A = _decodepoint(public_key)
    S = _decodeint(signature[_b // 8: _b // 4])
    if S >= _l:
        # RFC 8032 requires 0 <= S < L. Without this, S + k*L verifies
        # identically for any k, letting an attacker mutate a valid
        # signature into other "valid" signatures for the same message -
        # caught by a real on-device review (Codex) testing this exact
        # case against cryptography's own Ed25519, which rejects it.
        raise ValueError("signature S value is not canonical (S >= L)")
    h = _hint(_encodepoint(R) + public_key + message)
    left = _scalarmult(_BASE, S)
    right = _edwards(R, _scalarmult(A, h))
    if left != right:
        raise ValueError("signature does not pass verification")
