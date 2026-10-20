"""A pycryptodome-based drop-in for the small slice of `cryptography` that
wire.py uses, for platforms where `cryptography` itself cannot be installed.

`cryptography`'s modern releases need a Rust toolchain to cross-compile, and
that does not work reliably in python-for-android's Android build (the
toolchain this project's Android app is built with) - other projects (e.g.
Sideband/Reticulum) hit the same wall and dropped `cryptography` on Android.
pycryptodome is pure C with no Rust dependency and has a working Android
build recipe.

Every primitive below was checked byte-for-byte against `cryptography`'s own
output before this module was written - see tests/test_crypto_backend_compat.py,
which runs against both backends whenever `cryptography` is installed (every
desktop test run) and will fail loudly if either implementation ever drifts.
wire.py imports from here only when `cryptography` is not importable at all,
so desktop behavior is completely unaffected by this module.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from typing import Optional

from Crypto.Cipher import AES
from Crypto.Protocol.DH import import_x25519_private_key, import_x25519_public_key
from Crypto.Protocol.KDF import HKDF as _pycryptodome_hkdf
from Crypto.Protocol.KDF import scrypt as _pycryptodome_scrypt
from Crypto.Hash import SHA256 as _pycryptodome_sha256

import wire_ed25519_pure


class InvalidTag(Exception):
    """Raised when AES-GCM authentication fails, matching cryptography.exceptions.InvalidTag."""


class InvalidToken(Exception):
    """Raised when a Fernet token is invalid/tampered, matching cryptography.fernet.InvalidToken."""


class InvalidSignature(Exception):
    """Raised when an Ed25519 signature fails to verify, matching cryptography.exceptions.InvalidSignature."""


def scrypt(password: bytes, salt: bytes, n: int, r: int, p: int, dklen: int = 32) -> bytes:
    return _pycryptodome_scrypt(password, salt, dklen, N=n, r=r, p=p)


# --- X25519 (RFC 7748) ---------------------------------------------------

class X25519PublicKey:
    def __init__(self, raw: bytes) -> None:
        if len(raw) != 32:
            raise ValueError("an X25519 public key is 32 bytes")
        self._raw = bytes(raw)

    @classmethod
    def from_public_bytes(cls, data: bytes) -> "X25519PublicKey":
        return cls(bytes(data))

    def public_bytes(self, encoding=None, format=None) -> bytes:
        return self._raw

    def public_bytes_raw(self) -> bytes:
        return self._raw


class X25519PrivateKey:
    def __init__(self, raw: bytes) -> None:
        if len(raw) != 32:
            raise ValueError("an X25519 private key is 32 bytes")
        self._raw = bytes(raw)
        self._key = import_x25519_private_key(self._raw)

    @classmethod
    def generate(cls) -> "X25519PrivateKey":
        import os
        return cls(os.urandom(32))

    @classmethod
    def from_private_bytes(cls, data: bytes) -> "X25519PrivateKey":
        return cls(bytes(data))

    def private_bytes(self, encoding=None, format=None, encryption_algorithm=None) -> bytes:
        return self._raw

    def public_key(self) -> X25519PublicKey:
        return X25519PublicKey(self._key.pointQ.x.to_bytes(32, "little"))

    def exchange(self, peer_public_key: X25519PublicKey) -> bytes:
        peer = import_x25519_public_key(peer_public_key.public_bytes_raw())
        shared_point = peer.pointQ * self._key.d
        return shared_point.x.to_bytes(32, "little")


# --- Ed25519 (RFC 8032) ---------------------------------------------------

class Ed25519PublicKey:
    def __init__(self, raw: bytes) -> None:
        if len(raw) != 32:
            raise ValueError("an Ed25519 public key is 32 bytes")
        self._raw = bytes(raw)

    @classmethod
    def from_public_bytes(cls, data: bytes) -> "Ed25519PublicKey":
        return cls(bytes(data))

    def public_bytes(self, encoding=None, format=None) -> bytes:
        return self._raw

    def public_bytes_raw(self) -> bytes:
        return self._raw

    def verify(self, signature: bytes, data: bytes) -> None:
        # Pure Python, not pycryptodome's compiled _ed25519.abi3.so: that
        # native module crashes the whole process (no catchable exception,
        # no tombstone) within milliseconds of first use on at least one
        # real Android device. X25519 from the same pycryptodome build is
        # unaffected and stays as-is; only Ed25519 needed this fallback.
        try:
            wire_ed25519_pure.verify(signature, data, self._raw)
        except ValueError as exc:
            raise InvalidSignature(str(exc)) from exc


class Ed25519PrivateKey:
    def __init__(self, raw: bytes) -> None:
        if len(raw) != 32:
            raise ValueError("an Ed25519 private key is 32 bytes")
        self._raw = bytes(raw)
        self._public = wire_ed25519_pure.public_from_seed(self._raw)

    @classmethod
    def generate(cls) -> "Ed25519PrivateKey":
        import os
        return cls(os.urandom(32))

    @classmethod
    def from_private_bytes(cls, data: bytes) -> "Ed25519PrivateKey":
        return cls(bytes(data))

    def private_bytes(self, encoding=None, format=None, encryption_algorithm=None) -> bytes:
        return self._raw

    def public_key(self) -> Ed25519PublicKey:
        return Ed25519PublicKey(self._public)

    def sign(self, data: bytes) -> bytes:
        return wire_ed25519_pure.sign(data, self._raw, self._public)


class x25519:  # noqa: N801 - matches the `x25519` module name wire.py imports
    X25519PrivateKey = X25519PrivateKey
    X25519PublicKey = X25519PublicKey


class ed25519:  # noqa: N801 - matches the `ed25519` module name wire.py imports
    Ed25519PrivateKey = Ed25519PrivateKey
    Ed25519PublicKey = Ed25519PublicKey


# --- AES-256-GCM -----------------------------------------------------------

class AESGCM:
    def __init__(self, key: bytes) -> None:
        self._key = key

    def encrypt(self, nonce: bytes, data: bytes, associated_data: Optional[bytes]) -> bytes:
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)
        if associated_data:
            cipher.update(associated_data)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return ciphertext + tag

    def decrypt(self, nonce: bytes, data: bytes, associated_data: Optional[bytes]) -> bytes:
        if len(data) < 16:
            raise InvalidTag("ciphertext too short to contain a GCM tag")
        body, tag = data[:-16], data[-16:]
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)
        if associated_data:
            cipher.update(associated_data)
        try:
            return cipher.decrypt_and_verify(body, tag)
        except ValueError as exc:
            raise InvalidTag(str(exc)) from exc


# --- HKDF-SHA256 -------------------------------------------------------------

class _SHA256Algorithm:
    """Sentinel matching cryptography.hazmat.primitives.hashes.SHA256()."""


class hashes:  # noqa: N801 - matches the `hashes` module name wire.py imports
    SHA256 = _SHA256Algorithm


class HKDF:
    def __init__(self, algorithm, length: int, salt: Optional[bytes], info: Optional[bytes]) -> None:
        if not isinstance(algorithm, _SHA256Algorithm):
            raise ValueError("this HKDF shim only implements SHA-256")
        self._length = length
        self._salt = salt or b""
        self._info = info or b""

    def derive(self, key_material: bytes) -> bytes:
        return _pycryptodome_hkdf(key_material, self._length, salt=self._salt,
                                   hashmod=_pycryptodome_sha256, context=self._info)


# --- serialization namespace (Raw encoding only, which is all wire.py uses) -

class _Encoding:
    Raw = "raw"


class _PrivateFormat:
    Raw = "raw"


class _PublicFormat:
    Raw = "raw"


class NoEncryption:
    pass


class serialization:  # noqa: N801 - matches the `serialization` module name wire.py imports
    Encoding = _Encoding
    PrivateFormat = _PrivateFormat
    PublicFormat = _PublicFormat
    NoEncryption = NoEncryption


# --- Fernet (matches cryptography.fernet.Fernet's exact token format) ------

class Fernet:
    """Re-implements cryptography.fernet's token format exactly: a version
    byte, an 8-byte big-endian timestamp, a 16-byte IV, AES-128-CBC
    ciphertext, and a 32-byte HMAC-SHA256 signature, all base64url-encoded.
    Required so an identity backup encrypted by this backend can be
    decrypted by a real `cryptography`-based Wire client, and vice versa.
    """
    _VERSION = b"\x80"

    def __init__(self, key: bytes) -> None:
        raw_key = base64.urlsafe_b64decode(key)
        if len(raw_key) != 32:
            raise ValueError("Fernet key must decode to 32 bytes")
        self._signing_key = raw_key[:16]
        self._encryption_key = raw_key[16:]

    def encrypt(self, data: bytes) -> bytes:
        import os
        iv = os.urandom(16)
        pad_len = 16 - (len(data) % 16)
        padded = data + bytes([pad_len]) * pad_len
        ciphertext = AES.new(self._encryption_key, AES.MODE_CBC, iv=iv).encrypt(padded)
        header = self._VERSION + struct.pack(">Q", int(time.time())) + iv + ciphertext
        signature = hmac.new(self._signing_key, header, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(header + signature)

    def decrypt(self, token: bytes, ttl: Optional[int] = None) -> bytes:
        try:
            decoded = base64.urlsafe_b64decode(token)
        except Exception as exc:
            raise InvalidToken("not valid base64") from exc
        if len(decoded) < 25 + 32 or decoded[0:1] != self._VERSION:
            raise InvalidToken("bad version or truncated token")
        header, signature = decoded[:-32], decoded[-32:]
        expected = hmac.new(self._signing_key, header, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, signature):
            raise InvalidToken("signature mismatch")
        iv, ciphertext = header[9:25], header[25:]
        if not ciphertext or len(ciphertext) % 16 != 0:
            raise InvalidToken("bad ciphertext length")
        try:
            padded = AES.new(self._encryption_key, AES.MODE_CBC, iv=iv).decrypt(ciphertext)
        except ValueError as exc:
            raise InvalidToken("bad ciphertext") from exc
        pad_len = padded[-1]
        if not 1 <= pad_len <= 16 or padded[-pad_len:] != bytes([pad_len]) * pad_len:
            raise InvalidToken("bad padding")
        return padded[:-pad_len]


# --- minimal X.509 reader (DER, Ed25519 SubjectPublicKeyInfo only) ---------

# RFC 8410 fixes the DER encoding of an Ed25519 SubjectPublicKeyInfo: a
# 12-byte header (outer SEQUENCE, algorithm SEQUENCE, the Ed25519 OID
# 1.3.101.112, and the 33-byte BIT STRING wrapper) immediately followed by
# the raw 32-byte public key. That header is a fixed byte string, so finding
# it directly is sufficient without a general ASN.1 parser - the directory's
# TLS certificate here always embeds exactly one Ed25519 public key.
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


class _Certificate:
    def __init__(self, der: bytes) -> None:
        index = der.find(_ED25519_SPKI_PREFIX)
        if index == -1:
            raise ValueError("certificate does not contain an Ed25519 public key")
        start = index + len(_ED25519_SPKI_PREFIX)
        self._public_key = Ed25519PublicKey(der[start:start + 32])

    def public_key(self) -> Ed25519PublicKey:
        return self._public_key


class x509:  # noqa: N801 - matches the `x509` module name wire.py imports
    @staticmethod
    def load_der_x509_certificate(der: bytes) -> _Certificate:
        return _Certificate(der)
