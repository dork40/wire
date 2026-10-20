"""wire_crypto_android.py re-implements wire.py's small `cryptography`
surface on top of pycryptodome, for the Android build where `cryptography`
itself cannot be compiled (it needs a Rust toolchain python-for-android does
not provide). These tests pin every primitive to cryptography's real output
byte-for-byte, so the two backends can never silently drift - a device on
one backend must always be able to talk to, and recover identities created
on, a device using the other.
"""
import importlib.util
import os
import unittest
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    from cryptography.hazmat.primitives import hashes as real_hashes
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF as RealHKDF
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as RealAESGCM
    from cryptography.fernet import Fernet as RealFernet
    from cryptography import x509 as real_x509
    from cryptography.x509.oid import NameOID
    import datetime
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False

spec = importlib.util.spec_from_file_location(
    "wire_crypto_android", Path(__file__).parents[1] / "wire_crypto_android.py"
)
shim = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shim)


@unittest.skipUnless(HAVE_CRYPTOGRAPHY, "cryptography is not installed; nothing to compare against")
class CryptoBackendCompatTests(unittest.TestCase):
    def test_x25519_exchange_matches_both_directions(self):
        a_raw, b_raw = os.urandom(32), os.urandom(32)
        real_a, real_b = x25519.X25519PrivateKey.from_private_bytes(a_raw), x25519.X25519PrivateKey.from_private_bytes(b_raw)
        shim_a, shim_b = shim.X25519PrivateKey.from_private_bytes(a_raw), shim.X25519PrivateKey.from_private_bytes(b_raw)

        real_a_pub = real_a.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        shim_a_pub = shim_a.public_key().public_bytes()
        self.assertEqual(real_a_pub, shim_a_pub)

        real_shared = real_a.exchange(x25519.X25519PublicKey.from_public_bytes(real_b.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)))
        shim_shared = shim_a.exchange(shim.X25519PublicKey.from_public_bytes(shim_b.public_key().public_bytes()))
        self.assertEqual(real_shared, shim_shared)

        # Cross-backend exchange: a real private key with a shim public key (and
        # vice versa) must derive the identical shared secret either way.
        cross_1 = real_a.exchange(x25519.X25519PublicKey.from_public_bytes(shim_b.public_key().public_bytes()))
        cross_2 = shim_b.exchange(shim.X25519PublicKey.from_public_bytes(real_a_pub))
        self.assertEqual(real_shared, cross_1)
        self.assertEqual(real_shared, cross_2)

    def test_ed25519_sign_and_verify_cross_backend(self):
        raw = os.urandom(32)
        message = b"wire-v1 cross backend check"
        real_priv = ed25519.Ed25519PrivateKey.from_private_bytes(raw)
        shim_priv = shim.Ed25519PrivateKey.from_private_bytes(raw)

        real_pub_bytes = real_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.assertEqual(real_pub_bytes, shim_priv.public_key().public_bytes())

        real_sig = real_priv.sign(message)
        shim_sig = shim_priv.sign(message)
        self.assertEqual(real_sig, shim_sig)

        shim.Ed25519PublicKey.from_public_bytes(real_pub_bytes).verify(real_sig, message)
        ed25519.Ed25519PublicKey.from_public_bytes(real_pub_bytes).verify(shim_sig, message)

        with self.assertRaises(shim.InvalidSignature):
            shim.Ed25519PublicKey.from_public_bytes(real_pub_bytes).verify(real_sig, b"tampered")

    def test_aes_gcm_ciphertext_and_decrypt_match(self):
        key, nonce, aad = os.urandom(32), os.urandom(12), b"wire-v1-message"
        plaintext = b"same ciphertext from either backend, please"
        real_ct = RealAESGCM(key).encrypt(nonce, plaintext, aad)
        shim_ct = shim.AESGCM(key).encrypt(nonce, plaintext, aad)
        self.assertEqual(real_ct, shim_ct)
        self.assertEqual(shim.AESGCM(key).decrypt(nonce, real_ct, aad), plaintext)
        self.assertEqual(RealAESGCM(key).decrypt(nonce, shim_ct, aad), plaintext)
        with self.assertRaises(shim.InvalidTag):
            shim.AESGCM(key).decrypt(nonce, real_ct[:-1] + bytes([real_ct[-1] ^ 1]), aad)

    def test_hkdf_sha256_matches(self):
        shared = os.urandom(32)
        real_out = RealHKDF(algorithm=real_hashes.SHA256(), length=32, salt=None, info=b"wire-v1").derive(shared)
        shim_out = shim.HKDF(algorithm=shim.hashes.SHA256(), length=32, salt=None, info=b"wire-v1").derive(shared)
        self.assertEqual(real_out, shim_out)

    def test_scrypt_matches_hashlib(self):
        import hashlib
        salt = os.urandom(16)
        real_out = hashlib.scrypt(b"a password", salt=salt, n=2**14, r=8, p=5, dklen=32)
        shim_out = shim.scrypt(b"a password", salt, n=2**14, r=8, p=5, dklen=32)
        self.assertEqual(real_out, shim_out)

    def test_fernet_tokens_interop_both_directions(self):
        key = __import__("base64").urlsafe_b64encode(os.urandom(32))
        payload = b'{"name": "alice", "private": "..."}'
        real_token = RealFernet(key).encrypt(payload)
        shim_token = shim.Fernet(key).encrypt(payload)
        self.assertEqual(shim.Fernet(key).decrypt(real_token), payload)
        self.assertEqual(RealFernet(key).decrypt(shim_token), payload)

    def test_fernet_rejects_tampered_tokens(self):
        key = __import__("base64").urlsafe_b64encode(os.urandom(32))
        token = bytearray(shim.Fernet(key).encrypt(b"secret"))
        token[-1] ^= 1
        with self.assertRaises(shim.InvalidToken):
            shim.Fernet(key).decrypt(bytes(token))

    def test_ed25519_public_key_extracted_from_a_real_tls_certificate(self):
        key = ed25519.Ed25519PrivateKey.generate()
        subject = issuer = real_x509.Name([real_x509.NameAttribute(NameOID.COMMON_NAME, "Wire Directory")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (real_x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                .public_key(key.public_key()).serial_number(real_x509.random_serial_number())
                .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(real_x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(key, None))
        der = cert.public_bytes(encoding=Encoding.DER)
        extracted = shim.x509.load_der_x509_certificate(der).public_key()
        self.assertIsInstance(extracted, shim.Ed25519PublicKey)
        self.assertEqual(extracted.public_bytes_raw(), key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


if __name__ == "__main__":
    unittest.main()
