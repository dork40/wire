import base64
import json
from unittest import TestCase, mock

from cryptography.hazmat.primitives.asymmetric import ed25519

import wire


class _Response:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.value).encode("utf-8")


class SignedUpdateTests(TestCase):
    def manifest(self):
        private = ed25519.Ed25519PrivateKey.generate()
        version = "9.8.7"
        commit = "a" * 40
        message = b"wire-update-v1\0" + commit.encode() + b"\0" + version.encode()
        signature = base64.b64encode(private.sign(message)).decode()
        public = base64.b64encode(private.public_key().public_bytes_raw()).decode()
        return private, public, {"version": version, "commit": commit, "signature": signature}

    def test_valid_signed_manifest_is_accepted(self):
        _private, public, manifest = self.manifest()
        with mock.patch.object(wire, "RELEASE_SIGNING_PUBLIC_KEY", public), \
             mock.patch.object(wire.urllib.request, "urlopen", return_value=_Response(manifest)):
            self.assertEqual(wire.verified_release_manifest(), {"version": "9.8.7", "commit": "a" * 40})

    def test_tampered_manifest_is_rejected(self):
        _private, public, manifest = self.manifest()
        manifest["version"] = "9.8.8"
        with mock.patch.object(wire, "RELEASE_SIGNING_PUBLIC_KEY", public), \
             mock.patch.object(wire.urllib.request, "urlopen", return_value=_Response(manifest)):
            with self.assertRaisesRegex(ValueError, "signature verification failed"):
                wire.verified_release_manifest()

    def test_updater_refuses_same_or_older_signed_release(self):
        with mock.patch.object(wire, "verified_release_manifest", return_value={"version": "1.0.0", "commit": "a" * 40}), \
             mock.patch.object(wire, "wire_version", return_value="Wire v1.0.0"), \
             mock.patch.object(wire.os, "name", "nt"):
            with self.assertRaisesRegex(ValueError, "already up to date"):
                wire.start_update_after_exit()
