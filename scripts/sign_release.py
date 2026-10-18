"""Create Wire's release manifest with the offline Ed25519 release key."""

import argparse
import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    raw = base64.b64decode(args.key.read_text(encoding="ascii").strip(), validate=True)
    if len(raw) != 32:
        raise ValueError("release signing key must contain one base64-encoded 32-byte key")
    message = b"wire-update-v1\0" + args.commit.encode("ascii") + b"\0" + args.version.encode("ascii")
    signature = ed25519.Ed25519PrivateKey.from_private_bytes(raw).sign(message)
    value = {
        "version": args.version,
        "commit": args.commit,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    args.output.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
