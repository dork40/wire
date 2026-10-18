import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import wire


class PrivateServerTests(unittest.TestCase):
    def test_parses_lan_tailscale_dns_and_custom_port(self):
        self.assertEqual(wire.parse_directory_endpoint("192.168.1.199"), ("192.168.1.199", 47666))
        self.assertEqual(wire.parse_directory_endpoint("100.90.80.70:49000"), ("100.90.80.70", 49000))
        self.assertEqual(wire.parse_directory_endpoint("wirebox.example.net"), ("wirebox.example.net", 47666))
        self.assertEqual(wire.parse_directory_endpoint("[fd7a:115c:a1e0::1]:47666"), ("fd7a:115c:a1e0::1", 47666))

    def test_rejects_urls_paths_and_bad_ports(self):
        for value in ("https://nas:47666", "nas/path", "nas name", "nas:0", "nas:70000", "bad_name"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                wire.parse_directory_endpoint(value)

    def test_private_choice_persists_before_login(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / "server.json"
            with patch.object(wire, "SERVER_CONFIG", config), patch.object(wire, "DATA", Path(temp)):
                app = wire.Wire()
                app.switch_directory("private", "192.168.1.50", 47666)
                self.assertEqual(json.loads(config.read_text(encoding="utf-8")), {
                    "mode": "private", "host": "192.168.1.50", "port": 47666,
                })

    def test_public_mode_restores_default_endpoint(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / "server.json"
            with patch.object(wire, "SERVER_CONFIG", config), patch.object(wire, "DATA", Path(temp)):
                wire.save_directory_config("private", "10.0.0.5", 47666)
                wire.save_directory_config("public", wire.DEFAULT_DIRECTORY_HOST, wire.DEFAULT_DIRECTORY_PORT)
                self.assertEqual(wire.load_directory_config()["mode"], "public")


if __name__ == "__main__":
    unittest.main()
