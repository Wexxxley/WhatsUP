import os
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from tools.generate_certificate import ensure_server_certificate


class TestServerCertificateGeneration(unittest.TestCase):
    def test_existing_certificate_and_key_are_preserved(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cert_dir = Path(temp_dir)
            cert_path = cert_dir / "server.crt"
            key_path = cert_dir / "server.key"
            cert_path.write_bytes(b"existing certificate")
            key_path.write_bytes(b"existing key")

            generated = ensure_server_certificate(cert_dir)

            self.assertFalse(generated)
            self.assertEqual(cert_path.read_bytes(), b"existing certificate")
            self.assertEqual(key_path.read_bytes(), b"existing key")

    def test_missing_part_of_pair_generates_matching_certificate_and_key(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cert_dir = Path(temp_dir)
            (cert_dir / "server.crt").write_bytes(b"stale certificate")

            generated = ensure_server_certificate(cert_dir)

            self.assertTrue(generated)
            private_key = serialization.load_pem_private_key(
                (cert_dir / "server.key").read_bytes(),
                password=None,
            )
            certificate = x509.load_pem_x509_certificate(
                (cert_dir / "server.crt").read_bytes()
            )
            self.assertEqual(
                certificate.public_key().public_numbers(),
                private_key.public_key().public_numbers(),
            )
            self.assertEqual(
                os.stat(cert_dir / "server.key").st_mode & 0o777,
                0o600,
            )


if __name__ == "__main__":
    unittest.main()
