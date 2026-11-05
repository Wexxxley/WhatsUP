import tempfile
import unittest
from pathlib import Path

from cryptography import x509

from tools.generate_certificate import (
    generate_server_credentials,
    load_or_generate_server_credentials,
)


class TestServerCredentialGeneration(unittest.TestCase):
    def test_only_public_certificate_is_written(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cert_dir = Path(temp_dir)
            private_key, certificate_bytes = generate_server_credentials(cert_dir)
            certificate = x509.load_pem_x509_certificate(certificate_bytes)

            self.assertEqual(
                certificate.public_key().public_numbers(),
                private_key.public_key().public_numbers(),
            )
            self.assertEqual((cert_dir / "server.crt").read_bytes(), certificate_bytes)
            self.assertFalse((cert_dir / "server.key").exists())

    def test_each_call_generates_a_new_key_and_certificate(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cert_dir = Path(temp_dir)
            first_key, first_certificate = generate_server_credentials(cert_dir)
            second_key, second_certificate = generate_server_credentials(cert_dir)

            self.assertNotEqual(
                first_key.public_key().public_numbers().n,
                second_key.public_key().public_numbers().n,
            )
            self.assertNotEqual(first_certificate, second_certificate)
            self.assertFalse((cert_dir / "server.key").exists())

    def test_persistent_credentials_are_reused(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cert_dir = Path(temp_dir)
            first_key, first_certificate = load_or_generate_server_credentials(cert_dir)
            second_key, second_certificate = load_or_generate_server_credentials(cert_dir)

            self.assertEqual(first_certificate, second_certificate)
            self.assertEqual(
                first_key.public_key().public_numbers(),
                second_key.public_key().public_numbers(),
            )
            self.assertTrue((cert_dir / "server.key").exists())

    def test_mismatched_persistent_credentials_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cert_dir = Path(temp_dir)
            load_or_generate_server_credentials(cert_dir)
            replacement_key, _ = generate_server_credentials(cert_dir)
            self.assertTrue(replacement_key)

            with self.assertRaisesRegex(ValueError, "não corresponde"):
                load_or_generate_server_credentials(cert_dir)


if __name__ == "__main__":
    unittest.main()
