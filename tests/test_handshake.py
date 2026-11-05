import unittest
import tempfile
from pathlib import Path

from protocol.ids import generate_client_id
from protocol.keys import generate_key_pair, serialize_public_key
from protocol.handshake import (
    create_server_handshake_response,
    verify_server_handshake_response
)
from cryptography.exceptions import InvalidSignature
from tools.generate_certificate import generate_server_credentials

class TestHandshake(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.cert_path = Path(cls.temp_dir.name) / "server.crt"
        cls.priv_key, cls.cert_bytes = generate_server_credentials(
            Path(cls.temp_dir.name)
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_handshake_positive(self):
        client_id = generate_client_id()
        _, pk = generate_key_pair()
        pk_bytes = serialize_public_key(pk)
        
        response, salt_srv = create_server_handshake_response(
            self.priv_key,
            self.cert_bytes,
            pk_bytes,
            client_id
        )
        
        verified_salt = verify_server_handshake_response(
            response,
            str(self.cert_path),
            pk_bytes,
            client_id
        )
        
        self.assertEqual(verified_salt, salt_srv)
        self.assertEqual(len(verified_salt), 16)
        print("Teste positivo de handshake passou!")

    def test_handshake_negative_signature_corruption(self):
        client_id = generate_client_id()
        _, pk = generate_key_pair()
        pk_bytes = serialize_public_key(pk)
        
        response, _ = create_server_handshake_response(
            self.priv_key,
            self.cert_bytes,
            pk_bytes,
            client_id
        )
        
        cert_len = int.from_bytes(response[:4], 'big')
        sig_len_idx = 4 + cert_len
        sig_len = int.from_bytes(response[sig_len_idx:sig_len_idx+4], 'big')
        sig_start = sig_len_idx + 4
        
        corrupted_response = bytearray(response)
        corrupted_response[sig_start + sig_len - 1] ^= 0xFF
        
        with self.assertRaises((InvalidSignature, ValueError)):
            verify_server_handshake_response(
                bytes(corrupted_response),
                str(self.cert_path),
                pk_bytes,
                client_id
            )
        print("Teste negativo de corrupção de assinatura passou!")

    def test_handshake_negative_salt_corruption(self):
        client_id = generate_client_id()
        _, pk = generate_key_pair()
        pk_bytes = serialize_public_key(pk)
        
        response, _ = create_server_handshake_response(
            self.priv_key,
            self.cert_bytes,
            pk_bytes,
            client_id
        )
        
        corrupted_response = bytearray(response)
        corrupted_response[-1] ^= 0xFF
        
        with self.assertRaises((InvalidSignature, ValueError)):
            verify_server_handshake_response(
                bytes(corrupted_response),
                str(self.cert_path),
                pk_bytes,
                client_id
            )
        print("Teste negativo de corrupção de salt passou!")

    def test_handshake_signature_is_bound_to_client_key_and_id(self):
        client_id = generate_client_id()
        other_client_id = generate_client_id()
        _, client_pk = generate_key_pair()
        _, other_client_pk = generate_key_pair()
        client_pk_bytes = serialize_public_key(client_pk)
        other_client_pk_bytes = serialize_public_key(other_client_pk)
        response, _ = create_server_handshake_response(
            self.priv_key, self.cert_bytes, client_pk_bytes, client_id
        )

        with self.assertRaises(InvalidSignature):
            verify_server_handshake_response(
                response, str(self.cert_path), other_client_pk_bytes, client_id
            )

        with self.assertRaises(InvalidSignature):
            verify_server_handshake_response(
                response, str(self.cert_path), client_pk_bytes, other_client_id
            )

    def test_handshake_rejects_a_different_pinned_certificate(self):
        client_id = generate_client_id()
        _, client_pk = generate_key_pair()
        client_pk_bytes = serialize_public_key(client_pk)

        with tempfile.TemporaryDirectory() as other_dir:
            other_cert_path = Path(other_dir) / "server.crt"
            _, other_cert_bytes = generate_server_credentials(Path(other_dir))
            other_cert_path.write_bytes(other_cert_bytes)
            response, _ = create_server_handshake_response(
                self.priv_key, self.cert_bytes, client_pk_bytes, client_id
            )

            with self.assertRaisesRegex(ValueError, "Pinning"):
                verify_server_handshake_response(
                    response, str(other_cert_path), client_pk_bytes, client_id
                )

if __name__ == "__main__":
    unittest.main()