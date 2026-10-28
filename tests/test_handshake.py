import unittest
from protocol.framing import send_frame, recv_frame
from protocol.ids import generate_client_id
from protocol.keys import generate_key_pair, serialize_public_key
from protocol.handshake import (
    load_server_private_key,
    load_server_certificate,
    get_server_pubkey_bytes,
    create_server_handshake_response,
    verify_server_handshake_response
)
from cryptography.exceptions import InvalidSignature

class TestHandshake(unittest.TestCase):
    def test_handshake_positive(self):
        priv_key = load_server_private_key("certs/server.key")
        with open("certs/server.crt", "rb") as f:
            cert_bytes = f.read()
            
        client_id = generate_client_id()
        _, pk = generate_key_pair()
        pk_bytes = serialize_public_key(pk)
        
        response, salt_srv = create_server_handshake_response(
            priv_key,
            cert_bytes,
            pk_bytes,
            client_id
        )
        
        verified_salt = verify_server_handshake_response(
            response,
            "certs/server.crt",
            pk_bytes,
            client_id
        )
        
        self.assertEqual(verified_salt, salt_srv)
        self.assertEqual(len(verified_salt), 16)
        print("Teste positivo de handshake passou!")

    def test_handshake_negative_signature_corruption(self):
        priv_key = load_server_private_key("certs/server.key")
        with open("certs/server.crt", "rb") as f:
            cert_bytes = f.read()
            
        client_id = generate_client_id()
        _, pk = generate_key_pair()
        pk_bytes = serialize_public_key(pk)
        
        response, _ = create_server_handshake_response(
            priv_key,
            cert_bytes,
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
                "certs/server.crt",
                pk_bytes,
                client_id
            )
        print("Teste negativo de corrupção de assinatura passou!")

    def test_handshake_negative_salt_corruption(self):
        priv_key = load_server_private_key("certs/server.key")
        with open("certs/server.crt", "rb") as f:
            cert_bytes = f.read()
            
        client_id = generate_client_id()
        _, pk = generate_key_pair()
        pk_bytes = serialize_public_key(pk)
        
        response, _ = create_server_handshake_response(
            priv_key,
            cert_bytes,
            pk_bytes,
            client_id
        )
        
        corrupted_response = bytearray(response)
        corrupted_response[-1] ^= 0xFF
        
        with self.assertRaises((InvalidSignature, ValueError)):
            verify_server_handshake_response(
                bytes(corrupted_response),
                "certs/server.crt",
                pk_bytes,
                client_id
            )
        print("Teste negativo de corrupção de salt passou!")

    def test_handshake_signature_is_bound_to_client_key_and_id(self):
        priv_key = load_server_private_key("certs/server.key")
        with open("certs/server.crt", "rb") as f:
            cert_bytes = f.read()

        client_id = generate_client_id()
        other_client_id = generate_client_id()
        _, client_pk = generate_key_pair()
        _, other_client_pk = generate_key_pair()
        client_pk_bytes = serialize_public_key(client_pk)
        other_client_pk_bytes = serialize_public_key(other_client_pk)
        response, _ = create_server_handshake_response(
            priv_key, cert_bytes, client_pk_bytes, client_id
        )

        with self.assertRaises(InvalidSignature):
            verify_server_handshake_response(
                response, "certs/server.crt", other_client_pk_bytes, client_id
            )

        with self.assertRaises(InvalidSignature):
            verify_server_handshake_response(
                response, "certs/server.crt", client_pk_bytes, other_client_id
            )

if __name__ == "__main__":
    unittest.main()