import unittest
import secrets
from cryptography.exceptions import InvalidTag
from protocol.keys import generate_key_pair, serialize_public_key
from protocol.ids import generate_client_id, format_client_id
from protocol.crypto import (
    derive_e2e_keys,
    encrypt_e2e_message,
    decrypt_e2e_message,
    validate_and_decrypt_frame,
    MAX_PLAINTEXT_SIZE
)
from protocol.spec import MIN_E2E_FRAME_SIZE

class TestCrypto(unittest.TestCase):
    def test_e2e_key_derivation_symmetry(self):
        id_a = generate_client_id()
        id_b = generate_client_id()
        
        sk_a, pk_a = generate_key_pair()
        sk_b, pk_b = generate_key_pair()
        
        pk_a_bytes = serialize_public_key(pk_a)
        pk_b_bytes = serialize_public_key(pk_b)
        
        salt_srv = secrets.token_bytes(16)
        
        key_send_a, key_recv_a, iv_a = derive_e2e_keys(
            sk_a, pk_b_bytes, id_a, id_b, salt_srv
        )
        key_send_b, key_recv_b, iv_b = derive_e2e_keys(
            sk_b, pk_a_bytes, id_b, id_a, salt_srv
        )
        
        self.assertEqual(key_send_a, key_recv_b)
        self.assertEqual(key_send_b, key_recv_a)
        self.assertNotEqual(key_send_a, key_send_b)
        self.assertEqual(len(key_send_a), 16)
        self.assertEqual(len(key_recv_a), 16)
        self.assertEqual(len(iv_a), 4)
        self.assertEqual(len(iv_b), 4)
        print("Teste de simetria e derivação de chaves E2E passou!")

    def test_different_salts_produce_different_keys(self):
        id_a = generate_client_id()
        id_b = generate_client_id()
        
        sk_a, pk_a = generate_key_pair()
        _, pk_b = generate_key_pair()
        pk_b_bytes = serialize_public_key(pk_b)
        
        salt1 = secrets.token_bytes(16)
        salt2 = secrets.token_bytes(16)
        
        k1_send, k1_recv, _ = derive_e2e_keys(sk_a, pk_b_bytes, id_a, id_b, salt1)
        k2_send, k2_recv, _ = derive_e2e_keys(sk_a, pk_b_bytes, id_a, id_b, salt2)
        
        self.assertNotEqual(k1_send, k2_send)
        self.assertNotEqual(k1_recv, k2_recv)
        print("Teste de salt diferente produzindo chaves distintas passou!")

    def test_e2e_encryption_decryption_roundtrip(self):
        id_a = generate_client_id()
        id_b = generate_client_id()
        
        sk_a, pk_a = generate_key_pair()
        sk_b, pk_b = generate_key_pair()
        
        pk_a_bytes = serialize_public_key(pk_a)
        pk_b_bytes = serialize_public_key(pk_b)
        salt_srv = secrets.token_bytes(16)
        
        key_send_a, _, iv_a = derive_e2e_keys(sk_a, pk_b_bytes, id_a, id_b, salt_srv)
        _, key_recv_b, _ = derive_e2e_keys(sk_b, pk_a_bytes, id_b, id_a, salt_srv)
        
        peers_b = {
            format_client_id(id_a): {
                "key_recv": key_recv_b,
                "seq_recv": -1,
                "IV_base_recv": None
            }
        }
        
        plaintext = b"Ola, este e um teste de criptografia E2E com AES-GCM!"
        frame, next_seq = encrypt_e2e_message(id_a, id_b, plaintext, key_send_a, iv_a, 0)
        self.assertEqual(next_seq, 1)
        
        sender_str, dec_plaintext = validate_and_decrypt_frame(frame, id_b, peers_b)
        self.assertEqual(sender_str, format_client_id(id_a))
        self.assertEqual(dec_plaintext, plaintext)
        self.assertEqual(peers_b[format_client_id(id_a)]["seq_recv"], 0)
        self.assertEqual(peers_b[format_client_id(id_a)]["IV_base_recv"], iv_a)
        print("Teste de roundtrip e validação de frame passou!")

    def test_anti_replay_protection(self):
        id_a = generate_client_id()
        id_b = generate_client_id()
        
        sk_a, pk_a = generate_key_pair()
        sk_b, pk_b = generate_key_pair()
        
        pk_a_bytes = serialize_public_key(pk_a)
        pk_b_bytes = serialize_public_key(pk_b)
        salt_srv = secrets.token_bytes(16)
        
        key_send_a, _, iv_a = derive_e2e_keys(sk_a, pk_b_bytes, id_a, id_b, salt_srv)
        _, key_recv_b, _ = derive_e2e_keys(sk_b, pk_a_bytes, id_b, id_a, salt_srv)
        
        peers_b = {
            format_client_id(id_a): {
                "key_recv": key_recv_b,
                "seq_recv": -1,
                "IV_base_recv": None
            }
        }
        
        # Enviar mensagem com seq_no = 0
        frame0, seq1 = encrypt_e2e_message(id_a, id_b, b"Msg 1", key_send_a, iv_a, 0)
        # Enviar mensagem com seq_no = 1
        frame1, seq2 = encrypt_e2e_message(id_a, id_b, b"Msg 2", key_send_a, iv_a, seq1)
        self.assertNotEqual(frame0[:12], frame1[:12])
        self.assertEqual(frame0[:4], iv_a)
        self.assertEqual(frame0[4:12], (0).to_bytes(8, "big"))
        self.assertEqual(frame1[4:12], (1).to_bytes(8, "big"))
        
        # Receber frame 0 com sucesso (seq_recv vira 0)
        sender, pt = validate_and_decrypt_frame(frame0, id_b, peers_b)
        self.assertEqual(pt, b"Msg 1")
        self.assertEqual(peers_b[format_client_id(id_a)]["seq_recv"], 0)

        # Receber frame 1 com sucesso (seq_recv vira 1)
        sender, pt = validate_and_decrypt_frame(frame1, id_b, peers_b)
        self.assertEqual(pt, b"Msg 2")
        self.assertEqual(peers_b[format_client_id(id_a)]["seq_recv"], 1)

        # Tentar reesviar frame 0 (Ataque de Replay: seq_no = 0 <= seq_recv = 1)
        with self.assertRaises(ValueError) as ctx:
            validate_and_decrypt_frame(frame0, id_b, peers_b)
        self.assertIn("replay rejected", str(ctx.exception))
        print("Teste de proteção anti-replay passou!")

    def test_out_of_order_sequence_is_rejected_without_advancing_state(self):
        id_a = generate_client_id()
        id_b = generate_client_id()
        sk_a, pk_a = generate_key_pair()
        sk_b, pk_b = generate_key_pair()
        salt_srv = secrets.token_bytes(16)

        key_send_a, _, iv_a = derive_e2e_keys(
            sk_a, serialize_public_key(pk_b), id_a, id_b, salt_srv
        )
        _, key_recv_b, _ = derive_e2e_keys(
            sk_b, serialize_public_key(pk_a), id_b, id_a, salt_srv
        )
        peers_b = {
            format_client_id(id_a): {
                "key_recv": key_recv_b,
                "seq_recv": -1,
                "IV_base_recv": None,
            }
        }
        skipped_frame, _ = encrypt_e2e_message(
            id_a, id_b, b"Mensagem fora de ordem", key_send_a, iv_a, 1
        )

        with self.assertRaisesRegex(ValueError, "replay rejected"):
            validate_and_decrypt_frame(skipped_frame, id_b, peers_b)

        peer_state = peers_b[format_client_id(id_a)]
        self.assertEqual(peer_state["seq_recv"], -1)
        self.assertIsNone(peer_state["IV_base_recv"])

    def test_changed_iv_base_is_rejected_without_advancing_state(self):
        id_a = generate_client_id()
        id_b = generate_client_id()
        sk_a, pk_a = generate_key_pair()
        sk_b, pk_b = generate_key_pair()
        salt_srv = secrets.token_bytes(16)

        key_send_a, _, iv_a = derive_e2e_keys(
            sk_a, serialize_public_key(pk_b), id_a, id_b, salt_srv
        )
        _, key_recv_b, _ = derive_e2e_keys(
            sk_b, serialize_public_key(pk_a), id_b, id_a, salt_srv
        )
        peers_b = {
            format_client_id(id_a): {
                "key_recv": key_recv_b,
                "seq_recv": -1,
                "IV_base_recv": None,
            }
        }
        first_frame, _ = encrypt_e2e_message(
            id_a, id_b, b"Primeira", key_send_a, iv_a, 0
        )
        validate_and_decrypt_frame(first_frame, id_b, peers_b)

        changed_iv_base = bytes([iv_a[0] ^ 1]) + iv_a[1:]
        changed_iv_frame, _ = encrypt_e2e_message(
            id_a, id_b, b"Base alterada", key_send_a, changed_iv_base, 1
        )
        with self.assertRaisesRegex(ValueError, "tag mismatch"):
            validate_and_decrypt_frame(changed_iv_frame, id_b, peers_b)

        peer_state = peers_b[format_client_id(id_a)]
        self.assertEqual(peer_state["seq_recv"], 0)
        self.assertEqual(peer_state["IV_base_recv"], iv_a)

    def test_e2e_tampering_fails(self):
        id_a = generate_client_id()
        id_b = generate_client_id()
        
        sk_a, pk_a = generate_key_pair()
        sk_b, pk_b = generate_key_pair()
        
        pk_a_bytes = serialize_public_key(pk_a)
        pk_b_bytes = serialize_public_key(pk_b)
        salt_srv = secrets.token_bytes(16)
        
        key_send_a, _, iv_a = derive_e2e_keys(sk_a, pk_b_bytes, id_a, id_b, salt_srv)
        _, key_recv_b, _ = derive_e2e_keys(sk_b, pk_a_bytes, id_b, id_a, salt_srv)
        
        peers_b = {
            format_client_id(id_a): {
                "key_recv": key_recv_b,
                "seq_recv": -1,
                "IV_base_recv": None
            }
        }
        
        plaintext = b"Mensagem secreta"
        frame, _ = encrypt_e2e_message(id_a, id_b, plaintext, key_send_a, iv_a, 0)
        
        # Teste 1: Alterar 1 bit no ciphertext/tag
        tampered_frame_ct = bytearray(frame)
        tampered_frame_ct[-1] ^= 0xFF
        
        with self.assertRaises(ValueError):
            validate_and_decrypt_frame(bytes(tampered_frame_ct), id_b, peers_b)
        self.assertEqual(peers_b[format_client_id(id_a)]["seq_recv"], -1)
        self.assertIsNone(peers_b[format_client_id(id_a)]["IV_base_recv"])

        print("Testes negativos de adulteração (tampering / InvalidTag) passaram!")

    def test_max_plaintext_limit(self):
        id_a = generate_client_id()
        id_b = generate_client_id()
        key_send = secrets.token_bytes(16)
        iv_base = secrets.token_bytes(4)

        frame, next_seq = encrypt_e2e_message(
            id_a, id_b, b"A" * MAX_PLAINTEXT_SIZE, key_send, iv_base, 0
        )
        self.assertEqual(next_seq, 1)
        self.assertEqual(len(frame), MIN_E2E_FRAME_SIZE + MAX_PLAINTEXT_SIZE)

        too_large_plaintext = b"A" * (MAX_PLAINTEXT_SIZE + 1)
        with self.assertRaises(ValueError):
            encrypt_e2e_message(id_a, id_b, too_large_plaintext, key_send, iv_base, 0)
        print("Teste de limite máximo de plaintext passou!")

    def test_e2e_frame_shorter_than_minimum_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "frame muito curto"):
            validate_and_decrypt_frame(
                b"\x00" * (MIN_E2E_FRAME_SIZE - 1),
                generate_client_id(),
                {},
            )

if __name__ == "__main__":
    unittest.main()
