import unittest
import secrets
from cryptography.exceptions import InvalidTag
from protocol.keys import generate_key_pair, serialize_public_key
from protocol.ids import generate_client_id
from protocol.crypto import derive_e2e_keys, encrypt_e2e_message, decrypt_e2e_message, MAX_PLAINTEXT_SIZE

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
        
        key_send_a, key_recv_a, iv_a = derive_e2e_keys(sk_a, pk_b_bytes, id_a, id_b, salt_srv)
        key_send_b, key_recv_b, iv_b = derive_e2e_keys(sk_b, pk_a_bytes, id_b, id_a, salt_srv)
        
        plaintext = b"Ola, este e um teste de criptografia E2E com AES-GCM!"
        seq_send = 0
        
        # A envia para B
        frame, next_seq = encrypt_e2e_message(
            sender_id=id_a,
            recipient_id=id_b,
            plaintext=plaintext,
            key_send=key_send_a,
            iv_base_send=iv_a,
            seq_send=seq_send
        )
        self.assertEqual(next_seq, 1)
        
        # B recebe e decifra
        iv_base_recv = None
        dec_sender, dec_plaintext, _, dec_seq, iv_base_recv = decrypt_e2e_message(
            frame=frame,
            key_recv=key_recv_b,
            expected_recipient_id=id_b,
            expected_iv_base_recv=iv_base_recv
        )
        
        self.assertEqual(dec_sender, id_a)
        self.assertEqual(dec_plaintext, plaintext)
        self.assertEqual(dec_seq, 0)
        self.assertEqual(iv_base_recv, iv_a)
        print("Teste de roundtrip de criptografia/decifragem E2E passou!")

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
        
        plaintext = b"Mensagem secreta"
        frame, _ = encrypt_e2e_message(id_a, id_b, plaintext, key_send_a, iv_a, 0)
        
        # Teste 1: Alterar 1 bit no ciphertext/tag
        tampered_frame_ct = bytearray(frame)
        tampered_frame_ct[-1] ^= 0xFF
        
        iv_base_recv = None
        with self.assertRaises(InvalidTag):
            decrypt_e2e_message(bytes(tampered_frame_ct), key_recv_b, id_b, iv_base_recv)

        # Teste 2: Alterar 1 bit no recipient_id (que faz parte do AAD)
        tampered_frame_aad = bytearray(frame)
        tampered_frame_aad[30] ^= 0xFF
        
        with self.assertRaises(InvalidTag):
            decrypt_e2e_message(bytes(tampered_frame_aad), key_recv_b, id_b, iv_base_recv)

        print("Testes negativos de adulteração (tampering / InvalidTag) passaram!")

    def test_max_plaintext_limit(self):
        id_a = generate_client_id()
        id_b = generate_client_id()
        key_send = secrets.token_bytes(16)
        iv_base = secrets.token_bytes(4)
        
        too_large_plaintext = b"A" * (MAX_PLAINTEXT_SIZE + 1)
        with self.assertRaises(ValueError):
            encrypt_e2e_message(id_a, id_b, too_large_plaintext, key_send, iv_base, 0)
            
        print("Teste de limite máximo de plaintext passou!")

if __name__ == "__main__":
    unittest.main()
