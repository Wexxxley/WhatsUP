import unittest
import secrets
from protocol.ids import generate_client_id, format_client_id
from protocol.keys import generate_key_pair, serialize_public_key, deserialize_public_key
from protocol.crypto import (
    derive_e2e_keys,
    encrypt_e2e_message,
    validate_and_decrypt_frame
)
from protocol.framing import MAX_FRAME_SIZE

class TestIntegrationRubric(unittest.TestCase):
    def setUp(self):
        # Setup two honest clients A and B
        self.id_a = generate_client_id()
        self.id_b = generate_client_id()
        
        self.sk_a, self.pk_a = generate_key_pair()
        self.sk_b, self.pk_b = generate_key_pair()
        
        self.pk_a_bytes = serialize_public_key(self.pk_a)
        self.pk_b_bytes = serialize_public_key(self.pk_b)
        
        self.salt_srv = secrets.token_bytes(16)
        
        # Derivar chaves simétricas E2E em ambos os lados
        self.key_send_a, self.key_recv_a, self.iv_a = derive_e2e_keys(
            self.sk_a, self.pk_b_bytes, self.id_a, self.id_b, self.salt_srv
        )
        self.key_send_b, self.key_recv_b, self.iv_b = derive_e2e_keys(
            self.sk_b, self.pk_a_bytes, self.id_b, self.id_a, self.salt_srv
        )
        
        # Tabelas de peers simuladas
        self.peers_a = {
            format_client_id(self.id_b): {
                "key_recv": self.key_recv_a,
                "seq_recv": -1,
                "IV_base_recv": None
            }
        }
        self.peers_b = {
            format_client_id(self.id_a): {
                "key_recv": self.key_recv_b,
                "seq_recv": -1,
                "IV_base_recv": None
            }
        }

    def test_t1_happy_path_e2e(self):
        """T1 — E2E feliz: A envia mensagem para B e B decifra corretamente."""
        plaintext = b"Ola do Cliente A para o Cliente B!"
        frame, _ = encrypt_e2e_message(
            sender_id=self.id_a,
            recipient_id=self.id_b,
            plaintext=plaintext,
            key_send=self.key_send_a,
            iv_base_send=self.iv_a,
            seq_send=0
        )
        
        sender_str, decrypted_text = validate_and_decrypt_frame(
            frame=frame,
            client_id_self=self.id_b,
            peers=self.peers_b
        )
        
        self.assertEqual(sender_str, format_client_id(self.id_a))
        self.assertEqual(decrypted_text, plaintext)
        print("[T1] Happy Path E2E passou com sucesso!")

    def test_t2_bitflips_tampering(self):
        """T2 — Bitflip: frame adulterado (no ciphertext ou AAD) deve ser rejeitado com InvalidTag."""
        plaintext = b"Mensagem secreta importante"
        frame, _ = encrypt_e2e_message(
            sender_id=self.id_a,
            recipient_id=self.id_b,
            plaintext=plaintext,
            key_send=self.key_send_a,
            iv_base_send=self.iv_a,
            seq_send=0
        )
        
        # Teste 2a: Bitflip no ciphertext (último byte)
        tampered_ct = bytearray(frame)
        tampered_ct[-1] ^= 0x01
        
        with self.assertRaises(ValueError) as ctx:
            validate_and_decrypt_frame(bytes(tampered_ct), self.id_b, self.peers_b)
        self.assertIn("tag mismatch", str(ctx.exception))

        # Teste 2b: Bitflip no AAD (ex: recipient_id)
        tampered_aad = bytearray(frame)
        tampered_aad[30] ^= 0x01 # byte dentro do recipient_id
        
        with self.assertRaises(ValueError) as ctx:
            validate_and_decrypt_frame(bytes(tampered_aad), self.id_b, self.peers_b)
        self.assertIn("tag mismatch", str(ctx.exception))
        print("[T2] Teste de Bitflip / Tampering passou com sucesso!")

    def test_t3_replay_attack(self):
        """T3 — Replay: reenvio de frame com seq_no já usado deve ser rejeitado por replay."""
        plaintext = b"Mensagem original"
        frame, _ = encrypt_e2e_message(
            sender_id=self.id_a,
            recipient_id=self.id_b,
            plaintext=plaintext,
            key_send=self.key_send_a,
            iv_base_send=self.iv_a,
            seq_send=0
        )
        
        # Primeira entrega: deve passar
        validate_and_decrypt_frame(frame, self.id_b, self.peers_b)
        
        # Segunda entrega (replay): deve ser rejeitada
        with self.assertRaises(ValueError) as ctx:
            validate_and_decrypt_frame(frame, self.id_b, self.peers_b)
        self.assertIn("replay rejected", str(ctx.exception))
        print("[T3] Teste de Anti-Replay passou com sucesso!")

    def test_t4_framing_limit(self):
        """T4 — Framing inválido: exceder o tamanho máximo de frame deve disparar erro de protocolo."""
        from protocol.framing import MAX_FRAME_SIZE
        # Tentar cifrar um plaintext que, somado ao overhead do frame, excede MAX_FRAME_SIZE
        large_plaintext = b"A" * (MAX_FRAME_SIZE + 100)
        with self.assertRaises(ValueError):
            encrypt_e2e_message(
                sender_id=self.id_a,
                recipient_id=self.id_b,
                plaintext=large_plaintext,
                key_send=self.key_send_a,
                iv_base_send=self.iv_a,
                seq_send=0
            )
        print("[T4] Teste de Limite de Framing passou com sucesso!")

if __name__ == "__main__":
    unittest.main()
