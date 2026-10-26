import unittest
import secrets
from protocol.keys import generate_key_pair, serialize_public_key
from protocol.ids import generate_client_id
from protocol.crypto import derive_e2e_keys

class TestCrypto(unittest.TestCase):
    def test_e2e_key_derivation_symmetry(self):
        # Gerar identidades e pares X25519 para Cliente A e Cliente B
        id_a = generate_client_id()
        id_b = generate_client_id()
        
        # Garantir ordem fixa para o teste se necessário, ou testar independentemente
        # Vamos ordenar manualmente id_a e id_b para teste explícito ou testar a função diretamente
        sk_a, pk_a = generate_key_pair()
        sk_b, pk_b = generate_key_pair()
        
        pk_a_bytes = serialize_public_key(pk_a)
        pk_b_bytes = serialize_public_key(pk_b)
        
        salt_srv = secrets.token_bytes(16)
        
        # Derivação vista por A (peer é B)
        key_send_a, key_recv_a, iv_a = derive_e2e_keys(
            sk_a, pk_b_bytes, id_a, id_b, salt_srv
        )
        
        # Derivação vista por B (peer é A)
        key_send_b, key_recv_b, iv_b = derive_e2e_keys(
            sk_b, pk_a_bytes, id_b, id_a, salt_srv
        )
        
        # A chave que A envia deve ser exatamente a chave que B recebe
        self.assertEqual(key_send_a, key_recv_b)
        
        # A chave que B envia deve ser exatamente a chave que A recebe
        self.assertEqual(key_send_b, key_recv_a)
        
        # As chaves de envio de A e B devem ser distintas entre si (separação de direção)
        self.assertNotEqual(key_send_a, key_send_b)
        
        # Verificar tamanho das chaves (16 bytes para AES-128)
        self.assertEqual(len(key_send_a), 16)
        self.assertEqual(len(key_recv_a), 16)
        
        # Verificar tamanho do IV base (4 bytes)
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

if __name__ == "__main__":
    unittest.main()
