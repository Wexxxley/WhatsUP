"""Demonstra por que o relay não consegue decifrar uma mensagem E2E.

Esta demonstração não é uma prova matemática de impossibilidade. Ela reproduz
o que um observador/relay possui (frame, IDs, chaves públicas e salt) e mostra
que a tentativa de decifrar sem a chave privada X25519 do destinatário falha.
"""

import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from protocol.crypto import derive_e2e_keys, encrypt_e2e_message
from protocol.ids import generate_client_id
from protocol.keys import generate_key_pair, serialize_public_key
from protocol.spec import NONCE_SIZE, CLIENT_ID_SIZE, SEQUENCE_SIZE


def main() -> None:
    client_a_id = generate_client_id()
    client_b_id = generate_client_id()
    client_a_sk, client_a_pk = generate_key_pair()
    client_b_sk, client_b_pk = generate_key_pair()
    salt_srv = secrets.token_bytes(16)

    key_a_send, _, iv_base = derive_e2e_keys(
        client_a_sk,
        serialize_public_key(client_b_pk),
        client_a_id,
        client_b_id,
        salt_srv,
    )
    frame, _ = encrypt_e2e_message(
        client_a_id,
        client_b_id,
        b"Mensagem que somente o Cliente B deve ler",
        key_a_send,
        iv_base,
        0,
    )

    # O relay consegue observar o cabeçalho necessário para rotear o frame,
    # mas não possui a chave AES derivada entre A e B.
    ciphertext = frame[NONCE_SIZE + CLIENT_ID_SIZE * 2 + SEQUENCE_SIZE:]
    server_guess = secrets.token_bytes(16)

    try:
        AESGCM(server_guess).decrypt(
            frame[:NONCE_SIZE],
            ciphertext,
            frame[NONCE_SIZE:NONCE_SIZE + CLIENT_ID_SIZE * 2 + SEQUENCE_SIZE],
        )
    except InvalidTag:
        print("[OK] O relay vê o frame, mas não possui a chave AES E2E.")
        print("[OK] A tentativa de decifragem sem a chave privada do peer falhou (InvalidTag).")
        print("[OK] O relay pode encaminhar os bytes, mas não consegue obter o plaintext.")
        return

    raise AssertionError("A tentativa de decifragem inesperadamente foi aceita")


if __name__ == "__main__":
    main()
