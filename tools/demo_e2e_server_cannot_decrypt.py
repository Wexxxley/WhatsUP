"""Demonstra, com transparência, o que o relay vê e o que ele não possui."""

import hashlib
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509

from protocol.crypto import decrypt_e2e_message, derive_e2e_keys, encrypt_e2e_message
from protocol.ids import generate_client_id
from protocol.keys import generate_key_pair, serialize_public_key
from protocol.spec import NONCE_SIZE, CLIENT_ID_SIZE, SEQUENCE_SIZE
from tools.generate_certificate import load_or_generate_server_credentials


def fingerprint(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()[:16]


def show_server_view(
    frame: bytes,
    client_a_id: bytes,
    client_b_id: bytes,
    client_a_pk: bytes,
    client_b_pk: bytes,
    salt_srv: bytes,
    server_cert_bytes: bytes,
) -> None:
    nonce = frame[:NONCE_SIZE]
    sender_id = frame[NONCE_SIZE:NONCE_SIZE + CLIENT_ID_SIZE]
    recipient_start = NONCE_SIZE + CLIENT_ID_SIZE
    recipient_id = frame[recipient_start:recipient_start + CLIENT_ID_SIZE]
    sequence_start = recipient_start + CLIENT_ID_SIZE
    sequence_bytes = frame[sequence_start:sequence_start + SEQUENCE_SIZE]
    encrypted_part = frame[sequence_start + SEQUENCE_SIZE:]

    print("=== DADOS VISÍVEIS PARA O SERVIDOR/RELAY ===")
    print(f"client_id A:              {client_a_id.hex()}")
    print(f"client_id B:              {client_b_id.hex()}")
    print(f"sender_id no frame:       {sender_id.hex()}")
    print(f"recipient_id no frame:    {recipient_id.hex()}")
    print(f"pk_A tamanho:             {len(client_a_pk)} bytes")
    print(f"pk_A fingerprint:         {fingerprint(client_a_pk)}")
    print(f"pk_B tamanho:             {len(client_b_pk)} bytes")
    print(f"pk_B fingerprint:         {fingerprint(client_b_pk)}")
    print(f"certificado server.crt:   SHA-256 {fingerprint(server_cert_bytes)}")
    print(f"salt_srv:                 16 bytes (fingerprint {fingerprint(salt_srv)})")
    print(f"nonce:                    {len(nonce)} bytes (não exibido)")
    print(f"seq_no:                   {int.from_bytes(sequence_bytes, 'big')}")
    print(f"ciphertext + tag:         {len(encrypted_part)} bytes")
    print(f"frame total:              {len(frame)} bytes")
    print("plaintext:                NÃO está presente em claro")
    print()


def show_server_missing_data() -> None:
    print("=== DADOS QUE O SERVIDOR NÃO POSSUI ===")
    print("sk_A (privada X25519):    indisponível")
    print("sk_B (privada X25519):    indisponível")
    print("Z_AB (segredo ECDH):      indisponível")
    print("key_A2B (chave AES):      indisponível")
    print("plaintext:                indisponível")
    print()


def main() -> None:
    client_a_id = generate_client_id()
    client_b_id = generate_client_id()
    client_a_sk, client_a_pk = generate_key_pair()
    client_b_sk, client_b_pk = generate_key_pair()
    salt_srv = secrets.token_bytes(16)
    client_a_pk_bytes = serialize_public_key(client_a_pk)
    client_b_pk_bytes = serialize_public_key(client_b_pk)

    # O servidor possui a chave RSA para assinar o handshake. Ela não é usada
    # para derivar a chave AES E2E e nunca é impressa pela demonstração.
    server_private_key, server_cert_bytes = load_or_generate_server_credentials()
    server_certificate = x509.load_pem_x509_certificate(server_cert_bytes)

    key_a_send, _, iv_base = derive_e2e_keys(
        client_a_sk,
        client_b_pk_bytes,
        client_a_id,
        client_b_id,
        salt_srv,
    )
    _, key_b_recv, _ = derive_e2e_keys(
        client_b_sk,
        client_a_pk_bytes,
        client_b_id,
        client_a_id,
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

    show_server_view(
        frame,
        client_a_id,
        client_b_id,
        client_a_pk_bytes,
        client_b_pk_bytes,
        salt_srv,
        server_cert_bytes,
    )
    print("=== CREDENCIAL DO SERVIDOR ===")
    print(f"RSA do servidor:          {server_private_key.key_size} bits")
    print(f"server.crt sujeito:       {server_certificate.subject.rfc4514_string()}")
    print("Uso da RSA:               assinar/autenticar, não decifrar mensagens E2E")
    print()
    show_server_missing_data()

    # O relay consegue observar o cabeçalho necessário para rotear o frame,
    # mas não possui a chave AES derivada entre A e B. Mesmo conhecendo as
    # chaves públicas, ele não consegue calcular Z_AB sem sk_A ou sk_B.
    ciphertext = frame[NONCE_SIZE + CLIENT_ID_SIZE * 2 + SEQUENCE_SIZE:]
    server_guess = secrets.token_bytes(16)

    print("=== TENTATIVA DE DECRIPTAÇÃO DO RELAY ===")
    print("Operação: AESGCM(server_guess).decrypt(nonce, ciphertext+tag, aad)")
    print(f"chave usada pelo relay:   {len(server_guess)} bytes (incorreta, não exibida)")
    print(f"nonce recebido:            {len(frame[:NONCE_SIZE])} bytes")
    print(f"ciphertext + tag recebido: {len(ciphertext)} bytes")
    print(
        "AAD recebido:              "
        f"{len(frame[NONCE_SIZE:NONCE_SIZE + CLIENT_ID_SIZE * 2 + SEQUENCE_SIZE])} bytes"
    )

    try:
        decrypted_by_server = AESGCM(server_guess).decrypt(
            frame[:NONCE_SIZE],
            ciphertext,
            frame[NONCE_SIZE:NONCE_SIZE + CLIENT_ID_SIZE * 2 + SEQUENCE_SIZE],
        )
    except InvalidTag as error:
        print("Retorno da chamada:       exceção; nenhum plaintext foi retornado")
        print(f"Tipo da exceção:           {type(error).__name__}")
        print(f"Mensagem da exceção:       {str(error) or '(vazia)'}")
        print(f"Representação:             {error!r}")
        print("[OK] O relay pode encaminhar os bytes, mas não consegue obter o plaintext.")

    else:
        print(f"Retorno inesperado:         {len(decrypted_by_server)} bytes")
        raise AssertionError("A tentativa de decifragem do relay foi aceita")

    print()
    print("=== DECRIPTAÇÃO PELO DESTINATÁRIO ===")
    sender_id, plaintext, _, sequence, _ = decrypt_e2e_message(
        frame,
        key_b_recv,
        client_b_id,
        None,
    )
    print("Cliente B possui a chave privada X25519 e derivou a chave AES correta.")
    print(f"sender_id validado:       {sender_id.hex()}")
    print(f"seq_no validado:           {sequence}")
    print(f"Retorno da chamada:        {len(plaintext)} bytes de plaintext")
    print(f"Mensagem decifrada:        {plaintext.decode('utf-8')}")
    print("[OK] O destinatário decifrou; o relay não conseguiu.")


if __name__ == "__main__":
    main()
