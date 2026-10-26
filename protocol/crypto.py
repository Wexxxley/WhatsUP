import secrets
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from protocol.keys import deserialize_public_key

MAX_PLAINTEXT_SIZE = 4096

def derive_e2e_keys(
    sk_client: X25519PrivateKey,
    pk_peer_bytes: bytes,
    client_id_self: bytes,
    client_id_peer: bytes,
    salt_srv: bytes
) -> tuple[bytes, bytes, bytes]:
    """
    Calcula Z_AB via ECDH entre a chave privada do cliente e a chave pública do peer,
    deriva as chaves simétricas E2E usando HKDF-SHA256 (com labels 'A2B' e 'B2A'),
    determina A e B deterministicamente pela ordem dos client_ids (menor id é A),
    e retorna (key_send, key_recv, iv_base_send).
    O segredo Z_AB é descartado após a derivação.
    """
    pk_peer_obj = deserialize_public_key(pk_peer_bytes)
    z_ab = sk_client.exchange(pk_peer_obj)

    # Derivar chaves via HKDF-SHA256
    hkdf_a2b = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt_srv,
        info=b"A2B"
    )
    key_a2b = hkdf_a2b.derive(z_ab)

    hkdf_b2a = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt_srv,
        info=b"B2A"
    )
    key_b2a = hkdf_b2a.derive(z_ab)

    # Regra determinística: o menor client_id (em comparação de bytes) é "A"
    if client_id_self < client_id_peer:
        # Self é A, Peer é B
        key_send = key_a2b
        key_recv = key_b2a
    else:
        # Self é B, Peer é A
        key_send = key_b2a
        key_recv = key_a2b

    iv_base_send = secrets.token_bytes(4)

    # Z_ab sai de escopo aqui e é coletado pelo garbage collector (descartado)
    return key_send, key_recv, iv_base_send

def encrypt_e2e_message(
    sender_id: bytes,
    recipient_id: bytes,
    plaintext: bytes,
    key_send: bytes,
    iv_base_send: bytes,
    seq_send: int
) -> tuple[bytes, int]:
    """
    Cifra uma mensagem E2E usando AES-128-GCM.
    Estrutura do frame: [nonce 12B] || [sender_id 16B] || [recipient_id 16B] || [seq_no 8B] || [ciphertext + tag]
    AAD: sender_id || recipient_id || seq_no
    Nonce: IV_base_send (4B) || seq_no (8B big-endian)
    """
    if len(plaintext) > MAX_PLAINTEXT_SIZE:
        raise ValueError(f"Plaintext excede o limite máximo de {MAX_PLAINTEXT_SIZE} bytes")

    seq_bytes = seq_send.to_bytes(8, 'big')
    nonce = iv_base_send + seq_bytes
    aad = sender_id + recipient_id + seq_bytes

    aesgcm = AESGCM(key_send)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad)

    frame = nonce + sender_id + recipient_id + seq_bytes + ciphertext_with_tag
    
    # Retorna o frame montado e o próximo valor de seq_send (incrementado)
    return frame, seq_send + 1

def decrypt_e2e_message(
    frame: bytes,
    key_recv: bytes,
    expected_recipient_id: bytes,
    expected_iv_base_recv: bytes | None
) -> tuple[bytes, bytes, bytes, int, bytes]:
    """
    Decifra um frame E2E usando AES-128-GCM.
    Valida tamanho mínimo, IV_base (congelado após o primeiro frame) e tag GCM (que protege AAD e ciphertext).
    Retorna (sender_id, plaintext, iv_base, seq_no, updated_iv_base_recv).
    """
    MIN_FRAME_SIZE = 12 + 16 + 16 + 8 + 16 # nonce + sender + recipient + seq + tag(16)
    if len(frame) < MIN_FRAME_SIZE:
        raise ValueError("Frame E2E muito curto")

    nonce = frame[:12]
    sender_id = frame[12:28]
    recipient_id = frame[28:44]
    seq_bytes = frame[44:52]
    ciphertext_with_tag = frame[52:]

    iv_base = nonce[:4]
    seq_no = int.from_bytes(seq_bytes, 'big')

    if expected_iv_base_recv is None:
        expected_iv_base_recv = iv_base
    elif iv_base != expected_iv_base_recv:
        raise ValueError("IV base do nonce mudou no meio da sessão (violação de segurança)")

    aad = sender_id + recipient_id + seq_bytes

    # AAD inclui recipient_id, sender_id e seq_no. Qualquer adulteração causará InvalidTag.
    aesgcm = AESGCM(key_recv)
    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)

    if recipient_id != expected_recipient_id:
        raise ValueError("Recipient ID do frame não confere com o ID esperado")

    return sender_id, plaintext, iv_base, seq_no, expected_iv_base_recv
