import secrets
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from protocol.keys import deserialize_public_key
from protocol.ids import format_client_id
from protocol.spec import (
    MAX_PLAINTEXT_SIZE,
    MIN_E2E_FRAME_SIZE,
    NONCE_SIZE,
    CLIENT_ID_SIZE,
    SEQUENCE_SIZE
)

def derive_e2e_keys(
    sk_a: X25519PrivateKey,
    pk_b_bytes: bytes,
    client_id_a: bytes,
    client_id_b: bytes,
    pair_salt: bytes
) -> tuple[bytes, bytes, bytes]:
    """
    Calcula Z_AB via ECDH entre a chave privada do cliente e a chave pública do peer,
    deriva as chaves simétricas E2E usando HKDF-SHA256,
    e retorna (key_send, key_recv, iv_base_send).
    O segredo Z_AB é descartado após a derivação.
    """
    pk_b = deserialize_public_key(pk_b_bytes)
    z_ab = sk_a.exchange(pk_b) # pk_a = sk_A · G  (fator gerador, n secreto)-> Z_aB = sk_A · (sk_B · G)
    
    # Derivar chaves via HKDF-SHA256
    hkdf_a = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=pair_salt,
        info=b"A" # chave exclusiva para msg de A para B
    )
    key_a = hkdf_a.derive(z_ab)

    hkdf_b = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=pair_salt, 
        info=b"B" # chave exclusiva para msg de B para A
    )
    key_b = hkdf_b.derive(z_ab)

    if client_id_a < client_id_b:
        # A é o menor, B é o maior
        key_send = key_a
        key_recv = key_b
    else:
        # B é o menor, A é o maior
        key_send = key_b
        key_recv = key_a

    iv_base_send = secrets.token_bytes(4) # 

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

    seq_bytes = seq_send.to_bytes(SEQUENCE_SIZE, 'big')
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
    if len(frame) < MIN_E2E_FRAME_SIZE:
        raise ValueError("Frame E2E muito curto")

    nonce = frame[:NONCE_SIZE]
    sender_id = frame[NONCE_SIZE:NONCE_SIZE + CLIENT_ID_SIZE]
    recipient_id = frame[NONCE_SIZE + CLIENT_ID_SIZE:NONCE_SIZE + 2 * CLIENT_ID_SIZE]
    seq_bytes = frame[NONCE_SIZE + 2 * CLIENT_ID_SIZE:NONCE_SIZE + 2 * CLIENT_ID_SIZE + SEQUENCE_SIZE]
    ciphertext_with_tag = frame[NONCE_SIZE + 2 * CLIENT_ID_SIZE + SEQUENCE_SIZE:]

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

def validate_and_decrypt_frame(
    frame: bytes,
    client_id_self: bytes,
    peers: dict
) -> tuple[str, bytes]:
    """
    Valida e decifra um frame E2E aplicando anti-replay (seq_no > seq_recv)
    e ordem correta de verificação (seq -> decifragem/tag -> atualiza seq_recv).
    """
    if len(frame) < MIN_E2E_FRAME_SIZE:
        raise ValueError("bad framing: frame muito curto")

    sender_id = frame[NONCE_SIZE:NONCE_SIZE + CLIENT_ID_SIZE]
    recipient_id = frame[NONCE_SIZE + CLIENT_ID_SIZE:NONCE_SIZE + 2 * CLIENT_ID_SIZE]
    seq_bytes = frame[NONCE_SIZE + 2 * CLIENT_ID_SIZE:NONCE_SIZE + 2 * CLIENT_ID_SIZE + SEQUENCE_SIZE]
    
    sender_id_str = format_client_id(sender_id)

    if sender_id_str not in peers:
        raise ValueError(f"Remetente desconhecido: {sender_id_str}")

    peer = peers[sender_id_str]
    seq_no = int.from_bytes(seq_bytes, 'big')

    # 1. Validação anti-replay: aceitar apenas seq_no > seq_recv
    if seq_no <= peer["seq_recv"]:
        print(f"[LOG] replay rejected: peer={sender_id_str}, seq_received={seq_no}, seq_recv={peer['seq_recv']}")
        raise ValueError("replay rejected")

    # 2. Decifragem e validação da tag GCM (autenticidade e integridade)
    try:
        _, plaintext, _, _, updated_iv_base = decrypt_e2e_message(
            frame=frame,
            key_recv=peer["key_recv"],
            expected_recipient_id=client_id_self,
            expected_iv_base_recv=peer["IV_base_recv"]
        )
        peer["IV_base_recv"] = updated_iv_base
    except Exception as e:
        print(f"[LOG] tag mismatch / decrypion error: peer={sender_id_str}")
        raise ValueError("tag mismatch") from e

    # 3. Atualizar seq_recv APÓS decifragem bem-sucedida
    peer["seq_recv"] = seq_no

    return sender_id_str, plaintext
