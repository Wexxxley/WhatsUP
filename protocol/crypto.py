import secrets
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from protocol.keys import deserialize_public_key

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
