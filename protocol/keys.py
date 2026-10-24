from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes

def generate_key_pair():
    sk = X25519PrivateKey.generate()
    pk = sk.public_key()
    return (sk, pk)

# Serializa a chave pública para bytes (32 bytes)
def serialize_public_key(pk: X25519PublicKey) -> bytes:
    return pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

# Deserializa os bytes de volta para uma chave pública X25519   
def deserialize_public_key(pk_bytes: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(pk_bytes)

# Usado para gerar o fingerprint da chave pública, que é uma representação curta da chave.
def get_key_fingerprint(pk: X25519PublicKey) -> str:
    pk_bytes = serialize_public_key(pk)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(pk_bytes)
    return digest.finalize().hex()[:16]
