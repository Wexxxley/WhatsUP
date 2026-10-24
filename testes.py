
### ==================================== Testando a geração de chaves X25519 ====================================

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
    
private_key = X25519PrivateKey.generate()
public_key = private_key.public_key()

# Passar parra bytes puros
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw, 
    format=serialization.PublicFormat.Raw
)

# Verifica o tamanho
print(f"Tamanho em bytes: {len(public_key_bytes)}")
