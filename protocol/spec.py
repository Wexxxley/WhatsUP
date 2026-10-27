"""
Especificações e constantes do protocolo WhatsUp.
Define tamanhos de frames, offsets, limites e parâmetros criptográficos,
incluindo mensagens administrativas e de controle.
"""

# Limites de tamanho de payload e frames
MAX_FRAME_SIZE = 4200
MAX_PLAINTEXT_SIZE = 4096

# Dimensões de identificadores e chaves (em bytes)
CLIENT_ID_SIZE = 16         # UUID v4 binário
X25519_KEY_SIZE = 32        # Chave pública/privada X25519 crua
SALT_SIZE = 16              # Salt aleatório para HKDF / Handshake
NONCE_SIZE = 12             # Nonce do AES-GCM (iv_base 4B + seq_no 8B)
SEQUENCE_SIZE = 8           # Contador de sequência (uint64 big-endian)
TAG_SIZE = 16               # Tag de autenticação do AES-GCM

# Tamanhos de Frames específicos
REGISTRATION_FRAME_SIZE = CLIENT_ID_SIZE + X25519_KEY_SIZE  # 48 bytes
MIN_E2E_FRAME_SIZE = NONCE_SIZE + CLIENT_ID_SIZE + CLIENT_ID_SIZE + SEQUENCE_SIZE + TAG_SIZE  # 68 bytes

# Mensagens Administrativas / Controle de Peers (48 bytes)
# Formato: [client_id 16B] || [pk_bytes 32B]
# Se pk_bytes for PEER_LEAVE_PUBLIC_KEY, indica saída de peer (Leave).
# Caso contrário, indica entrada/registro de peer (Join).
PEER_LEAVE_PUBLIC_KEY = b"\x00" * X25519_KEY_SIZE
