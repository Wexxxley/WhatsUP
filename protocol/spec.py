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
ADMIN_HEADER_SIZE = 96
ADMIN_SIGNATURE_LENGTH_SIZE = 2
ADMIN_MIN_FRAME_SIZE = ADMIN_HEADER_SIZE + ADMIN_SIGNATURE_LENGTH_SIZE + 256
ADMIN_MAX_FRAME_SIZE = MAX_FRAME_SIZE

# Frames administrativos assinados são definidos em protocol.admin.
# O frame de registro continua sendo o único payload administrativo sem
# assinatura, pois ocorre antes da autenticação do servidor.
