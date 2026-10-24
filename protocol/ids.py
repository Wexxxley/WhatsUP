import uuid

def generate_client_id() -> bytes:
    """Gera um UUID v4 e retorna seus 16 bytes"""
    return uuid.uuid4().bytes

def format_client_id(client_id_bytes: bytes) -> str:
    """Converte 16 bytes de volta para representação textual de UUID."""
    return str(uuid.UUID(bytes=client_id_bytes))
