import secrets
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

# RSA-PSS(SHA-256) algoritmo de criptografia assimétrica para assinatura

def load_server_private_key(key_path: str = "certs/server.key") -> rsa.RSAPrivateKey:
    with open(key_path, "rb") as f: # rb: read binary
        return serialization.load_pem_private_key( 
            f.read(),
            password=None
        )

def load_server_certificate() -> x509.Certificate:
    with open("certs/server.crt", "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def get_server_pubkey_bytes(cert: x509.Certificate) -> bytes:
    pub_key = cert.public_key()
    return pub_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def create_server_handshake_response(
    server_priv_key: rsa.RSAPrivateKey,
    server_cert_bytes: bytes,
    pk_c_bytes: bytes,
    client_id_bytes: bytes
) -> tuple[bytes, bytes]:
    """
    1 - Gera o salt_srv
    2 - monta (pk_S || pk_C || client_id || salt_srv),
    3 - assina com RSA-PSS(SHA-256)
    4 - empacota a resposta: [cert_len (4B)] + [cert_bytes] + [sig_len (4B)] + [signature] + [salt_srv (16B)]
    5 - Retorna (response_payload, salt_srv).
    """
    
    cert = x509.load_pem_x509_certificate(server_cert_bytes)
    pk_s_bytes = get_server_pubkey_bytes(cert)
    
    # Cria salt aleatório de 16 bytes para o handshake
    salt_srv = secrets.token_bytes(16) 
    
    # H = SHA256(pk_server || pk_client || client_id || salt)    
    signature = server_priv_key.sign(
        pk_s_bytes + pk_c_bytes + client_id_bytes + salt_srv,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    
    cert_len = len(server_cert_bytes)
    sig_len = len(signature)
    
    response_payload = (
        cert_len.to_bytes(4, 'big') +
        server_cert_bytes +
        sig_len.to_bytes(4, 'big') +
        signature +
        salt_srv
    )
    
    return (response_payload, salt_srv)

def verify_server_handshake_response(
    response_payload: bytes,
    pinned_cert_path: str,
    pk_c_bytes: bytes,
    client_id_bytes: bytes
) -> bytes:
    """
    Verifica a resposta do handshake do servidor:
    1. Compara o certificado recebido com o certificado pinado
    2. Extrai pk_S do certificado.
    3. Remonta o material pk_S || pk_C || client_id || salt_srv.
    4. Verifica a assinatura RSA-PSS(SHA-256).
    Retorna o salt_srv se bem-sucedido. Levanta exceção (ex: ValueError, InvalidSignature) em caso de falha.
    """
    with open(pinned_cert_path, "rb") as f:
        pinned_cert_bytes = f.read()
        
    if len(response_payload) < 8:
        raise ValueError("Payload de handshake muito curto")
        
    cert_len = int.from_bytes(response_payload[:4], 'big')
    idx = 4
    
    if len(response_payload) < idx + cert_len + 4:
        raise ValueError("Payload de handshake inválido (certificado)")
        
    received_cert_bytes = response_payload[idx:idx + cert_len]
    idx += cert_len
    
    sig_len = int.from_bytes(response_payload[idx:idx + 4], 'big')
    idx += 4
    
    if len(response_payload) < idx + sig_len + 16:
        raise ValueError("Payload de handshake inválido (assinatura ou salt)")
        
    signature = response_payload[idx:idx + sig_len]
    idx += sig_len
    
    salt_srv = response_payload[idx:idx + 16]
    
    # Pinning check: comparar certificado recebido com o pinado
    # Normalizamos removendo whitespaces/newlines para comparação robusta ou comparando hash/bytes
    if received_cert_bytes.strip() != pinned_cert_bytes.strip():
        raise ValueError("Falha de Pinning: certificado do servidor não confere com o pinado!")
        
    # Extrair pk_S e remontar material
    cert = x509.load_pem_x509_certificate(received_cert_bytes)
    pk_s_bytes = get_server_pubkey_bytes(cert)
    server_pub_key = cert.public_key()
    
    material = pk_s_bytes + pk_c_bytes + client_id_bytes + salt_srv
    
    # Verificar assinatura RSA-PSS
    try:
        server_pub_key.verify(
            signature,
            material,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature as e:
        raise InvalidSignature("Assinatura do servidor inválida (RSA-PSS falhou)") from e
        
    return salt_srv
