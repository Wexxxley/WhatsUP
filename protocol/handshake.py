import secrets
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
from protocol.spec import SALT_SIZE

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
    3 - assina com RSA-PSS(SHA-256) - criptografia assimétrica
    4 - empacota a resposta: [cert_len (4B)] + [cert_bytes] + [sig_len (4B)] + [signature] + [salt_srv (16B)]
    5 - Retorna (response_payload, salt_srv).
    """
    
    cert = x509.load_pem_x509_certificate(server_cert_bytes)
    pk_s_bytes = get_server_pubkey_bytes(cert)
    
    # Cria salt aleatório de 16 bytes para o handshake
    salt_srv = secrets.token_bytes(16) 
    
    # assina SHA256 (pk_server || pk_client || client_id || salt)    
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
        salt_srv # para o cliente
    )
    
    return (response_payload, salt_srv) # para o registration em server.py

def verify_server_handshake_response(
    response_payload: bytes,
    pinned_cert_path: str,
    pk_c_bytes: bytes,
    client_id_bytes: bytes
) -> bytes:
    """
    Verifica a resposta do handshake do servidor:
    1. Carrega o certificado pinado local.
    2. Realiza o parsing binário do payload recebido (certificado + assinatura + salt_srv).
    3. Executa a validação de Pinning (compara o certificado recebido com o pinado).
    4. Extrai a chave pública do servidor (pk_S) e remonta o material assinado:
       (pk_S || pk_C || client_id || salt_srv).
    5. Valida a assinatura digital RSA-PSS(SHA-256).
    Retorna o salt_srv se bem-sucedido; levanta exceção caso contrário (Fail-closed).
    """
    # 1. Carregar certificado pinado local
    with open(pinned_cert_path, "rb") as f:
        pinned_cert_bytes = f.read()
        
    if len(response_payload) < 8:
        raise ValueError("Payload de handshake muito curto (menor que o cabeçalho mínimo)")
        
    # 2. Parsing do payload binário
    offset = 0
    # 2.1 Extrair certificado do servidor
    cert_len = int.from_bytes(response_payload[offset:offset + 4], 'big')
    offset += 4
    
    if len(response_payload) < offset + cert_len + 4:
        raise ValueError("Payload truncado ao ler o certificado do servidor")
        
    received_cert_bytes = response_payload[offset:offset + cert_len]
    offset += cert_len
    
    # 2.2 Extrair assinatura RSA-PSS
    sig_len = int.from_bytes(response_payload[offset:offset + 4], 'big')
    offset += 4
    
    if len(response_payload) < offset + sig_len + 16:
        raise ValueError("Payload truncado ao ler a assinatura ou o salt do servidor")
        
    signature = response_payload[offset:offset + sig_len]
    offset += sig_len
    
    # 2.3 Extrair salt_srv (16 bytes finais)
    salt_srv = response_payload[offset:offset + 16]
    
    # 3. Validação do certificado
    if received_cert_bytes.strip() != pinned_cert_bytes.strip():
        raise ValueError("Falha de Pinning: O certificado recebido não confere com o certificado pinado!")
        
    # 4. Extração de pk_S e Remontagem do Material Assinado
    server_cert = x509.load_pem_x509_certificate(received_cert_bytes)
    pk_s_bytes = get_server_pubkey_bytes(server_cert)
    server_pub_key = server_cert.public_key()
    
    # Ordem estrita do contrato do protocolo
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
