import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

def generate_server_certificate(cert_dir: Path = Path("certs")) -> None:
    cert_dir.mkdir(parents=True, exist_ok=True)
    key_path = cert_dir / "server.key"
    cert_path = cert_dir / "server.crt"
    
    # 1. Gerar chave privada RSA (3072 bits)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    
    # 2. Gerar certificado autoassinado
    #Subject (no caso o servidor) e Issuer (emissor do certificado) são os mesmos, pois é autoassinado
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"tp3-server"),])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key() # Chave pública correspondente à chave privada
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).sign(private_key, hashes.SHA256())
    
    # 3. Salvar server.key e server.crt
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    os.chmod(key_path, 0o600)
        
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        
    print(f"Certificado e chave do servidor gerados com sucesso em {cert_dir}/.")


def ensure_server_certificate(cert_dir: Path = Path("certs")) -> bool:
    """Gera um novo par se o certificado ou a chave privada estiver ausente."""
    cert_path = cert_dir / "server.crt"
    key_path = cert_dir / "server.key"

    if cert_path.is_file() and key_path.is_file():
        return False

    if cert_path.exists() or key_path.exists():
        print("Par de certificado incompleto; será gerado um novo par. ")

    generate_server_certificate(cert_dir)
    return True

# Se este arquivo for executado diretamente, gerar o certificado do servidor
if __name__ == "__main__":
    generate_server_certificate()
