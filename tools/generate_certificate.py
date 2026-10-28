import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

def generate_server_certificate():
    os.makedirs("certs", exist_ok=True)
    
    # 1. Gerar chave privada RSA (3072 bits)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    
    # 2. Gerar certificado autoassinado
    #Subject (assunto, no caso o servidor) e Issuer (emissor do certificado) são os mesmos, pois é autoassinado
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"tp3-server"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
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
    with open("certs/server.key", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    with open("certs/server.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        
    print("Certificado e chave do servidor gerados com sucesso em certs/.")

if __name__ == "__main__":
    generate_server_certificate()
