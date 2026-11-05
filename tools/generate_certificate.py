import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_server_credentials(
    cert_dir: Path = Path("certs"),
) -> tuple[rsa.RSAPrivateKey, bytes]:
    """Generate a fresh in-memory private key and write only its public certificate."""
    cert_dir.mkdir(parents=True, exist_ok=True)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "tp3-server"),
    ])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        )
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    certificate_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    (cert_dir / "server.crt").write_bytes(certificate_bytes)
    return private_key, certificate_bytes


def load_or_generate_server_credentials(
    cert_dir: Path = Path("certs"),
) -> tuple[rsa.RSAPrivateKey, bytes]:
    """Load the pinned server credentials or create them on first startup."""
    cert_dir.mkdir(parents=True, exist_ok=True)
    key_path = cert_dir / "server.key"
    cert_path = cert_dir / "server.crt"

    if key_path.exists() and cert_path.exists():
        private_key = serialization.load_pem_private_key(
            key_path.read_bytes(),
            password=None,
        )
        certificate_bytes = cert_path.read_bytes()
        certificate = x509.load_pem_x509_certificate(certificate_bytes)
        if certificate.public_key().public_numbers() != private_key.public_key().public_numbers():
            raise ValueError("server.crt não corresponde a server.key")
        return private_key, certificate_bytes

    private_key, certificate_bytes = generate_server_credentials(cert_dir)
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return private_key, certificate_bytes
