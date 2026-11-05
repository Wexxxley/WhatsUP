import struct
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from protocol.spec import (
    ADMIN_MAX_FRAME_SIZE,
    ADMIN_MIN_FRAME_SIZE,
    CLIENT_ID_SIZE,
    SALT_SIZE,
    X25519_KEY_SIZE,
)

ADMIN_MAGIC = b"WUA1"
ADMIN_VERSION = 1
ADMIN_JOIN = 1
ADMIN_ROTATE = 2
ADMIN_LEAVE = 3
ADMIN_TYPES = frozenset((ADMIN_JOIN, ADMIN_ROTATE, ADMIN_LEAVE))
ADMIN_HEADER_FORMAT = "!4sBBQ16s16s32s16s"
ADMIN_HEADER_SIZE = struct.calcsize(ADMIN_HEADER_FORMAT)
ADMIN_SIGNATURE_LENGTH_SIZE = 2


@dataclass(frozen=True)
class AdminAnnouncement:
    announcement_type: int
    seq_admin: int
    announced_id: bytes
    recipient_id: bytes
    public_key: bytes
    salt_srv: bytes


def _validate_fields(
    announcement_type: int,
    seq_admin: int,
    announced_id: bytes,
    recipient_id: bytes,
    public_key: bytes,
    salt_srv: bytes,
) -> None:
    if announcement_type not in ADMIN_TYPES:
        raise ValueError("Tipo de anúncio administrativo inválido")
    if seq_admin < 0:
        raise ValueError("seq_admin não pode ser negativo")
    if len(announced_id) != CLIENT_ID_SIZE:
        raise ValueError("announced_id deve ter 16 bytes")
    if len(recipient_id) != CLIENT_ID_SIZE:
        raise ValueError("recipient_id deve ter 16 bytes")
    if len(public_key) != X25519_KEY_SIZE:
        raise ValueError("public_key deve ter 32 bytes")
    if len(salt_srv) != SALT_SIZE:
        raise ValueError("salt_srv deve ter 16 bytes")
    if announcement_type == ADMIN_LEAVE and public_key != b"\x00" * X25519_KEY_SIZE:
        raise ValueError("Anúncio de saída deve usar chave sentinela")
    if announcement_type != ADMIN_LEAVE and public_key == b"\x00" * X25519_KEY_SIZE:
        raise ValueError("Anúncio de entrada/rotação exige chave pública")


def _signed_material(
    announcement_type: int,
    seq_admin: int,
    announced_id: bytes,
    recipient_id: bytes,
    public_key: bytes,
    salt_srv: bytes,
) -> bytes:
    return struct.pack(
        ADMIN_HEADER_FORMAT,
        ADMIN_MAGIC,
        ADMIN_VERSION,
        announcement_type,
        seq_admin,
        announced_id,
        recipient_id,
        public_key,
        salt_srv,
    )


def create_admin_frame(
    server_private_key: rsa.RSAPrivateKey,
    announcement_type: int,
    seq_admin: int,
    announced_id: bytes,
    recipient_id: bytes,
    public_key: bytes,
    salt_srv: bytes,
) -> bytes:
    _validate_fields(
        announcement_type,
        seq_admin,
        announced_id,
        recipient_id,
        public_key,
        salt_srv,
    )
    material = _signed_material(
        announcement_type,
        seq_admin,
        announced_id,
        recipient_id,
        public_key,
        salt_srv,
    )
    signature = server_private_key.sign(
        material,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    if len(signature) > 0xFFFF:
        raise ValueError("Assinatura administrativa excede o limite")
    return material + len(signature).to_bytes(2, "big") + signature


def parse_admin_frame(frame: bytes) -> AdminAnnouncement:
    if len(frame) < ADMIN_MIN_FRAME_SIZE:
        raise ValueError("Frame administrativo muito curto")
    if len(frame) > ADMIN_MAX_FRAME_SIZE:
        raise ValueError("Frame administrativo excede o limite")

    fields = struct.unpack(
        ADMIN_HEADER_FORMAT,
        frame[:ADMIN_HEADER_SIZE],
    )
    (
        magic,
        version,
        announcement_type,
        seq_admin,
        announced_id,
        recipient_id,
        public_key,
        salt_srv,
    ) = fields
    if magic != ADMIN_MAGIC or version != ADMIN_VERSION:
        raise ValueError("Frame administrativo sem versão válida")
    _validate_fields(
        announcement_type,
        seq_admin,
        announced_id,
        recipient_id,
        public_key,
        salt_srv,
    )

    signature_length_start = ADMIN_HEADER_SIZE
    signature_length = int.from_bytes(
        frame[signature_length_start:signature_length_start + 2],
        "big",
    )
    signature_start = signature_length_start + 2
    if signature_length == 0 or len(frame) != signature_start + signature_length:
        raise ValueError("Tamanho da assinatura administrativa inválido")

    return AdminAnnouncement(
        announcement_type=announcement_type,
        seq_admin=seq_admin,
        announced_id=announced_id,
        recipient_id=recipient_id,
        public_key=public_key,
        salt_srv=salt_srv,
    )


def verify_admin_frame(
    frame: bytes,
    pinned_cert_path: str,
    expected_recipient_id: bytes,
    expected_salt_srv: bytes,
) -> AdminAnnouncement:
    announcement = parse_admin_frame(frame)
    if announcement.recipient_id != expected_recipient_id:
        raise ValueError("Destinatário do anúncio administrativo não confere")
    if announcement.salt_srv != expected_salt_srv:
        raise ValueError("Salt do anúncio administrativo não confere")

    with open(pinned_cert_path, "rb") as certificate_file:
        certificate = x509.load_pem_x509_certificate(certificate_file.read())

    signature_start = ADMIN_HEADER_SIZE + ADMIN_SIGNATURE_LENGTH_SIZE
    signature = frame[signature_start:]
    material = _signed_material(
        announcement.announcement_type,
        announcement.seq_admin,
        announcement.announced_id,
        announcement.recipient_id,
        announcement.public_key,
        announcement.salt_srv,
    )
    try:
        certificate.public_key().verify(
            signature,
            material,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except InvalidSignature as error:
        raise InvalidSignature(
            "Assinatura do anúncio administrativo inválida"
        ) from error
    return announcement
