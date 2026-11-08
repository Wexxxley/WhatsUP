import asyncio
import uuid
from uuid import UUID
from typing import TypedDict
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from protocol.framing import send_frame, recv_frame
from protocol.keys import generate_key_pair, serialize_public_key
from protocol.admin import (
    ADMIN_LEAVE,
    ADMIN_JOIN,
    ADMIN_MAGIC,
    verify_admin_frame,
)
from protocol.crypto import (
    derive_e2e_keys,
    encrypt_e2e_message,
    validate_and_decrypt_frame,
    deserialize_public_key
)
from protocol.handshake import verify_server_handshake_response
from protocol.constants import (
    MIN_E2E_FRAME_SIZE
)
from client_terminal import MessageEntry, terminal_chat

class PeerData(TypedDict):
    public_key_b: X25519PublicKey
    key_send: bytes
    key_recv: bytes
    seq_send: int
    seq_recv: int
    IV_base_send: bytes
    IV_base_recv: bytes | None

peers: dict[str, PeerData] = {}

# Histórico de mensagens por peer.
# A lista de um chat específico armazena tanto as que você enviou quanto as que você recebeu daquele peer
history: dict[str, list[MessageEntry]] = {}

# Última sequência administrativa aceita na conexão atual com o servidor.
last_admin_sequence_received = -1

client_lock = asyncio.Lock()

#--------------------------------------------------------------------------------------------

async def main():
    """Orquestra registro, handshake, sincronização de peers e chat."""
    global peers, history, last_admin_sequence_received
    async with client_lock:
        peers.clear()
        history.clear()
        last_admin_sequence_received = -1
    
    # FASE 1: criar identidade e chave efêmera e registrar no servidor.
    id_a = uuid.uuid4().bytes
    client_id_str = str(uuid.UUID(bytes=id_a))
    print(f"Meu client_id: {client_id_str}")
    
    sk_a, pk_a = generate_key_pair()
    pk_bytes = serialize_public_key(pk_a)

    (reader, writer) = await asyncio.open_connection('127.0.0.1', 8888)

    registration_frame = id_a + pk_bytes
    await send_frame(writer, registration_frame)
    print(f"Enviado ID de registro: {client_id_str}")

    # FASE 3: autenticar o servidor e carregar a lista inicial de peers (Fase 4).
    try:
        handshake_response = await recv_frame(reader)
        verify_server_handshake_response(
            handshake_response, "certs/server.crt", pk_bytes, id_a
        )
        
        num_peers_bytes = await recv_frame(reader)
        num_peers = int.from_bytes(num_peers_bytes, 'big')
        print(f"Recebendo {num_peers} peer(s) inicial(is)...")
        
        for _ in range(num_peers):
            peer_frame = await recv_frame(reader)
            announcement = await apply_admin_frame(
                peer_frame, id_a, sk_a
            )
            if announcement.announcement_type == ADMIN_JOIN:
                print(f"Peer online: {str(uuid.UUID(bytes=announcement.announced_id))}")

    except Exception as e:
        print(f"ERRO DE HANDSHAKE / DERIVAÇÃO DE CHAVES: {e}")
        writer.close()
        await writer.wait_closed()
        return

    receiver = asyncio.create_task(
        receive_messages(reader, id_a, sk_a)
    ) # Tarefa assíncrona para receber mensagens de forma contínua
    try:
        await terminal_chat(
            writer,
            id_a,
            peers,
            history,
            client_lock,
            send_chat_message,
        )
    except KeyboardInterrupt:
        pass
    finally:
        receiver.cancel()
        try:
            await receiver
        except asyncio.CancelledError:
            pass
        writer.close()
        await writer.wait_closed()


# FASE 4: validar anúncios administrativos recebidos do servidor.
async def apply_admin_frame(
    frame: bytes,
    client_id: bytes,
    sk_a: X25519PrivateKey,
    pinned_cert_path: str = "certs/server.crt",
):
    """Valida um anúncio do servidor e atualiza o estado dos peers."""
    global last_admin_sequence_received

    announcement = verify_admin_frame(
        frame,
        pinned_cert_path,
        client_id,
        None,
    )
    if announcement.seq_admin != last_admin_sequence_received + 1:
        raise ValueError("replay rejected: anúncio administrativo repetido")

    peer_id_str = str(uuid.UUID(bytes=announcement.announced_id))
    if announcement.announcement_type == ADMIN_LEAVE:
        async with client_lock:
            peers.pop(peer_id_str, None)
            history.setdefault("*", []).append(
                {"sender": "*", "message": f"{peer_id_str} saiu."}
            )
    else:
        await add_peer(
            peer_id_str,
            announcement.announced_id,
            announcement.public_key,
            client_id,
            sk_a,
            announcement.salt_srv,
        )
    last_admin_sequence_received = announcement.seq_admin
    return announcement


# FASE 5: derivar as chaves E2E quando um peer é anunciado.
async def add_peer(
    peer_id_str: str,
    peer_id_bytes: bytes,
    peer_pk_bytes: bytes,
    client_id: bytes,
    sk_a: X25519PrivateKey,
    salt_srv: bytes,
) -> None:
    """Adiciona um peer usando o salt autenticado do handshake."""
    if len(salt_srv) != 16:
        raise ValueError("salt_srv deve ter exatamente 16 bytes")

    # Deriva as chaves de envio e recebimento para comunicação E2E com o peer
    key_send, key_recv, iv_base_send = derive_e2e_keys(
        sk_a, peer_pk_bytes, client_id, peer_id_bytes, salt_srv
    )
    public_key_b = deserialize_public_key(peer_pk_bytes)

    async with client_lock:
        existing_peer = peers.get(peer_id_str)
        if existing_peer is not None:
            existing_public_key_bytes = serialize_public_key(existing_peer["public_key_b"])
            if existing_public_key_bytes == peer_pk_bytes:
                return
            # A chave mudou para um ID já conhecido; substitua o estado para
            # iniciar novas sequências e nonces com a nova chave.

        peers[peer_id_str] = {
            "public_key_b": public_key_b,
            "key_send": key_send,
            "key_recv": key_recv,
            "seq_send": 0, # Seq da próxima msg enviada ao peer
            "seq_recv": -1, # Seq da última msg recebida do peer
            "IV_base_send": iv_base_send,
            "IV_base_recv": None,
        }

# FASE 6: cifrar e enviar uma mensagem E2E.
async def send_chat_message(
    writer: asyncio.StreamWriter,
    sender_id: bytes,
    recipient_id: str,
    message_text: str,
) -> None:
    """Cifra e envia uma mensagem E2E para um peer conhecido."""
    sender_id_bytes = sender_id
    recipient_id_bytes = UUID(recipient_id).bytes
    recipient_id_str = str(uuid.UUID(bytes=recipient_id_bytes))

    async with client_lock:
        peer = peers.get(recipient_id_str)
        if peer is None:
            raise ValueError(f"{recipient_id_str} não está mais online")

        frame, next_seq = encrypt_e2e_message(
            sender_id=sender_id_bytes,
            recipient_id=recipient_id_bytes,
            plaintext=message_text.encode("utf-8"),
            key_send=peer["key_send"],
            iv_base_send=peer["IV_base_send"],
            seq_send=peer["seq_send"],
        )

        await send_frame(writer, frame)
        peer["seq_send"] = next_seq
        history.setdefault(recipient_id_str, []).append({
            "sender": str(uuid.UUID(bytes=sender_id_bytes)),
            "message": message_text,
        })
    

# FASE 7: receber anúncios e mensagens E2E enquanto o chat está ativo.
async def receive_messages(
    reader: asyncio.StreamReader,
    id_a: bytes,
    sk_a: X25519PrivateKey,
) -> None:
    """Recebe frames do servidor e atualiza peers e histórico de mensagens."""

    while True:
        # A espera de um frame
        try:
            payload = await recv_frame(reader)
        except asyncio.IncompleteReadError:
            async with client_lock:
                history.setdefault("*", []).append(
                    {"sender": "*", "message": "Conexão encerrada pelo servidor."}
                )
            return

        # Se for um anúncio administrativo, aplica a validação e atualização de peers.
        if payload.startswith(ADMIN_MAGIC):
            try:
                await apply_admin_frame(payload, id_a, sk_a)
            except (ValueError, InvalidSignature) as e:
                async with client_lock:
                    history.setdefault("*", []).append(
                        {
                            "sender": "*",
                            "message": f"Anúncio administrativo inválido: {e}",
                        }
                    )
                    
        # Se não for anúncio de peer e for menor que 68 bytes, é um frame inválido.
        elif len(payload) < MIN_E2E_FRAME_SIZE:
            async with client_lock:
                history.setdefault("*", []).append( {"sender": "*", "message": f"Frame inesperado recebido ({len(payload)} bytes)."})
        
        # Só frames E2E (68 bytes ou mais) chegam à validação criptográfica.
        else:
            try:
                async with client_lock:
                    (id_b, plaintext) = validate_and_decrypt_frame(payload, id_a, peers)
                    message = plaintext.decode("utf-8", errors="replace")
                    history.setdefault(id_b, []).append({"sender": id_b, "message": message})
            except ValueError as e:
                # Mensagem E2E inválida 
                async with client_lock:
                    history.setdefault("*", []).append( {"sender": "*", "message": f"Mensagem recebida inválida: {e}"})

if __name__ == "__main__":
    asyncio.run(main())