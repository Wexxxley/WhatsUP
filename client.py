import asyncio
import curses
import locale
import textwrap
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
from protocol.spec import (
    MIN_E2E_FRAME_SIZE
)

class PeerData(TypedDict):
    public_key_b: X25519PublicKey
    key_send: bytes
    key_recv: bytes
    seq_send: int
    seq_recv: int
    IV_base_send: bytes
    IV_base_recv: bytes | None

class MessageEntry(TypedDict):
    sender: str
    message: str

peers: dict[str, PeerData] = {}
history: dict[str, list[MessageEntry]] = {} # Histórico de mensagens por peer. A lista de um chat específico armazena tanto as que você enviou quanto as que você recebeu daquele
admin_last_seq: dict[tuple[bytes, bytes, bytes], int] = {}

client_lock = asyncio.Lock()

#--------------------------------------------------------------------------------------------

async def main():
    global peers, history
    async with client_lock:
        peers.clear()
        history.clear()
    
    # Geração do ID do cliente
    id_a = uuid.uuid4().bytes
    client_id_str = str(uuid.UUID(bytes=id_a))
    print(f"Meu client_id: {client_id_str}")
    
    # Geração das chaves pública e privada do cliente
    sk_a, pk_a = generate_key_pair()
    pk_bytes = serialize_public_key(pk_a)

    (reader, writer) = await asyncio.open_connection('127.0.0.1', 8888)

    # Frame de registro: client_id (16 bytes) + pk (32 bytes) = 48 bytes
    registration_frame = id_a + pk_bytes
    await send_frame(writer, registration_frame)
    print(f"Enviado ID de registro: {client_id_str}")

    # Receber e verificar resposta do handshake do servidor
    try:
        handshake_response = await recv_frame(reader)
        salt_srv = verify_server_handshake_response(handshake_response,"certs/server.crt",pk_bytes,id_a)
        
        num_peers_bytes = await recv_frame(reader)
        num_peers = int.from_bytes(num_peers_bytes, 'big')
        print(f"Recebendo {num_peers} peer(s) inicial(is)...")
        for _ in range(num_peers):
            peer_frame = await recv_frame(reader)
            announcement = await apply_admin_frame(
                peer_frame, id_a, sk_a, salt_srv
            )
            if announcement.announcement_type == ADMIN_JOIN:
                print(f"Peer online: {str(uuid.UUID(bytes=announcement.announced_id))}")

    except Exception as e:
        print(f"ERRO DE HANDSHAKE / DERIVAÇÃO DE CHAVES: {e}")
        writer.close()
        await writer.wait_closed()
        return

    receiver = asyncio.create_task(
        receive_messages(reader, id_a, sk_a, salt_srv)
    ) # Tarefa assíncrona para receber mensagens de forma contínua
    try:
        await terminal_chat(writer, id_a)
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


async def apply_admin_frame(
    frame: bytes,
    client_id: bytes,
    sk_a: X25519PrivateKey,
    _session_salt: bytes | None,
    pinned_cert_path: str = "certs/server.crt",
):
    announcement = verify_admin_frame(
        frame,
        pinned_cert_path,
        client_id,
        None,
    )
    replay_key = (
        announcement.salt_srv,
        announcement.announced_id,
        announcement.recipient_id,
    )
    last_seq = admin_last_seq.get(replay_key, -1)
    if announcement.seq_admin <= last_seq:
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
    admin_last_seq[replay_key] = announcement.seq_admin
    return announcement


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

    
async def receive_messages(
    reader: asyncio.StreamReader,
    id_a: bytes,
    sk_a: X25519PrivateKey,
    salt_srv: bytes,
) -> None:
    """Recebe frames do servidor e atualiza peers e histórico de mensagens."""

    while True:
        try:
            payload = await recv_frame(reader)
        except asyncio.IncompleteReadError:
            # O servidor encerrou a conexão ou não terminou de enviar o frame. Registra o encerramento
            async with client_lock:
                history.setdefault("*", []).append(
                    {"sender": "*", "message": "Conexão encerrada pelo servidor."}
                )
            return

        if payload.startswith(ADMIN_MAGIC):
            try:
                await apply_admin_frame(payload, id_a, sk_a, salt_srv)
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


async def terminal_chat(
    writer: asyncio.StreamWriter,
    client_id: bytes,
) -> None:
    """Executa o loop de chat no terminal."""

    locale.setlocale(locale.LC_ALL, "")
    screen = curses.initscr()
    curses.noecho()
    curses.cbreak()
    screen.keypad(True)
    screen.nodelay(True)

    selected_peer = 0
    active_peer: str | None = None
    input_buffer = ""
    notice = ""

    try:
        while True:
            async with client_lock:
                peer_ids = sorted(peers)
                if peer_ids:
                    selected_peer = min(selected_peer, len(peer_ids) - 1)
                else:
                    selected_peer = 0
                    active_peer = None
                if active_peer is not None and active_peer not in peers:
                    notice = f"{active_peer} saiu da conversa."
                    active_peer = None
                    input_buffer = ""
                conversation = (
                    list(history.get(active_peer, [])) + list(history.get("*", []))
                    if active_peer is not None
                    else []
                )

            _draw_terminal(
                screen, client_id, peer_ids, selected_peer,
                active_peer, conversation, input_buffer, notice
            )
            notice = ""

            try:
                key = screen.get_wch()
            except curses.error:
                key = None

            if key is not None:
                if key == "\x03":
                    return
                if active_peer is None:
                    if key in ("q", "Q"):
                        return
                    if key == curses.KEY_UP and peer_ids:
                        selected_peer = (selected_peer - 1) % len(peer_ids)
                    elif key == curses.KEY_DOWN and peer_ids:
                        selected_peer = (selected_peer + 1) % len(peer_ids)
                    elif key in ("\n", "\r", curses.KEY_ENTER) and peer_ids:
                        active_peer = peer_ids[selected_peer]
                        input_buffer = ""
                else:
                    if key == curses.KEY_EXIT or key == "\x1b":
                        active_peer = None
                        input_buffer = ""
                    elif key in ("\n", "\r", curses.KEY_ENTER):
                        message = input_buffer
                        input_buffer = ""
                        command = message.strip().lower()
                        if command in ("/voltar", "/back"):
                            active_peer = None
                        elif command in ("/sair", "/quit"):
                            return
                        elif message:
                            try:
                                await send_chat_message(
                                    writer, client_id, active_peer, message
                                )
                            except (ValueError, OSError) as e:
                                notice = f"Falha no envio: {e}"
                    elif key in (curses.KEY_BACKSPACE, "\b", "\x7f"):
                        input_buffer = input_buffer[:-1]
                    elif isinstance(key, str) and key.isprintable():
                        input_buffer += key

            await asyncio.sleep(0.04)
    finally:
        screen.keypad(False)
        curses.nocbreak()
        curses.echo()
        curses.endwin()


def _draw_terminal(
    screen,
    id_a: bytes,
    peer_ids: list[str],
    selected_peer: int,
    active_peer: str | None,
    conversation: list[MessageEntry],
    input_buffer: str,
    notice: str,
) -> None:
    screen.erase()
    height, width = screen.getmaxyx()
    if height < 5 or width < 20:
        screen.addnstr(0, 0, "Aumente o tamanho do terminal.", max(1, width - 1))
        screen.refresh()
        return

    _add_line(screen, 0, f"WhatsUp | {str(uuid.UUID(bytes=id_a))} | online: {len(peer_ids)}", width)
    if active_peer is None:
        _add_line(screen, 1, "↑/↓ selecionar  Enter conversar  q sair", width)
        _add_line(screen, 2, "-" * (width - 1), width)
        rows = height - 4
        if not peer_ids:
            _add_line(screen, 3, "Aguardando outros peers entrarem...", width)
        else:
            first_peer = max(0, min(selected_peer - rows + 1, len(peer_ids) - rows))
            visible_peers = peer_ids[first_peer:first_peer + rows]
            for offset, peer_id in enumerate(visible_peers):
                index = first_peer + offset
                marker = ">" if index == selected_peer else " "
                _add_line(screen, 3 + offset, f"{marker} {peer_id}", width)
    else:
        _add_line(screen, 1, f"Conversa com {active_peer} | Esc voltar | /sair encerrar", width)
        _add_line(screen, 2, "-" * (width - 1), width)
        available_rows = max(1, height - 5)
        wrapped_history: list[str] = []
        for entry in conversation:
            sender = entry["sender"]
            message = entry["message"]
            label = "Você" if sender == str(uuid.UUID(bytes=id_a)) else sender
            prefix = f"{label}: "
            lines = textwrap.wrap(
                prefix + message, width=max(1, width - 2),
                subsequent_indent="  ", replace_whitespace=False,
                drop_whitespace=False
            ) or [prefix]
            wrapped_history.extend(lines)
        for row, line in enumerate(wrapped_history[-available_rows:], start=3):
            _add_line(screen, row, line, width)
        _add_line(screen, height - 2, "-" * (width - 1), width)
        _add_line(screen, height - 1, f"> {input_buffer}", width)

    if notice:
        _add_line(screen, height - 1, notice, width)
    screen.refresh()


def _add_line(screen, row: int, text: str, width: int) -> None:
    if row < 0:
        return
    try:
        screen.addnstr(row, 0, text, max(0, width - 1))
    except curses.error:
        pass


if __name__ == "__main__":
    asyncio.run(main())
