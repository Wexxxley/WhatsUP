import asyncio
import curses
import hashlib
import locale
import textwrap
from uuid import UUID
from typing import TypedDict
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from protocol.framing import send_frame, recv_frame
from protocol.ids import generate_client_id, format_client_id
from protocol.keys import generate_key_pair, serialize_public_key
from protocol.crypto import (
    derive_e2e_keys,
    encrypt_e2e_message,
    validate_and_decrypt_frame,
    deserialize_public_key
)
from protocol.handshake import verify_server_handshake_response
from protocol.spec import (
    PEER_LEAVE_PUBLIC_KEY,
    REGISTRATION_FRAME_SIZE,
    MIN_E2E_FRAME_SIZE
)

class PeerData(TypedDict):
    public_key_b: X25519PrivateKey
    key_send: bytes
    key_recv: bytes
    seq_send: int
    seq_recv: int
    IV_base_send: bytes
    IV_base_recv: bytes | None

class MessageEntry(TypedDict):
    sender: str
    message: str

client_lock = asyncio.Lock()
peers: dict[str, PeerData] = {}
history: dict[str, list[MessageEntry]] = {} # Histórico de mensagens por peer. A lista de um chat específico armazena tanto as que você enviou quanto as que você recebeu daquele


async def main():
    global peers, history
    async with client_lock:
        peers.clear()
        history.clear()
    
    # Geração do ID do cliente
    id_a = generate_client_id()
    client_id_str = format_client_id(id_a)
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
        salt_srv = verify_server_handshake_response(
            handshake_response,
            "certs/server.crt",
            pk_bytes,
            id_a
        )
        print(f"Handshake verificado com sucesso! Salt recebido (hex): {salt_srv.hex()}")

        num_peers_bytes = await recv_frame(reader)
        num_peers = int.from_bytes(num_peers_bytes, 'big')
        print(f"Recebendo {num_peers} peer(s) inicial(is)...")

        for _ in range(num_peers):
            peer_frame = await recv_frame(reader)
            if len(peer_frame) != 48:
                raise ValueError("Frame de peer inválido")
            peer_client_id_bytes = peer_frame[:16]
            peer_pk_bytes = peer_frame[16:]
            peer_id_str = format_client_id(peer_client_id_bytes)

            async with client_lock:
                add_peer(
                    peers, peer_id_str, peer_client_id_bytes, peer_pk_bytes,
                    id_a, sk_a
                )
            print(f"Peer online: {peer_id_str}")

    except Exception as e:
        print(f"ERRO DE HANDSHAKE / DERIVAÇÃO DE CHAVES: {e}")
        writer.close()
        await writer.wait_closed()
        return

    receiver = asyncio.create_task(receive_messages(reader, id_a, sk_a)) # Tarefa assíncrona para receber mensagens de forma contínua 
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


def add_peer(
    target_peers: dict[str, PeerData],
    peer_id_str: str,
    peer_id_bytes: bytes,
    peer_pk_bytes: bytes,
    client_id: bytes,
    sk_a: X25519PrivateKey,
) -> None:
    """Adiciona um novo peer à lista de contatos informada."""
    pair_salt = hashlib.sha256(b"WhatsUp E2E" + min(client_id, peer_id_bytes) + max(client_id, peer_id_bytes)).digest()
    
    key_send, key_recv, iv_base_send = derive_e2e_keys(sk_a, peer_pk_bytes, client_id, peer_id_bytes, pair_salt)
    
    target_peers[peer_id_str] = {
        "public_key_b": deserialize_public_key(peer_pk_bytes),
        "key_send": key_send,
        "key_recv": key_recv,
        "seq_send": 0,
        "seq_recv": -1,
        "IV_base_send": iv_base_send,
        "IV_base_recv": None,
    }


async def send_chat_message(
    writer: asyncio.StreamWriter,
    target_peers_or_sender_id: dict[str, PeerData] | bytes,
    sender_id_or_recipient_id: bytes | str,
    recipient_id_or_message: bytes | str,
    message_or_peers: str | dict[str, PeerData] | None = None,
    history_dict: dict[str, list[MessageEntry]] | None = None,
) -> None:
    """Cifra e envia uma mensagem E2E para um peer conhecido."""
    if isinstance(target_peers_or_sender_id, dict):
        target_peers = target_peers_or_sender_id
        sender_id = sender_id_or_recipient_id
        recipient_id = recipient_id_or_message
        message_text = message_or_peers
        target_history = history_dict if history_dict is not None else history
    else:
        sender_id = target_peers_or_sender_id
        recipient_id = sender_id_or_recipient_id
        message_text = recipient_id_or_message
        target_peers = message_or_peers if isinstance(message_or_peers, dict) else peers
        target_history = history_dict if history_dict is not None else history

    if not isinstance(message_text, str):
        raise ValueError("Mensagem não informada")

    sender_id_bytes = sender_id if isinstance(sender_id, bytes) else UUID(str(sender_id)).bytes
    recipient_id_bytes = recipient_id if isinstance(recipient_id, bytes) else UUID(str(recipient_id)).bytes
    recipient_id_str = format_client_id(recipient_id_bytes)

    async with client_lock:
        peer = target_peers.get(recipient_id_str)
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
        target_history.setdefault(recipient_id_str, []).append({
            "sender": format_client_id(sender_id_bytes),
            "message": message_text,
        })

    
async def receive_messages(
    reader: asyncio.StreamReader,
    id_a: bytes,
    sk_a: X25519PrivateKey,
    peers_dict: dict[str, PeerData] | None = None,
    history_dict: dict[str, list[MessageEntry]] | None = None,
) -> None:
    target_peers = peers_dict if peers_dict is not None else peers
    target_history = history_dict if history_dict is not None else history

    while True:
        try:
            payload = await recv_frame(reader)
        except asyncio.IncompleteReadError:
            async with client_lock:
                target_history.setdefault("*", []).append(
                    {"sender": "*", "message": "Conexão encerrada pelo servidor."}
                )
            return

        if len(payload) == REGISTRATION_FRAME_SIZE:
            peer_id_bytes = payload[:16]
            peer_id_str = format_client_id(peer_id_bytes)
            peer_pk_bytes = payload[16:]

            async with client_lock:
                if peer_pk_bytes == PEER_LEAVE_PUBLIC_KEY:
                    if target_peers.pop(peer_id_str, None) is not None:
                        target_history.setdefault("*", []).append(
                            {"sender": "*", "message": f"{peer_id_str} saiu."}
                        )
                    continue

                try:
                    add_peer(
                        target_peers, peer_id_str, peer_id_bytes, peer_pk_bytes,
                        id_a, sk_a
                    )
                except ValueError as e:
                    target_history.setdefault("*", []).append(
                        {"sender": "*", "message": f"Falha ao adicionar {peer_id_str}: {e}"}
                    )
            continue

        if len(payload) < MIN_E2E_FRAME_SIZE:
            async with client_lock:
                target_history.setdefault("*", []).append(
                    {"sender": "*", "message": f"Frame inesperado recebido ({len(payload)} bytes)."}
                )
            continue

        try:
            async with client_lock:
                sender_id, plaintext = validate_and_decrypt_frame(
                    payload, id_a, target_peers
                )
                message = plaintext.decode("utf-8", errors="replace")
                target_history.setdefault(sender_id, []).append({"sender": sender_id, "message": message})
        except ValueError as e:
            async with client_lock:
                target_history.setdefault("*", []).append(
                    {"sender": "*", "message": f"Mensagem recebida inválida: {e}"}
                )


async def terminal_chat(
    writer: asyncio.StreamWriter,
    client_id: bytes,
    target_peers: dict[str, PeerData] | None = None,
    target_history: dict[str, list[MessageEntry]] | None = None,
) -> None:
    """Executa o loop de chat no terminal."""
    target_peers = target_peers if target_peers is not None else peers
    target_history = target_history if target_history is not None else history

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
                peer_ids = sorted(target_peers)
                if peer_ids:
                    selected_peer = min(selected_peer, len(peer_ids) - 1)
                else:
                    selected_peer = 0
                    active_peer = None
                if active_peer is not None and active_peer not in target_peers:
                    notice = f"{active_peer} saiu da conversa."
                    active_peer = None
                    input_buffer = ""

            _draw_terminal(
                screen, client_id, peer_ids, selected_peer,
                active_peer, target_history, input_buffer, notice
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
                                    writer, target_peers, client_id, active_peer,
                                    message, target_history
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
    history_dict: dict[str, list[MessageEntry]],
    input_buffer: str,
    notice: str,
) -> None:
    screen.erase()
    height, width = screen.getmaxyx()
    if height < 5 or width < 20:
        screen.addnstr(0, 0, "Aumente o tamanho do terminal.", max(1, width - 1))
        screen.refresh()
        return

    _add_line(screen, 0, f"WhatsUp | {format_client_id(id_a)} | online: {len(peer_ids)}", width)
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
        conversation = history_dict.get(active_peer, []) + history_dict.get("*", [])
        for entry in conversation:
            sender = entry["sender"]
            message = entry["message"]
            label = "Você" if sender == format_client_id(id_a) else sender
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
