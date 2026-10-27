import asyncio
import curses
import hashlib
import locale
import textwrap
from uuid import UUID
from typing import TypedDict
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from protocol.framing import send_frame, recv_frame
from protocol.ids import generate_client_id, format_client_id
from protocol.keys import generate_key_pair, serialize_public_key, deserialize_public_key
from protocol.handshake import verify_server_handshake_response
from protocol.crypto import (
    derive_e2e_keys,
    encrypt_e2e_message,
    validate_and_decrypt_frame,
)

class PeerData(TypedDict):
    public_key: X25519PublicKey
    key_send: bytes
    key_recv: bytes
    seq_send: int
    seq_recv: int
    IV_base_send: bytes
    IV_base_recv: bytes | None

async def main():
    
    # Geração do ID do cliente
    client_id = generate_client_id()
    client_id_str = format_client_id(client_id)
    print(f"Meu client_id: {client_id_str}")
    
    # Geração das chaves pública e privada do cliente
    sk, pk = generate_key_pair()
    pk_bytes = serialize_public_key(pk)

    peers: dict[str, PeerData] = {}

    (reader, writer) = await asyncio.open_connection('127.0.0.1', 8888)

    # Frame de registro: client_id (16 bytes) + pk (32 bytes) = 48 bytes
    registration_frame = client_id + pk_bytes
    await send_frame(writer, registration_frame)
    print(f"Enviado ID de registro: {client_id_str}")

    # Receber e verificar resposta do handshake do servidor
    try:
        handshake_response = await recv_frame(reader)
        salt_srv = verify_server_handshake_response(
            handshake_response,
            "certs/server.crt",
            pk_bytes,
            client_id
        )
        print(f"Handshake verificado com sucesso! Salt recebido (hex): {salt_srv.hex()}")

        # Receber número de peers existentes
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

            add_peer(
                peers, peer_id_str, peer_client_id_bytes, peer_pk_bytes,
                client_id, sk
            )
            print(f"Peer online: {peer_id_str}")

    except Exception as e:
        print(f"ERRO DE HANDSHAKE / DERIVAÇÃO DE CHAVES: {e}")
        writer.close()
        await writer.wait_closed()
        return

    history: dict[str, list[tuple[str, str]]] = {}
    receiver = asyncio.create_task(
        receive_messages(reader, peers, client_id, sk, history)
    )
    try:
        await terminal_chat(writer, peers, client_id, history)
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
    peers: dict[str, PeerData],
    peer_id_str: str,
    peer_id_bytes: bytes,
    peer_pk_bytes: bytes,
    client_id: bytes,
    sk: X25519PrivateKey,
) -> None:
    # Handshake salts are per connection, so both peers derive the same public pair salt.
    pair_salt = hashlib.sha256(
        b"WhatsUp E2E" + min(client_id, peer_id_bytes) + max(client_id, peer_id_bytes)
    ).digest()
    key_send, key_recv, iv_base_send = derive_e2e_keys(
        sk, peer_pk_bytes, client_id, peer_id_bytes, pair_salt
    )
    peers[peer_id_str] = {
        "public_key": deserialize_public_key(peer_pk_bytes),
        "key_send": key_send,
        "key_recv": key_recv,
        "seq_send": 0,
        "seq_recv": -1,
        "IV_base_send": iv_base_send,
        "IV_base_recv": None,
    }


async def receive_messages(
    reader: asyncio.StreamReader,
    peers: dict[str, PeerData],
    client_id: bytes,
    sk: X25519PrivateKey,
    history: dict[str, list[tuple[str, str]]],
) -> None:
    while True:
        try:
            payload = await recv_frame(reader)
        except asyncio.IncompleteReadError:
            history.setdefault("*", []).append(
                ("*", "Conexão encerrada pelo servidor.")
            )
            return

        if len(payload) == 48:
            peer_id_bytes = payload[:16]
            peer_id_str = format_client_id(peer_id_bytes)
            peer_pk_bytes = payload[16:]

            if peer_pk_bytes == b"\x00" * 32:
                if peers.pop(peer_id_str, None) is not None:
                    history.setdefault("*", []).append(
                        ("*", f"{peer_id_str} saiu.")
                    )
                continue

            try:
                add_peer(
                    peers, peer_id_str, peer_id_bytes, peer_pk_bytes,
                    client_id, sk
                )
            except ValueError as e:
                history.setdefault("*", []).append(
                    ("*", f"Falha ao adicionar {peer_id_str}: {e}")
                )
            continue

        if len(payload) < 68:
            history.setdefault("*", []).append(
                ("*", f"Frame inesperado recebido ({len(payload)} bytes).")
            )
            continue

        try:
            sender_id, plaintext = validate_and_decrypt_frame(
                payload, client_id, peers
            )
            message = plaintext.decode("utf-8", errors="replace")
            history.setdefault(sender_id, []).append((sender_id, message))
        except ValueError as e:
            history.setdefault("*", []).append(
                ("*", f"Mensagem recebida inválida: {e}")
            )


async def terminal_chat(
    writer: asyncio.StreamWriter,
    peers: dict[str, PeerData],
    client_id: bytes,
    history: dict[str, list[tuple[str, str]]],
) -> None:
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

            _draw_terminal(
                screen, client_id, peer_ids, selected_peer,
                active_peer, history, input_buffer, notice
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
                                    writer, peers, client_id, active_peer,
                                    message, history
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
    client_id: bytes,
    peer_ids: list[str],
    selected_peer: int,
    active_peer: str | None,
    history: dict[str, list[tuple[str, str]]],
    input_buffer: str,
    notice: str,
) -> None:
    screen.erase()
    height, width = screen.getmaxyx()
    if height < 5 or width < 20:
        screen.addnstr(0, 0, "Aumente o tamanho do terminal.", max(1, width - 1))
        screen.refresh()
        return

    _add_line(screen, 0, f"WhatsUp | {format_client_id(client_id)} | online: {len(peer_ids)}", width)
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
        conversation = history.get(active_peer, []) + history.get("*", [])
        for sender, message in conversation:
            label = "Você" if sender == format_client_id(client_id) else sender
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


async def send_chat_message(
    writer: asyncio.StreamWriter,
    peers: dict[str, PeerData],
    client_id: bytes,
    recipient_id: str,
    message: str,
    history: dict[str, list[tuple[str, str]]],
) -> None:
    peer = peers.get(recipient_id)
    if peer is None:
        raise ValueError(f"{recipient_id} não está mais online")

    frame, next_seq = encrypt_e2e_message(
        sender_id=client_id,
        recipient_id=UUID(recipient_id).bytes,
        plaintext=message.encode("utf-8"),
        key_send=peer["key_send"],
        iv_base_send=peer["IV_base_send"],
        seq_send=peer["seq_send"],
    )
    await send_frame(writer, frame)
    peer["seq_send"] = next_seq
    history.setdefault(recipient_id, []).append(
        (format_client_id(client_id), message)
    )

if __name__ == "__main__":
    asyncio.run(main())
