import asyncio
import curses
import locale
import textwrap
import uuid
from collections.abc import Awaitable, Callable, Mapping
from typing import TypedDict

class MessageEntry(TypedDict):
    sender: str
    message: str

async def terminal_chat(
    writer: asyncio.StreamWriter,
    client_id: bytes,
    peers: Mapping[str, object],
    history: Mapping[str, list[MessageEntry]],
    client_lock: asyncio.Lock,
    send_message: Callable[
        [asyncio.StreamWriter, bytes, str, str],
        Awaitable[None],
    ],
) -> None:
    """Executa a interface de chat no terminal."""
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
                screen,
                client_id,
                peer_ids,
                selected_peer,
                active_peer,
                conversation,
                input_buffer,
                notice,
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
                elif key == curses.KEY_EXIT or key == "\x1b":
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
                            await send_message(
                                writer, client_id, active_peer, message
                            )
                        except (ValueError, OSError) as error:
                            notice = f"Falha no envio: {error}"
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
    conversation: list[MessageEntry],
    input_buffer: str,
    notice: str,
) -> None:
    screen.erase()
    height, width = screen.getmaxyx()
    if height < 5 or width < 20:
        _add_line(screen, 0, "Aumente o tamanho do terminal.", width)
        screen.refresh()
        return

    client_id_str = str(uuid.UUID(bytes=client_id))
    _add_line(
        screen,
        0,
        f"WhatsUp | {client_id_str} | online: {len(peer_ids)}",
        width,
    )
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
        _add_line(
            screen,
            1,
            f"Conversa com {active_peer} | Esc voltar | /sair encerrar",
            width,
        )
        _add_line(screen, 2, "-" * (width - 1), width)
        available_rows = max(1, height - 5)
        wrapped_history: list[str] = []
        for entry in conversation:
            sender = entry["sender"]
            message = entry["message"]
            label = "Você" if sender == client_id_str else sender
            prefix = f"{label}: "
            lines = textwrap.wrap(
                prefix + message,
                width=max(1, width - 2),
                subsequent_indent="  ",
                replace_whitespace=False,
                drop_whitespace=False,
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
