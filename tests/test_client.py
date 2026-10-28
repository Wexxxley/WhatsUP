import asyncio
import unittest
from unittest.mock import patch

from client import PeerData, add_peer, send_chat_message, terminal_chat
from protocol.crypto import (
    encrypt_e2e_message,
    validate_and_decrypt_frame,
)
from protocol.ids import generate_client_id, format_client_id
from protocol.keys import generate_key_pair, serialize_public_key


class MemoryWriter:
    def __init__(self):
        self.frames = []

    def write(self, data):
        self.frames.append(data)

    async def drain(self):
        pass


class MemoryScreen:
    def __init__(self, keys):
        self.keys = iter(keys)
        self.rows = {}
        self.frames = []

    def keypad(self, _enabled):
        pass

    def nodelay(self, _enabled):
        pass

    def getmaxyx(self):
        return 24, 80

    def erase(self):
        self.rows = {}

    def get_wch(self):
        return next(self.keys)

    def addnstr(self, row, _column, text, count):
        self.rows[row] = text[:count]

    def refresh(self):
        self.frames.append("\n".join(self.rows.values()))


class TestClientPeerRegistration(unittest.TestCase):
    def test_peers_derive_matching_keys_and_exchange_message(self):
        client_a_id = generate_client_id()
        client_b_id = generate_client_id()
        client_a_sk, client_a_pk = generate_key_pair()
        client_b_sk, client_b_pk = generate_key_pair()

        peers_a: dict[str, PeerData] = {}
        peers_b: dict[str, PeerData] = {}
        client_a_peer_id = format_client_id(client_b_id)
        client_b_peer_id = format_client_id(client_a_id)

        with patch("client.peers", peers_a), patch("client.history", {}):
            asyncio.run(add_peer(
                client_a_peer_id, client_b_id,
                serialize_public_key(client_b_pk), client_a_id, client_a_sk
            ))
        with patch("client.peers", peers_b), patch("client.history", {}):
            asyncio.run(add_peer(
                client_b_peer_id, client_a_id,
                serialize_public_key(client_a_pk), client_b_id, client_b_sk
            ))

        plaintext = b"Mensagem entre clientes"
        peer_a = peers_a[client_a_peer_id]
        frame, _ = encrypt_e2e_message(
            sender_id=client_a_id,
            recipient_id=client_b_id,
            plaintext=plaintext,
            key_send=peer_a["key_send"],
            iv_base_send=peer_a["IV_base_send"],
            seq_send=peer_a["seq_send"],
        )

        sender_id, received = validate_and_decrypt_frame(
            frame, client_b_id, peers_b
        )

        self.assertEqual(sender_id, client_b_peer_id)
        self.assertEqual(received, plaintext)

    def test_conversation_sends_multiple_messages_without_reselecting_peer(self):
        client_id = generate_client_id()
        peer_id = generate_client_id()
        sk, client_pk = generate_key_pair()
        peer_sk, peer_pk = generate_key_pair()
        peer_id_str = format_client_id(peer_id)
        peers: dict[str, PeerData] = {}
        writer = MemoryWriter()
        history = {}

        async def send_messages():
            await add_peer(
                peer_id_str, peer_id, serialize_public_key(peer_pk), client_id, sk
            )
            await send_chat_message(
                writer, client_id, peer_id_str, "Oi"
            )
            await send_chat_message(
                writer, client_id, peer_id_str, "Tudo bem?"
            )

        with patch("client.peers", peers), patch("client.history", history):
            asyncio.run(send_messages())
        self.assertEqual(len(writer.frames), 2)
        self.assertEqual(peers[peer_id_str]["seq_send"], 2)
        self.assertEqual(
            [entry["message"] for entry in history[peer_id_str]],
            ["Oi", "Tudo bem?"]
        )

        receiver_peers: dict[str, PeerData] = {}
        with patch("client.peers", receiver_peers), patch("client.history", {}):
            asyncio.run(add_peer(
                format_client_id(client_id), client_id,
                serialize_public_key(client_pk), peer_id, peer_sk
            ))
        received_messages = []
        for framed_data in writer.frames:
            payload_size = int.from_bytes(framed_data[:4], "big")
            payload = framed_data[4:4 + payload_size]
            _, plaintext = validate_and_decrypt_frame(
                payload, peer_id, receiver_peers
            )
            received_messages.append(plaintext.decode("utf-8"))

        self.assertEqual(received_messages, ["Oi", "Tudo bem?"])

    def test_terminal_chat_keeps_messages_and_input_in_one_screen(self):
        client_id = generate_client_id()
        peer_id = generate_client_id()
        sk, _ = generate_key_pair()
        peer_sk, peer_pk = generate_key_pair()
        peer_id_str = format_client_id(peer_id)
        peers: dict[str, PeerData] = {}
        writer = MemoryWriter()
        history = {}
        screen = MemoryScreen(["\n", "h", "i", "\n", "\x1b", "q"])

        with (
            patch("client.peers", peers),
            patch("client.history", history),
            patch("client.curses.initscr", return_value=screen),
            patch("client.curses.noecho"),
            patch("client.curses.cbreak"),
            patch("client.curses.nocbreak"),
            patch("client.curses.echo"),
            patch("client.curses.endwin"),
            patch("client.locale.setlocale"),
        ):
            async def run_chat():
                await add_peer(
                    peer_id_str, peer_id, serialize_public_key(peer_pk),
                    client_id, sk
                )
                await terminal_chat(writer, client_id)

            asyncio.run(run_chat())

        self.assertEqual(len(writer.frames), 1)
        self.assertEqual(history[peer_id_str][0]["message"], "hi")
        self.assertTrue(any("Você: hi" in frame for frame in screen.frames))


if __name__ == "__main__":
    unittest.main()
