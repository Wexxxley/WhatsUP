import asyncio
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import server
from protocol.admin import parse_admin_frame
from protocol.keys import generate_key_pair, serialize_public_key
from tools.generate_certificate import generate_server_credentials


class CaptureWriter:
    def __init__(self):
        self.frames = []

    def write(self, data):
        self.frames.append(data)

    async def drain(self):
        pass


class TestServerRegistration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.server_private_key, cls.server_cert_bytes = generate_server_credentials(
            Path(cls.temp_dir.name)
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_duplicate_active_client_id_is_rejected_without_replacing_session(self):
        client_id = uuid.uuid4().bytes
        _, public_key = generate_key_pair()
        registration_frame = client_id + serialize_public_key(public_key)
        writer = CaptureWriter()
        existing_session = {"writer": object()}
        client_id_str = str(uuid.UUID(bytes=client_id))

        async def register_duplicate():
            reader = asyncio.StreamReader()
            reader.feed_data(
                len(registration_frame).to_bytes(4, "big") + registration_frame
            )
            with (
                patch.object(server, "sessions", {client_id_str: existing_session}),
                patch.object(server, "SERVER_PRIV_KEY", self.server_private_key),
                patch.object(server, "SERVER_CERT_BYTES", self.server_cert_bytes),
            ):
                with self.assertRaisesRegex(ValueError, "client_id já conectado"):
                    await server.registration(reader, writer)

                self.assertIs(server.sessions[client_id_str], existing_session)
                self.assertEqual(writer.frames, [])

        asyncio.run(register_duplicate())

    def test_admin_sequence_is_independent_for_each_client_session(self):
        clients = [
            (uuid.uuid4().bytes, generate_key_pair())
            for _ in range(3)
        ]
        writers = [CaptureWriter() for _ in clients]
        sessions = {}

        async def register_all():
            with (
                patch.object(server, "sessions", sessions),
                patch.object(server, "SERVER_PRIV_KEY", self.server_private_key),
                patch.object(server, "SERVER_CERT_BYTES", self.server_cert_bytes),
            ):
                for (client_id, (_, public_key)), writer in zip(clients, writers):
                    registration_frame = client_id + serialize_public_key(public_key)
                    reader = asyncio.StreamReader()
                    reader.feed_data(
                        len(registration_frame).to_bytes(4, "big")
                        + registration_frame
                    )
                    await server.registration(reader, writer)

        asyncio.run(register_all())

        first_client_frame = parse_admin_frame(writers[0].frames[-2][4:])
        second_client_frame = parse_admin_frame(writers[1].frames[2][4:])
        third_client_frames = [
            parse_admin_frame(frame[4:])
            for frame in writers[2].frames[2:]
        ]

        self.assertEqual(first_client_frame.seq_admin, 0)
        self.assertEqual(second_client_frame.seq_admin, 0)
        self.assertEqual(
            [announcement.seq_admin for announcement in third_client_frames],
            [0, 1],
        )
        self.assertEqual(
            [session["seq_send"] for session in sessions.values()],
            [2, 2, 2],
        )


if __name__ == "__main__":
    unittest.main()
