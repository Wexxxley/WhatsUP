import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import server
from protocol.ids import generate_client_id, format_client_id
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
        client_id = generate_client_id()
        _, public_key = generate_key_pair()
        registration_frame = client_id + serialize_public_key(public_key)
        writer = CaptureWriter()
        existing_session = {"writer": object()}
        client_id_str = format_client_id(client_id)

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


if __name__ == "__main__":
    unittest.main()
