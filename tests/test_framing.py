import asyncio
import unittest

from protocol.framing import recv_frame, send_frame
from protocol.constants import MAX_FRAME_SIZE


class MemoryWriter:
    def __init__(self):
        self.data = bytearray()

    def write(self, data: bytes) -> None:
        self.data.extend(data)

    async def drain(self) -> None:
        pass


async def receive_payload(data: bytes) -> bytes:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return await recv_frame(reader)


class TestFraming(unittest.TestCase):
    def test_send_frame_prefixes_big_endian_payload_length(self):
        payload = b"conteudo do frame"
        writer = MemoryWriter()

        asyncio.run(send_frame(writer, payload))

        self.assertEqual(int.from_bytes(writer.data[:4], "big"), len(payload))
        self.assertEqual(bytes(writer.data[4:]), payload)
        self.assertEqual(
            asyncio.run(receive_payload(bytes(writer.data))),
            payload,
        )

    def test_oversized_frame_length_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "excede o limite máximo"):
            asyncio.run(receive_payload((MAX_FRAME_SIZE + 1).to_bytes(4, "big")))

    def test_truncated_frame_header_is_rejected(self):
        with self.assertRaises(asyncio.IncompleteReadError):
            asyncio.run(receive_payload(b"\x00\x00"))

    def test_truncated_frame_payload_is_rejected(self):
        with self.assertRaises(asyncio.IncompleteReadError):
            asyncio.run(receive_payload((3).to_bytes(4, "big") + b"ab"))


if __name__ == "__main__":
    unittest.main()
