import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature

import client
from client import apply_admin_frame
from protocol.admin import (
    ADMIN_JOIN,
    ADMIN_LEAVE,
    ADMIN_ROTATE,
    ADMIN_HEADER_SIZE,
    create_admin_frame,
    verify_admin_frame,
)
from protocol.ids import generate_client_id, format_client_id
from protocol.keys import generate_key_pair, serialize_public_key
from tools.generate_certificate import generate_server_credentials


class TestAdministrativeFrames(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.cert_dir = Path(cls.temp_dir.name)
        cls.private_key, cls.cert_bytes = generate_server_credentials(cls.cert_dir)
        cls.cert_path = str(cls.cert_dir / "server.crt")

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def setUp(self):
        self.announced_id = generate_client_id()
        self.recipient_id = generate_client_id()
        self.salt_srv = b"S" * 16
        _, peer_public_key = generate_key_pair()
        self.peer_public_key = serialize_public_key(peer_public_key)

    def frame(self, announcement_type=ADMIN_JOIN, seq_admin=0):
        public_key = (
            b"\x00" * 32
            if announcement_type == ADMIN_LEAVE
            else self.peer_public_key
        )
        return create_admin_frame(
            self.private_key,
            announcement_type,
            seq_admin,
            self.announced_id,
            self.recipient_id,
            public_key,
            self.salt_srv,
        )

    def test_valid_join_rotation_and_leave(self):
        join = verify_admin_frame(
            self.frame(ADMIN_JOIN, 0),
            self.cert_path,
            self.recipient_id,
            self.salt_srv,
        )
        rotation = verify_admin_frame(
            self.frame(ADMIN_ROTATE, 1),
            self.cert_path,
            self.recipient_id,
            self.salt_srv,
        )
        leave = verify_admin_frame(
            self.frame(ADMIN_LEAVE, 2),
            self.cert_path,
            self.recipient_id,
            self.salt_srv,
        )
        self.assertEqual(join.announcement_type, ADMIN_JOIN)
        self.assertEqual(rotation.announcement_type, ADMIN_ROTATE)
        self.assertEqual(leave.announcement_type, ADMIN_LEAVE)

    def test_each_recipient_gets_a_distinct_signed_frame(self):
        other_recipient = generate_client_id()
        first = self.frame(ADMIN_JOIN, 0)
        second = create_admin_frame(
            self.private_key,
            ADMIN_JOIN,
            1,
            self.announced_id,
            other_recipient,
            self.peer_public_key,
            self.salt_srv,
        )
        self.assertNotEqual(first, second)
        verify_admin_frame(
            first,
            self.cert_path,
            self.recipient_id,
            self.salt_srv,
        )
        verify_admin_frame(
            second,
            self.cert_path,
            other_recipient,
            self.salt_srv,
        )

    def test_tampering_each_signed_field_is_rejected(self):
        frame = self.frame(ADMIN_JOIN, 1)
        old_frame = self.frame(ADMIN_JOIN, 0)
        offsets = (
            0,  # magic
            4,  # version
            5,  # type
            6,  # sequence
            ADMIN_HEADER_SIZE - 64,  # announced_id
            ADMIN_HEADER_SIZE - 48,  # recipient_id
            ADMIN_HEADER_SIZE - 32,  # public key
            ADMIN_HEADER_SIZE - 16,  # salt
            len(frame) - 1,  # signature
        )
        for offset in offsets:
            with self.subTest(offset=offset):
                tampered = bytearray(frame)
                tampered[offset] ^= 0x01
                with self.assertRaises((ValueError, InvalidSignature)):
                    verify_admin_frame(
                        bytes(tampered),
                        self.cert_path,
                        self.recipient_id,
                        self.salt_srv,
                    )

    def test_wrong_recipient_and_salt_are_rejected(self):
        frame = self.frame()
        with self.assertRaisesRegex(ValueError, "Destinatário"):
            verify_admin_frame(
                frame,
                self.cert_path,
                generate_client_id(),
                self.salt_srv,
            )
        with self.assertRaisesRegex(ValueError, "Salt"):
            verify_admin_frame(
                frame,
                self.cert_path,
                self.recipient_id,
                b"T" * 16,
            )

    def test_legacy_unsigned_frame_is_rejected(self):
        with self.assertRaises(ValueError):
            verify_admin_frame(
                self.announced_id + self.peer_public_key,
                self.cert_path,
                self.recipient_id,
                self.salt_srv,
            )

    def test_replay_is_rejected_across_two_client_connections(self):
        client_private_key, _ = generate_key_pair()
        frame = self.frame(ADMIN_JOIN, 1)
        old_frame = self.frame(ADMIN_JOIN, 0)
        peer_id_str = format_client_id(self.announced_id)
        peers = {}

        async def receive_once():
            await apply_admin_frame(
                frame,
                self.recipient_id,
                client_private_key,
                self.salt_srv,
                self.cert_path,
            )

        with (
            patch("client.peers", peers),
            patch("client.history", {}),
        ):
            client.admin_last_seq.clear()
            asyncio.run(receive_once())
            peers.clear()
            with self.assertRaisesRegex(ValueError, "replay rejected"):
                asyncio.run(
                    apply_admin_frame(
                        old_frame,
                        self.recipient_id,
                        client_private_key,
                        self.salt_srv,
                        self.cert_path,
                    )
                )

        self.assertNotIn(peer_id_str, peers)

    def test_forged_leave_does_not_remove_peer(self):
        client_private_key, _ = generate_key_pair()
        peer_id_str = format_client_id(self.announced_id)
        peers = {
            peer_id_str: {
                "public_key_b": generate_key_pair()[1],
                "key_send": b"A" * 16,
                "key_recv": b"B" * 16,
                "seq_send": 0,
                "seq_recv": -1,
                "IV_base_send": b"I" * 4,
                "IV_base_recv": None,
            }
        }
        forged = bytearray(self.frame(ADMIN_LEAVE, 0))
        forged[-1] ^= 0x01

        async def receive_forged():
            await apply_admin_frame(
                bytes(forged),
                self.recipient_id,
                client_private_key,
                self.salt_srv,
                self.cert_path,
            )

        with (
            patch("client.peers", peers),
            patch("client.history", {}),
        ):
            with self.assertRaises((ValueError, InvalidSignature)):
                asyncio.run(receive_forged())
            self.assertIn(peer_id_str, peers)
