"""Comprehensive unit tests for models/envelope.py – Cryptographic Envelope Models."""

import struct
import secrets
import pytest

from models.envelope import (
    RatchetEnvelope,
    PQCEncvelope,
    RATCHET_ENVELOPE_MAGIC,
    PQC_ENVELOPE_MAGIC,
    identify_envelope_type,
)


# ---------------------------------------------------------------------------
# Tests: RatchetEnvelope
# ---------------------------------------------------------------------------

class TestRatchetEnvelope:
    def test_build_basic(self):
        env = RatchetEnvelope(
            sender_name="Alice",
            header=b'\x01' * 40,
            ciphertext=b'\x02' * 50,
        )
        packet = env.build()
        assert packet[0] == RATCHET_ENVELOPE_MAGIC
        assert len(packet) > 0

    def test_build_roundtrip(self):
        env = RatchetEnvelope(
            sender_name="Bob",
            header=secrets.token_bytes(40),
            ciphertext=secrets.token_bytes(100),
        )
        packet = env.build()
        parsed = RatchetEnvelope.parse(packet)

        assert parsed.sender_name == "Bob"
        assert parsed.header == env.header
        assert parsed.ciphertext == env.ciphertext

    def test_build_unicode_name(self):
        env = RatchetEnvelope(
            sender_name="Алиса",
            header=b'\x01' * 40,
            ciphertext=b'\x02' * 50,
        )
        packet = env.build()
        parsed = RatchetEnvelope.parse(packet)
        assert parsed.sender_name == "Алиса"

    def test_build_long_name_raises(self):
        env = RatchetEnvelope(
            sender_name="A" * 300,  # > 255 bytes when UTF-8 encoded
            header=b'\x01' * 40,
            ciphertext=b'\x02' * 50,
        )
        with pytest.raises(ValueError, match="too long"):
            env.build()

    def test_parse_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            RatchetEnvelope.parse(b'\xD0\x01')

    def test_parse_wrong_magic(self):
        with pytest.raises(ValueError, match="Invalid ratchet envelope magic"):
            RatchetEnvelope.parse(b'\x00\x05Hello\x00\x01ab')

    def test_parse_truncated_name(self):
        # Magic + name_len=100 but only 2 bytes of name
        packet = bytes([RATCHET_ENVELOPE_MAGIC, 100]) + b"AB"
        with pytest.raises(ValueError, match="truncated"):
            RatchetEnvelope.parse(packet)

    def test_parse_truncated_header(self):
        # Build valid packet but truncate header
        env = RatchetEnvelope(
            sender_name="X",
            header=b'\x01' * 40,
            ciphertext=b'\x02' * 50,
        )
        packet = env.build()
        # Truncate the header portion
        truncated = packet[:10]
        with pytest.raises(ValueError):
            RatchetEnvelope.parse(truncated)

    def test_parse_empty_ciphertext_raises(self):
        # Build a packet with empty ciphertext
        name = b"Test"
        header = b'\x01' * 40
        packet = (
            bytes([RATCHET_ENVELOPE_MAGIC])
            + bytes([len(name)])
            + name
            + struct.pack(">H", len(header))
            + header
        )
        with pytest.raises(ValueError, match="empty ciphertext"):
            RatchetEnvelope.parse(packet)

    def test_parse_invalid_utf8_name(self):
        # Build packet with invalid UTF-8 in name
        name = b"\xff\xfe"  # Invalid UTF-8
        header = b'\x01' * 40
        ct = b'\x02' * 50
        packet = (
            bytes([RATCHET_ENVELOPE_MAGIC])
            + bytes([len(name)])
            + name
            + struct.pack(">H", len(header))
            + header
            + ct
        )
        with pytest.raises(ValueError, match="invalid UTF-8"):
            RatchetEnvelope.parse(packet)

    def test_magic_byte_value(self):
        assert RATCHET_ENVELOPE_MAGIC == 0xD0

    def test_frozen_dataclass(self):
        env = RatchetEnvelope(
            sender_name="Alice",
            header=b'\x01',
            ciphertext=b'\x02',
        )
        with pytest.raises(AttributeError):
            env.sender_name = "Bob"


# ---------------------------------------------------------------------------
# Tests: PQCEncvelope
# ---------------------------------------------------------------------------

class TestPQCEncvelope:
    def test_build_basic(self):
        env = PQCEncvelope(
            kem_ciphertext=secrets.token_bytes(100),
            nonce=secrets.token_bytes(12),
            aes_ciphertext=secrets.token_bytes(50),
        )
        packet = env.build()
        assert packet[0] == PQC_ENVELOPE_MAGIC
        assert len(packet) > 0

    def test_build_roundtrip(self):
        env = PQCEncvelope(
            kem_ciphertext=secrets.token_bytes(200),
            nonce=secrets.token_bytes(12),
            aes_ciphertext=secrets.token_bytes(100),
        )
        packet = env.build()
        parsed = PQCEncvelope.parse(packet)

        assert parsed.kem_ciphertext == env.kem_ciphertext
        assert parsed.nonce == env.nonce
        assert parsed.aes_ciphertext == env.aes_ciphertext

    def test_build_wrong_nonce_length_raises(self):
        env = PQCEncvelope(
            kem_ciphertext=secrets.token_bytes(100),
            nonce=secrets.token_bytes(16),  # Wrong! Must be 12
            aes_ciphertext=secrets.token_bytes(50),
        )
        with pytest.raises(ValueError, match="nonce must be 12 bytes"):
            env.build()

    def test_parse_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            PQCEncvelope.parse(b'\x50\x00')

    def test_parse_wrong_magic(self):
        with pytest.raises(ValueError, match="Invalid PQC envelope magic"):
            PQCEncvelope.parse(b'\x00\x00\x01' + b'\x00' * 50)

    def test_parse_truncated_kem_ciphertext(self):
        # Magic + kem_ct_len=100 but only 10 bytes available
        packet = bytes([PQC_ENVELOPE_MAGIC]) + struct.pack(">H", 100) + b'\x00' * 10
        with pytest.raises(ValueError, match="truncated"):
            PQCEncvelope.parse(packet)

    def test_parse_truncated_nonce(self):
        kem_ct = secrets.token_bytes(50)
        packet = (
            bytes([PQC_ENVELOPE_MAGIC])
            + struct.pack(">H", len(kem_ct))
            + kem_ct
            + b'\x00' * 5  # Less than 12 bytes for nonce
        )
        with pytest.raises(ValueError, match="truncated"):
            PQCEncvelope.parse(packet)

    def test_parse_aes_ciphertext_too_short(self):
        kem_ct = secrets.token_bytes(50)
        nonce = secrets.token_bytes(12)
        # AES ciphertext must be at least 16 bytes (tag)
        packet = (
            bytes([PQC_ENVELOPE_MAGIC])
            + struct.pack(">H", len(kem_ct))
            + kem_ct
            + nonce
            + b'\x00' * 10  # Less than 16 bytes
        )
        with pytest.raises(ValueError, match="too short"):
            PQCEncvelope.parse(packet)

    def test_magic_byte_value(self):
        assert PQC_ENVELOPE_MAGIC == 0x50

    def test_nonce_length_constant(self):
        assert PQCEncvelope.NONCE_LENGTH == 12

    def test_frozen_dataclass(self):
        env = PQCEncvelope(
            kem_ciphertext=b'\x01',
            nonce=b'\x02' * 12,
            aes_ciphertext=b'\x03',
        )
        with pytest.raises(AttributeError):
            env.nonce = b'\x04' * 12


# ---------------------------------------------------------------------------
# Tests: identify_envelope_type
# ---------------------------------------------------------------------------

class TestIdentifyEnvelopeType:
    def test_ratchet_type(self):
        packet = bytes([RATCHET_ENVELOPE_MAGIC]) + b'\x00' * 10
        assert identify_envelope_type(packet) == "ratchet"

    def test_pqc_type(self):
        packet = bytes([PQC_ENVELOPE_MAGIC]) + b'\x00' * 10
        assert identify_envelope_type(packet) == "pqc"

    def test_unknown_type(self):
        packet = bytes([0xFF]) + b'\x00' * 10
        assert identify_envelope_type(packet) is None

    def test_empty_packet(self):
        assert identify_envelope_type(b"") is None

    def test_zero_magic(self):
        assert identify_envelope_type(b'\x00') is None

    def test_single_byte(self):
        assert identify_envelope_type(bytes([RATCHET_ENVELOPE_MAGIC])) == "ratchet"
        assert identify_envelope_type(bytes([PQC_ENVELOPE_MAGIC])) == "pqc"


# ---------------------------------------------------------------------------
# Tests: Edge Cases
# ---------------------------------------------------------------------------

class TestEnvelopeEdgeCases:
    def test_ratchet_envelope_max_name(self):
        """Test with exactly 255-byte name."""
        name = "A" * 255
        env = RatchetEnvelope(
            sender_name=name,
            header=b'\x01' * 40,
            ciphertext=b'\x02' * 50,
        )
        packet = env.build()
        parsed = RatchetEnvelope.parse(packet)
        assert parsed.sender_name == name

    def test_ratchet_envelope_empty_name(self):
        env = RatchetEnvelope(
            sender_name="",
            header=b'\x01' * 40,
            ciphertext=b'\x02' * 50,
        )
        packet = env.build()
        parsed = RatchetEnvelope.parse(packet)
        assert parsed.sender_name == ""

    def test_pqc_envelope_large_kem_ciphertext(self):
        """Test with large KEM ciphertext."""
        env = PQCEncvelope(
            kem_ciphertext=secrets.token_bytes(5000),
            nonce=secrets.token_bytes(12),
            aes_ciphertext=secrets.token_bytes(1000),
        )
        packet = env.build()
        parsed = PQCEncvelope.parse(packet)
        assert parsed.kem_ciphertext == env.kem_ciphertext

    def test_ratchet_envelope_structure(self):
        """Verify the exact wire format structure."""
        env = RatchetEnvelope(
            sender_name="Test",
            header=b'\xAA' * 40,
            ciphertext=b'\xBB' * 20,
        )
        packet = env.build()

        offset = 0
        assert packet[offset] == RATCHET_ENVELOPE_MAGIC
        offset += 1

        name_len = packet[offset]
        offset += 1
        assert name_len == 4  # "Test" is 4 bytes

        name = packet[offset:offset + name_len]
        offset += name_len
        assert name == b"Test"

        header_len = struct.unpack(">H", packet[offset:offset + 2])[0]
        offset += 2
        assert header_len == 40

        header = packet[offset:offset + header_len]
        offset += header_len
        assert header == b'\xAA' * 40

        ciphertext = packet[offset:]
        assert ciphertext == b'\xBB' * 20

    def test_pqc_envelope_structure(self):
        """Verify the exact wire format structure."""
        kem_ct = b'\xCC' * 100
        nonce = b'\xDD' * 12
        aes_ct = b'\xEE' * 50

        env = PQCEncvelope(
            kem_ciphertext=kem_ct,
            nonce=nonce,
            aes_ciphertext=aes_ct,
        )
        packet = env.build()

        offset = 0
        assert packet[offset] == PQC_ENVELOPE_MAGIC
        offset += 1

        kem_ct_len = struct.unpack(">H", packet[offset:offset + 2])[0]
        offset += 2
        assert kem_ct_len == 100

        kem_ciphertext = packet[offset:offset + kem_ct_len]
        offset += kem_ct_len
        assert kem_ciphertext == kem_ct

        nonce_data = packet[offset:offset + 12]
        offset += 12
        assert nonce_data == nonce

        aes_ciphertext = packet[offset:]
        assert aes_ciphertext == aes_ct


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
