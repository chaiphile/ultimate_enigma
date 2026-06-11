"""
Cryptographic Envelope Models.

Defines structured representations for the binary wire formats used by
Double Ratchet and Post-Quantum Hybrid KEM encryption. Centralizes all
magic bytes, struct packing/unpacking, and format validation so that
services never manipulate raw envelope bytes directly.
"""

from __future__ import annotations

import struct
import logging
from dataclasses import dataclass
from typing import Tuple

logger = logging.getLogger(__name__)

# Magic bytes identifying envelope types
RATCHET_ENVELOPE_MAGIC: int = 0xD0
PQC_ENVELOPE_MAGIC: int = 0x50


@dataclass(frozen=True)
class RatchetEnvelope:
    """Structured representation of a Double Ratchet message envelope.

    Wire format:
        0xD0 | name_len(1B) | name(UTF-8) | hdr_len(2B BE) | header | ciphertext

    Attributes:
        sender_name: UTF-8 encoded friend name embedded in the envelope.
        header: Raw Double Ratchet header bytes (DH pub + msg_num + prev_chain_len).
        ciphertext: AES-GCM encrypted payload including nonce and tag.
    """

    sender_name: str
    header: bytes
    ciphertext: bytes

    def build(self) -> bytes:
        """Serialize this envelope into its binary wire format.

        Returns:
            The complete envelope as bytes.

        Raises:
            ValueError: If sender_name exceeds 255 bytes when UTF-8 encoded.
        """
        name_bytes = self.sender_name.encode("utf-8")
        if len(name_bytes) > 255:
            raise ValueError(
                f"Sender name too long for ratchet envelope "
                f"({len(name_bytes)} bytes, max 255)."
            )

        return (
            bytes([RATCHET_ENVELOPE_MAGIC])
            + bytes([len(name_bytes)])
            + name_bytes
            + struct.pack(">H", len(self.header))
            + self.header
            + self.ciphertext
        )

    @classmethod
    def parse(cls, packet: bytes) -> RatchetEnvelope:
        """Deserialize a binary packet into a RatchetEnvelope.

        Args:
            packet: Raw bytes starting with the RATCHET_ENVELOPE_MAGIC byte.

        Returns:
            A parsed RatchetEnvelope instance.

        Raises:
            ValueError: If the packet is malformed or magic byte mismatches.
        """
        if len(packet) < 4:
            raise ValueError("Ratchet envelope too short.")

        if packet[0] != RATCHET_ENVELOPE_MAGIC:
            raise ValueError(
                f"Invalid ratchet envelope magic: expected 0x{RATCHET_ENVELOPE_MAGIC:02X}, "
                f"got 0x{packet[0]:02X}."
            )

        try:
            offset = 1
            name_len = packet[offset]
            offset += 1

            if offset + name_len > len(packet):
                raise ValueError("Ratchet envelope truncated at sender name.")

            sender_name = packet[offset : offset + name_len].decode("utf-8")
            if not sender_name:
                raise ValueError("Ratchet envelope contains empty sender name.")
            offset += name_len

            if offset + 2 > len(packet):
                raise ValueError("Ratchet envelope truncated at header length.")

            header_len = struct.unpack(">H", packet[offset : offset + 2])[0]
            offset += 2

            if offset + header_len > len(packet):
                raise ValueError("Ratchet envelope truncated at header.")

            header = packet[offset : offset + header_len]
            offset += header_len

            ciphertext = packet[offset:]

            if len(ciphertext) == 0:
                raise ValueError("Ratchet envelope contains empty ciphertext.")

            return cls(
                sender_name=sender_name,
                header=header,
                ciphertext=ciphertext,
            )

        except UnicodeDecodeError as exc:
            raise ValueError("Ratchet envelope contains invalid UTF-8 sender name.") from exc
        except struct.error as exc:
            raise ValueError("Ratchet envelope has corrupted length fields.") from exc


@dataclass(frozen=True)
class PQCEncvelope:
    """Structured representation of a Post-Quantum Hybrid KEM message envelope.

    Wire format:
        0x50 | kem_ct_len(2B BE) | kem_ciphertext | nonce(12B) | aes_gcm_ciphertext+tag

    Attributes:
        kem_ciphertext: The KEM encapsulation output (Kyber768 + X25519 combined).
        nonce: 12-byte AES-GCM nonce.
        aes_ciphertext: AES-256-GCM encrypted payload including authentication tag.
    """

    kem_ciphertext: bytes
    nonce: bytes
    aes_ciphertext: bytes

    NONCE_LENGTH: int = 12

    def build(self) -> bytes:
        """Serialize this envelope into its binary wire format.

        Returns:
            The complete envelope as bytes.

        Raises:
            ValueError: If nonce length is not exactly 12 bytes.
        """
        if len(self.nonce) != self.NONCE_LENGTH:
            raise ValueError(
                f"PQC envelope nonce must be {self.NONCE_LENGTH} bytes, "
                f"got {len(self.nonce)}."
            )

        return (
            bytes([PQC_ENVELOPE_MAGIC])
            + struct.pack(">H", len(self.kem_ciphertext))
            + self.kem_ciphertext
            + self.nonce
            + self.aes_ciphertext
        )

    @classmethod
    def parse(cls, packet: bytes) -> PQCEncvelope:
        """Deserialize a binary packet into a PQCEncvelope.

        Args:
            packet: Raw bytes starting with the PQC_ENVELOPE_MAGIC byte.

        Returns:
            A parsed PQCEncvelope instance.

        Raises:
            ValueError: If the packet is malformed or magic byte mismatches.
        """
        if len(packet) < 3:
            raise ValueError("PQC envelope too short.")

        if packet[0] != PQC_ENVELOPE_MAGIC:
            raise ValueError(
                f"Invalid PQC envelope magic: expected 0x{PQC_ENVELOPE_MAGIC:02X}, "
                f"got 0x{packet[0]:02X}."
            )

        try:
            offset = 1
            kem_ct_len = struct.unpack(">H", packet[offset : offset + 2])[0]
            offset += 2

            if offset + kem_ct_len > len(packet):
                raise ValueError("PQC envelope truncated at KEM ciphertext.")

            kem_ciphertext = packet[offset : offset + kem_ct_len]
            offset += kem_ct_len

            nonce_end = offset + cls.NONCE_LENGTH
            if nonce_end > len(packet):
                raise ValueError("PQC envelope truncated at nonce.")

            nonce = packet[offset:nonce_end]
            offset = nonce_end

            aes_ciphertext = packet[offset:]

            if len(aes_ciphertext) < 16:
                raise ValueError(
                    "PQC envelope AES ciphertext too short (missing tag?)."
                )

            return cls(
                kem_ciphertext=kem_ciphertext,
                nonce=nonce,
                aes_ciphertext=aes_ciphertext,
            )

        except struct.error as exc:
            raise ValueError("PQC envelope has corrupted length fields.") from exc


def identify_envelope_type(packet: bytes) -> str | None:
    """Identify the envelope type from the first byte of a packet.

    Args:
        packet: Raw packet bytes (must be at least 1 byte).

    Returns:
        'ratchet', 'pqc', or None if unrecognized.
    """
    if not packet:
        return None

    magic = packet[0]
    if magic == RATCHET_ENVELOPE_MAGIC:
        return "ratchet"
    if magic == PQC_ENVELOPE_MAGIC:
        return "pqc"
    return None
