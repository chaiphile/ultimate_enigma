"""Comprehensive unit tests for ntp_client.py – NTP time retrieval."""

import socket
import struct
import pytest
from unittest.mock import patch, MagicMock

from ntp_client import get_ntp_time, NTP_DELTA


class TestGetNTPTime:
    def _build_ntp_response(self, unix_ts: int) -> bytes:
        """Build a minimal valid NTP response with the given Unix timestamp."""
        ntp_seconds = unix_ts + NTP_DELTA
        packet = bytearray(48)
        # Transmit timestamp starts at byte 40
        struct.pack_into("!I", packet, 40, ntp_seconds)
        struct.pack_into("!I", packet, 44, 0)  # fractional part = 0
        return bytes(packet)

    @patch("ntp_client.socket.socket")
    def test_successful_query(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        expected_ts = 1700000000
        mock_sock.recvfrom.return_value = (self._build_ntp_response(expected_ts), ("1.2.3.4", 123))

        result = get_ntp_time(server="test.ntp.org", timeout=1)
        assert result is not None
        assert abs(result - expected_ts) < 1.0

        mock_sock.sendto.assert_called_once()
        mock_sock.close.assert_called_once()

    @patch("ntp_client.socket.socket")
    def test_timeout_returns_none(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recvfrom.side_effect = socket.timeout()

        result = get_ntp_time(server="test.ntp.org", timeout=1)
        assert result is None
        mock_sock.close.assert_called_once()

    @patch("ntp_client.socket.socket")
    def test_os_error_returns_none(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recvfrom.side_effect = OSError("Network unreachable")

        result = get_ntp_time(timeout=1)
        assert result is None

    @patch("ntp_client.socket.socket")
    def test_sendto_error_returns_none(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.sendto.side_effect = OSError("DNS failure")

        result = get_ntp_time(timeout=1)
        assert result is None

    @patch("ntp_client.socket.socket")
    def test_fractional_seconds(self, mock_socket_cls):
        """Verify that fractional NTP seconds are correctly converted."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        ntp_sec = 1700000000 + NTP_DELTA
        frac = 2**31  # 0.5 in NTP fractional
        packet = bytearray(48)
        struct.pack_into("!I", packet, 40, ntp_sec)
        struct.pack_into("!I", packet, 44, frac)
        mock_sock.recvfrom.return_value = (bytes(packet), ("1.2.3.4", 123))

        result = get_ntp_time(timeout=1)
        expected = 1700000000 + frac / 2**32
        assert abs(result - expected) < 0.001

    @patch("ntp_client.socket.socket")
    def test_custom_server_and_port(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recvfrom.return_value = (self._build_ntp_response(1700000000), ("5.6.7.8", 123))

        get_ntp_time(server="custom.server", timeout=1)
        mock_sock.sendto.assert_called_once()
        args = mock_sock.sendto.call_args[0]
        assert args[1] == ("custom.server", 123)

    @patch("ntp_client.socket.socket")
    def test_socket_always_closed(self, mock_socket_cls):
        """Ensure socket is closed even on exception."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recvfrom.side_effect = Exception("unexpected")

        try:
            get_ntp_time(server="test.ntp.org", timeout=1)
        except Exception:
            pass
        mock_sock.close.assert_called_once()
