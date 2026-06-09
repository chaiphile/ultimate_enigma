# ntp_client.py
import socket
import struct
import time

NTP_SERVER = "ntp.day.ir"
NTP_PORT = 123
NTP_PACKET_FORMAT = "!B B B b 11I"  # mode 3 (client)
NTP_DELTA = 2208988800  # seconds between 1900-01-01 and 1970-01-01

def get_ntp_time(server=NTP_SERVER, timeout=2):
    """
    Query NTP server and return Unix timestamp (float).
    Returns None if the server is unreachable.
    """
    # Build request packet (mode 3 - client)
    packet = bytearray(48)
    packet[0] = 0x1B  # LI=0, VN=3, Mode=3

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, NTP_PORT))
        data, _ = sock.recvfrom(48)
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()

    # Unpack the transmit timestamp (bytes 40-47)
    t = struct.unpack("!12I", data)[10]  # Transmit Timestamp integer part
    frac = struct.unpack("!12I", data)[11]  # fractional part
    # Convert NTP epoch (1900) to Unix epoch (1970)
    return t - NTP_DELTA + frac / 2**32