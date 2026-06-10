# ntp_client.py
import socket
import struct
import time
import statistics

# Multiple NTP servers for consensus (pool.ntp.org recommended)
NTP_SERVERS = [
    "0.pool.ntp.org",
    "1.pool.ntp.org",
    "2.pool.ntp.org",
    "3.pool.ntp.org",
    "time.google.com",
    "time.cloudflare.com",
]
NTP_PORT = 123
NTP_PACKET_FORMAT = "!B B B b 11I"
NTP_DELTA = 2208988800
TIMEOUT = 3
MIN_SERVERS_AGREE = 3       # Need at least 3 servers to agree
MAX_OFFSET_DEVIATION_MS = 500  # Reject servers deviating > 500ms from median


def _query_single_server(server: str) -> float:
    """Query a single NTP server. Returns Unix timestamp or raises."""
    packet = bytearray(48)
    packet[0] = 0x1B
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    try:
        t_before = time.time()
        sock.sendto(packet, (server, NTP_PORT))
        data, _ = sock.recvfrom(1024)
        t_after = time.time()
    finally:
        sock.close()

    if len(data) < 48:
        raise ValueError("Response too short")

    t = struct.unpack("!12I", data)[10]
    frac = struct.unpack("!12I", data)[11]
    server_time = t - NTP_DELTA + frac / 2**32

    # Round-trip correction (simple Marzullo-style)
    rtt = t_after - t_before
    corrected = server_time + (rtt / 2)
    return corrected


def get_ntp_time(timeout: int = 10, server: str = None) -> float:
    """
    Query NTP servers and return a consensus time.

    Args:
        timeout: Maximum total time to spend querying (currently unused,
                 per-server TIMEOUT constant is used instead).
        server: If provided, query only this single server (no consensus).
                If None, query all NTP_SERVERS and apply outlier rejection.

    Returns:
        Unix timestamp as float, or None if sync failed.
    """
    # Single-server mode (used by UI when user picks a specific server)
    if server is not None:
        try:
            return _query_single_server(server)
        except Exception:
            return None

    # Multi-server consensus mode
    results = []
    for srv in NTP_SERVERS:
        try:
            t = _query_single_server(srv)
            results.append(t)
        except Exception:
            continue

    if len(results) < MIN_SERVERS_AGREE:
        return None

    # Use median as robust central estimate
    median_time = statistics.median(results)

    # Filter out outliers (servers deviating more than MAX_OFFSET_DEVIATION_MS)
    filtered = [
        t for t in results
        if abs(t - median_time) < MAX_OFFSET_DEVIATION_MS / 1000.0
    ]

    if len(filtered) < MIN_SERVERS_AGREE:
        return None

    return statistics.mean(filtered)
