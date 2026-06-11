# ntp_client.py
"""
Simple, robust NTP client.

Design philosophy: NO ThreadPoolExecutor, NO threading for DNS.
The caller (app.py) already runs this in a background thread,
so we keep the client itself single-threaded and predictable.

Sequential queries with short timeouts are slightly slower but
eliminate all deadlock/hang possibilities on Windows.
"""
import socket
import struct
import time
import statistics
import logging

logger = logging.getLogger(__name__)

# Ordered by reliability. IPs used where DNS may hang.
NTP_SERVERS = [
    "time.cloudflare.com",
    "0.pool.ntp.org",
    "1.pool.ntp.org",
    "2.pool.ntp.org",
    "3.pool.ntp.org",
    "time.nist.gov",
    "ntp.ubuntu.com",
    "ntp.day.ir",
    "time.google.com",       # Often blocked/slow, placed last
]

NTP_PORT = 123
NTP_DELTA = 2208988800
PER_SERVER_TIMEOUT = 2      # Socket timeout per server (seconds)
MAX_SERVERS_TO_TRY = 5      # Stop after this many attempts (success or not)
MIN_RESPONSES = 1           # Minimum valid responses to return a time


def _query_one(server: str, timeout: float = PER_SERVER_TIMEOUT) -> float:
    """Query a single NTP server. Returns Unix timestamp or raises."""
    packet = bytearray(48)
    packet[0] = 0x1B

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        t_before = time.time()
        sock.sendto(packet, (server, NTP_PORT))
        data, _ = sock.recvfrom(1024)
        t_after = time.time()
    finally:
        sock.close()

    if len(data) < 48:
        raise ValueError(f"Short response ({len(data)} bytes)")

    t = struct.unpack("!12I", data)[10]
    frac = struct.unpack("!12I", data)[11]
    server_time = t - NTP_DELTA + frac / 2**32

    rtt = t_after - t_before
    return server_time + (rtt / 2)


def get_ntp_time(timeout: int = 10, server: str = None) -> float | None:
    """
    Query NTP servers and return a consensus time.

    Args:
        timeout: Unused (kept for API compatibility).
        server: If provided, query only this one server.
                If None, query NTP_SERVERS sequentially.

    Returns:
        Unix timestamp as float, or None if all servers fail.
    """
    # ── Single-server mode ──
    if server is not None:
        try:
            return _query_one(server)
        except Exception:
            return None

    # ── Multi-server sequential mode ──
    results: dict[str, float] = {}
    errors: dict[str, str] = {}

    servers_to_try = NTP_SERVERS[:MAX_SERVERS_TO_TRY]
    logger.info("Querying up to %d NTP servers sequentially (timeout=%ds each)...",
                len(servers_to_try), PER_SERVER_TIMEOUT)

    for srv in servers_to_try:
        try:
            t = _query_one(srv)
            results[srv] = t
            logger.debug("✓ %s: %.6f", srv, t)
        except socket.gaierror as e:
            errors[srv] = f"DNS: {e}"
            logger.debug("✗ %s DNS failed: %s", srv, e)
        except socket.timeout:
            errors[srv] = "timeout"
            logger.debug("✗ %s timed out", srv)
        except OSError as e:
            errors[srv] = f"net: {e}"
            logger.debug("✗ %s network error: %s", srv, e)
        except Exception as e:
            errors[srv] = str(e)
            logger.debug("✗ %s: %s", srv, e)

    logger.info("NTP done: %d/%d responded", len(results), len(servers_to_try))
    if results:
        logger.info("  OK: %s", ", ".join(results))
    if errors:
        logger.info("  Fail: %s", "; ".join(f"{s} ({e})" for s, e in errors.items()))

    if not results:
        logger.error("All NTP servers unreachable")
        return None

    # Use median for robustness
    timestamps = list(results.values())
    if len(timestamps) == 1:
        return timestamps[0]

    median_time = statistics.median(timestamps)

    # Filter outliers (>500ms from median)
    filtered = [t for t in timestamps if abs(t - median_time) < 0.5]

    if filtered:
        return statistics.mean(filtered)

    # All outliers – return raw median
    logger.warning("All responses are outliers, using raw median")
    return median_time
