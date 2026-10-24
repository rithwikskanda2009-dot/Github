"""Per-link connectivity probing.

A link is probed by opening a TCP connection to a well-known public endpoint
*through that link*: the socket is bound to the link's own source address and
pinned to its interface index with IP_UNICAST_IF (network byte order - verified
empirically on Windows 10/11, the native-order packing is rejected).
"""

import socket
import struct
import time
from dataclasses import dataclass

IP_UNICAST_IF = 31

# Public endpoints used to test "does this link actually reach the internet".
# Several are tried in order so one blocked port/host does not fail the link.
PROBE_TARGETS = (("1.1.1.1", 443), ("8.8.8.8", 53), ("9.9.9.9", 53))


def connect_via(link, dst_ip, dst_port, timeout=8.0):
    """Open a TCP socket to (dst_ip, dst_port) forced out through *link*."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((link.ip, 0))
        s.setsockopt(socket.IPPROTO_IP, IP_UNICAST_IF, struct.pack(">I", link.index))
        s.settimeout(timeout)
        s.connect((dst_ip, dst_port))
        return s
    except OSError:
        s.close()
        raise


@dataclass
class HealthResult:
    ok: bool
    latency_ms: float = 0.0
    error: str = ""
    checked_at: float = 0.0


def check_link(link, timeout=3.0, targets=None):
    """Probe a link; returns HealthResult. Latency is from the first success."""
    targets = PROBE_TARGETS if targets is None else targets
    last_error = "no probe targets"
    for host, port in targets:
        start = time.monotonic()
        try:
            sock = connect_via(link, host, port, timeout=timeout)
        except OSError as exc:
            last_error = f"{host}:{port} {getattr(exc, 'strerror', None) or exc}"
            continue
        try:
            latency = (time.monotonic() - start) * 1000.0
            return HealthResult(True, round(latency, 1), "", time.time())
        finally:
            sock.close()
    return HealthResult(False, 0.0, last_error, time.time())
