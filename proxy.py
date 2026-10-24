"""Local HTTP + SOCKS5 proxy that spreads connections across bonded links.

Both listeners share one Balancer. For every client connection the proxy picks
a link, opens the upstream socket *through that link* (bind to its address +
IP_UNICAST_IF pinning) and relays bytes. If the upstream connect fails the
proxy marks the link failed and retries on the next link, so a dying link only
costs one connect attempt, not the request.

The proxy binds to 127.0.0.1 only - it is a local tool, not a gateway for
other machines.
"""

import socket
import threading

MAX_HEADER = 65536
RELAY_IDLE_TIMEOUT = 300.0


def _recv_until(sock, marker=b"\r\n\r\n", limit=MAX_HEADER):
    buf = bytearray()
    while marker not in buf:
        if len(buf) >= limit:
            raise OSError("request headers too large")
        chunk = sock.recv(4096)
        if not chunk:
            raise OSError("client closed during request")
        buf.extend(chunk)
    head, _, rest = bytes(buf).partition(marker)
    return head, rest


def _relay(a, b, on_bytes=None):
    """Pump bytes a->b until either side closes. Returns bytes moved."""
    moved = 0
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
            moved += len(data)
    except OSError:
        pass
    finally:
        if on_bytes:
            on_bytes(moved)
    return moved


def _tunnel(client, upstream, st, balancer, pre_sent=0):
    """Relay in both directions and account traffic on the chosen link.

    ``pre_sent`` is request bytes already written to the upstream socket
    before the tunnel started (the rewritten HTTP request), so upload
    accounting covers them too.
    """
    counters = {"in": 0, "out": pre_sent}
    lock = threading.Lock()

    def from_client(n):
        with lock:
            counters["out"] += n

    def from_upstream(n):
        with lock:
            counters["in"] += n

    t = threading.Thread(target=_relay, args=(client, upstream, from_client), daemon=True)
    t.start()
    try:
        _relay(upstream, client, from_upstream)
    finally:
        with lock:
            balancer.record_traffic(st, counters["out"], counters["in"])
        for sock in (client, upstream):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass


class ProxyError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


class BondProxy:
    """HTTP proxy + SOCKS5 proxy sharing one Balancer."""

    def __init__(self, balancer, host="127.0.0.1", http_port=8811, socks_port=8812):
        self.balancer = balancer
        self.host = host
        self.http_port = http_port
        self.socks_port = socks_port
        self._listeners = []
        self._threads = []
        self._stopped = threading.Event()

    # -- lifecycle -----------------------------------------------------------

    def start(self):
        self._stopped.clear()
        specs = (("http", self.http_port, self._serve_http),
                 ("socks", self.socks_port, self._serve_socks))
        for name, port, handler in specs:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                listener.bind((self.host, port))
            except OSError:
                listener.close()
                self.stop()
                raise
            listener.listen(128)
            listener.settimeout(0.5)
            actual = listener.getsockname()[1]
            if name == "http":
                self.http_port = actual
            else:
                self.socks_port = actual
            self._listeners.append(listener)
            t = threading.Thread(target=handler, args=(listener,), daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self):
        self._stopped.set()
        for listener in self._listeners:
            try:
                listener.close()
            except OSError:
                pass
        self._listeners = []
        self._threads = []

    @property
    def running(self):
        return bool(self._listeners) and not self._stopped.is_set()

    # -- accept loops --------------------------------------------------------

    def _serve_http(self, listener):
        while not self._stopped.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_http, args=(client,), daemon=True).start()

    def _serve_socks(self, listener):
        while not self._stopped.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_socks, args=(client,), daemon=True).start()

    # -- HTTP proxy ----------------------------------------------------------

    def _handle_http(self, client):
        client.settimeout(30.0)
        try:
            head, extra = _recv_until(client)
            lines = head.split(b"\r\n")
            parts = lines[0].split(b" ")
            if len(parts) < 2:
                raise ProxyError(400, "malformed request")
            method, target = parts[0].decode("latin-1"), parts[1].decode("latin-1")
            headers = {}
            for line in lines[1:]:
                if b":" in line:
                    k, _, v = line.partition(b":")
                    headers[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")

            if method.upper() == "CONNECT":
                host, port = self._split_hostport(target, 443)
                upstream, st = self.balancer.open_upstream(host, port, timeout=10.0)
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                _tunnel(client, upstream, st, self.balancer)
                return

            host, port, path = self._parse_absolute_uri(target, headers)
            upstream, st = self.balancer.open_upstream(host, port, timeout=10.0)
            try:
                origin_line = f"{method} {path} HTTP/1.1".encode("latin-1")
                out = [origin_line]
                for line in lines[1:]:
                    low = line.lower()
                    if low.startswith(b"proxy-connection:") or low.startswith(b"proxy-authorization:"):
                        continue
                    out.append(line)
                out.append(f"X-NetBond-Link: {st.link.name}".encode("latin-1"))
                request = b"\r\n".join(out) + b"\r\n\r\n"
                upstream.sendall(request)
                if extra:
                    upstream.sendall(extra)
                _tunnel(client, upstream, st, self.balancer,
                        pre_sent=len(request) + len(extra))
            finally:
                pass
        except ProxyError as exc:
            self._send_http_error(client, exc.status, exc.message)
        except OSError as exc:
            status = 503 if "no usable links" in str(exc) else 502
            self._send_http_error(client, status, str(exc))
        finally:
            try:
                client.close()
            except OSError:
                pass

    @staticmethod
    def _split_hostport(target, default_port):
        if target.startswith("["):  # [v6]:port
            host, sep, rest = target[1:].partition("]")
            port = int(rest[1:]) if sep and rest.startswith(":") else default_port
            return host, port
        if ":" in target:
            host, _, port = target.rpartition(":")
            try:
                return host, int(port)
            except ValueError:
                pass
        return target, default_port

    @classmethod
    def _parse_absolute_uri(cls, target, headers):
        if target.startswith("http://"):
            rest = target[7:]
            hostport, _, path = rest.partition("/")
            path = "/" + path
            host, port = cls._split_hostport(hostport, 80)
            return host, port, path
        if target.startswith("/"):
            hostport = headers.get("host", "")
            if not hostport:
                raise ProxyError(400, "missing Host header")
            host, port = cls._split_hostport(hostport, 80)
            return host, port, target
        raise ProxyError(400, f"unsupported request target: {target[:80]}")

    @staticmethod
    def _send_http_error(client, status, message):
        body = f"NetBond proxy: {message}\r\n".encode("utf-8", "replace")
        reason = {400: "Bad Request", 502: "Bad Gateway", 503: "Service Unavailable"}.get(status, "Error")
        head = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("latin-1")
        try:
            client.sendall(head + body)
        except OSError:
            pass

    # -- SOCKS5 --------------------------------------------------------------

    def _handle_socks(self, client):
        client.settimeout(30.0)
        upstream = None
        try:
            header = self._read_socks(client, 2)
            if header[0] != 5:
                raise ProxyError(400, "not SOCKS5")
            nmethods = header[1]
            self._read_socks(client, nmethods)
            client.sendall(b"\x05\x00")  # no auth

            req = self._read_socks(client, 4)
            ver, cmd, _, atyp = req
            if ver != 5:
                raise ProxyError(400, "not SOCKS5")
            if cmd != 1:  # CONNECT only
                self._socks_reply(client, 0x07)
                return
            if atyp == 1:  # IPv4
                raw = self._read_socks(client, 4)
                host = socket.inet_ntoa(raw)
            elif atyp == 3:  # domain
                length = self._read_socks(client, 1)[0]
                host = self._read_socks(client, length).decode("latin-1")
            elif atyp == 4:  # IPv6
                raw = self._read_socks(client, 16)
                host = socket.inet_ntop(socket.AF_INET6, raw)
            else:
                self._socks_reply(client, 0x08)
                return
            port = int.from_bytes(self._read_socks(client, 2), "big")

            try:
                upstream, st = self.balancer.open_upstream(host, port, timeout=10.0)
            except OSError as exc:
                code = 0x04 if "no usable links" in str(exc) else 0x05
                self._socks_reply(client, code)
                return
            self._socks_reply(client, 0x00, upstream.getsockname())
            _tunnel(client, upstream, st, self.balancer)
        except ProxyError:
            try:
                self._socks_reply(client, 0x01)
            except OSError:
                pass
        except OSError:
            pass
        finally:
            for sock in (client, upstream):
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass

    @staticmethod
    def _read_socks(sock, n):
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise OSError("socks client closed")
            buf.extend(chunk)
        return bytes(buf)

    @staticmethod
    def _socks_reply(client, code, addr=None):
        bind = b"\x00\x00\x00\x00\x00\x00"
        if addr:
            try:
                bind = socket.inet_aton(addr[0]) + addr[1].to_bytes(2, "big")
            except OSError:
                bind = b"\x00\x00\x00\x00\x00\x00"
        client.sendall(b"\x05" + bytes([code]) + b"\x00\x01" + bind)
