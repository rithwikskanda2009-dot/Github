"""Headless behavioral verification for NetBond.

Drives the real modules end-to-end: link discovery, per-link probes, weighted
distribution, cooldown/failover, the HTTP and SOCKS5 proxy paths, per-link
traffic counters, and the reversible system-proxy registry toggle (against a
scratch registry key, never the real proxy settings).

Run:  python tests/verify_headless.py
"""

import os
import socket
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from netbond import sysproxy  # noqa: E402
from netbond.balancer import Balancer  # noqa: E402
from netbond.health import HealthResult, check_link  # noqa: E402
from netbond.interfaces import Link, _merge, _parse_speed, discover_links  # noqa: E402
from netbond.proxy import BondProxy  # noqa: E402

FAILURES = []
SKIPS = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" :: {detail}" if detail else ""))
    if not cond:
        FAILURES.append(name)


def skip(name, reason):
    print(f"[SKIP] {name} :: {reason}")
    SKIPS.append(name)


# --------------------------------------------------------------------------
# local HTTP origin that reports which proxy link forwarded the request
# --------------------------------------------------------------------------

class Origin:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(32)
        self.sock.settimeout(0.5)
        self.port = self.sock.getsockname()[1]
        self.requests = []
        self._stop = threading.Event()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
        try:
            self.sock.close()
        except OSError:
            pass

    def _handle(self, conn):
        conn.settimeout(5.0)
        try:
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            head = buf.partition(b"\r\n\r\n")[0].decode("latin-1", "replace")
            lines = head.split("\r\n")
            self.requests.append(lines[0] if lines else "")
            link = ""
            for line in lines[1:]:
                if line.lower().startswith("x-netbond-link:"):
                    link = line.partition(":")[2].strip()
            body = f"ORIGIN OK served-by={link} path={lines[0] if lines else ''}"
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                + body.encode()
            )
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        self._stop.set()


# --------------------------------------------------------------------------
# protocol clients
# --------------------------------------------------------------------------

def http_get(proxy_port, url, timeout=10):
    """Plain HTTP proxy GET with an absolute-URI request line."""
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    try:
        hostport = url.split("//", 1)[1].split("/", 1)[0]
        s.sendall(
            f"GET {url} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n\r\n".encode()
        )
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    finally:
        s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1]) if head.startswith(b"HTTP/") and len(head.split(b" ")) > 1 else 0
    return status, head.decode("latin-1", "replace"), body.decode("latin-1", "replace")


def socks5_get(proxy_port, host, port, path="/", atyp=1, timeout=10):
    """Minimal SOCKS5 client: greet, CONNECT, then an HTTP GET."""
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    try:
        s.sendall(b"\x05\x01\x00")
        greet = s.recv(2)
        if greet != b"\x05\x00":
            return 0, f"bad greeting {greet!r}", ""
        req = b"\x05\x01\x00" + bytes([atyp])
        if atyp == 1:
            req += socket.inet_aton(host)
        elif atyp == 3:
            hb = host.encode()
            req += bytes([len(hb)]) + hb
        req += port.to_bytes(2, "big")
        s.sendall(req)
        reply = s.recv(10)
        if len(reply) < 4 or reply[1] != 0:
            return 0, f"socks reply {reply!r}", ""
        s.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
        )
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    finally:
        s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1]) if head.startswith(b"HTTP/") and len(head.split(b" ")) > 1 else 0
    return status, head.decode("latin-1", "replace"), body.decode("latin-1", "replace")


# --------------------------------------------------------------------------
# fake links / fake transport helpers
# --------------------------------------------------------------------------

def fake_link(name, speed, ip="10.0.0."):
    n = abs(hash(name)) % 200 + 2
    return Link(name=name, index=n, ip=f"{ip}{n}", speed_mbps=speed,
                gateway="10.0.0.1", kind="other")


def make_connect(origin, failing=()):
    def connect_fn(link, dst_ip, dst_port, timeout=8.0):
        if link.name in failing:
            raise OSError(10051, f"simulated network unreachable on {link.name}")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(("127.0.0.1", origin.port))
        return s
    return connect_fn


def make_health(failing=(), latencies=None):
    latencies = latencies or {}
    def health_fn(link, timeout=None, targets=None):
        if link.name in failing:
            return HealthResult(False, 0.0, f"simulated down ({link.name})", time.time())
        return HealthResult(True, latencies.get(link.name, 50.0), "", time.time())
    return health_fn


# ==========================================================================
# tests
# ==========================================================================

def test_interfaces_unit():
    check("speed parse 426 Mbps", _parse_speed("426.0 Mbps") == 426.0)
    check("speed parse 1 Gbps", _parse_speed("1 Gbps") == 1000.0)
    check("speed parse 100 Mbps", _parse_speed("100 Mbps") == 100.0)
    check("speed parse garbage -> 0", _parse_speed("n/a") == 0.0)

    data = {
        "adapters": [
            {"Name": "Ethernet 3", "ifIndex": 19, "Status": "Up", "LinkSpeed": "426.0 Mbps",
             "InterfaceDescription": "USB GbE"},
            {"Name": "Wi-Fi", "ifIndex": 6, "Status": "Disconnected", "LinkSpeed": "0 bps",
             "InterfaceDescription": "Wireless"},
            {"Name": "Ethernet", "ifIndex": 27, "Status": "Up", "LinkSpeed": "1 Gbps",
             "InterfaceDescription": "Realtek"},
        ],
        "ips": [
            {"Alias": "Ethernet 3", "Idx": 19, "IPv4": ["10.88.153.71"], "GW": ["10.88.153.4"]},
            {"Alias": "Wi-Fi", "Idx": 6, "IPv4": ["169.254.84.225"], "GW": []},
            {"Alias": "Ethernet", "Idx": 27, "IPv4": ["169.254.195.160"], "GW": []},
        ],
    }
    links = _merge(data)
    names = [l.name for l in links]
    check("merge drops disconnected adapter", "Wi-Fi" not in names, str(names))
    check("merge drops APIPA-only adapter", "Ethernet" not in names, str(names))
    check("merge keeps routable adapter", "Ethernet 3" in names, str(names))
    if links:
        l = links[0]
        check("merge parses gateway", l.gateway == "10.88.153.4", l.gateway)
        check("merge parses speed", l.speed_mbps == 426.0, str(l.speed_mbps))
        check("merge classifies USB description", l.kind == "usb", l.kind)
        check("tier maps 426 Mbps -> 3", l.tier == 3, str(l.tier))
    # dict (single row) not list must not crash
    check("merge tolerates single-object JSON",
          isinstance(_merge({"adapters": data["adapters"][0], "ips": data["ips"][0]}), list))


def test_discovery_integration():
    try:
        links = discover_links()
    except Exception as exc:
        check("discover_links() runs", False, str(exc))
        return []
    check("discover_links() returns a list", isinstance(links, list))
    check("at least one link on this machine", len(links) >= 1, f"{len(links)} links")
    check("no APIPA addresses leak through",
          all(not l.ip.startswith("169.254.") for l in links),
          ",".join(l.ip for l in links))
    check("all interface indexes are real", all(l.index > 0 for l in links))
    for l in links:
        print(f"       link: {l.name} idx={l.index} ip={l.ip} "
              f"{l.speed_mbps:.0f} Mbps gw={l.gateway or '-'} kind={l.kind} tier={l.tier}")
    return links


def test_health_real(links):
    if not links:
        skip("check_link(real link)", "no links discovered")
        return
    with_gw = [l for l in links if l.gateway] or links
    target = with_gw[0]
    res = check_link(target, timeout=4.0)
    if res.ok:
        check(f"check_link({target.name}) reaches internet", True, f"{res.latency_ms} ms")
    else:
        skip(f"check_link({target.name})", f"link has no internet right now: {res.error}")


def test_swrr_distribution():
    links = [fake_link("W4", 1000), fake_link("W3", 150),
             fake_link("W2", 50), fake_link("W1", 10)]
    b = Balancer()
    b.set_links(links)
    counts = {l.name: 0 for l in links}
    for _ in range(1000):
        st = b.pick()
        counts[st.link.name] += 1
    check("weights 4:3:2:1 over 1000 picks are exact",
          counts == {"W4": 400, "W3": 300, "W2": 200, "W1": 100}, str(counts))

    # latency modifiers: fast link boosted, slow link floored at weight >= 1
    b2 = Balancer()
    b2.set_links([fake_link("FAST", 100), fake_link("SLOW", 100)])
    fast = [s for s in b2.states if s.link.name == "FAST"][0]
    slow = [s for s in b2.states if s.link.name == "SLOW"][0]
    fast.latency_ms, slow.latency_ms = 40.0, 400.0
    check("low latency boosts weight", fast.effective_weight() == 6, str(fast.effective_weight()))
    check("high latency halves but never starves", slow.effective_weight() == 1,
          str(slow.effective_weight()))


def test_cooldown_and_recovery():
    now = [0.0]
    b = Balancer(clock=lambda: now[0], health_fn=make_health())
    b.set_links([fake_link("A", 100), fake_link("B", 100)])
    st_b = [s for s in b.states if s.link.name == "B"][0]

    b.report_failure(st_b, "boom")
    check("failure starts 2s cooldown", abs(st_b.cooldown_until - 2.0) < 1e-6,
          str(st_b.cooldown_until))
    picked = {b.pick().link.name for _ in range(50)}
    check("link in cooldown is never picked", picked == {"A"}, str(picked))

    now[0] = 2.5
    picked = {b.pick().link.name for _ in range(50)}
    check("link returns after cooldown expiry", "B" in picked, str(picked))

    b.report_success(st_b)
    check("success clears failures", st_b.failures == 0)
    check("success clears cooldown", st_b.cooldown_until == 0.0)

    for i in range(3):
        now[0] += 60
        b.report_failure(st_b, f"fail{i}")
    check("3 failures mark link down", st_b.healthy is False)
    now[0] += 120  # way past any cooldown
    picked = {b.pick().link.name for _ in range(50)}
    check("dead link stays excluded until re-probed", picked == {"A"}, str(picked))

    results = b.probe_all()
    check("probe_all recovers a dead link", st_b.healthy is True and st_b.failures == 0)
    check("probe_all reports latency", all(r.ok for _, r in results))
    picked = {b.pick().link.name for _ in range(50)}
    check("recovered link picks again", "B" in picked, str(picked))


def test_open_upstream_failover(origin):
    b = Balancer(connect_fn=make_connect(origin, failing=("B",)))
    b.set_links([fake_link("A", 100), fake_link("B", 100), fake_link("C", 100)])
    served = set()
    ok = True
    for _ in range(12):
        try:
            sock, st = b.open_upstream("127.0.0.1", origin.port, timeout=3.0)
        except OSError as exc:
            ok = False
            print(f"       open_upstream raised: {exc}")
            break
        served.add(st.link.name)
        sock.close()
    check("open_upstream keeps serving despite a dead link", ok)
    check("traffic uses only healthy links",
          served and "B" not in served and served <= {"A", "C"}, str(served))
    snap = {r["name"]: r for r in b.snapshot()}
    check("dead link recorded failures", snap["B"]["failures"] >= 1, str(snap["B"]["failures"]))
    check("dead link got no successful requests", snap["B"]["requests"] == 0)

    b2 = Balancer(connect_fn=make_connect(origin, failing=("A", "B", "C")))
    b2.set_links([fake_link("A", 100), fake_link("B", 100)])
    try:
        b2.open_upstream("127.0.0.1", origin.port, timeout=3.0)
        check("all links failing raises", False, "no exception")
    except OSError as exc:
        check("all links failing raises the last error", "simulated" in str(exc), str(exc))

    b3 = Balancer(connect_fn=make_connect(origin))
    b3.set_links([fake_link("A", 100)])
    b3.set_enabled("A", False)
    try:
        b3.open_upstream("127.0.0.1", origin.port, timeout=3.0)
        check("no usable links raises OSError('no usable links')", False, "no exception")
    except OSError as exc:
        check("no usable links raises OSError('no usable links')",
              "no usable links" in str(exc), str(exc))


def test_http_proxy(origin):
    b = Balancer(connect_fn=make_connect(origin))
    b.set_links([fake_link("A", 1000), fake_link("B", 150), fake_link("C", 50)])
    proxy = BondProxy(b, http_port=0, socks_port=0)
    proxy.start()
    try:
        status, head, body = http_get(proxy.http_port,
                                      f"http://127.0.0.1:{origin.port}/t?x=1")
        check("HTTP proxy serves origin", status == 200, f"status={status}")
        check("HTTP response body intact", body.startswith("ORIGIN OK"), body[:80])
        check("response says which link served it", "served-by=" in body,
              body.split(" served-by=")[-1][:40])
        check("request reached origin unchanged (origin-form path)",
              any("/t?x=1" in r for r in origin.requests), str(origin.requests[-1:]))

        snap = {r["name"]: r for r in b.snapshot()}
        total_reqs = sum(r["requests"] for r in snap.values())
        check("per-link request counter incremented", total_reqs == 1, str(snap))
        serving = [n for n, r in snap.items() if r["requests"] == 1][0]
        check("traffic counters > 0 on serving link",
              snap[serving]["bytes_in"] > 0 and snap[serving]["bytes_out"] > 0,
              str({k: (v["bytes_in"], v["bytes_out"]) for k, v in snap.items()}))

        # many requests: distribution across all three healthy links
        for i in range(12):
            s, _, _ = http_get(proxy.http_port, f"http://127.0.0.1:{origin.port}/d/{i}")
            if s != 200:
                break
        snap = {r["name"]: r for r in b.snapshot()}
        served = sorted(n for n, r in snap.items() if r["requests"] > 0)
        check("requests spread across all healthy links", len(served) == 3, str(snap))
    finally:
        proxy.stop()


def test_http_failover(origin):
    b = Balancer(connect_fn=make_connect(origin, failing=("B",)))
    b.set_links([fake_link("A", 100), fake_link("B", 100), fake_link("C", 100)])
    proxy = BondProxy(b, http_port=0, socks_port=0)
    proxy.start()
    try:
        statuses = []
        for i in range(9):
            s, _, body = http_get(proxy.http_port, f"http://127.0.0.1:{origin.port}/f/{i}")
            statuses.append(s)
        check("all requests succeed while one link is dying",
              all(s == 200 for s in statuses), str(statuses))
        snap = {r["name"]: r for r in b.snapshot()}
        check("dead link accumulated failures", snap["B"]["failures"] >= 1,
              str(snap["B"]["failures"]))
        check("dead link served zero requests", snap["B"]["requests"] == 0,
              str(snap["B"]["requests"]))

        # disable every link -> immediate 503 with NetBond error body
        for name in snap:
            b.set_enabled(name, False)
        s, _, body = http_get(proxy.http_port, f"http://127.0.0.1:{origin.port}/none")
        check("all links disabled -> 503", s == 503, f"status={s}")
        check("503 body is NetBond's", "NetBond" in body, body[:60])
    finally:
        proxy.stop()


def test_all_links_down_first_request(origin):
    b = Balancer(connect_fn=make_connect(origin, failing=("A",)))
    b.set_links([fake_link("A", 100)])
    proxy = BondProxy(b, http_port=0, socks_port=0)
    proxy.start()
    try:
        s1, _, _ = http_get(proxy.http_port, f"http://127.0.0.1:{origin.port}/1")
        s2, _, body = http_get(proxy.http_port, f"http://127.0.0.1:{origin.port}/2")
        check("connect failure answers 502/503", s1 in (502, 503), f"status={s1}")
        check("after cooldown, answer is 503", s2 == 503, f"status={s2}")
        check("503 mentions NetBond", "NetBond" in body, body[:60])
        snap = b.snapshot()
        check("link marked down after repeated failures", snap[0]["failures"] >= 1)
    finally:
        proxy.stop()


def test_socks5_proxy(origin):
    b = Balancer(connect_fn=make_connect(origin))
    b.set_links([fake_link("A", 100), fake_link("B", 100)])
    proxy = BondProxy(b, http_port=0, socks_port=0)
    proxy.start()
    try:
        s, head, body = socks5_get(proxy.socks_port, "127.0.0.1", origin.port,
                                   "/s/ipv4", atyp=1)
        check("SOCKS5 IPv4 CONNECT serves request", s == 200, f"status={s} {head[:60]}")
        check("SOCKS5 body intact", body.startswith("ORIGIN OK"), body[:60])

        s, _, body = socks5_get(proxy.socks_port, "localhost", origin.port,
                                "/s/domain", atyp=3)
        check("SOCKS5 domain CONNECT serves request", s == 200, f"status={s}")
        check("SOCKS5 domain body intact", body.startswith("ORIGIN OK"), body[:60])

        snap = {r["name"]: r for r in b.snapshot()}
        total = sum(r["requests"] for r in snap.values())
        check("SOCKS5 requests counted per link", total == 2, str(snap))

        for name in snap:
            b.set_enabled(name, False)
        s, head, _ = socks5_get(proxy.socks_port, "127.0.0.1", origin.port, "/none")
        check("SOCKS5 with no links returns failure reply", s == 0, head)
        # head is the repr of the raw reply: b'\x05\x04...' -> code byte 04
        check("SOCKS5 no-links reply code is 0x04 (net unreachable)",
              "\\x04" in head, head)
    finally:
        proxy.stop()


def test_real_internet_path(links):
    usable = [l for l in links if l.gateway]
    if not usable:
        skip("real internet through proxy", "no link with a gateway")
        return
    b = Balancer()  # real connect_via: bind + IP_UNICAST_IF
    b.set_links(usable)
    proxy = BondProxy(b, http_port=0, socks_port=0)
    proxy.start()
    try:
        status, head, body = http_get(proxy.http_port, "http://example.com/", timeout=15)
        check("real traffic through real link",
              status in (200, 301, 302) and len(body) >= 0,
              f"status={status} bytes={len(body)}")
        snap = {r["name"]: r for r in b.snapshot()}
        served = [n for n, r in snap.items() if r["requests"] > 0]
        check("real request attributed to a real link", len(served) == 1, str(snap))
    except OSError as exc:
        skip("real internet through proxy", f"network unreachable right now: {exc}")
    finally:
        proxy.stop()


def test_sysproxy_roundtrip():
    import winreg
    orig_key = sysproxy._KEY_PATH
    scratch = rf"Software\NetBondTest_{os.getpid()}"
    sysproxy._KEY_PATH = scratch
    try:
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, scratch)
        except FileNotFoundError:
            pass
        check("proxy_server_value format",
              sysproxy.proxy_server_value("127.0.0.1", 8811, 8812)
              == "http=127.0.0.1:8811;https=127.0.0.1:8811;socks=127.0.0.1:8812")

        snap = sysproxy.apply("127.0.0.1", 8811, 8812)
        after = sysproxy.read_settings()
        check("apply enables ProxyEnable", after.get("ProxyEnable") == 1,
              str(after.get("ProxyEnable")))
        check("apply points at local proxy",
              "127.0.0.1:8811" in str(after.get("ProxyServer", "")),
              str(after.get("ProxyServer")))
        check("apply sets an override", bool(after.get("ProxyOverride")),
              str(after.get("ProxyOverride")))
        check("is_enabled detects active bond", sysproxy.is_enabled("127.0.0.1", 8811))
        check("snapshot captured prior (empty) state", snap == {}, str(snap))

        sysproxy.restore(snap)
        restored = sysproxy.read_settings()
        check("restore clears the proxy values", restored == {}, str(restored))
        check("is_enabled false after restore",
              not sysproxy.is_enabled("127.0.0.1", 8811))

        # second apply with pre-existing values must round-trip them exactly
        with sysproxy._open(create=True) as key:
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "old.example:8080")
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        snap2 = sysproxy.apply("127.0.0.1", 9999, 9998)
        check("snapshot keeps previous server", snap2.get("ProxyServer") == "old.example:8080",
              str(snap2.get("ProxyServer")))
        sysproxy.restore(snap2)
        back = sysproxy.read_settings()
        check("restore brings back exact prior values",
              back.get("ProxyServer") == "old.example:8080" and back.get("ProxyEnable") == 1,
              str(back))
        sysproxy.restore({})
    finally:
        sysproxy._KEY_PATH = orig_key
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, scratch)
        except OSError:
            pass


def main():
    print("=" * 70)
    print("NetBond headless verification")
    print("=" * 70)
    origin = Origin()
    try:
        test_interfaces_unit()
        links = test_discovery_integration()
        test_health_real(links)
        test_swrr_distribution()
        test_cooldown_and_recovery()
        test_open_upstream_failover(origin)
        test_http_proxy(origin)
        test_http_failover(origin)
        test_all_links_down_first_request(origin)
        test_socks5_proxy(origin)
        test_real_internet_path(links)
        test_sysproxy_roundtrip()
    finally:
        origin.close()

    print("=" * 70)
    for s in SKIPS:
        print(f"SKIPPED: {s}")
    if FAILURES:
        print(f"RESULT: {len(FAILURES)} FAILURE(S): {FAILURES}")
        return 1
    print("RESULT: ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
