"""GUI smoke test: boots the real Tk app, drives the Bond toggle, asserts the
system proxy is enabled during bonding and restored exactly on stop/close.

Never leaves the machine dirty: the prior registry state is captured up front
and force-restored in a finally block even if an assertion fails.

Run:  python tests/gui_smoke.py
"""

import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import tkinter as tk  # noqa: E402

from netbond import sysproxy  # noqa: E402
from netbond.gui import App  # noqa: E402

FAILURES = []
ERRORS = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" :: {detail}" if detail else ""))
    if not cond:
        FAILURES.append(name)


def pump(root, seconds, until=None, poll=0.05):
    """Run the Tk event loop for up to `seconds`, stopping early once until()."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        root.update()
        if until is not None and until():
            return True
        time.sleep(poll)
    return until is None or until()


def main():
    prior = sysproxy.read_settings()  # real user settings, to restore no matter what
    root = tk.Tk()
    callback_errors = []
    root.report_callback_exception = (
        lambda exc, val, tb: callback_errors.append(f"{exc.__name__}: {val}"))
    app = App(root)
    # The window opens on a live desktop; disable the real buttons so stray
    # mouse input can't drive the state machine mid-test. The handlers are
    # driven directly below - the same code the buttons invoke.
    for btn in (app.bond_btn, app.rescan_btn, app.probe_btn):
        btn.state(["disabled"])

    try:
        # 1. discovery lands, probe runs, and the table renders
        ok = pump(root, 25, lambda: len(app.balancer.snapshot()) > 0
                  and len(app.tree.get_children("")) > 0)
        check("discovery populated balancer and table", ok,
              str([r["name"] for r in app.balancer.snapshot()]))
        check("table has a row", len(app.tree.get_children("")) > 0,
              str(app.tree.get_children("")))
        rows = app.balancer.snapshot()
        check("discovered rows are real addresses",
              all(not r["ip"].startswith("169.254.") for r in rows),
              ",".join(r["ip"] for r in rows))

        # 2. initial probe ran (latency recorded or link marked down)
        ok = pump(root, 25, lambda: all(r["latency_ms"] > 0 for r in app.balancer.snapshot()))
        check("health probe produced latencies", ok,
              str({r["name"]: r["latency_ms"] for r in app.balancer.snapshot()}))

        # 3. bond start -> proxy up + system proxy enabled
        app.toggle_bond()
        ok = pump(root, 25, lambda: app.bonded)
        check("bond button starts the proxy", ok, f"bonded={app.bonded}")
        if app.bonded:
            check("proxy listens on HTTP port", app.proxy.running and app.proxy.http_port > 0,
                  f"http={app.proxy.http_port} socks={app.proxy.socks_port}")
            check("system proxy enabled while bonded",
                  sysproxy.is_enabled("127.0.0.1", app.proxy.http_port),
                  str(sysproxy.read_settings().get("ProxyServer")))

            # 4. real traffic through the running proxy
            import socket
            try:
                s = socket.create_connection(("127.0.0.1", app.proxy.http_port), timeout=10)
                s.sendall(b"GET http://example.com/ HTTP/1.1\r\n"
                          b"Host: example.com\r\nConnection: close\r\n\r\n")
                data = b""
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                s.close()
                status = int(data.split(b" ")[1]) if data.startswith(b"HTTP/") else 0
                check("live traffic through the bonded proxy", status in (200, 301, 302),
                      f"status={status} bytes={len(data)}")
            except OSError as exc:
                check("live traffic through the bonded proxy", False, str(exc))

            # 5. stop -> system proxy restored to exact prior values
            app.toggle_bond()
            ok = pump(root, 25, lambda: not app.bonded)
            check("bond button stops the proxy", ok, f"bonded={app.bonded}")
            after_stop = sysproxy.read_settings()
            check("system proxy restored exactly after stop", after_stop == prior,
                  f"now={after_stop} prior={prior}")

        # 6. clean shutdown
        app.on_close()
        pump(root, 1.0)
        try:
            destroyed = not root.winfo_exists()
        except tk.TclError:
            destroyed = True  # the tk application itself is gone
        check("window destroyed on close", destroyed)
        check("no Tk callback exceptions", not callback_errors, "; ".join(callback_errors[:3]))
        check("proxy stopped after close", not app.proxy.running)
    finally:
        # belt and braces: real registry must end exactly as it started
        if sysproxy.read_settings() != prior:
            sysproxy.restore(prior)
            print("       (registry force-restored to prior state)")

    if FAILURES:
        print(f"RESULT: {len(FAILURES)} FAILURE(S): {FAILURES}")
        return 1
    print("RESULT: GUI SMOKE PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
