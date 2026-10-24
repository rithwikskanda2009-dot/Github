"""tkinter dashboard for NetBond.

Workers (link discovery, health probes, proxy I/O) run in background threads
and publish into a queue; the Tk thread drains the queue with `after()`, so no
widget is ever touched off the UI thread. Closing the window stops the proxy
and restores the system proxy before exiting.
"""

import queue
import threading
import tkinter as tk
from tkinter import scrolledtext, ttk

from . import __version__
from .balancer import Balancer
from .interfaces import DiscoveryError, discover_links
from .proxy import BondProxy
from . import sysproxy

DEFAULT_HOST = "127.0.0.1"
DEFAULT_HTTP_PORT = 8811
DEFAULT_SOCKS_PORT = 8812
REFRESH_MS = 2000
PROBE_MS = 15000

KIND_LABEL = {"usb": "USB tether", "wifi": "Wi-Fi", "ethernet": "Ethernet", "other": "Other"}


def _human(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TB"


class App:
    def __init__(self, root, host=DEFAULT_HOST, http_port=DEFAULT_HTTP_PORT,
                 socks_port=DEFAULT_SOCKS_PORT):
        self.root = root
        self.host = host
        self.http_port = http_port
        self.socks_port = socks_port
        self.balancer = Balancer()
        self.proxy = BondProxy(self.balancer, host=host, http_port=http_port,
                               socks_port=socks_port)
        self.events = queue.Queue()
        self.sysproxy_snapshot = None
        self.bonded = False
        self._closed = False
        self._build()
        self._log(f"NetBond {__version__} ready. Press 'Bond All Links' to start.")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(100, self._drain)
        self.rescan_links(background=True)

    # -- UI construction -----------------------------------------------------

    def _build(self):
        self.root.title(f"NetBond {__version__} - link bonding")
        self.root.geometry("880x560")
        self.root.minsize(760, 480)

        top = ttk.Frame(self.root, padding=(12, 10))
        top.pack(fill="x")
        self.bond_btn = ttk.Button(top, text="Bond All Links", command=self.toggle_bond)
        self.bond_btn.pack(side="left")
        self.status_var = tk.StringVar(value="Idle - system proxy untouched")
        ttk.Label(top, textvariable=self.status_var).pack(side="left", padx=12)

        ports = ttk.Frame(top)
        ports.pack(side="right")
        ttk.Label(ports, text="HTTP").pack(side="left")
        self.http_var = tk.StringVar(value=str(self.http_port))
        ttk.Entry(ports, textvariable=self.http_var, width=6).pack(side="left", padx=(2, 8))
        ttk.Label(ports, text="SOCKS5").pack(side="left")
        self.socks_var = tk.StringVar(value=str(self.socks_port))
        ttk.Entry(ports, textvariable=self.socks_var, width=6).pack(side="left", padx=2)

        columns = ("kind", "ip", "speed", "latency", "weight", "status", "reqs", "in", "out")
        self.tree = ttk.Treeview(self.root, columns=columns, show="tree headings", height=10)
        headings = {
            "#0": ("Link", 170), "kind": ("Type", 90), "ip": ("Address", 130),
            "speed": ("Speed", 90), "latency": ("Latency", 80), "weight": ("Weight", 60),
            "status": ("Status", 110), "reqs": ("Requests", 80),
            "in": ("Downloaded", 100), "out": ("Uploaded", 100),
        }
        for col, (label, width) in headings.items():
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, anchor="w")
        self.tree.pack(fill="both", expand=False, padx=12, pady=(8, 4))

        actions = ttk.Frame(self.root, padding=(12, 0))
        actions.pack(fill="x")
        self.rescan_btn = ttk.Button(actions, text="Rescan Links",
                                     command=lambda: self.rescan_links(background=True))
        self.rescan_btn.pack(side="left")
        self.probe_btn = ttk.Button(actions, text="Probe Now",
                                    command=lambda: self.probe(background=True))
        self.probe_btn.pack(side="left", padx=8)

        ttk.Label(self.root, text="Log", padding=(12, 4)).pack(fill="x")
        self.log = scrolledtext.ScrolledText(self.root, height=12, state="disabled", wrap="word")
        self.log.pack(fill="both", expand=True, padx=12, pady=(0, 10))

    # -- helpers -------------------------------------------------------------

    def _log(self, text):
        self.log.configure(state="normal")
        self.log.insert("end", text.rstrip() + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _emit(self, kind, payload=None):
        self.events.put((kind, payload))

    def _run_bg(self, fn, name):
        def runner():
            try:
                fn()
            except Exception as exc:  # surfaced in the UI, never silent
                self._emit("error", f"{name}: {exc}")
        threading.Thread(target=runner, daemon=True).start()

    # -- actions -------------------------------------------------------------

    def rescan_links(self, background=False):
        def job():
            self._emit("log", "Scanning network links...")
            try:
                links = discover_links()
            except DiscoveryError as exc:
                self._emit("log", f"Link scan failed: {exc}")
                return
            self.balancer.set_links(links)
            if links:
                names = ", ".join(f"{l.name} ({l.ip})" for l in links)
                self._emit("log", f"Found {len(links)} link(s): {names}")
                # Probe right away so the table shows real health/latency and
                # the first picks are weighted by it - not just link speed.
                self.probe()
            else:
                self._emit("log", "No usable links found - connect a tether/Wi-Fi/Ethernet and rescan.")
        if background:
            self._run_bg(job, "rescan")
        else:
            job()

    def probe(self, background=False):
        def job():
            results = self.balancer.probe_all()
            for st, res in results:
                if res.ok:
                    self._emit("log", f"{st.link.name}: up ({res.latency_ms:.0f} ms)")
                else:
                    self._emit("log", f"{st.link.name}: DOWN ({res.error})")
        if background:
            self._run_bg(job, "probe")
        else:
            job()

    def toggle_bond(self):
        if self.bonded:
            self._stop_bond()
        else:
            self._start_bond()

    def _start_bond(self):
        try:
            http_port = int(self.http_var.get())
            socks_port = int(self.socks_var.get())
        except ValueError:
            self._log("Ports must be numbers.")
            return
        self.http_port, self.socks_port = http_port, socks_port
        self.proxy.http_port, self.proxy.socks_port = http_port, socks_port

        def job():
            self._emit("log", "Starting local proxy...")
            try:
                if not self.balancer.states:
                    links = discover_links()
                    self.balancer.set_links(links)
                if not self.balancer.usable() and self.balancer.states:
                    self.balancer.probe_all()
                if not self.balancer.states:
                    self._emit("log", "No links available - bond cancelled.")
                    return
                self.proxy.start()
            except OSError as exc:
                self._emit("log", f"Proxy failed to start: {exc}")
                return
            self._emit("bonded", None)

        self._run_bg(job, "start-bond")

    def _stop_bond(self):
        def job():
            self.proxy.stop()
            if self.sysproxy_snapshot is not None:
                try:
                    sysproxy.restore(self.sysproxy_snapshot)
                    self._emit("log", "System proxy restored to previous settings.")
                except OSError as exc:
                    self._emit("log", f"Could not restore system proxy: {exc}")
                self.sysproxy_snapshot = None
            self._emit("unbonded", None)
        self._run_bg(job, "stop-bond")

    # -- event drain ---------------------------------------------------------

    def _drain(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "log":
                    self._log(payload)
                elif kind == "error":
                    self._log(f"ERROR {payload}")
                elif kind == "bonded":
                    self.bonded = True
                    self.bond_btn.configure(text="Stop Bonding")
                    try:
                        self.sysproxy_snapshot = sysproxy.apply(
                            self.host, self.proxy.http_port, self.proxy.socks_port)
                        self._emit("log", "System proxy enabled - all browser traffic now uses NetBond.")
                    except OSError as exc:
                        self._emit("log", f"System proxy toggle failed: {exc} "
                                          f"(proxy itself is running on port {self.proxy.http_port})")
                    self._emit("log", f"Proxy up: HTTP 127.0.0.1:{self.proxy.http_port}, "
                                      f"SOCKS5 127.0.0.1:{self.proxy.socks_port}")
                    self.probe(background=True)
                elif kind == "unbonded":
                    self.bonded = False
                    self.bond_btn.configure(text="Bond All Links")
                    self._emit("log", "Bonding stopped.")
                self.events.task_done()
        except queue.Empty:
            pass
        try:
            self._refresh_table()
        except Exception as exc:  # never let a render error kill the UI loop
            msg = str(exc)
            if msg != getattr(self, "_last_refresh_error", None):
                self._last_refresh_error = msg
                self._log(f"table refresh error: {msg}")
        if not self._closed:
            self.root.after(REFRESH_MS, self._drain)

    def _refresh_table(self):
        rows = self.balancer.snapshot()
        existing = set(self.tree.get_children(""))
        wanted = []  # (name, values) per link, rebuilt every refresh
        for row in rows:
            status = ("disabled" if row["disabled"]
                      else "up" if row["healthy"] and row["cooldown_left"] == 0
                      else f"cooldown {row['cooldown_left']:.0f}s" if row["cooldown_left"]
                      else "down")
            values = (
                KIND_LABEL.get(row["kind"], row["kind"]), row["ip"],
                f"{row['speed_mbps']:.0f} Mbps",
                f"{row['latency_ms']:.0f} ms" if row["latency_ms"] else "-",
                row["weight"], status, row["requests"],
                _human(row["bytes_in"]), _human(row["bytes_out"]),
            )
            wanted.append((f"{row['name']}#{row['index']}", row["name"], values, status))
        for iid in existing:
            self.tree.delete(iid)
        for iid, label, values, status in wanted:
            self.tree.insert("", "end", iid=iid, text=label, values=values)

    # -- shutdown ------------------------------------------------------------

    def on_close(self):
        if self._closed:
            return
        self._closed = True
        self.proxy.stop()
        if self.sysproxy_snapshot is not None:
            try:
                sysproxy.restore(self.sysproxy_snapshot)
            except OSError:
                pass
            self.sysproxy_snapshot = None
        self.root.destroy()


def main(http_port=None, socks_port=None):
    root = tk.Tk()
    try:
        style = ttk.Style(root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
    except tk.TclError:
        pass
    App(root,
        http_port=DEFAULT_HTTP_PORT if http_port is None else http_port,
        socks_port=DEFAULT_SOCKS_PORT if socks_port is None else socks_port)
    root.mainloop()
