"""Weighted load balancing across links with automatic failover.

Selection uses nginx-style smooth weighted round-robin over the links that are
currently usable (up, not in cooldown, not disabled by the user). Every failed
upstream connection puts that link into an exponentially growing cooldown
(2s, 4s, 8s, 16s, 30s cap); a successful connection clears it again, so a dead
link recovers on its own without restarting anything.
"""

import threading
import time
from dataclasses import dataclass, field

from .health import check_link, connect_via


def _cooldown_seconds(failures: int) -> float:
    return float(min(30, 2 ** min(max(failures, 1), 5)))


@dataclass
class LinkState:
    link: object
    healthy: bool = True
    disabled: bool = False
    failures: int = 0
    cooldown_until: float = 0.0
    requests: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    latency_ms: float = 0.0
    current_weight: int = 0
    last_error: str = ""
    checked_at: float = 0.0

    @property
    def tier(self) -> int:
        return getattr(self.link, "tier", 1)

    def effective_weight(self) -> int:
        w = self.tier
        # Fast links get a boost, slow links are not starved to zero.
        if self.latency_ms:
            if self.latency_ms < 80:
                w *= 2
            elif self.latency_ms > 250:
                w = max(1, w // 2)
        return max(1, w)

    def in_cooldown(self, now: float) -> bool:
        return now < self.cooldown_until


class Balancer:
    """Picks links for new connections and tracks per-link outcomes."""

    def __init__(self, connect_fn=None, clock=time.monotonic, health_fn=None):
        self._connect = connect_fn or connect_via
        self._health = health_fn or check_link
        self._clock = clock
        self._lock = threading.Lock()
        self.states = []
        self.probe_timeout = 3.0

    # -- link set management -------------------------------------------------

    def set_links(self, links):
        """Replace the link set, preserving counters of links that stay."""
        with self._lock:
            old = {self._key(s.link): s for s in self.states}
            merged = []
            for link in links:
                prev = old.get(self._key(link))
                if prev is None:
                    merged.append(LinkState(link=link))
                else:
                    prev.link = link  # speed/gateway may have changed
                    prev.current_weight = 0
                    merged.append(prev)
            self.states = merged

    @staticmethod
    def _key(link):
        return (link.name, link.index, link.ip)

    def set_enabled(self, name, enabled):
        with self._lock:
            for st in self.states:
                if st.link.name == name:
                    st.disabled = not enabled

    # -- selection -----------------------------------------------------------

    def usable(self, now=None):
        now = self._clock() if now is None else now
        with self._lock:
            return [st for st in self.states
                    if st.healthy and not st.disabled and not st.in_cooldown(now)]

    def pick(self):
        """Smooth weighted round-robin over usable links; None if none left."""
        now = self._clock()
        with self._lock:
            candidates = [st for st in self.states
                          if st.healthy and not st.disabled and not st.in_cooldown(now)]
            if not candidates:
                return None
            total = 0
            best = None
            for st in candidates:
                w = st.effective_weight()
                total += w
                st.current_weight += w
                if best is None or st.current_weight > best.current_weight:
                    best = st
            best.current_weight -= total
            return best

    # -- outcome reporting ---------------------------------------------------

    def report_success(self, st):
        with self._lock:
            st.failures = 0
            st.cooldown_until = 0.0
            st.healthy = True

    def report_failure(self, st, error=""):
        with self._lock:
            st.failures += 1
            st.last_error = str(error)[:200]
            st.cooldown_until = self._clock() + _cooldown_seconds(st.failures)
            # A link that keeps failing is treated as down until probed again.
            if st.failures >= 3:
                st.healthy = False

    def record_traffic(self, st, sent, received):
        with self._lock:
            st.requests += 1
            st.bytes_out += sent
            st.bytes_in += received

    # -- upstream connections ------------------------------------------------

    def open_upstream(self, dst_ip, dst_port, timeout=8.0, attempts=4):
        """Connect through the best usable link; fails over on connect errors.

        Returns (sock, LinkState). Raises OSError('no usable links') when every
        link is down or in cooldown - the proxy answers 503 for that.
        """
        tried = set()
        last_error = None
        for _ in range(max(1, attempts)):
            st = self.pick()
            if st is None:
                break
            tried.add(self._key(st.link))
            try:
                sock = self._connect(st.link, dst_ip, dst_port, timeout)
            except OSError as exc:
                last_error = exc
                self.report_failure(st, exc)
                continue
            self.report_success(st)
            return sock, st
        if last_error is not None:
            raise last_error
        raise OSError("no usable links")

    # -- health --------------------------------------------------------------

    def probe_all(self):
        """Probe every link; updates healthy/cooldown/latency. Thread-safe."""
        results = []
        with self._lock:
            states = list(self.states)
        for st in states:
            res = self._health(st.link, timeout=self.probe_timeout)
            with self._lock:
                st.checked_at = res.checked_at or time.time()
                st.latency_ms = res.latency_ms
                if res.ok:
                    recovered = not st.healthy
                    st.healthy = True
                    st.failures = 0
                    st.cooldown_until = 0.0
                    st.last_error = ""
                    if recovered:
                        st.current_weight = 0
                else:
                    st.healthy = False
                    st.last_error = res.error
                    st.cooldown_until = self._clock() + 30.0
            results.append((st, res))
        return results

    # -- snapshots for the GUI ----------------------------------------------

    def snapshot(self):
        now = self._clock()
        with self._lock:
            out = []
            for st in self.states:
                out.append({
                    "name": st.link.name,
                    "kind": st.link.kind,
                    "ip": st.link.ip,
                    "index": st.link.index,
                    "speed_mbps": st.link.speed_mbps,
                    "gateway": st.link.gateway,
                    "healthy": st.healthy,
                    "disabled": st.disabled,
                    "cooldown_left": max(0.0, round(st.cooldown_until - now, 1)),
                    "failures": st.failures,
                    "requests": st.requests,
                    "bytes_in": st.bytes_in,
                    "bytes_out": st.bytes_out,
                    "latency_ms": st.latency_ms,
                    "weight": st.effective_weight() if (st.healthy and not st.disabled) else 0,
                    "last_error": st.last_error,
                })
            return out
