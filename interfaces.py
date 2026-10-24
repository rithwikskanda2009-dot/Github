"""Discovery of the machine's active IPv4 network links.

Uses PowerShell (Get-NetAdapter + Get-NetIPConfiguration) in a single call and
merges the results. Only "Up" adapters with a real (non-APIPA) IPv4 address are
returned, since an interface without a usable address cannot carry traffic.
"""

import json
import subprocess
from dataclasses import dataclass

_POWERSHELL = (
    "$ErrorActionPreference='SilentlyContinue';"
    "$a=Get-NetAdapter | Select-Object Name,ifIndex,Status,LinkSpeed,InterfaceDescription;"
    "$i=Get-NetIPConfiguration | ForEach-Object {"
    "[PSCustomObject]@{Alias=$_.InterfaceAlias;Idx=$_.InterfaceIndex;"
    "IPv4=@($_.IPv4Address.IPAddress);GW=@($_.IPv4DefaultGateway.NextHop)}};"
    "@{adapters=$a;ips=$i} | ConvertTo-Json -Compress -Depth 6"
)


class DiscoveryError(RuntimeError):
    """Raised when link discovery itself fails (not when no links are up)."""


@dataclass(frozen=True)
class Link:
    name: str
    index: int
    ip: str
    speed_mbps: float
    gateway: str
    kind: str  # "ethernet" | "wifi" | "usb" | "other"

    @property
    def tier(self) -> int:
        """Speed tier used as the base load-balancing weight (1..4)."""
        mbps = self.speed_mbps or 0
        if mbps >= 500:
            return 4
        if mbps >= 100:
            return 3
        if mbps >= 25:
            return 2
        return 1


def _parse_speed(text) -> float:
    """'426.0 Mbps' -> 426.0, '1 Gbps' -> 1000.0, '10 Mbps' -> 10.0."""
    if not text:
        return 0.0
    raw = str(text).strip().upper().replace("BITS/S", "BPS")
    try:
        if "GBPS" in raw:
            return float(raw.split()[0]) * 1000.0
        if "MBPS" in raw:
            return float(raw.split()[0])
        if raw.endswith("KBPS"):
            return float(raw.split()[0]) / 1000.0
        if raw.endswith("BPS"):
            return float(raw.split()[0]) / 1_000_000.0
    except (ValueError, IndexError):
        pass
    return 0.0


def _classify(name: str, description: str) -> str:
    blob = f"{name} {description}".lower()
    if any(k in blob for k in ("wi-fi", "wifi", "wireless", "802.11")):
        return "wifi"
    if any(k in blob for k in ("usb", "tether", "remote ndis", "mobile", "iphone", "android", "bluetooth")):
        return "usb"
    if "ethernet" in blob or "lan" in blob:
        return "ethernet"
    return "other"


def _merge(data: dict) -> list:
    adapters = data.get("adapters") or []
    ips = data.get("ips") or []
    if isinstance(adapters, dict):
        adapters = [adapters]
    if isinstance(ips, dict):
        ips = [ips]

    by_idx = {}
    for a in adapters:
        if not a:
            continue
        idx = a.get("ifIndex")
        if idx is None:
            continue
        by_idx[int(idx)] = {
            "name": a.get("Name") or f"if{idx}",
            "status": (a.get("Status") or "").strip().lower(),
            "speed": _parse_speed(a.get("LinkSpeed")),
            "desc": a.get("InterfaceDescription") or "",
        }

    links = []
    for row in ips:
        if not row:
            continue
        try:
            idx = int(row.get("Idx"))
        except (TypeError, ValueError):
            continue
        addrs = [ip for ip in (row.get("IPv4") or []) if ip]
        if not addrs:
            continue
        gws = [g for g in (row.get("GW") or []) if g]
        info = by_idx.get(idx, {})
        status = info.get("status", "up")
        if status and status != "up":
            continue
        name = info.get("name") or row.get("Alias") or f"if{idx}"
        if name.lower().startswith(("loopback", "isatap", "teredo")):
            continue
        # Prefer a routable address; APIPA-only interfaces cannot carry traffic.
        usable = [ip for ip in addrs if not ip.startswith("169.254.")]
        if not usable:
            continue
        ip = usable[0]
        links.append(
            Link(
                name=name,
                index=idx,
                ip=ip,
                speed_mbps=info.get("speed", 0.0),
                gateway=(gws[0] if gws else ""),
                kind=_classify(name, info.get("desc", "")),
            )
        )
    links.sort(key=lambda l: (-l.speed_mbps, l.index))
    return links


def discover_links(timeout=20):
    """Return the list of usable IPv4 links. Raises DiscoveryError on failure."""
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _POWERSHELL],
            capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise DiscoveryError(f"powershell not available: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise DiscoveryError(f"link discovery timed out after {timeout}s") from exc
    out = (proc.stdout or "").strip()
    if proc.returncode != 0 or not out:
        err = (proc.stderr or "").strip()
        raise DiscoveryError(
            f"link discovery failed (exit {proc.returncode}): {err or out or 'no output'}"
        )
    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        raise DiscoveryError(f"link discovery returned invalid JSON: {exc}") from exc
    return _merge(data)
