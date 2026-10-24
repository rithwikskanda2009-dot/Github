"""Toggle the Windows system proxy to NetBond's local proxy, reversibly.

Writes HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings and
notifies WinINet so running applications pick the change up immediately. The
previous values are captured as a snapshot and written back on restore, so
turning NetBond off returns the machine to exactly its prior proxy state.

_KEY_PATH is a module global so the headless test can point it at a scratch
key instead of the real user settings.
"""

import ctypes
from contextlib import contextmanager

try:
    import winreg
except ImportError:  # pragma: no cover - non-Windows guard
    winreg = None

KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_KEY_PATH = KEY_PATH
_VALUES = ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL")

INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37


def proxy_server_value(host, http_port, socks_port):
    return f"http={host}:{http_port};https={host}:{http_port};socks={host}:{socks_port}"


def _default_override():
    return "localhost;127.0.0.1;<local>"


@contextmanager
def _open(create=False):
    if winreg is None:
        raise OSError("winreg unavailable - system proxy toggle is Windows-only")
    access = winreg.KEY_READ | (winreg.KEY_SET_VALUE if create else 0)
    if create:
        key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, _KEY_PATH, 0, access)
    else:
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KEY_PATH, 0, access)
        except FileNotFoundError:
            yield {}
            return
    try:
        yield key
    finally:
        winreg.CloseKey(key)


def read_settings():
    """Current proxy-related values (missing values are absent from the dict)."""
    out = {}
    with _open() as key:
        if not isinstance(key, dict):
            for name in _VALUES:
                try:
                    out[name] = winreg.QueryValueEx(key, name)[0]
                except FileNotFoundError:
                    pass
        else:
            out = key
    return out


def apply(host, http_port, socks_port):
    """Point the system proxy at NetBond. Returns the previous settings snapshot."""
    snapshot = read_settings()
    with _open(create=True) as key:
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ,
                          proxy_server_value(host, http_port, socks_port))
        if "ProxyOverride" not in snapshot or not snapshot.get("ProxyOverride"):
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, _default_override())
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
    refresh()
    return snapshot


def restore(snapshot):
    """Write the snapshot back (or clear the proxy when there is none)."""
    with _open(create=True) as key:
        for name in _VALUES:
            if snapshot and name in snapshot:
                value = snapshot[name]
                kind = winreg.REG_DWORD if isinstance(value, int) else winreg.REG_SZ
                winreg.SetValueEx(key, name, 0, kind, value)
            else:
                try:
                    winreg.DeleteValue(key, name)
                except FileNotFoundError:
                    pass
    refresh()


def disable(snapshot=None):
    restore(snapshot if snapshot is not None else {})


def refresh():
    """Broadcast the settings change to WinINet so apps notice immediately."""
    try:
        wininet = ctypes.windll.Wininet  # noqa: PLC0415 - Windows only
    except (AttributeError, OSError):
        return
    wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
    wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, None, 0)


def is_enabled(host, http_port):
    """True when the system proxy currently points at NetBond's HTTP port."""
    try:
        settings = read_settings()
    except OSError:
        return False
    server = str(settings.get("ProxyServer") or "")
    enabled = settings.get("ProxyEnable") == 1
    return enabled and f"{host}:{http_port}" in server
