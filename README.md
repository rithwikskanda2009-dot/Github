# NetBond

Bond every internet link your laptop has — USB tethering, Wi-Fi, Ethernet —
behind **one local proxy**, with weighted load-balancing and instant failover,
and flip the whole machine onto it with a single click.

Built with Python + tkinter only (no third-party packages). Windows 10/11.

## What it actually does

Windows cannot merge separate links into one faster-than-the-fastest stream
(that needs a server on the other end of every link). What NetBond does instead:

1. **Discovers** every active IPv4 link (`Get-NetAdapter` + `Get-NetIPConfiguration`),
   ignoring disconnected and APIPA-only interfaces.
2. **Probes** each link with a TCP connect forced out *through that link*
   (source-address bind + `IP_UNICAST_IF` pinning), measuring latency.
3. **Spreads** every new connection across the healthy links with nginx-style
   smooth weighted round-robin — faster links (and lower-latency links) get
   proportionally more traffic.
4. **Fails over** automatically: a failed upstream connect pushes that link
   into an exponentially growing cooldown (2s → 30s); the request is retried
   on the next link, so a dying tether costs one connect attempt, not the page.
   Probing brings links back on their own.
5. **Serves** the pool through a local **HTTP proxy** and a **SOCKS5 proxy**,
   both bound to `127.0.0.1` only.
6. **One-click system proxy**: "Bond All Links" points Windows' WinINet
   settings at the local proxy (so browsers and most apps follow), and stopping
   the bond writes back *exactly* the previous proxy settings.

Per-link request/byte counters show what each link contributed.

## Run it

```bat
python -m netbond            &:: dashboard
pythonw NetBond.pyw          &:: same, no console window (this is what the desktop shortcut runs)
```

Press **Bond All Links** to start. The dashboard shows links, latency, weight,
status (`up` / `cooldown Ns` / `down` / `disabled`), requests and traffic.
**Rescan Links** re-runs discovery, **Probe Now** re-probes every link.

Closing the window stops the proxy and restores the previous system proxy.

## Ports

| Listener | Default | Used by |
|---|---|---|
| HTTP proxy | 8811 | the Windows system proxy (`http=`, `https=`) |
| SOCKS5 proxy | 8812 | apps with native SOCKS5 support (browsers, curl, proxies) |

Change them in the dashboard before bonding; the system proxy points at
whatever ports are active.

## Limits (honest version)

- **Not bandwidth aggregation into one flow**: a single TCP connection still
  goes over one link. Parallel connections (page loads, downloads, updates)
  spread across all links, and a dead link no longer drops your internet.
- **System proxy ≠ VPN**: apps that ignore the system proxy won't be bonded.
  Point them at `127.0.0.1:8811` (HTTP) or `127.0.0.1:8812` (SOCKS5) manually.
- **DNS** is resolved by Windows normally, not pinned per link.
- **Windows only** (registry + `IP_UNICAST_IF` + PowerShell discovery).
- Bind the app's traffic to the links it claims: every upstream socket is
  bound to the link's own IP and pinned to its interface index, so traffic
  genuinely leaves on the link that was picked.

## Layout

```
netbond/
  interfaces.py   link discovery (PowerShell, merged + filtered)
  health.py       per-link probes + connect_via() (bind + IP_UNICAST_IF)
  balancer.py     smooth weighted round-robin, cooldowns, counters
  proxy.py        HTTP + SOCKS5 servers, per-request failover
  sysproxy.py     reversible WinINet proxy toggle (registry)
  gui.py          tkinter dashboard
tests/
  verify_headless.py   end-to-end behavioral tests (run: python tests/verify_headless.py)
```

## Uninstall

Stop the bond (restores proxy settings), then delete the `netbond` folder and
the desktop shortcut.
