"""`python -m netbond` launches the NetBond dashboard."""

import argparse

from . import __version__
from .gui import DEFAULT_HTTP_PORT, DEFAULT_SOCKS_PORT, main


def cli(argv=None):
    parser = argparse.ArgumentParser(
        prog="netbond",
        description="Bond USB tethering, Wi-Fi and Ethernet links behind one local proxy.",
    )
    parser.add_argument("--http-port", type=int, default=DEFAULT_HTTP_PORT,
                        help="local HTTP proxy port (default %(default)s)")
    parser.add_argument("--socks-port", type=int, default=DEFAULT_SOCKS_PORT,
                        help="local SOCKS5 proxy port (default %(default)s)")
    parser.add_argument("--version", action="version", version=f"NetBond {__version__}")
    return parser.parse_args(argv)


def run(argv=None):
    args = cli(argv)
    from . import gui
    gui.main(http_port=args.http_port, socks_port=args.socks_port)


if __name__ == "__main__":
    run()
