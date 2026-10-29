"""`fios-mcp` command line.

    fios-mcp [serve]            run the MCP server on stdio (what MCP clients launch)
    fios-mcp trust [--yes]      fetch the router's certificate, show it, pin it
    fios-mcp check              log in once, report firmware and verification status, log out
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
import ssl
import sys
import tempfile
from urllib.parse import urlparse

from .config import CONFIG_DIR, Config, ConfigError


def _serve() -> int:
    from .server import mcp, rt

    async def run() -> None:
        try:
            await mcp.run_stdio_async()
        finally:
            await rt.close()

    asyncio.run(run())
    return 0


def _trust(url: str, yes: bool) -> int:
    u = urlparse(url)
    host, port = u.hostname or "192.168.1.1", u.port or 443
    pem = ssl.get_server_certificate((host, port))
    der = ssl.PEM_cert_to_DER_cert(pem)
    fp = hashlib.sha256(der).hexdigest().upper()
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write(pem)
    try:
        info = ssl._ssl._test_decode_cert(f.name)  # type: ignore[attr-defined]
    finally:
        os.unlink(f.name)
    subject = ", ".join("=".join(x) for rdn in info.get("subject", ()) for x in rdn)
    issuer = ", ".join("=".join(x) for rdn in info.get("issuer", ()) for x in rdn)
    print(f"router:   {host}:{port}")
    print(f"subject:  {subject}\nissuer:   {issuer}\nvalid:    {info.get('notBefore')} -> {info.get('notAfter')}")
    print("sha256:   " + ":".join(fp[i:i + 2] for i in range(0, len(fp), 2)))
    print("note:     every CR1000A presents the same Verizon certificate; pinning it blocks other\n"
          "          certificates, but does not identify your particular router.")
    if not yes and input("pin this certificate? [y/N] ").strip().lower() != "y":
        print("not pinned")
        return 1
    CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    dest = CONFIG_DIR / "router.pem"
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as out:
        out.write(pem)
    print(f"pinned:   {dest}")
    return 0


def _check() -> int:
    from .backend.stock.backend import StockBackend
    from .backend.stock.transport import RouterError, RouterTransport, tls_context
    from .service import VERIFIED_FIRMWARE

    async def run() -> int:
        cfg = Config.load()
        async with RouterTransport(cfg.url, cfg.password, verify=tls_context(cfg.pin_file)) as t:
            b = StockBackend(t)
            try:
                st = await b.status()
            except RouterError as e:
                print(f"error: {e}", file=sys.stderr)
                return 1
            fw = st.firmware.version if st.firmware else "?"
            print(f"router:   {st.model} ({st.name}) at {cfg.url}")
            print(f"firmware: {fw} - {'verified' if fw in VERIFIED_FIRMWARE else 'NOT verified: writes refused'}")
            print(f"WAN:      {st.wan_proto} {st.wan_ip or '(no address)'}; LAN {st.lan_ip}/{st.lan_mask}")
            print(f"logins:   {t.logins_performed} (logged out on exit)")
        return 0

    return asyncio.run(run())


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="fios-mcp", description="MCP server for the Verizon Fios CR1000A")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("serve", help="run the MCP server on stdio (default)")
    tp = sub.add_parser("trust", help="pin the router's TLS certificate")
    tp.add_argument("--url", default=os.environ.get("FIOS_ROUTER_URL", "https://192.168.1.1"))
    tp.add_argument("--yes", action="store_true", help="pin without asking")
    sub.add_parser("check", help="log in once and report firmware/verification status")
    args = p.parse_args(argv)
    try:
        if args.cmd == "trust":
            return _trust(args.url, args.yes)
        if args.cmd == "check":
            return _check()
        return _serve()
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
