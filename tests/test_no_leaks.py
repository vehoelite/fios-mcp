"""Fail if the repository contains anything that looks like a real network's data.

Allowed: MACs in 02:00:00:xx:xx:xx (locally administered test range), private
and documentation IP ranges, and a few well-known public resolvers used as
examples. A private, gitignored `.scrub-denylist` (one literal per line: your
real MACs, WAN IP, SSIDs, domain) is checked too, so local commits can't leak
what CI cannot know.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
from pathlib import Path

from fios_mcp.service import VERIFIED_FIRMWARE

ROOT = Path(__file__).resolve().parents[1]
MAC = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
WELL_KNOWN = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "172.64.36.1", "172.64.36.2"}
WELL_KNOWN |= VERIFIED_FIRMWARE  # firmware versions look like IPv4 addresses
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def tracked_files() -> list[Path]:
    out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"],
                         cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    return [ROOT / p for p in out if (ROOT / p).is_file() and not p.endswith((".png", ".jpg"))]


def _text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return ""


def test_no_real_macs():
    bad = []
    for p in tracked_files():
        for m in MAC.findall(_text(p)):
            if not m.upper().startswith("02:00:00:") and m != "00:00:00:00:00:00":
                bad.append(f"{p.relative_to(ROOT)}: {m}")
    assert not bad, "real-looking MAC addresses:\n" + "\n".join(bad)


def test_no_public_ips():
    bad = []
    for p in tracked_files():
        for m in IPV4.findall(_text(p)):
            try:
                ip = ipaddress.IPv4Address(m)
            except ValueError:
                continue
            if (ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved
                    or ip.is_link_local or m in WELL_KNOWN or any(ip in n for n in DOC_NETS)
                    or m.startswith("255.")):
                continue
            bad.append(f"{p.relative_to(ROOT)}: {m}")
    assert not bad, "public IP addresses:\n" + "\n".join(bad)


def test_private_denylist():
    deny = ROOT / ".scrub-denylist"
    if not deny.exists():
        return
    needles = [ln.strip() for ln in deny.read_text().splitlines() if ln.strip() and not ln.startswith("#")]
    bad = [f"{p.relative_to(ROOT)}: {n}" for p in tracked_files() if p.name != ".scrub-denylist"
           for n in needles if n.lower() in _text(p).lower()]
    assert not bad, "denylisted strings:\n" + "\n".join(bad)
