"""Owner-held guard-rails, read from `policy.toml` (never committed).

    [dns]
    allowed_servers = ["172.64.36.1", "172.64.36.2"]

    [protect]
    reservations = ["02:00:00:00:00:10", "192.168.1.11"]   # MACs or IPs
    port_forwards = ["vpn-sstp", "443/tcp"]                 # names or port/protocol
    static_routes = ["10.99.0.0/24"]

    [features]
    allow_dmz = false        # a DMZ host receives every unsolicited port
    allow_reboot = true
    allow_block = true
    allow_wifi = true        # radios, SSIDs, Wi-Fi passwords
    allow_lan_change = false # moving the router's LAN address / DHCP pool

With no policy file the defaults are conservative: DNS changes are refused
until an allowlist exists, DMZ is refused and the LAN cannot be moved.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .models import normalize_mac


@dataclass
class Policy:
    allowed_dns: list[str] = field(default_factory=list)
    protected_reservations: set[str] = field(default_factory=set)
    protected_forwards: set[str] = field(default_factory=set)
    protected_routes: set[str] = field(default_factory=set)
    allow_dmz: bool = False
    allow_reboot: bool = True
    allow_block: bool = True
    allow_wifi: bool = True
    allow_lan_change: bool = False
    source: str = "defaults (no policy.toml)"

    @classmethod
    def load(cls, path: Path | None) -> Policy:
        if path is None or not path.exists():
            return cls()
        if path.stat().st_mode & 0o022:
            raise PermissionError(f"{path} is writable by group/others; chmod 600 it")
        raw = tomllib.loads(path.read_text())
        prot = raw.get("protect", {})
        feat = raw.get("features", {})

        def _res(v: str) -> str:
            try:
                return normalize_mac(v)
            except ValueError:
                return v.strip()

        return cls(
            allowed_dns=[str(s) for s in raw.get("dns", {}).get("allowed_servers", [])],
            protected_reservations={_res(str(v)) for v in prot.get("reservations", [])},
            protected_forwards={str(v).lower() for v in prot.get("port_forwards", [])},
            protected_routes={str(v) for v in prot.get("static_routes", [])},
            allow_dmz=bool(feat.get("allow_dmz", False)),
            allow_reboot=bool(feat.get("allow_reboot", True)),
            allow_block=bool(feat.get("allow_block", True)),
            allow_wifi=bool(feat.get("allow_wifi", True)),
            allow_lan_change=bool(feat.get("allow_lan_change", False)),
            source=str(path),
        )

    def summary(self) -> dict:
        return {
            "source": self.source,
            "allowed_dns_servers": self.allowed_dns,
            "protected_reservations": sorted(self.protected_reservations),
            "protected_port_forwards": sorted(self.protected_forwards),
            "protected_static_routes": sorted(self.protected_routes),
            "allow_dmz": self.allow_dmz,
            "allow_reboot": self.allow_reboot,
            "allow_block": self.allow_block,
            "allow_wifi": self.allow_wifi,
            "allow_lan_change": self.allow_lan_change,
        }
