"""Config snapshots, diffs and a desired-state file for migrations.

A snapshot is every setting this tool can read, saved as JSON (0600) under
`$XDG_STATE_HOME/fios-mcp/snapshots/`. `diff` compares two snapshots (or a
snapshot and the live router) by natural keys, so a router swap can be checked
for anything missing.

`desired.toml` describes what the router should hold:

    [dns]
    mode = "manual"
    servers = ["172.64.36.1", "172.64.36.2"]

    [[reservations]]
    mac = "02:00:00:00:00:10"
    ip = "192.168.1.10"
    name = "nas"

    [[port_forwards]]
    name = "vpn-sstp"
    protocol = "tcp"
    external_ports = ["443"]
    internal_ip = "192.168.1.20"

    [[static_routes]]
    destination = "10.99.0.0/24"
    gateway = "192.168.1.11"

    [upnp]
    enabled = false
"""

from __future__ import annotations

import datetime as dt
import json
import os
import tomllib
from pathlib import Path
from typing import Any

from .backend.stock.backend import StockBackend
from .models import DhcpReservation, PortForward, StaticRoute

SECTION_KEYS = {
    "port_forwards": lambda x: f"{','.join(x['external_ports'])}/{x['protocol']}",
    "reservations": lambda x: x["mac"],
    "static_routes": lambda x: x["destination"],
    "blocked_devices": lambda x: x["mac"],
}
_VOLATILE = {"id", "slot"}


def state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    d = Path(base) / "fios-mcp" / "snapshots"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return d


async def take(b: StockBackend) -> dict[str, Any]:
    fw = await b.firmware()
    return {
        "taken_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "firmware": fw.version,
        "lan": (await b.get_lan()).model_dump(exclude={"reserved_range_note"}),
        "dns": (await b.get_dns()).model_dump(exclude={"active"}),
        "port_forwards": [p.model_dump() for p in await b.list_port_forwards()],
        "reservations": [r.model_dump() for r in await b.list_reservations()],
        "static_routes": [r.model_dump() for r in await b.list_static_routes()],
        "dmz": (await b.get_dmz()).model_dump(),
        "upnp": (await b.get_upnp()).model_dump(),
        "firewall": (await b.get_firewall()).model_dump(),
        "remote_admin": (await b.get_remote_admin()).model_dump(),
        "blocked_devices": [x.model_dump() for x in await b.list_blocked()],
    }


def save(snap: dict[str, Any]) -> str:
    name = snap["taken_at"].replace(":", "").replace("+0000", "Z")
    path = state_dir() / f"{name}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(snap, f, indent=1)
    return path.stem


def list_saved() -> list[str]:
    return sorted(p.stem for p in state_dir().glob("*.json"))


def load(snapshot_id: str) -> dict[str, Any]:
    path = state_dir() / f"{Path(snapshot_id).name}.json"
    return json.loads(path.read_text())


def _strip(x: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in x.items() if k not in _VOLATILE}


def diff(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for section in sorted(set(a) | set(b)):
        if section in ("taken_at",):
            continue
        av, bv = a.get(section), b.get(section)
        if section in SECTION_KEYS:
            key = SECTION_KEYS[section]
            am = {key(x): _strip(x) for x in av or []}
            bm = {key(x): _strip(x) for x in bv or []}
            added = [bm[k] for k in bm.keys() - am.keys()]
            removed = [am[k] for k in am.keys() - bm.keys()]
            changed = [{"key": k, "from": am[k], "to": bm[k]} for k in am.keys() & bm.keys() if am[k] != bm[k]]
            if added or removed or changed:
                out[section] = {"added": added, "removed": removed, "changed": changed}
        elif av != bv:
            out[section] = {"from": av, "to": bv}
    return out


def load_desired(path: Path) -> dict[str, Any]:
    raw = tomllib.loads(path.read_text())
    return {
        "dns": raw.get("dns"),
        "reservations": [DhcpReservation(**r) for r in raw.get("reservations", [])],
        "port_forwards": [PortForward(**p) for p in raw.get("port_forwards", [])],
        "static_routes": [StaticRoute(**r) for r in raw.get("static_routes", [])],
        "upnp": raw.get("upnp"),
    }


async def drift(b: StockBackend, desired: dict[str, Any]) -> list[dict[str, Any]]:
    """Items the router does not yet match. Extra items on the router are reported, never removed."""
    out: list[dict[str, Any]] = []
    if desired.get("dns"):
        cur = await b.get_dns()
        want = desired["dns"]
        if cur.mode != want.get("mode") or (want.get("mode") == "manual" and cur.servers != want.get("servers")):
            out.append({"kind": "dns", "want": want, "have": cur.model_dump(exclude={"active"})})
    have_res = {r.mac: r for r in await b.list_reservations()}
    for r in desired["reservations"]:
        h = have_res.get(r.mac)
        if h is None or h.ip != r.ip or h.name != r.name:
            out.append({"kind": "reservation", "want": r.model_dump(exclude={"slot"}),
                        "have": h.model_dump(exclude={"slot"}) if h else None})
    have_pf = await b.list_port_forwards()
    for p in desired["port_forwards"]:
        if not any(h.external_ports == p.external_ports and str(h.protocol) == str(p.protocol)
                   and h.internal_ip == p.internal_ip and h.enabled == p.enabled for h in have_pf):
            out.append({"kind": "port_forward", "want": p.model_dump(exclude={"id"})})
    have_rt = {r.destination: r for r in await b.list_static_routes()}
    for r in desired["static_routes"]:
        h = have_rt.get(r.destination)
        if h is None or h.gateway != r.gateway:
            out.append({"kind": "static_route", "want": r.model_dump(exclude={"slot"}),
                        "have": h.model_dump(exclude={"slot"}) if h else None})
    if desired.get("upnp") is not None:
        cur_u = await b.get_upnp()
        if cur_u.enabled != bool(desired["upnp"].get("enabled")):
            out.append({"kind": "upnp", "want": desired["upnp"], "have": cur_u.model_dump()})
    return out
