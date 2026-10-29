"""MCP tools for the Verizon Fios CR1000A.

Tool names that also exist in the community TP-Link router MCP keep the same
names, so moving settings between the two is a side-by-side conversation.

Every tool that changes the router is two-phase: call it once to get a
preview and a `state_etag`, then again with `confirm=true` and
`expected_etag=<state_etag>` to apply. The result reports whether a read-back
shows the change.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from . import snapshot
from .backend.stock.backend import PAGES, StockBackend
from .backend.stock.transport import RouterTransport, tls_context
from .config import Config, ConfigError
from .models import DhcpReservation, PortForward, StaticRoute
from .policy import Policy
from .service import VERIFIED_FIRMWARE, Service

INSTRUCTIONS = """\
Manages a Verizon Fios CR1000A router over its local web interface.
Changes are two-phase: call a write tool without confirm to get a preview and
state_etag, show the preview to the user, then call again with confirm=true and
expected_etag. Never confirm a change the user has not seen. Wi-Fi keys and
passwords are always redacted. On this router DHCP reservations in .100-.150
are reserved for Verizon devices and are refused.
"""

READ = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False)
DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False)

mcp = MCPServer(name="fios-mcp", instructions=INSTRUCTIONS)


class Runtime:
    def __init__(self) -> None:
        self.service: Service | None = None
        self.transport: RouterTransport | None = None
        self.config_error: str | None = None

    def get(self) -> Service:
        if self.service is None:
            cfg = Config.load()
            self.transport = RouterTransport(cfg.url, cfg.password, verify=tls_context(cfg.pin_file))
            self.service = Service(StockBackend(self.transport), Policy.load(cfg.policy_file))
        return self.service

    async def close(self) -> None:
        if self.transport is not None:
            await self.transport.aclose()


rt = Runtime()


def _svc() -> Service:
    return rt.get()


def _err(e: Exception) -> dict[str, Any]:
    return {"ok": False, "errors": [str(e)], "warnings": []}


async def _read(fn_name: str, *args: Any) -> dict[str, Any]:
    try:
        s = _svc()
    except (ConfigError, OSError) as e:
        return _err(e)
    return await s.read(lambda: getattr(s.b, fn_name)(*args))


# -- status & diagnostics ---------------------------------------------------

@mcp.tool(annotations=READ)
async def router_status() -> dict[str, Any]:
    """Model, firmware, WAN address and DNS in use, LAN address."""
    return await _read("status")


@mcp.tool(annotations=READ)
async def router_firmware() -> dict[str, Any]:
    """Firmware version/date and whether this tool has been verified against it."""
    return await _read("firmware")


@mcp.tool(annotations=READ)
async def router_diagnostics() -> dict[str, Any]:
    """Connection, session and policy state of this MCP server (never secrets)."""
    try:
        s = _svc()
    except (ConfigError, OSError) as e:
        return _err(e)
    out = await s.read(s.b.session_settings)
    t = rt.transport
    out["server"] = {
        "router_url": t.base_url if t else None,
        "logins_this_process": t.logins_performed if t else 0,
        "policy": s.policy.summary(),
        "firmware_verified": s._firmware in VERIFIED_FIRMWARE,
    }
    return out


@mcp.tool(annotations=READ)
async def ping(target: str, count: int = 4) -> dict[str, Any]:
    """Ping an IPv4 address from the router itself (1-20 packets)."""
    return await _read("ping", target, count)


@mcp.tool(annotations=READ)
async def read_router_page(page: str) -> dict[str, Any]:
    """Raw (redacted) contents of one router page, for settings without a dedicated tool.

    Pages: see the fios://pages resource."""
    return await _read("read_page", page)


@mcp.resource("fios://pages", description="Router pages readable with read_router_page")
def pages() -> str:
    return "\n".join(PAGES)


@mcp.tool(annotations=READ)
async def get_policy() -> dict[str, Any]:
    """The owner's policy.toml guard-rails as loaded."""
    try:
        return {"ok": True, "data": _svc().policy.summary(), "warnings": [], "errors": []}
    except (ConfigError, OSError) as e:
        return _err(e)


# -- devices ------------------------------------------------------------------

@mcp.tool(annotations=READ)
async def list_connected_devices(active_only: bool = False) -> dict[str, Any]:
    """Devices the router knows, with MAC, IP, hostname and whether they are active."""
    out = await _read("list_devices")
    if active_only and out.get("ok"):
        out["data"] = [d for d in out["data"] if d["active"]]
    return out


@mcp.tool(annotations=READ)
async def list_dhcp_leases() -> dict[str, Any]:
    """Current DHCP leases (hostname, IP, MAC, seconds left)."""
    return await _read("list_leases")


@mcp.tool(annotations=READ)
async def list_arp_table() -> dict[str, Any]:
    """The router's ARP table."""
    return await _read("list_arp")


@mcp.tool(annotations=READ)
async def get_wifi_summary() -> dict[str, Any]:
    """SSIDs, enabled state and security type of the primary, guest and IoT networks (no keys)."""
    return await _read("wifi_summary")


@mcp.tool(annotations=READ)
async def list_blocked_devices() -> dict[str, Any]:
    """Devices blocked from the network."""
    return await _read("list_blocked")


@mcp.tool(annotations=WRITE)
async def block_device(mac: str, confirm: bool = False, expected_etag: str | None = None) -> dict[str, Any]:
    """Block a device (by MAC) from the network. Two-phase."""
    return await _svc().block_device(mac, True, confirm=confirm, expected_etag=expected_etag)


@mcp.tool(annotations=WRITE)
async def unblock_device(mac: str, confirm: bool = False, expected_etag: str | None = None) -> dict[str, Any]:
    """Unblock a previously blocked device. Two-phase."""
    return await _svc().block_device(mac, False, confirm=confirm, expected_etag=expected_etag)


# -- port forwarding ----------------------------------------------------------

@mcp.tool(annotations=READ)
async def list_port_forwarding() -> dict[str, Any]:
    """Port forwarding rules with their ports, target and enabled state."""
    return await _read("list_port_forwards")


@mcp.tool(annotations=WRITE)
async def add_port_forwarding(
    name: str,
    external_ports: list[str],
    internal_ip: str,
    protocol: Literal["tcp", "udp", "both"] = "tcp",
    internal_port: int | None = None,
    enabled: bool = True,
    replace: bool = False,
    confirm: bool = False,
    expected_etag: str | None = None,
) -> dict[str, Any]:
    """Forward external port(s) (e.g. ["443"] or ["1000-2000"]) to a LAN host. Two-phase.

    internal_port: only if different from the external port. replace=true updates
    an existing rule on the same port instead of refusing."""
    try:
        pf = PortForward(name=name, external_ports=external_ports, internal_ip=internal_ip,
                         protocol=protocol, internal_port=internal_port, enabled=enabled)
    except ValueError as e:
        return _err(e)
    return await _svc().add_port_forward(pf, confirm=confirm, expected_etag=expected_etag, replace=replace)


@mcp.tool(annotations=DESTRUCTIVE)
async def delete_port_forwarding(
    name: str | None = None,
    external_port: str | None = None,
    protocol: Literal["tcp", "udp", "both"] | None = None,
    confirm: bool = False,
    expected_etag: str | None = None,
) -> dict[str, Any]:
    """Delete a port forward by name, or by external port (+ protocol). Two-phase."""
    if name is None and external_port is None:
        return _err(ValueError("give name or external_port"))
    return await _svc().delete_port_forward(name=name, external_port=external_port, protocol=protocol,
                                            confirm=confirm, expected_etag=expected_etag)


@mcp.tool(annotations=WRITE)
async def set_port_forwarding_enabled(name: str, enabled: bool, confirm: bool = False,
                                      expected_etag: str | None = None) -> dict[str, Any]:
    """Enable or disable a port forward without deleting it. Two-phase."""
    return await _svc().set_port_forward_enabled(name, enabled, confirm=confirm, expected_etag=expected_etag)


# -- DHCP ---------------------------------------------------------------------

@mcp.tool(annotations=READ)
async def get_lan_settings() -> dict[str, Any]:
    """LAN address, mask, DHCP range and lease time."""
    return await _read("get_lan")


@mcp.tool(annotations=READ)
async def list_dhcp_reservations() -> dict[str, Any]:
    """DHCP reservations (MAC -> fixed IP)."""
    return await _read("list_reservations")


@mcp.tool(annotations=WRITE)
async def add_dhcp_reservation(mac: str, ip: str, name: str = "", replace: bool = False,
                               confirm: bool = False, expected_etag: str | None = None) -> dict[str, Any]:
    """Reserve an IP for a MAC. Refuses .100-.150 (reserved for Verizon devices). Two-phase."""
    try:
        r = DhcpReservation(mac=mac, ip=ip, name=name)
    except ValueError as e:
        return _err(e)
    return await _svc().add_reservation(r, confirm=confirm, expected_etag=expected_etag, replace=replace)


@mcp.tool(annotations=DESTRUCTIVE)
async def delete_dhcp_reservation(mac: str, confirm: bool = False,
                                  expected_etag: str | None = None) -> dict[str, Any]:
    """Remove the reservation for a MAC. Two-phase."""
    try:
        return await _svc().delete_reservation(mac, confirm=confirm, expected_etag=expected_etag)
    except ValueError as e:
        return _err(e)


# -- routing & DNS ------------------------------------------------------------

@mcp.tool(annotations=READ)
async def list_static_routes(include_live_table: bool = False) -> dict[str, Any]:
    """Configured IPv4 static routes (max 20); optionally the router's live routing table."""
    out = await _read("list_static_routes")
    if include_live_table and out.get("ok"):
        out["live_routing_table"] = (await _read("live_routes")).get("data")
    return out


@mcp.tool(annotations=WRITE)
async def add_static_route(destination: str, gateway: str, metric: int = 1, confirm: bool = False,
                           expected_etag: str | None = None) -> dict[str, Any]:
    """Route a network (CIDR, e.g. 10.99.0.0/24) via a LAN gateway. Two-phase."""
    try:
        r = StaticRoute(destination=destination, gateway=gateway, metric=metric)
    except ValueError as e:
        return _err(e)
    return await _svc().add_static_route(r, confirm=confirm, expected_etag=expected_etag)


@mcp.tool(annotations=DESTRUCTIVE)
async def delete_static_route(destination: str, confirm: bool = False,
                              expected_etag: str | None = None) -> dict[str, Any]:
    """Delete the static route to a network (CIDR). Two-phase."""
    try:
        return await _svc().delete_static_route(destination, confirm=confirm, expected_etag=expected_etag)
    except ValueError as e:
        return _err(e)


@mcp.tool(annotations=READ)
async def get_dns_settings() -> dict[str, Any]:
    """WAN DNS (IPv4 mode/servers in use, and IPv6 DNS mode). LAN clients use the router.

    Warns when IPv6 DNS is automatic: that is a second path to the ISP's resolvers."""
    try:
        return await _svc().get_dns()
    except (ConfigError, OSError) as e:
        return _err(e)


@mcp.tool(annotations=WRITE)
async def set_dns_settings(mode: Literal["manual", "auto"], servers: list[str] | None = None,
                           confirm: bool = False, expected_etag: str | None = None) -> dict[str, Any]:
    """Set WAN DNS. Manual servers must be in policy.toml's allowlist. Two-phase."""
    return await _svc().set_dns(mode, servers or [], confirm=confirm, expected_etag=expected_etag)


# -- security settings --------------------------------------------------------

@mcp.tool(annotations=READ)
async def get_firewall_settings() -> dict[str, Any]:
    """Firewall security levels (IPv4/IPv6)."""
    return await _read("get_firewall")


@mcp.tool(annotations=READ)
async def get_remote_admin_settings() -> dict[str, Any]:
    """Whether remote (WAN-side) administration and WAN ping/traceroute replies are enabled."""
    return await _read("get_remote_admin")


@mcp.tool(annotations=READ)
async def get_dmz_settings() -> dict[str, Any]:
    """DMZ host settings."""
    return await _read("get_dmz")


@mcp.tool(annotations=DESTRUCTIVE)
async def set_dmz(enabled: bool, ip: str = "", confirm: bool = False,
                  expected_etag: str | None = None) -> dict[str, Any]:
    """Enable (needs features.allow_dmz in policy.toml) or disable the DMZ host. Two-phase."""
    return await _svc().set_dmz(enabled, ip, confirm=confirm, expected_etag=expected_etag)


@mcp.tool(annotations=READ)
async def get_upnp_settings() -> dict[str, Any]:
    """Whether UPnP (devices opening ports themselves) is enabled."""
    return await _read("get_upnp")


@mcp.tool(annotations=WRITE)
async def set_upnp(enabled: bool, confirm: bool = False, expected_etag: str | None = None) -> dict[str, Any]:
    """Enable or disable UPnP. Two-phase."""
    return await _svc().set_upnp(enabled, confirm=confirm, expected_etag=expected_etag)


@mcp.tool(annotations=DESTRUCTIVE)
async def reboot_router(confirm: bool = False) -> dict[str, Any]:
    """Reboot the router (~4 minutes of downtime). Without confirm, only previews."""
    return await _svc().reboot(confirm=confirm)


# -- snapshots & desired state -----------------------------------------------

@mcp.tool(annotations=READ)
async def snapshot_config() -> dict[str, Any]:
    """Save every readable setting to a local snapshot file (0600); returns its id."""
    try:
        s = _svc()
        snap = await snapshot.take(s.b)
        return {"ok": True, "snapshot_id": snapshot.save(snap), "data": snap, "warnings": [], "errors": []}
    except Exception as e:  # noqa: BLE001 - report, don't crash the server
        return _err(e)


@mcp.tool(annotations=READ)
async def list_snapshots() -> dict[str, Any]:
    """Ids of saved snapshots, oldest first."""
    return {"ok": True, "data": snapshot.list_saved(), "warnings": [], "errors": []}


@mcp.tool(annotations=READ)
async def diff_config(snapshot_a: str, snapshot_b: str = "live") -> dict[str, Any]:
    """Differences between two snapshots, or a snapshot and the live router ("live")."""
    try:
        a = snapshot.load(snapshot_a)
        b = await snapshot.take(_svc().b) if snapshot_b == "live" else snapshot.load(snapshot_b)
        return {"ok": True, "data": snapshot.diff(a, b), "warnings": [], "errors": []}
    except Exception as e:  # noqa: BLE001
        return _err(e)


@mcp.tool(annotations=READ)
async def check_desired_state(path: str) -> dict[str, Any]:
    """Compare the router to a desired-state TOML file; lists what is missing or different."""
    try:
        s = _svc()
        desired = snapshot.load_desired(Path(path).expanduser())
        items = await snapshot.drift(s.b, desired)
        warnings = s.ipv6_dns_warnings(await s.b.get_dns()) if desired.get("dns") else []
        return {"ok": True, "data": items, "in_sync": not items, "warnings": warnings, "errors": []}
    except Exception as e:  # noqa: BLE001
        return _err(e)


@mcp.tool(annotations=WRITE)
async def apply_desired_state(path: str, confirm: bool = False) -> dict[str, Any]:
    """Apply a desired-state TOML file item by item (never removes extra entries).

    Without confirm, returns the plan. With confirm, applies each item through the
    same validation and read-back as the individual tools, stopping at the first failure."""
    try:
        s = _svc()
        desired = snapshot.load_desired(Path(path).expanduser())
        items = await snapshot.drift(s.b, desired)
    except Exception as e:  # noqa: BLE001
        return _err(e)
    if not confirm or not items:
        return {"ok": True, "preview": bool(items), "plan": items, "in_sync": not items,
                "warnings": [], "errors": []}
    results = []
    for item in items:
        op = _op_for(s, item)
        pre = await op(confirm=False, expected_etag=None)
        res = pre if not pre.get("ok") or pre.get("result") == "no_change" else \
            await op(confirm=True, expected_etag=pre.get("state_etag"))
        results.append({"item": item, "ok": res.get("ok"), "errors": res.get("errors"),
                        "verified": res.get("verified")})
        if not res.get("ok"):
            break
    return {"ok": all(r["ok"] for r in results), "results": results, "warnings": [], "errors": []}


def _op_for(s: Service, item: dict[str, Any]):
    w = item["want"]
    kind = item["kind"]
    if kind == "reservation":
        r = DhcpReservation(**w)
        return lambda **kw: s.add_reservation(r, replace=True, **kw)
    if kind == "port_forward":
        p = PortForward(**w)
        return lambda **kw: s.add_port_forward(p, replace=True, **kw)
    if kind == "static_route":
        rt_ = StaticRoute(**{k: v for k, v in w.items() if k != "interface"})
        return lambda **kw: s.add_static_route(rt_, **kw)
    if kind == "dns":
        return lambda **kw: s.set_dns(w.get("mode", "manual"), w.get("servers", []), **kw)
    if kind == "upnp":
        return lambda **kw: s.set_upnp(bool(w.get("enabled")), **kw)
    raise ValueError(f"unknown item kind {kind}")
