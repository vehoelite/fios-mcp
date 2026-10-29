"""Safe change orchestration on top of a backend.

Every mutating operation goes through `Service._change`:

1. read the current state and fingerprint it (`state_etag`);
2. validate the request against the router's real rules and the owner's policy;
3. without `confirm`, return a preview of exactly what would change;
4. with `confirm` + the preview's `expected_etag`, re-read, refuse if anything
   moved in between (e.g. an edit in the web UI), write, read back, and report
   whether the router now holds what was asked for.
"""

from __future__ import annotations

import hashlib
import inspect
import ipaddress
import json
import os
import re
from collections.abc import Awaitable, Callable
from typing import Any

from .backend.stock.backend import WIFI_BANDS, StockBackend, in_verizon_reserved_range
from .backend.stock.transport import AuthError, RouterError
from .models import DhcpReservation, PortForward, StaticRoute, normalize_mac
from .policy import Policy

VERIFIED_FIRMWARE = {"3.3.1.2"}
_NAME = re.compile(r"^[0-9A-Za-z.\-_]+$")


def etag(obj: Any) -> str:
    def default(o: Any) -> Any:
        return o.model_dump() if hasattr(o, "model_dump") else str(o)

    blob = json.dumps(obj, sort_keys=True, default=default)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def dump(obj: Any) -> Any:
    if isinstance(obj, list):
        return [dump(o) for o in obj]
    return obj.model_dump() if hasattr(obj, "model_dump") else obj


class Service:
    def __init__(self, backend: StockBackend, policy: Policy):
        self.b = backend
        self.policy = policy
        self._firmware: str | None = None

    # -- envelope ----------------------------------------------------------

    def env(self, ok: bool, data: Any = None, *, warnings: list[str] | None = None,
            errors: list[str] | None = None, **extra: Any) -> dict[str, Any]:
        out: dict[str, Any] = {"ok": ok, "backend": self.b.name, "firmware": self._firmware}
        if data is not None:
            out["data"] = dump(data)
        out["warnings"] = warnings or []
        out["errors"] = errors or []
        out.update(extra)
        return out

    async def read(self, fn: Callable[[], Awaitable[Any]]) -> dict[str, Any]:
        try:
            await self._ensure_firmware()
            return self.env(True, await fn(), warnings=self._fw_warnings())
        except (RouterError, AuthError, ValueError) as e:
            return self.env(False, errors=[str(e)])

    # -- firmware guard ----------------------------------------------------

    async def _ensure_firmware(self) -> str:
        if self._firmware is None:
            self._firmware = (await self.b.firmware()).version
        return self._firmware

    def _fw_warnings(self) -> list[str]:
        if self._firmware and self._firmware not in VERIFIED_FIRMWARE:
            return [(f"unverified_firmware: {self._firmware} (verified: {sorted(VERIFIED_FIRMWARE)}); "
                     "writes are refused unless FIOS_MCP_ALLOW_UNVERIFIED_FIRMWARE=1")]
        return []

    def _writes_allowed(self) -> str | None:
        if self._firmware in VERIFIED_FIRMWARE or os.environ.get("FIOS_MCP_ALLOW_UNVERIFIED_FIRMWARE") == "1":
            return None
        return (f"refusing to write: firmware {self._firmware} has not been verified with this tool "
                "(set FIOS_MCP_ALLOW_UNVERIFIED_FIRMWARE=1 to override at your own risk)")

    # -- the change gate ---------------------------------------------------

    async def _change(
        self,
        *,
        action: str,
        read_state: Callable[[], Awaitable[Any]],
        plan: Callable[[Any], tuple[list[str], list[str], bool]],
        apply: Callable[[], Awaitable[None]],
        verify: Callable[[Any], bool],
        confirm: bool,
        expected_etag: str | None,
    ) -> dict[str, Any]:
        """plan(state) -> (errors, warnings, already_done)."""
        try:
            await self._ensure_firmware()
            state = await read_state()
            tag = etag(state)
            errors, warnings = [], self._fw_warnings()
            errs, warns, done = plan(state)
            errors += errs
            warnings += warns
            if errors:
                return self.env(False, state, errors=errors, warnings=warnings, action=action)
            if done:
                return self.env(True, state, warnings=warnings, action=action, result="no_change")
            if not confirm:
                return self.env(True, state, warnings=warnings, action=action, preview=True, state_etag=tag,
                                next_step="call again with confirm=true and expected_etag=state_etag")
            refused = self._writes_allowed()
            if refused:
                return self.env(False, errors=[refused], action=action)
            if expected_etag != tag:
                return self.env(False, state, action=action, errors=[
                    ("conflict: router state changed since the preview (or no expected_etag given); "
                     "preview again")], state_etag=tag)
            try:
                await apply()
            except KeyError as e:
                return self.env(False, action=action, errors=[
                    f"router page no longer has field {e}; firmware may have changed - refusing"])
            after = await read_state()
            ok = verify(after)
            if inspect.isawaitable(ok):
                ok = await ok
            return self.env(ok, after, warnings=warnings, action=action, verified=ok,
                            errors=[] if ok else ["write sent but read-back does not show the change"])
        except (RouterError, AuthError, ValueError) as e:
            return self.env(False, errors=[str(e)], action=action)

    # -- validation helpers ------------------------------------------------

    async def _lan(self) -> ipaddress.IPv4Interface:
        lan = await self.b.get_lan()
        return ipaddress.IPv4Interface(f"{lan.ip}/{lan.mask}")

    @staticmethod
    def _host_errors(ip: str, lan: ipaddress.IPv4Interface, what: str) -> list[str]:
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            return [f"{what}: {ip!r} is not an IPv4 address"]
        errs = []
        if addr not in lan.network:
            errs.append(f"{what}: {ip} is outside the LAN {lan.network}")
        if addr in (lan.network.network_address, lan.network.broadcast_address, lan.ip):
            errs.append(f"{what}: {ip} is the network, broadcast or router address")
        return errs

    # -- port forwarding ---------------------------------------------------

    async def add_port_forward(self, pf: PortForward, *, confirm: bool = False,
                               expected_etag: str | None = None, replace: bool = False) -> dict[str, Any]:
        lan = await self._lan()

        def plan(cur: list[PortForward]) -> tuple[list[str], list[str], bool]:
            errs = self._host_errors(pf.internal_ip, lan, "internal_ip")
            if str(pf.protocol) not in ("tcp", "udp", "both"):
                errs.append("protocol must be tcp, udp or both")
            if not pf.external_ports:
                errs.append("external_ports is empty")
            for p in pf.external_ports:
                parts = p.split("-")
                if not all(x.isdigit() and 1 <= int(x) <= 65535 for x in parts) or len(parts) > 2:
                    errs.append(f"bad port or range {p!r}")
            if not _NAME.match(pf.name):
                errs.append("name: letters, digits, '.', '-' and '_' only")
            for c in cur:
                same_proto = "both" in (str(c.protocol), str(pf.protocol)) or c.protocol == pf.protocol
                if set(c.external_ports) & set(pf.external_ports) and same_proto:
                    if c.internal_ip == pf.internal_ip and c.internal_port == pf.internal_port \
                            and c.enabled == pf.enabled:
                        return [], [], True
                    if not replace:
                        errs.append(f"conflicts with existing forward {c.name!r} (id {c.id}) on "
                                    f"{c.external_ports}/{c.protocol}; pass replace=true to update it")
            return errs, [], False

        async def apply() -> None:
            cur = await self.b.list_port_forwards()
            clash = [c for c in cur if set(c.external_ports) & set(pf.external_ports)]
            if clash and replace:
                await self.b.update_port_forward(pf.model_copy(update={"id": clash[0].id}))
            else:
                await self.b.add_port_forward(pf)

        def verify(after: list[PortForward]) -> bool:
            return any(a.external_ports == pf.external_ports and a.internal_ip == pf.internal_ip
                       and str(a.protocol) == str(pf.protocol) for a in after)

        return await self._change(action=f"add port forward {pf.name}", read_state=self.b.list_port_forwards,
                                  plan=plan, apply=apply, verify=verify, confirm=confirm,
                                  expected_etag=expected_etag)

    def _forward_protected(self, pf: PortForward) -> bool:
        keys = {pf.name.lower()} | {f"{p}/{pf.protocol}".lower() for p in pf.external_ports}
        return bool(keys & self.policy.protected_forwards)

    async def delete_port_forward(self, *, name: str | None = None, external_port: str | None = None,
                                  protocol: str | None = None, confirm: bool = False,
                                  expected_etag: str | None = None) -> dict[str, Any]:
        target: dict[str, PortForward] = {}

        def match(c: PortForward) -> bool:
            if name is not None:
                return c.name == name
            return external_port in c.external_ports and (protocol is None or str(c.protocol) == protocol)

        def plan(cur: list[PortForward]) -> tuple[list[str], list[str], bool]:
            hits = [c for c in cur if match(c)]
            if not hits:
                return [], ["no matching port forward"], True
            if len(hits) > 1:
                return [f"{len(hits)} forwards match; be more specific (name or port+protocol)"], [], False
            if self._forward_protected(hits[0]):
                return [f"{hits[0].name!r} is protected by policy.toml"], [], False
            target["pf"] = hits[0]
            return [], [], False

        async def apply() -> None:
            await self.b.delete_port_forward(target["pf"].id)  # type: ignore[arg-type]

        return await self._change(action="delete port forward", read_state=self.b.list_port_forwards,
                                  plan=plan, apply=apply,
                                  verify=lambda after: not any(match(a) for a in after),
                                  confirm=confirm, expected_etag=expected_etag)

    async def set_port_forward_enabled(self, name: str, enabled: bool, *, confirm: bool = False,
                                       expected_etag: str | None = None) -> dict[str, Any]:
        target: dict[str, PortForward] = {}

        def plan(cur: list[PortForward]) -> tuple[list[str], list[str], bool]:
            hits = [c for c in cur if c.name == name]
            if len(hits) != 1:
                return [f"expected exactly one forward named {name!r}, found {len(hits)}"], [], False
            if not enabled and self._forward_protected(hits[0]):
                return [f"{name!r} is protected by policy.toml"], [], False
            target["pf"] = hits[0]
            return [], [], hits[0].enabled == enabled

        async def apply() -> None:
            await self.b.update_port_forward(target["pf"].model_copy(update={"enabled": enabled}))

        return await self._change(
            action=f"{'enable' if enabled else 'disable'} port forward {name}",
            read_state=self.b.list_port_forwards, plan=plan, apply=apply,
            verify=lambda after: any(a.name == name and a.enabled == enabled for a in after),
            confirm=confirm, expected_etag=expected_etag)

    # -- DHCP reservations -------------------------------------------------

    async def add_reservation(self, r: DhcpReservation, *, confirm: bool = False,
                              expected_etag: str | None = None, replace: bool = False) -> dict[str, Any]:
        lan = await self._lan()

        def plan(cur: list[DhcpReservation]) -> tuple[list[str], list[str], bool]:
            errs = self._host_errors(r.ip, lan, "ip")
            if not errs and in_verizon_reserved_range(r.ip):
                errs.append(f"ip: {r.ip} is in .100-.150, which the CR1000A reserves for Verizon-managed "
                            "devices - the router stores such a reservation but never hands the address "
                            "out. Pick an address outside .100-.150.")
            if r.name and not _NAME.match(r.name):
                errs.append("name: letters, digits, '.', '-' and '_' only")
            for c in cur:
                if c.mac == r.mac:
                    if c.ip == r.ip and c.name == r.name:
                        return [], [], True
                    if not replace:
                        errs.append(f"{r.mac} already reserved as {c.ip}; pass replace=true to change it")
                    elif r.mac in self.policy.protected_reservations or c.ip in self.policy.protected_reservations:
                        errs.append(f"{r.mac} is protected by policy.toml")
                elif c.ip == r.ip:
                    errs.append(f"{r.ip} is already reserved for {c.mac} ({c.name})")
                elif r.name and c.name.lower() == r.name.lower():
                    errs.append(f"name {r.name!r} is already used by {c.mac}")
            return errs, [], False

        return await self._change(
            action=f"reserve {r.ip} for {r.mac}", read_state=self.b.list_reservations, plan=plan,
            apply=lambda: self.b.put_reservation(r),
            verify=lambda after: any(a.mac == r.mac and a.ip == r.ip for a in after),
            confirm=confirm, expected_etag=expected_etag)

    async def delete_reservation(self, mac: str, *, confirm: bool = False,
                                 expected_etag: str | None = None) -> dict[str, Any]:
        mac = normalize_mac(mac)

        def plan(cur: list[DhcpReservation]) -> tuple[list[str], list[str], bool]:
            hit = next((c for c in cur if c.mac == mac), None)
            if hit is None:
                return [], [f"no reservation for {mac}"], True
            if mac in self.policy.protected_reservations or hit.ip in self.policy.protected_reservations:
                return [f"{mac} ({hit.ip}) is protected by policy.toml"], [], False
            return [], [], False

        return await self._change(
            action=f"delete reservation {mac}", read_state=self.b.list_reservations, plan=plan,
            apply=lambda: self.b.delete_reservation(mac),
            verify=lambda after: not any(a.mac == mac for a in after),
            confirm=confirm, expected_etag=expected_etag)

    # -- static routes -----------------------------------------------------

    async def add_static_route(self, r: StaticRoute, *, confirm: bool = False,
                               expected_etag: str | None = None) -> dict[str, Any]:
        lan = await self._lan()

        def plan(cur: list[StaticRoute]) -> tuple[list[str], list[str], bool]:
            errs = self._host_errors(r.gateway, lan, "gateway")
            net = ipaddress.ip_network(r.destination)
            if net.overlaps(lan.network):
                errs.append(f"destination {net} overlaps the LAN {lan.network}")
            for c in cur:
                if c.destination == r.destination:
                    if c.gateway == r.gateway and c.metric == r.metric:
                        return [], [], True
                    errs.append(f"a route to {r.destination} already exists via {c.gateway}; delete it first")
            if len(cur) >= 20:
                errs.append("all 20 static route slots are in use")
            return errs, [], False

        return await self._change(
            action=f"route {r.destination} via {r.gateway}", read_state=self.b.list_static_routes, plan=plan,
            apply=lambda: self.b.add_static_route(r),
            verify=lambda after: any(a.destination == r.destination and a.gateway == r.gateway for a in after),
            confirm=confirm, expected_etag=expected_etag)

    async def delete_static_route(self, destination: str, *, confirm: bool = False,
                                  expected_etag: str | None = None) -> dict[str, Any]:
        dest = str(ipaddress.ip_network(destination, strict=True))

        def plan(cur: list[StaticRoute]) -> tuple[list[str], list[str], bool]:
            if not any(c.destination == dest for c in cur):
                return [], [f"no static route to {dest}"], True
            if dest in self.policy.protected_routes:
                return [f"route to {dest} is protected by policy.toml"], [], False
            return [], [], False

        return await self._change(
            action=f"delete route {dest}", read_state=self.b.list_static_routes, plan=plan,
            apply=lambda: self.b.delete_static_route(dest),
            verify=lambda after: not any(a.destination == dest for a in after),
            confirm=confirm, expected_etag=expected_etag)

    # -- DNS ---------------------------------------------------------------

    def ipv6_dns_warnings(self, dns: Any) -> list[str]:
        """IPv6 DNS is a second path out: the IPv4 manual setting does not cover it."""
        if dns.ipv6_mode == "auto":
            learned = f" (currently {dns.ipv6_learned})" if dns.ipv6_learned else ""
            return [("ipv6_dns_auto: IPv6 WAN DNS is automatic" + learned + ". On a WAN with IPv6 the router "
                     "can forward lookups to the ISP's IPv6 resolvers, bypassing the IPv4 DNS setting. This "
                     "tool cannot change IPv6 DNS yet: set it in the web UI (Network Settings > Network "
                     "Connections > Broadband > IPv6) or disable IPv6 on the WAN.")]
        bad = [s for s in dns.ipv6_servers if self.policy.allowed_dns and s not in self.policy.allowed_dns]
        if bad:
            return [f"ipv6_dns_not_allowlisted: IPv6 DNS servers {bad} are not in policy.toml's allowlist"]
        return []

    async def get_dns(self) -> dict[str, Any]:
        out = await self.read(self.b.get_dns)
        if out["ok"]:
            out["warnings"] += self.ipv6_dns_warnings(await self.b.get_dns())
        return out

    async def set_dns(self, mode: str, servers: list[str], *, confirm: bool = False,
                      expected_etag: str | None = None) -> dict[str, Any]:
        def plan(cur: Any) -> tuple[list[str], list[str], bool]:
            errs = []
            if mode == "manual":
                if not self.policy.allowed_dns:
                    errs.append("refusing to set DNS: no allowed_servers in policy.toml [dns]")
                bad = [s for s in servers if s not in self.policy.allowed_dns]
                if bad:
                    errs.append(f"{bad} not in the policy allowlist {self.policy.allowed_dns}")
                if not 1 <= len(servers) <= 2:
                    errs.append("manual DNS takes one or two servers")
            elif mode != "auto":
                errs.append("mode must be 'manual' or 'auto'")
            done = cur.mode == mode and (mode == "auto" or cur.servers == servers)
            warns = ["auto mode uses whatever DNS the ISP hands out"] if mode == "auto" else []
            return errs, warns + self.ipv6_dns_warnings(cur), done

        return await self._change(
            action=f"set WAN DNS {mode} {servers}", read_state=self.b.get_dns, plan=plan,
            apply=lambda: self.b.set_dns(mode, servers),
            verify=lambda after: after.mode == mode and (mode == "auto" or after.servers == servers),
            confirm=confirm, expected_etag=expected_etag)

    # -- DMZ / UPnP / blocking / reboot ------------------------------------

    async def set_dmz(self, enabled: bool, ip: str = "", *, confirm: bool = False,
                      expected_etag: str | None = None) -> dict[str, Any]:
        lan = await self._lan()

        def plan(cur: Any) -> tuple[list[str], list[str], bool]:
            errs: list[str] = []
            warns: list[str] = []
            if enabled:
                if not self.policy.allow_dmz:
                    errs.append("DMZ is disabled by policy (features.allow_dmz = false): a DMZ host "
                                "receives every unsolicited port from the internet")
                errs += self._host_errors(ip, lan, "ip")
                warns.append("the DMZ host will receive ALL unsolicited inbound traffic")
            return errs, warns, cur.enabled == enabled and (not enabled or cur.ip == ip)

        return await self._change(
            action=f"{'enable' if enabled else 'disable'} DMZ {ip}".strip(), read_state=self.b.get_dmz,
            plan=plan, apply=lambda: self.b.set_dmz(enabled, ip),
            verify=lambda after: after.enabled == enabled and (not enabled or after.ip == ip),
            confirm=confirm, expected_etag=expected_etag)

    async def set_upnp(self, enabled: bool, *, confirm: bool = False,
                       expected_etag: str | None = None) -> dict[str, Any]:
        def plan(cur: Any) -> tuple[list[str], list[str], bool]:
            warns = ["UPnP lets any LAN device open ports on the router without asking"] if enabled else []
            return [], warns, cur.enabled == enabled

        return await self._change(
            action=f"{'enable' if enabled else 'disable'} UPnP", read_state=self.b.get_upnp, plan=plan,
            apply=lambda: self.b.set_upnp(enabled), verify=lambda after: after.enabled == enabled,
            confirm=confirm, expected_etag=expected_etag)

    async def block_device(self, mac: str, blocked: bool, *, confirm: bool = False,
                           expected_etag: str | None = None) -> dict[str, Any]:
        mac = normalize_mac(mac)

        def plan(cur: list[Any]) -> tuple[list[str], list[str], bool]:
            errs = [] if self.policy.allow_block else ["device blocking is disabled by policy"]
            if blocked and (mac in self.policy.protected_reservations):
                errs.append(f"{mac} is protected by policy.toml")
            return errs, [], (mac in {b.mac for b in cur}) == blocked

        return await self._change(
            action=f"{'block' if blocked else 'unblock'} {mac}", read_state=self.b.list_blocked, plan=plan,
            apply=lambda: self.b.block_device(mac) if blocked else self.b.unblock_device(mac),
            verify=lambda after: (mac in {b.mac for b in after}) == blocked,
            confirm=confirm, expected_etag=expected_etag)

    async def reboot(self, *, confirm: bool = False) -> dict[str, Any]:
        if not self.policy.allow_reboot:
            return self.env(False, errors=["reboot is disabled by policy"])
        if not confirm:
            return self.env(True, preview=True, action="reboot router",
                            warnings=["the router and the whole network go down for about 4 minutes"],
                            next_step="call again with confirm=true")
        try:
            await self._ensure_firmware()
            refused = self._writes_allowed()
            if refused:
                return self.env(False, errors=[refused])
            await self.b.reboot()
            return self.env(True, action="reboot router", result="reboot requested; expect ~4 minutes down")
        except (RouterError, AuthError) as e:
            return self.env(False, errors=[str(e)])

    # -- Wi-Fi -------------------------------------------------------------

    async def set_wifi_radio(self, band: str, enabled: bool, *, confirm: bool = False,
                             expected_etag: str | None = None) -> dict[str, Any]:
        bands = list(WIFI_BANDS) if band == "all" else [band]

        def plan(cur: dict[str, Any]) -> tuple[list[str], list[str], bool]:
            errs = [] if self.policy.allow_wifi else ["Wi-Fi changes are disabled by policy (features.allow_wifi)"]
            if any(b not in WIFI_BANDS for b in bands):
                errs.append(f"band must be one of {', '.join(WIFI_BANDS)} or 'all'")
                return errs, [], False
            warns = ["the router restarts Wi-Fi: this call takes 1-2 minutes"]
            if not enabled:
                warns.append(f"every device on {', '.join(bands)} will be disconnected")
                if cur["mesh_enabled"]:
                    warns.append("Verizon mesh extenders lose their wireless link on bands that are switched off")
            return errs, warns, all(cur["radios"][b] == enabled for b in bands)

        return await self._change(
            action=f"turn {'on' if enabled else 'off'} Wi-Fi radio {band}", read_state=self.b.wifi_state,
            plan=plan, apply=lambda: self.b.set_wifi_radio(band, enabled),
            verify=lambda after: all(after["radios"][b] == enabled for b in bands),
            confirm=confirm, expected_etag=expected_etag)

    async def set_wifi_network(self, network: str, *, band: str | None = None, enabled: bool | None = None,
                               ssid: str | None = None, password: str | None = None,
                               security: str | None = None, confirm: bool = False,
                               expected_etag: str | None = None) -> dict[str, Any]:
        def nets(state: dict[str, Any]) -> list[dict[str, Any]]:
            if network == "primary":
                return [state["primary"][b] for b in (list(WIFI_BANDS) if band in (None, "all") else [band])]
            return [state[network]]

        def plan(cur: dict[str, Any]) -> tuple[list[str], list[str], bool]:
            errs: list[str] = [] if self.policy.allow_wifi else [
                "Wi-Fi changes are disabled by policy (features.allow_wifi)"]
            if network not in ("primary", "guest", "iot"):
                return [*errs, "network must be primary, guest or iot"], [], False
            if band not in (None, "all") and (network != "primary" or band not in WIFI_BANDS):
                errs.append("band applies to the primary network only: 2.4GHz, 5GHz, 6GHz or all")
            if ssid is not None and not 1 <= len(ssid.encode()) <= 32:
                errs.append("ssid must be 1-32 bytes")
            if password is not None and not (8 <= len(password) <= 63 and password.isascii()
                                              and password.isprintable()):
                errs.append("password must be 8-63 printable ASCII characters")
            if security is not None and security not in ("wpa2", "wpa3", "wpa2wpa3"):
                errs.append("security must be wpa2, wpa3 or wpa2wpa3")
            if all(v is None for v in (enabled, ssid, password, security)):
                errs.append("nothing to change")
            if errs:
                return errs, [], False
            warns = ["the router restarts Wi-Fi: this call takes 1-2 minutes",
                     "devices on this network reconnect; a new SSID or password means re-joining them"]
            if network == "primary" and cur["mesh_enabled"] and band not in (None, "all"):
                warns.append("mesh (SON) is on: the router keeps one SSID and password for 2.4 and 5 GHz, "
                             "so this applies to both")
            done = password is None and all(
                (enabled is None or n["enabled"] == enabled) and (ssid is None or n["ssid"] == ssid)
                and (security is None or n["security"] == security) for n in nets(cur))
            return [], warns, done

        async def verify(after: dict[str, Any]) -> bool:
            ok = all((enabled is None or n["enabled"] == enabled) and (ssid is None or n["ssid"] == ssid)
                     and (security is None or n["security"] == security) for n in nets(after))
            if ok and password is not None:
                ok = await self.b.wifi_secret_matches(network, band, password)
            return ok

        what = ", ".join(k for k, v in (("enabled", enabled), ("ssid", ssid), ("password", password),
                                         ("security", security)) if v is not None)
        return await self._change(
            action=f"change {network} Wi-Fi ({what})", read_state=self.b.wifi_state, plan=plan,
            apply=lambda: self.b.set_wifi_network(network, band=band, enabled=enabled, ssid=ssid,
                                                  password=password, security=security),
            verify=verify, confirm=confirm, expected_etag=expected_etag)

    # -- LAN -----------------------------------------------------------------

    async def set_lan(self, ip: str, mask: str = "255.255.255.0", dhcp_start: str | None = None,
                      dhcp_end: str | None = None, lease_time_min: int | None = None,
                      dhcp_enabled: bool = True, *, confirm: bool = False,
                      expected_etag: str | None = None) -> dict[str, Any]:
        """Move the router's LAN address / DHCP pool. When the address changes the session ends,
        so the result reports where to reconnect instead of a read-back."""
        try:
            await self._ensure_firmware()
            cur = await self.b.get_lan()
            new = ipaddress.IPv4Interface(f"{ip}/{mask}")
        except (RouterError, AuthError, ValueError) as e:
            return self.env(False, errors=[str(e)], action="change LAN")
        net = new.network
        start = dhcp_start or str(net.network_address + 2)
        end = dhcp_end or str(net.broadcast_address - 1)
        lease = lease_time_min or cur.lease_time_min or 1440
        state = {"lan": cur.model_dump(exclude={"reserved_range_note"})}
        tag = etag(state)
        errs: list[str] = []
        if not self.policy.allow_lan_change:
            errs.append("LAN changes are disabled by policy (features.allow_lan_change = false): "
                        "this moves the router and every device on the network")
        if new.ip in (net.network_address, net.broadcast_address):
            errs.append(f"{ip} is not a usable host address in {net}")
        try:
            s4, e4 = ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)
        except ValueError as e:
            return self.env(False, errors=[*errs, str(e)], action="change LAN")
        if dhcp_enabled:
            if s4 not in net or e4 not in net:
                errs.append(f"DHCP pool {start}-{end} must be inside {net}")
            if s4 > e4:
                errs.append("DHCP pool start is after its end")
            if s4 <= new.ip <= e4:
                errs.append(f"the router's own address {ip} must be outside the DHCP pool")
            if int(start.rsplit(".", 1)[1]) > 99 and int(end.rsplit(".", 1)[1]) < 151:
                errs.append("the DHCP pool cannot lie entirely inside .100-.150 (reserved for Verizon devices)")
            if not 1 <= lease <= 43200:
                errs.append("lease time must be 1-43200 minutes")
        moving = ip != cur.ip or mask != cur.mask
        warns: list[str] = []
        if moving:
            warns.append(f"the router moves to https://{ip}/ - this MCP session ends; set FIOS_ROUTER_URL "
                         f"(or url in config.toml) to https://{ip} and restart the MCP server")
            warns.append("every device must renew its DHCP lease (or reconnect) to get an address in the new "
                         "subnet; devices with static IPs must be changed by hand")
            stranded: list[str] = []
            for r in await self.b.list_reservations():
                if ipaddress.IPv4Address(r.ip) not in net:
                    stranded.append(f"reservation {r.mac} -> {r.ip}")
            for f in await self.b.list_port_forwards():
                if f.internal_ip and ipaddress.IPv4Address(f.internal_ip) not in net:
                    stranded.append(f"port forward {f.name} -> {f.internal_ip}")
            for rt in await self.b.list_static_routes():
                if ipaddress.IPv4Address(rt.gateway) not in net:
                    stranded.append(f"static route {rt.destination} via {rt.gateway}")
            dmz = await self.b.get_dmz()
            if dmz.enabled and dmz.ip and ipaddress.IPv4Address(dmz.ip) not in net:
                stranded.append(f"DMZ host {dmz.ip} (the router disables DMZ)")
            if stranded:
                warns.append("these entries point outside the new subnet and will stop working until "
                             "re-created with new addresses: " + "; ".join(stranded))
        action = f"set LAN {ip}/{mask}, DHCP {f'{start}-{end}' if dhcp_enabled else 'off'}"
        if errs:
            return self.env(False, state, errors=errs, warnings=warns, action=action)
        unchanged = (not moving and cur.dhcp_enabled == dhcp_enabled
                     and (not dhcp_enabled or (cur.dhcp_start, cur.dhcp_end, cur.lease_time_min) == (start, end, lease)))
        if unchanged:
            return self.env(True, state, action=action, result="no_change")
        if not confirm:
            return self.env(True, state, warnings=warns, action=action, preview=True, state_etag=tag,
                            next_step="call again with confirm=true and expected_etag=state_etag")
        refused = self._writes_allowed()
        if refused:
            return self.env(False, errors=[refused], action=action)
        if expected_etag != tag:
            return self.env(False, state, action=action, state_etag=tag, errors=[
                "conflict: router state changed since the preview (or no expected_etag given); preview again"])
        try:
            await self.b.set_lan(ip, mask, start, end, lease, dhcp_enabled)
        except KeyError as e:
            return self.env(False, action=action, errors=[f"router page no longer has field {e}; refusing"])
        except Exception:
            if not moving:
                raise
        if moving:
            return self.env(True, action=action, warnings=warns, moved_to=f"https://{ip}", verified=None,
                            result=("change sent; the router is moving. Reconnect at the new address "
                                    "(after this machine has an address in the new subnet) to verify."))
        after = await self.b.get_lan()
        ok = (after.dhcp_enabled == dhcp_enabled
              and (not dhcp_enabled or (after.dhcp_start, after.dhcp_end) == (start, end)))
        return self.env(ok, after, action=action, verified=ok, warnings=warns,
                        errors=[] if ok else ["write sent but read-back does not show the change"])
