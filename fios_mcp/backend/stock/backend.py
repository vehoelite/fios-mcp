"""CR1000A stock-firmware backend.

Every write here follows a recipe verified on a real router (see
`spec/DISCOVERY.md`): read the page fresh (field ids change on every read),
post by id, wait the same time the web UI waits. Read-back verification and
previews live in `fios_mcp.service`; this module only knows the router.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

from ...models import (
    ArpEntry,
    BlockedDevice,
    Device,
    DhcpReservation,
    DmzSettings,
    DnsSettings,
    FirewallSettings,
    FirmwareInfo,
    LanSettings,
    Lease,
    PingResult,
    PortForward,
    RemoteAdmin,
    RouterStatus,
    SessionSettings,
    StaticRoute,
    UpnpSettings,
    normalize_mac,
)
from ...redact import redact
from .jsparse import CgiData
from .transport import RouterError, RouterTransport

PROTO_CODE = {"tcp": 1, "udp": 2, "gre": 4, "esp": 5, "ah": 6, "both": 8}
CODE_PROTO = {v: k for k, v in PROTO_CODE.items()}
ROUTE_SLOTS = 20
ROUTE_FIELDS = ("idxen", "ipaddr", "mask", "gw", "ifname", "metric")
RESERVATION_SLOTS = 127
VERIZON_RESERVED_OCTETS = range(100, 151)
MAX_PORT_FORWARDS = 128

# Pages a client may read raw (redacted). Everything the UI exposes on firmware 3.3.1.2.
PAGES = ["arp", "bandwith", "basic", "bh_log", "diagnostics", "dmz", "dns_server", "dynamic_dns", "firewall_access_control", "firewall_general", "firewall_pinholes", "firewall_port_forward", "firewall_port_trigger", "firewall_static_nat", "firmware", "home", "ip_distribution", "ipv6", "ipv6_distribution", "known_devices", "lan_restore", "log", "ndp", "net_connections", "network_object", "ntp", "owl", "parental", "port_conf", "port_rule", "router_led", "routing", "scheduler", "sipalg", "status", "ui_admin", "ui_remote_admin", "upnp", "wan_mac_clone", "wifi_channel", "wifi_channel_history", "wifi_channel_settings", "wifi_guest", "wifi_iot", "wifi_primary", "wifi_qos", "wifi_wps", "zenreach"]

# How long the web UI waits after each kind of save before reloading.
WAIT = {"apply": 5.0, "dns": 16.0, "db": 3.0, "block": 4.0}


def in_verizon_reserved_range(ip: str) -> bool:
    return int(ip.rsplit(".", 1)[1]) in VERIZON_RESERVED_OCTETS


def _int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _float(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


class StockBackend:
    name = "stock"

    def __init__(self, transport: RouterTransport, *, wait_scale: float = 1.0):
        self.t = transport
        self._wait_scale = wait_scale  # tests run the mock router with 0

    async def _wait(self, kind: str) -> None:
        if self._wait_scale:
            await asyncio.sleep(WAIT[kind] * self._wait_scale)

    async def page(self, name: str) -> CgiData:
        return await self.t.get_cgi(name)

    async def read_page(self, name: str) -> dict[str, Any]:
        if name not in PAGES:
            raise RouterError(f"unknown page {name!r}; known pages: {', '.join(PAGES)}")
        d = await self.page(name)
        return redact({
            "config": {k: f.value for k, f in d.cfg.items()},
            "tables": d.rod,
            "skipped_statements": len(d.skipped),
        })

    # -- status ------------------------------------------------------------

    async def firmware(self) -> FirmwareInfo:
        rod = (await self.page("firmware")).rod
        return FirmwareInfo(
            version=str(rod.get("router_version", "")),
            date=str(rod.get("router_date", "")),
            commit=str(rod.get("router_commit", "")),
            driver=str(rod.get("router_driver", "")),
        )

    async def status(self) -> RouterStatus:
        st = await self.page("status")
        basic = await self.page("basic")
        wan_ip = st.rod.get("get_wan4_ip") or st.value("wan_dhcp4_addr")
        return RouterStatus(
            model=str(basic.rod.get("hardware_model", "")),
            name=str(basic.rod.get("router_name", "")),
            firmware=await self.firmware(),
            wan_proto=st.value("wan_proto"),
            wan_ip=str(wan_ip or ""),
            wan_mask=st.value("wan_dhcp4_mask"),
            wan_gateway=st.value("wan_dhcp4_gateway"),
            wan_mac=str(st.rod.get("cgi_wan_mac", "")),
            wan_dns_active=st.value("wan_ip4_dns").split(),
            lan_ip=st.value("lan_ip"),
            lan_mask=st.value("lan_mask"),
        )

    async def session_settings(self) -> SessionSettings:
        d = await self.page("ui_admin")
        return SessionSettings(
            session_max=_int(d.value("session_max")),
            session_timeout_s=_int(d.value("session_timeout")),
            max_login_failures=_int(d.value("http_maxFailTimes")),
        )

    # -- devices -----------------------------------------------------------

    async def list_devices(self) -> list[Device]:
        d = await self.page("ip_distribution")
        known = (d.rod.get("known_device_list") or {}).get("known_devices") or []
        out = []
        for k in known:
            out.append(Device(
                mac=str(k.get("mac", "")).upper(), ip=str(k.get("ip", "")), ipv6=str(k.get("ipv6", "")),
                hostname=str(k.get("hostname", "")), name=str(k.get("name", "")),
                active=bool(k.get("activity")), connection=str(k.get("port", "")),
                os=str(k.get("os", "")), device_type=str(k.get("device", "")),
                first_seen=str(k.get("time_first_seen", "")), last_active=str(k.get("time_last_active", "")),
                dhcp=bool(k.get("is_dhcp")) if "is_dhcp" in k else None,
            ))
        return out

    async def list_leases(self) -> list[Lease]:
        d = await self.page("ip_distribution")
        out = []
        for row in d.rod.get("dump_dhcp_leases") or []:
            if isinstance(row, list) and len(row) >= 3:
                out.append(Lease(hostname=str(row[0]), ip=str(row[1]), mac=str(row[2]).upper(),
                                 expires_in_s=_int(row[3]) if len(row) > 3 else None))
        return out

    async def list_arp(self) -> list[ArpEntry]:
        d = await self.page("arp")
        return [ArpEntry(ip=str(e.get("ip", "")), mac=str(e.get("mac", "")).upper(),
                         state=str(e.get("state", "")), interface=str(e.get("intf", "")))
                for e in d.rod.get("dump_arp_list") or [] if isinstance(e, dict)]

    async def wifi_summary(self) -> list[dict[str, Any]]:
        h = await self.page("home")
        nets = []
        for band, suffix in (("2.4GHz", "24G"), ("5GHz", "5G_H"), ("6GHz", "6G")):
            nets.append({"network": "primary", "band": band, "ssid": h.value(f"wl_ssid{suffix}"),
                         "enabled": h.value(f"wl_enable{suffix}") == "1",
                         "security": h.value(f"security_type{suffix}")})
        nets.append({"network": "guest", "ssid": h.value("guest_ssid"),
                     "enabled": h.value("guest_enable") == "1", "security": h.value("guest_security")})
        iot = await self.page("wifi_iot")
        nets.append({"network": "iot", "ssid": iot.value("iot_ssid"),
                     "enabled": iot.value("iot_enable") == "1", "security": iot.value("iot_security")})
        return nets

    # -- port forwarding ---------------------------------------------------

    async def _pf_tables(self) -> tuple[list[dict[str, Any]], dict[int, dict[str, Any]]]:
        d = await self.page("firewall_port_forward")
        rows = (d.rod.get("portforwardings") or {}).get("portforwardings") or []
        rules = {r["id"]: r for r in (d.rod.get("portrules") or {}).get("portrules") or []}
        return rows, rules

    @staticmethod
    def _pf_model(row: dict[str, Any], rules: dict[int, dict[str, Any]]) -> PortForward:
        rule = rules.get(row.get("port_rule_id"), {})
        ports = rule.get("ports") or []
        proto = CODE_PROTO.get(ports[0].get("type"), str(ports[0].get("type"))) if ports else "tcp"
        fwd = _int(row.get("forward_port")) or None
        sched = str(row.get("schedule_rule_id", 0))
        return PortForward(
            id=_int(row.get("id")), name=str(row.get("name") or rule.get("name") or ""),
            enabled=str(row.get("enable")) == "1", protocol=proto,
            external_ports=[str(p.get("dest_port", "")).replace(":", "-") for p in ports],
            internal_ip=str(row.get("privateIP", "")), internal_port=fwd,
            schedule="always" if sched == "0" else sched,
        )

    async def list_port_forwards(self) -> list[PortForward]:
        rows, rules = await self._pf_tables()
        return [self._pf_model(r, rules) for r in rows]

    @staticmethod
    def _pf_ports(pf: PortForward) -> list[dict[str, Any]]:
        code = PROTO_CODE[str(pf.protocol)]
        return [{"type": code, "source_type": 0, "source_port": "",
                 "dest_type": 2 if "-" in p else 1, "dest_port": p.replace("-", ":")}
                for p in pf.external_ports]

    async def add_port_forward(self, pf: PortForward) -> None:
        rows, _ = await self._pf_tables()
        if len(rows) >= MAX_PORT_FORWARDS:
            raise RouterError(f"router allows at most {MAX_PORT_FORWARDS} port forwards")
        rule = {"type": "create", "enable": "1" if pf.enabled else "0", "name": pf.name,
                "privateIP": pf.internal_ip, "forward_port": pf.internal_port or 0,
                "schedule_rule_id": "0", "ports": self._pf_ports(pf)}
        await self.t.db({"type": "edit", "to": "forwardrule", "body": [rule]})
        await self._wait("db")

    async def update_port_forward(self, pf: PortForward) -> None:
        rows, _ = await self._pf_tables()
        row = next((r for r in rows if r.get("id") == pf.id), None)
        if row is None:
            raise RouterError(f"no port forward with id {pf.id}")
        rule = {"type": "update", "id": pf.id, "enable": "1" if pf.enabled else "0", "name": pf.name,
                "privateIP": pf.internal_ip, "forward_port": pf.internal_port or 0,
                "schedule_rule_id": str(row.get("schedule_rule_id", "0")),
                "port_rule_id": row.get("port_rule_id"), "ports": self._pf_ports(pf)}
        await self.t.db({"type": "edit", "to": "forwardrule", "body": [rule]})
        await self._wait("db")

    async def delete_port_forward(self, forward_id: int) -> None:
        rows, _ = await self._pf_tables()
        row = next((r for r in rows if r.get("id") == forward_id), None)
        if row is None:
            raise RouterError(f"no port forward with id {forward_id}")
        await self.t.db({"type": "edit", "to": "forwardrule", "body": [{**row, "type": "delete"}]})
        await self._wait("db")

    # -- DHCP reservations -------------------------------------------------

    @staticmethod
    def _reservations(d: CgiData) -> list[DhcpReservation]:
        out = []
        for i in range(RESERVATION_SLOTS):
            mac = d.value(f"static_mac_{i}")
            if mac:
                out.append(DhcpReservation(mac=mac, ip=d.value(f"static_ip_{i}"),
                                           name=d.value(f"static_name_{i}"), slot=i))
        return out

    async def list_reservations(self) -> list[DhcpReservation]:
        return self._reservations(await self.page("ip_distribution"))

    async def put_reservation(self, r: DhcpReservation) -> None:
        d = await self.page("ip_distribution")
        mac = normalize_mac(r.mac)
        slot = next((i for i in range(RESERVATION_SLOTS) if d.value(f"static_mac_{i}").upper() == mac), None)
        if slot is None:
            slot = next((i for i in range(RESERVATION_SLOTS) if not d.value(f"static_mac_{i}")), None)
        if slot is None:
            raise RouterError(f"all {RESERVATION_SLOTS} reservation slots are in use")
        await self.t.apply({
            d.cfg[f"static_mac_{slot}"].id: mac,
            d.cfg[f"static_ip_{slot}"].id: r.ip,
            d.cfg[f"static_name_{slot}"].id: r.name,
            d.cfg["static_enable0"].id: "1",
        })
        await self._wait("apply")

    async def delete_reservation(self, mac: str) -> None:
        d = await self.page("ip_distribution")
        mac = normalize_mac(mac)
        slots = [i for i in range(RESERVATION_SLOTS) if d.value(f"static_mac_{i}").upper() == mac]
        if not slots:
            raise RouterError(f"no reservation for {mac}")
        await self.t.apply({d.cfg[f"{f}{s}"].id: "" for s in slots
                            for f in ("static_mac_", "static_ip_", "static_name_")})
        await self._wait("apply")

    # -- static routes -----------------------------------------------------

    @staticmethod
    def _routes(d: CgiData) -> list[StaticRoute]:
        out = []
        for i in range(ROUTE_SLOTS):
            if d.value(f"route_ipv4_idxen{i}") != "1":
                break  # the UI treats slots as contiguous
            net = f"{d.value(f'route_ipv4_ipaddr{i}')}/{d.value(f'route_ipv4_mask{i}')}"
            out.append(StaticRoute(
                destination=str(ipaddress.ip_network(net, strict=False)),
                gateway=d.value(f"route_ipv4_gw{i}"), metric=_int(d.value(f"route_ipv4_metric{i}")) or 0,
                interface=d.value(f"route_ipv4_ifname{i}"), slot=i,
            ))
        return out

    async def list_static_routes(self) -> list[StaticRoute]:
        return self._routes(await self.page("routing"))

    async def live_routes(self) -> list[dict[str, str]]:
        t = (await self.page("routing")).rod.get("rTable") or []
        return [dict(zip(("network", "mask", "gateway", "metric", "interface"), t[k:k + 5]))
                for k in range(0, len(t) - 4, 5)]

    async def add_static_route(self, r: StaticRoute) -> None:
        d = await self.page("routing")
        used = self._routes(d)
        if len(used) >= ROUTE_SLOTS:
            raise RouterError(f"all {ROUTE_SLOTS} static route slots are in use")
        s = len(used)
        net = ipaddress.ip_network(r.destination)
        values = {"idxen": "1", "ipaddr": str(net.network_address), "mask": str(net.prefixlen),
                  "gw": r.gateway, "ifname": "lan0", "metric": str(r.metric)}
        await self.t.apply(
            {d.cfg[f"route_ipv4_{f}{s}"].id: v for f, v in values.items()},
            action="ui_routing",
            action_params=f"{net.network_address},{net.netmask},{r.gateway},{r.metric}",
        )
        await self._wait("apply")

    async def delete_static_route(self, destination: str) -> None:
        d = await self.page("routing")
        used = self._routes(d)
        target = str(ipaddress.ip_network(destination, strict=True))
        idx = next((r.slot for r in used if r.destination == target), None)
        if idx is None:
            raise RouterError(f"no static route to {target}")
        fields: dict[str, str] = {}
        for s in range(idx, len(used) - 1):  # shift later slots down, as the UI does
            for f in ROUTE_FIELDS:
                fields[d.cfg[f"route_ipv4_{f}{s}"].id] = d.value(f"route_ipv4_{f}{s + 1}")
        last = len(used) - 1
        reset = {"idxen": "0", "ipaddr": "0.0.0.0", "mask": "0", "gw": "0.0.0.0", "ifname": "", "metric": "1"}
        for f, v in reset.items():
            fields[d.cfg[f"route_ipv4_{f}{last}"].id] = v
        await self.t.apply(fields, action="ui_del_route")
        await self._wait("apply")

    # -- DNS / LAN ---------------------------------------------------------

    async def get_dns(self) -> DnsSettings:
        d = await self.page("status")
        if d.value("wan_dns_enable") != "1":
            mode = "none"
        elif d.value("dns_auto_enable") == "1":
            mode = "auto"
        else:
            mode = "manual"
        servers = [s for s in d.value("wan_static_dns").split("|") if s]

        def v6list(name: str) -> list[str]:
            return [s for s in d.value(name).replace("|", " ").split() if s not in ("", "0")]

        return DnsSettings(
            mode=mode, servers=servers, active=d.value("wan_ip4_dns").split(),
            ipv6_mode="auto" if d.value("ip6wan_DnsAuto") != "0" else "manual",
            ipv6_servers=v6list("wan_ip6_dnslist"), ipv6_learned=v6list("wan_ip6_auto_dnslist"),
        )

    async def set_dns(self, mode: str, servers: list[str]) -> None:
        if mode == "manual":
            if not 1 <= len(servers) <= 2:
                raise RouterError("manual DNS takes one or two servers")
            values = {"wan_dns_enable": "1", "dns_auto_enable": "0",
                      "wan_static_dns": "|".join((servers + [""])[:2])}
        elif mode == "auto":
            values = {"wan_dns_enable": "1", "dns_auto_enable": "1", "wan_static_dns": ""}
        else:
            raise RouterError("mode must be 'manual' or 'auto'")
        d = await self.page("net_connections")
        await self.t.apply({d.cfg[k].id: v for k, v in values.items()},
                           action="ui_verizon_broad_settings", action_params="0,0,0,1")
        await self._wait("dns")

    async def get_lan(self) -> LanSettings:
        st = await self.page("status")
        d = await self.page("ip_distribution")
        return LanSettings(
            ip=st.value("lan_ip"), mask=st.value("lan_mask"),
            dhcp_enabled=d.value("dhcp_enable0") == "1",
            dhcp_start=d.value("dhcp_start_ip"), dhcp_end=d.value("dhcp_end_ip"),
            lease_time_min=_int(d.value("dhcp_lease_time")),
        )

    # -- DMZ / UPnP / firewall / remote admin ------------------------------

    async def get_dmz(self) -> DmzSettings:
        d = await self.page("dmz")
        return DmzSettings(enabled=d.value("firewall_dmz_enable") == "1", ip=d.value("firewall_dmz_ip"),
                           ipv6_enabled=d.value("firewall_dmz6_enable") == "1",
                           ipv6_mac=d.value("firewall_dmz6_mac"))

    async def set_dmz(self, enabled: bool, ip: str = "") -> None:
        d = await self.page("dmz")
        await self.t.apply({d.cfg["firewall_dmz_enable"].id: "1" if enabled else "0",
                            d.cfg["firewall_dmz_ip"].id: ip if enabled else ""}, action="ui_firewall")
        await self._wait("apply")

    async def get_upnp(self) -> UpnpSettings:
        d = await self.page("upnp")
        return UpnpSettings(enabled=d.value("upnp_enable") == "1",
                            auto_cleanup=d.value("upnp_autoclean") == "1")

    async def set_upnp(self, enabled: bool) -> None:
        d = await self.page("upnp")
        await self.t.apply({d.cfg["upnp_enable"].id: "1" if enabled else "0"}, action="ui_upnp")
        await self._wait("apply")

    async def get_firewall(self) -> FirewallSettings:
        d = await self.page("firewall_general")
        return FirewallSettings(ipv4_level=d.value("firewall_ipv4_level"),
                                ipv6_level=d.value("firewall_ipv6_level"),
                                allow_set_top_boxes=d.value("firewall_allow_stb"))

    async def get_remote_admin(self) -> RemoteAdmin:
        d = await self.page("ui_remote_admin")
        return RemoteAdmin(enabled=d.value("remote_enable") == "1", https_enabled=d.value("https_enable") == "1",
                           https_port=d.value("https_port"), wan_ping_v4=d.value("wan_ip4_ping") == "1",
                           wan_traceroute_v4=d.value("wan_ip4_traceroute") == "1")

    # -- access control ----------------------------------------------------

    async def list_blocked(self) -> list[BlockedDevice]:
        d = await self.page("known_devices")
        n = sum(1 for k in d.cfg if k.startswith("block_mac_"))
        return [BlockedDevice(mac=d.value(f"block_mac_{i}").upper(), slot=i) for i in range(n)
                if d.value(f"block_mac_{i}") and d.value(f"block_enable_{i}") == "1"]

    async def block_device(self, mac: str) -> None:
        mac = normalize_mac(mac)
        d = await self.page("known_devices")
        n = sum(1 for k in d.cfg if k.startswith("block_mac_"))
        slot = next((i for i in range(n) if not d.value(f"block_mac_{i}") or d.value(f"block_enable_{i}") == "0"),
                    None)
        if slot is None:
            raise RouterError("no free block slot")
        await self.t.apply({}, action="ui_block_dev", action_params=f"{mac},{slot}")
        await self._wait("block")

    async def unblock_device(self, mac: str) -> None:
        mac = normalize_mac(mac)
        blocked = {b.mac: b.slot for b in await self.list_blocked()}
        if mac not in blocked:
            raise RouterError(f"{mac} is not blocked")
        await self.t.apply({}, action="ui_remove_block_dev", action_params=str(blocked[mac]))
        await self._wait("block")

    # -- diagnostics / system ----------------------------------------------

    async def ping(self, target: str, count: int = 4) -> PingResult:
        ipaddress.IPv4Address(target)
        if not 1 <= count <= 20:
            raise RouterError("count must be 1..20")
        await self.t.post_form("diagnostics.cgi", {"cmd": "ping", "ping_dest_ip4": target,
                                                    "ping4_number": str(count)})
        # As the UI does: retry == 1 means still running; status 1 = finished,
        # -1 = no response, -2 = test failed. packets = [sent, received, loss %].
        state: Any = None
        outcome = "timeout"
        for _ in range(2 * count + 15):
            await asyncio.sleep(1.0 * (self._wait_scale or 0.001))
            state = (await self.page("diagnostics")).rod.get("oDiagnosticState")
            if not isinstance(state, dict) or str(state.get("retry")) == "1":
                continue
            status = str(state.get("status"))
            if status in ("1", "-1", "-2"):
                lossy = status == "1" and str((state.get("packets") or ["", "", "0"])[2]) != "0"
                outcome = {"1": "packet_loss" if lossy else "ok", "-1": "no_response", "-2": "failed"}[status]
                break
        pk = list((state or {}).get("packets") or []) + [None] * 3
        rt = list((state or {}).get("round_trip_time") or []) + [None] * 3
        return PingResult(target=target, outcome=outcome, sent=_int(pk[0]), received=_int(pk[1]),
                          loss_percent=_int(pk[2]), rtt_min_ms=_float(rt[0]), rtt_max_ms=_float(rt[1]),
                          rtt_avg_ms=_float(rt[2]), raw=state if isinstance(state, dict) else None)

    async def reboot(self) -> None:
        await self.t.apply({}, action="ui_reboot_reason", action_params="1")
        await self.t.apply({}, action="reboot")
