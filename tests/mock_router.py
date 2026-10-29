"""An in-process imitation of the CR1000A's web API, for tests without a router.

Behaviour copied from the real router (firmware 3.3.1.2, see spec/DISCOVERY.md):
field ids rotate on every read, writes need the CSRF form token, login answers
302 on success and a decodable 403 otherwise, sessions are capped, reads are
JavaScript (including a single-quoted array inside a string and trailing
commas), port forwards auto-create a service rule, and reservations in
.100-.150 are stored but never leased. All data is synthetic.
"""

from __future__ import annotations

import json
import secrets
from typing import Any, ClassVar
from urllib.parse import parse_qs

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from fios_mcp.backend.stock.auth import encode_password, encode_username

PASSWORD = "test-password"


class MockRouter:
    def __init__(self, *, session_max: int = 10, firmware: str = "3.3.1.2"):
        self.session_max = session_max
        self.firmware = firmware
        self.sessions: set[str] = set()
        self.form_tokens: dict[str, str] = {}
        self.login_token = secrets.token_hex(8)
        self.ids: dict[str, str] = {}  # id -> field name, accumulates across reads
        self.actions: list[tuple[str, str]] = []
        self.logins = 0
        self.rebooted = False
        self.cfg: dict[str, str] = {
            "lan_ip": "192.168.1.1", "lan_mask": "255.255.255.0",
            "wan_proto": "dhcp", "wan_dhcp4_addr": "", "wan_dhcp4_mask": "", "wan_dhcp4_gateway": "",
            "wan_dns_enable": "1", "dns_auto_enable": "1", "wan_static_dns": "", "wan_ip4_dns": "",
            "ip6wan_DnsAuto": "1", "wan_ip6_dnslist": "0", "wan_ip6_auto_dnslist": "",
            "dhcp_enable0": "1", "dhcp_start_ip": "192.168.1.2", "dhcp_end_ip": "192.168.1.254",
            "dhcp_lease_time": "1440", "static_enable0": "1",
            "firewall_dmz_enable": "0", "firewall_dmz_ip": "", "firewall_dmz6_enable": "0",
            "firewall_dmz6_mac": "",
            "upnp_enable": "1", "upnp_autoclean": "1",
            "firewall_ipv4_level": "1", "firewall_ipv6_level": "1", "firewall_allow_stb": "0",
            "remote_enable": "0", "https_enable": "0", "https_port": "443",
            "wan_ip4_ping": "0", "wan_ip4_traceroute": "0",
            "session_max": str(session_max), "session_timeout": "600", "http_maxFailTimes": "10",
            "user_userPass": "admin-secret",
            "wl_ssid24G": "test-net", "wl_ssid5G_H": "test-net", "wl_ssid6G": "test-net",
            "wl_enable24G": "1", "wl_enable5G_H": "1", "wl_enable6G": "0",
            "security_type24G": "wpa2", "security_type5G_H": "wpa2", "security_type6G": "wpa3",
            "sharedkey24G": "wifi-secret", "sharedkey5G_H": "wifi-secret", "sharedkey6G": "wifi-secret",
            "guest_ssid": "test-guest", "guest_enable": "0", "guest_security": "wpa2",
            "guest_password": "guest-secret",
            "iot_ssid": "test-iot", "iot_enable": "0", "iot_security": "wpa2", "iot_password": "iot-secret",
            "Wireless_enable24G": "1", "Wireless_enable5G_H": "1", "Wireless_enable6G": "1", "mesh_enable": "1",
            "lan_mask0": "255.255.255.0", "dhcp_ip": "192.168.1.1", "dhcp_mask": "255.255.255.0",
            "dhcp_opt60_src_0_0": "192.168.1.100", "dhcp_opt60_dst_0_0": "192.168.1.150",
            "dhcp_enable1": "1", "dhcp_enable2": "1", "dhcp_enable3": "1",
        }
        for i in range(128):
            for f in ("static_mac_", "static_ip_", "static_name_"):
                self.cfg[f"{f}{i}"] = ""
        for i in range(20):
            # Unused slots can hold leftovers on a real router; only idxen matters.
            self.cfg.update({f"route_ipv4_idxen{i}": "0", f"route_ipv4_ipaddr{i}": "192.168.1.0",
                             f"route_ipv4_mask{i}": "255.255.255.0", f"route_ipv4_gw{i}": "192.168.1.1",
                             f"route_ipv4_ifname{i}": "lan", f"route_ipv4_metric{i}": "0"})
        for i in range(255):
            self.cfg[f"block_mac_{i}"] = ""
            self.cfg[f"block_enable_{i}"] = "0"
        self.forwards: list[dict[str, Any]] = []
        self.portrules: list[dict[str, Any]] = [
            {"id": 1, "name": "FTP", "description": "File Transfer", "used": 0,
             "ports": [{"id": 1, "type": 1, "source_type": 0, "source_port": "", "dest_type": 1,
                        "dest_port": "21"}]}]
        self.devices = [{"mac": "02:00:00:00:00:01", "hostname": "laptop", "ip": "192.168.1.20", "ipv6": "",
                         "name": "laptop", "activity": 1, "os": "", "device": "", "port": "eth1",
                         "time_first_seen": "", "time_last_active": "", "is_dhcp": 1}]
        self.diag: dict[str, Any] = {"status": "0", "packets": [], "round_trip_time": [], "retry": "0"}

    # -- pages ------------------------------------------------------------

    PAGES: ClassVar[dict[str, tuple[str, ...]]] = {
        "status": ("lan_ip", "lan_mask", "wan_proto", "wan_dhcp4_addr", "wan_dhcp4_mask", "wan_dhcp4_gateway",
                   "wan_dns_enable", "dns_auto_enable", "wan_static_dns", "wan_ip4_dns",
                   "ip6wan_DnsAuto", "wan_ip6_dnslist", "wan_ip6_auto_dnslist"),
        "net_connections": ("wan_dns_enable", "dns_auto_enable", "wan_static_dns", "lan_ip", "lan_mask",
                            "lan_mask0", "dhcp_ip", "dhcp_mask", "dhcp_opt60_src_0_0", "dhcp_opt60_dst_0_0",
                            "dhcp_enable0", "dhcp_enable1", "dhcp_enable2", "dhcp_enable3", "dhcp_start_ip",
                            "dhcp_end_ip", "dhcp_lease_time"),
        "wifi_channel_settings": ("Wireless_enable24G", "Wireless_enable5G_H", "Wireless_enable6G",
                                  "wl_enable24G", "mesh_enable"),
        "wifi_primary": ("Wireless_enable24G", "Wireless_enable5G_H", "Wireless_enable6G", "mesh_enable",
                         "wl_enable24G", "wl_enable5G_H", "wl_enable6G", "wl_ssid24G", "wl_ssid5G_H",
                         "wl_ssid6G", "sharedkey24G", "sharedkey5G_H", "sharedkey6G", "security_type24G",
                         "security_type5G_H", "security_type6G"),
        "wifi_guest": ("Wireless_enable24G", "guest_enable", "guest_ssid", "guest_password", "guest_security"),
        "dmz": ("firewall_dmz_enable", "firewall_dmz_ip", "firewall_dmz6_enable", "firewall_dmz6_mac",
                "lan_ip", "lan_mask"),
        "upnp": ("upnp_enable", "upnp_autoclean"),
        "firewall_general": ("firewall_ipv4_level", "firewall_ipv6_level", "firewall_allow_stb"),
        "ui_remote_admin": ("remote_enable", "https_enable", "https_port", "wan_ip4_ping", "wan_ip4_traceroute"),
        "ui_admin": ("session_max", "session_timeout", "http_maxFailTimes", "user_userPass"),
        "home": ("wl_ssid24G", "wl_ssid5G_H", "wl_ssid6G", "wl_enable24G", "wl_enable5G_H", "wl_enable6G",
                 "security_type24G", "security_type5G_H", "security_type6G", "sharedkey24G", "sharedkey5G_H",
                 "sharedkey6G", "guest_ssid", "guest_enable", "guest_security", "guest_password"),
        "wifi_iot": ("iot_ssid", "iot_enable", "iot_security", "iot_password"),
    }

    def page_fields(self, page: str) -> list[str]:
        if page in self.PAGES:
            return list(self.PAGES[page])
        if page == "ip_distribution":
            return ["dhcp_enable0", "dhcp_start_ip", "dhcp_end_ip", "dhcp_lease_time", "static_enable0"] + [
                f"{f}{i}" for i in range(128) for f in ("static_mac_", "static_ip_", "static_name_")]
        if page == "routing":
            return [f"route_ipv4_{f}{i}" for i in range(20)
                    for f in ("idxen", "ipaddr", "mask", "gw", "ifname", "metric")]
        if page == "known_devices":
            return [f"{f}{i}" for i in range(255) for f in ("block_mac_", "block_enable_")]
        return []

    def page_tables(self, page: str) -> list[str]:
        if page == "firmware":
            return [self._rod("router_version", self.firmware), self._rod("router_date", "Dec 19, 2024"),
                    self._rod("router_commit", "abc123"), self._rod("router_driver", "drv")]
        if page == "basic":
            return [self._rod("hardware_model", "CR1000A"), self._rod("router_name", "Test Router")]
        if page == "status":
            return [self._rod("get_wan4_ip", ""), self._rod("cgi_wan_mac", "02:00:00:00:00:99")]
        if page == "routing":
            flat: list[str] = ["192.168.1.0", "255.255.255.0", "0.0.0.0", "0", "LAN"]
            for i in range(20):
                if self.cfg[f"route_ipv4_idxen{i}"] == "1":
                    flat += [self.cfg[f"route_ipv4_ipaddr{i}"], "255.255.255.0", self.cfg[f"route_ipv4_gw{i}"],
                             self.cfg[f"route_ipv4_metric{i}"], "LAN"]
            inner = "[ " + ",".join(f"'{x}'" for x in flat) + "]"  # array inside a string, as the router does
            return [f'addROD("rTable",  {json.dumps(inner)});', 'addROD("routes6_Table",  "[]");']
        if page == "ip_distribution":
            leases = [[d["hostname"], d["ip"], d["mac"].upper(), "86000"] for d in self.devices]
            for i in range(128):
                mac, ip = self.cfg[f"static_mac_{i}"], self.cfg[f"static_ip_{i}"]
                if mac and ip and not 100 <= int(ip.rsplit(".", 1)[1]) <= 150:
                    leases.append([self.cfg[f"static_name_{i}"], ip, mac, "86000"])
            return [f'addROD("dump_dhcp_leases", {json.dumps(leases)} );',
                    self._rod("known_device_list", {"known_devices": self.devices})]
        if page == "arp":
            return [self._rod("dump_arp_list", [{"ip": d["ip"], "mac": d["mac"], "state": "REACHABLE",
                                                 "router": "0", "intf": "br-lan"} for d in self.devices])]
        if page == "firewall_port_forward":
            return ["// port rule (for ACL, port forwarding, static NAT)",
                    self._rod("portforwardings", {"portforwardings": self.forwards}),
                    self._rod("portrules", {"portrules": self.portrules}),
                    'addROD("reservePort", [4577,4567,]);']
        if page == "diagnostics":
            state, nxt = self.diag, getattr(self, "_diag_next", None)
            if nxt is not None:  # one "running" read, then the result
                self.diag, self._diag_next = nxt, None
            return [self._rod("oDiagnosticState", state)]
        return []

    @staticmethod
    def _rod(name: str, value: Any) -> str:
        return f"addROD({json.dumps(name)}, {json.dumps(value)});"

    def render(self, page: str) -> str:
        lines = []
        for name in self.page_fields(page):
            fid = secrets.token_urlsafe(24)  # a fresh id on every read, like the real router
            self.ids[fid] = name
            lines.append(f"addCfg({json.dumps(name)}, {json.dumps(fid)}, {json.dumps(self.cfg[name])});")
        lines += self.page_tables(page)
        return "\n".join(lines) + "\n"

    # -- request handling --------------------------------------------------

    def _session(self, request: Request) -> str | None:
        sid = request.cookies.get("sysauth")
        return sid if sid in self.sessions else None

    async def login_status(self, request: Request) -> Response:
        sid = self._session(request)
        return JSONResponse({"islogin": "1" if sid else "0", "wizard": "1", "expires": "600",
                             "token": self.form_tokens.get(sid, "") if sid else "",
                             "loginToken": self.login_token})

    async def login(self, request: Request) -> Response:
        form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
        good = (form.get("luci_username") == encode_username("admin")
                and form.get("luci_password") == encode_password(PASSWORD, self.login_token))
        self.login_token = secrets.token_hex(8)
        if not good:
            return JSONResponse({"flag": 1, "timeout": 0}, status_code=403)
        if len(self.sessions) >= self.session_max:
            return JSONResponse({"flag": 2, "timeout": 0, "maxsession": self.session_max}, status_code=403)
        sid = secrets.token_hex(16)
        self.sessions.add(sid)
        self.form_tokens[sid] = secrets.token_hex(16)
        self.logins += 1
        resp = Response(status_code=302, headers={"location": "/"})
        resp.set_cookie("sysauth", sid)
        return resp

    async def logout(self, request: Request) -> Response:
        sid = self._session(request)
        if sid:
            self.sessions.discard(sid)
            self.form_tokens.pop(sid, None)
        return PlainTextResponse("")

    async def cgi(self, request: Request) -> Response:
        if not self._session(request):
            return PlainTextResponse("", status_code=403)
        return PlainTextResponse(self.render(request.path_params["page"]), media_type="application/javascript")

    async def _form(self, request: Request) -> dict[str, str] | None:
        sid = self._session(request)
        form = {k: v[0] for k, v in parse_qs((await request.body()).decode(), keep_blank_values=True).items()}
        if not sid or form.get("token") != self.form_tokens.get(sid):
            return None
        return form

    async def apply(self, request: Request) -> Response:
        form = await self._form(request)
        if form is None:
            return PlainTextResponse("", status_code=403)
        action, params = form.pop("action", ""), form.pop("action_params", "")
        form.pop("token", None)
        changed = set()
        for fid, value in form.items():
            if fid not in self.ids:
                return PlainTextResponse("unknown field", status_code=400)
            self.cfg[self.ids[fid]] = value
            changed.add(self.ids[fid])
        if self.cfg["mesh_enable"] == "1":  # SON keeps one SSID/key for 2.4 and 5 GHz
            for f in ("wl_ssid", "sharedkey"):
                if f + "24G" in changed:
                    self.cfg[f + "5G_H"] = self.cfg[f + "24G"]
                elif f + "5G_H" in changed:
                    self.cfg[f + "24G"] = self.cfg[f + "5G_H"]
        self.cfg["lan_mask"] = self.cfg["lan_mask0"]
        self.actions.append((action, params))
        if action == "ui_block_dev":
            mac, slot = params.split(",")
            self.cfg[f"block_mac_{slot}"], self.cfg[f"block_enable_{slot}"] = mac, "1"
        elif action == "ui_remove_block_dev":
            self.cfg[f"block_mac_{params}"], self.cfg[f"block_enable_{params}"] = "", "0"
        elif action == "reboot":
            self.rebooted = True
        return PlainTextResponse("")

    async def db(self, request: Request) -> Response:
        form = await self._form(request)
        if form is None:
            return PlainTextResponse("", status_code=403)
        data = json.loads(form["data"])
        assert data["type"] == "edit" and data["to"] == "forwardrule"
        for rule in data["body"]:
            kind = rule["type"]
            if kind == "create":
                rid = max((p["id"] for p in self.portrules), default=0) + 1
                self.portrules.append({"id": rid, "name": "", "description": "", "used": 1,
                                       "ports": [dict(p, id=rid) for p in rule["ports"]]})
                fid = max((f["id"] for f in self.forwards), default=0) + 1
                self.forwards.append({"id": fid, "enable": int(rule["enable"]), "name": rule["name"],
                                      "privateIP": rule["privateIP"], "port_rule_id": rid,
                                      "forward_port": rule["forward_port"], "schedule_rule_id": 0,
                                      "snat_enable": -1, "snat_id": -1})
            elif kind == "update":
                row = next(f for f in self.forwards if f["id"] == rule["id"])
                row.update(enable=int(rule["enable"]), name=rule["name"], privateIP=rule["privateIP"],
                           forward_port=rule["forward_port"])
                pr = next(p for p in self.portrules if p["id"] == row["port_rule_id"])
                pr["ports"] = [dict(p, id=pr["id"]) for p in rule["ports"]]
            elif kind == "delete":
                row = next(f for f in self.forwards if f["id"] == rule["id"])
                self.forwards.remove(row)
                self.portrules = [p for p in self.portrules if p["id"] != row["port_rule_id"] or p["name"]]
        return PlainTextResponse("")

    async def diagnostics(self, request: Request) -> Response:
        form = await self._form(request)
        if form is None:
            return PlainTextResponse("", status_code=403)
        n = form.get("ping4_number", "4")
        # The real router first reports a running state (retry 1), then the result.
        self.diag = {"status": "", "packets": ["", "", ""], "round_trip_time": ["", "", ""], "retry": "1"}
        if form.get("ping_dest_ip4", "").endswith(".253"):  # nobody there
            self._diag_next = {"status": "-1", "packets": [n, "0", "100"], "round_trip_time": ["", "", ""],
                               "retry": "2"}
        else:
            self._diag_next = {"status": "1", "packets": [n, n, "0"], "round_trip_time": ["0.4", "0.9", "0.6"],
                               "retry": "2"}
        return PlainTextResponse("")

    def app(self) -> Starlette:
        return Starlette(routes=[
            Route("/loginStatus.cgi", self.login_status),
            Route("/login.cgi", self.login, methods=["POST"]),
            Route("/logout.cgi", self.logout, methods=["POST"]),
            Route("/cgi/cgi_{page}.js", self.cgi),
            Route("/apply_abstract.cgi", self.apply, methods=["POST"]),
            Route("/db.cgi", self.db, methods=["POST"]),
            Route("/diagnostics.cgi", self.diagnostics, methods=["POST"]),
        ])
