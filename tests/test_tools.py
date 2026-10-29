"""End-to-end tool tests against the in-process mock router (no hardware needed)."""

from __future__ import annotations

import json

import httpx
import pytest

from fios_mcp import server
from fios_mcp.backend.stock.backend import StockBackend
from fios_mcp.backend.stock.transport import AuthError, RouterTransport
from fios_mcp.policy import Policy
from fios_mcp.redact import REDACTED
from fios_mcp.service import Service

from .mock_router import PASSWORD, MockRouter

GATEWAY_DNS = ["172.64.36.1", "172.64.36.2"]


def make_transport(router: MockRouter) -> RouterTransport:
    return RouterTransport("https://router.test", PASSWORD, login_min_interval=0,
                           http_transport=httpx.ASGITransport(app=router.app()))


@pytest.fixture
async def router(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    r = MockRouter()
    t = make_transport(r)
    policy = Policy(allowed_dns=GATEWAY_DNS, protected_reservations={"02:00:00:00:00:AA"},
                    protected_forwards={"vpn-sstp"})
    server.rt.transport = t
    server.rt.service = Service(StockBackend(t, wait_scale=0), policy)
    yield r
    await t.aclose()
    server.rt.service = server.rt.transport = None


async def two_phase(tool, **kw):
    pre = await tool(**kw)
    assert pre["ok"] and pre.get("preview"), pre
    return await tool(confirm=True, expected_etag=pre["state_etag"], **kw)


# -- reads -------------------------------------------------------------------

async def test_status_and_firmware(router):
    st = await server.router_status()
    assert st["ok"] and st["data"]["model"] == "CR1000A"
    assert st["data"]["firmware"]["version"] == "3.3.1.2"
    assert st["warnings"] == []


async def test_secrets_never_leave(router):
    wifi = await server.get_wifi_summary()
    raw_home = await server.read_router_page("home")
    raw_admin = await server.read_router_page("ui_admin")
    blob = json.dumps([wifi, raw_home, raw_admin])
    for secret in ("wifi-secret", "guest-secret", "iot-secret", "admin-secret"):
        assert secret not in blob
    assert raw_home["data"]["config"]["sharedkey24G"] == REDACTED
    assert raw_admin["data"]["config"]["user_userPass"] == REDACTED


async def test_unknown_page_is_refused(router):
    out = await server.read_router_page("../../etc/passwd")
    assert not out["ok"]


async def test_devices_leases_arp(router):
    assert (await server.list_connected_devices(active_only=True))["data"][0]["hostname"] == "laptop"
    assert (await server.list_dhcp_leases())["data"][0]["ip"] == "192.168.1.20"
    assert (await server.list_arp_table())["data"][0]["state"] == "REACHABLE"


# -- static routes -------------------------------------------------------------

async def test_route_two_phase_conflict_idempotent(router):
    pre = await server.add_static_route("10.99.0.0/24", "192.168.1.11")
    assert pre["preview"] and router.actions == []
    stale = await server.add_static_route("10.99.0.0/24", "192.168.1.11", confirm=True, expected_etag="nope")
    assert not stale["ok"] and "conflict" in stale["errors"][0]
    ok = await server.add_static_route("10.99.0.0/24", "192.168.1.11", confirm=True,
                                       expected_etag=pre["state_etag"])
    assert ok["ok"] and ok["verified"]
    assert router.actions[-1] == ("ui_routing", "10.99.0.0,255.255.255.0,192.168.1.11,1")
    assert router.cfg["route_ipv4_mask0"] == "24"
    assert (await server.add_static_route("10.99.0.0/24", "192.168.1.11"))["result"] == "no_change"


async def test_route_delete_keeps_slots_contiguous(router):
    for net in ("10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24"):
        assert (await two_phase(server.add_static_route, destination=net, gateway="192.168.1.11"))["ok"]
    out = await two_phase(server.delete_static_route, destination="10.2.0.0/24")
    assert out["ok"] and out["verified"]
    routes = (await server.list_static_routes())["data"]
    assert [r["destination"] for r in routes] == ["10.1.0.0/24", "10.3.0.0/24"]
    assert router.cfg["route_ipv4_idxen2"] == "0"


async def test_route_validation(router):
    out = await server.add_static_route("10.99.0.0/24", "10.0.0.1")
    assert not out["ok"] and "outside the LAN" in out["errors"][0]
    out = await server.add_static_route("192.168.1.0/25", "192.168.1.11")
    assert not out["ok"] and "overlaps the LAN" in out["errors"][0]


# -- port forwarding -------------------------------------------------------------

async def test_port_forward_lifecycle(router):
    out = await two_phase(server.add_port_forwarding, name="vpn-sstp", external_ports=["443"],
                          internal_ip="192.168.1.160")
    assert out["ok"] and out["verified"]
    assert any(p["name"] == "" and p["ports"][0]["dest_port"] == "443" for p in router.portrules)
    out = await two_phase(server.add_port_forwarding, name="ike", external_ports=["500", "4500"],
                          internal_ip="192.168.1.160", protocol="udp")
    assert out["ok"]
    rows = (await server.list_port_forwarding())["data"]
    assert {(r["name"], tuple(r["external_ports"]), r["protocol"]) for r in rows} == {
        ("vpn-sstp", ("443",), "tcp"), ("ike", ("500", "4500"), "udp")}

    dup = await server.add_port_forwarding(name="other", external_ports=["443"], internal_ip="192.168.1.5")
    assert not dup["ok"] and "conflicts" in dup["errors"][0]

    out = await two_phase(server.set_port_forwarding_enabled, name="ike", enabled=False)
    assert out["ok"] and out["verified"]

    prot = await server.delete_port_forwarding(name="vpn-sstp")
    assert not prot["ok"] and "protected" in prot["errors"][0]
    out = await two_phase(server.delete_port_forwarding, name="ike")
    assert out["ok"] and out["verified"]
    assert any(p["name"] == "FTP" for p in router.portrules)  # predefined rules untouched


# -- DHCP reservations ---------------------------------------------------------------

async def test_reservation_rules(router):
    reserved = await server.add_dhcp_reservation("02:00:00:00:00:10", "192.168.1.122", "cam")
    assert not reserved["ok"] and ".100-.150" in reserved["errors"][0]
    out = await two_phase(server.add_dhcp_reservation, mac="02-00-00-00-00-10", ip="192.168.1.60", name="cam")
    assert out["ok"] and out["verified"]
    assert router.cfg["static_mac_0"] == "02:00:00:00:00:10"
    dup_ip = await server.add_dhcp_reservation("02:00:00:00:00:11", "192.168.1.60", "x")
    assert not dup_ip["ok"]
    change = await server.add_dhcp_reservation("02:00:00:00:00:10", "192.168.1.61", "cam")
    assert not change["ok"] and "replace=true" in change["errors"][0]
    out = await two_phase(server.add_dhcp_reservation, mac="02:00:00:00:00:10", ip="192.168.1.61",
                          name="cam", replace=True)
    assert out["ok"] and router.cfg["static_ip_0"] == "192.168.1.61"
    out = await two_phase(server.delete_dhcp_reservation, mac="02:00:00:00:00:10")
    assert out["ok"] and router.cfg["static_mac_0"] == ""


async def test_protected_reservation(router):
    await two_phase(server.add_dhcp_reservation, mac="02:00:00:00:00:AA", ip="192.168.1.10", name="server1")
    out = await server.delete_dhcp_reservation("02:00:00:00:00:AA")
    assert not out["ok"] and "protected" in out["errors"][0]


# -- DNS / DMZ / UPnP / blocking -------------------------------------------------------

async def test_dns_allowlist(router):
    out = await server.set_dns_settings("manual", ["8.8.8.8"])
    assert not out["ok"] and "allowlist" in out["errors"][0]
    out = await two_phase(server.set_dns_settings, mode="manual", servers=GATEWAY_DNS)
    assert out["ok"] and out["verified"]
    assert router.cfg["wan_static_dns"] == "172.64.36.1|172.64.36.2"
    assert router.actions[-1] == ("ui_verizon_broad_settings", "0,0,0,1")


async def test_ipv6_dns_warning(router):
    out = await server.get_dns_settings()
    assert out["ok"] and any(w.startswith("ipv6_dns_auto") for w in out["warnings"])
    router.cfg.update(ip6wan_DnsAuto="0", wan_ip6_dnslist="2606:4700:4700::1111")
    out = await server.get_dns_settings()
    assert any(w.startswith("ipv6_dns_not_allowlisted") for w in out["warnings"])
    server.rt.service.policy.allowed_dns.append("2606:4700:4700::1111")
    out = await server.get_dns_settings()
    assert out["warnings"] == [] and out["data"]["ipv6_servers"] == ["2606:4700:4700::1111"]


async def test_dns_refused_without_policy(router):
    server.rt.service.policy = Policy()
    out = await server.set_dns_settings("manual", GATEWAY_DNS)
    assert not out["ok"] and "no allowed_servers" in out["errors"][0]


async def test_dmz_requires_policy(router):
    out = await server.set_dmz(True, "192.168.1.200")
    assert not out["ok"] and "policy" in out["errors"][0]
    server.rt.service.policy.allow_dmz = True
    out = await two_phase(server.set_dmz, enabled=True, ip="192.168.1.200")
    assert out["ok"] and router.cfg["firewall_dmz_ip"] == "192.168.1.200"


async def test_upnp_and_blocking(router):
    assert (await two_phase(server.set_upnp, enabled=False))["verified"]
    assert router.cfg["upnp_enable"] == "0"
    assert (await two_phase(server.block_device, mac="02:00:00:00:00:33"))["verified"]
    assert (await server.list_blocked_devices())["data"][0]["mac"] == "02:00:00:00:00:33"
    assert (await two_phase(server.unblock_device, mac="02:00:00:00:00:33"))["verified"]


async def test_ping_and_reboot(router):
    p = await server.ping("192.168.1.20", 3)
    assert p["ok"] and p["data"]["outcome"] == "ok" and p["data"]["sent"] == 3
    assert p["data"]["loss_percent"] == 0
    dead = await server.ping("192.168.1.253", 2)
    assert dead["data"]["outcome"] == "no_response" and dead["data"]["received"] == 0
    pre = await server.reboot_router()
    assert pre["preview"] and not router.rebooted
    assert (await server.reboot_router(confirm=True))["ok"] and router.rebooted


# -- safety rails -----------------------------------------------------------------------

async def test_unverified_firmware_refuses_writes(router, monkeypatch):
    router.firmware = "9.9.9"
    server.rt.service._firmware = None
    pre = await server.add_static_route("10.99.0.0/24", "192.168.1.11")
    assert pre["ok"] and any("unverified_firmware" in w for w in pre["warnings"])
    out = await server.add_static_route("10.99.0.0/24", "192.168.1.11", confirm=True,
                                        expected_etag=pre["state_etag"])
    assert not out["ok"] and "not been verified" in out["errors"][0]
    monkeypatch.setenv("FIOS_MCP_ALLOW_UNVERIFIED_FIRMWARE", "1")
    out = await server.add_static_route("10.99.0.0/24", "192.168.1.11", confirm=True,
                                        expected_etag=pre["state_etag"])
    assert out["ok"]


async def test_session_cap_and_logout():
    r = MockRouter(session_max=1)
    a, b = make_transport(r), make_transport(r)
    await a.get_cgi("status")
    with pytest.raises(AuthError, match="too many open sessions"):
        await b.get_cgi("status")
    await a.aclose()  # logs out, freeing the session
    await b.get_cgi("status")
    await b.aclose()
    assert r.sessions == set()


async def test_one_login_for_many_calls(router):
    for _ in range(5):
        await server.router_status()
        await server.list_port_forwarding()
    assert router.logins == 1


# -- snapshots / desired state ------------------------------------------------------------

async def test_snapshot_diff_and_desired_state(router, tmp_path):
    snap = await server.snapshot_config()
    assert snap["ok"] and (await server.list_snapshots())["data"] == [snap["snapshot_id"]]
    desired = tmp_path / "desired.toml"
    desired.write_text(
        '[dns]\nmode = "manual"\nservers = ["172.64.36.1", "172.64.36.2"]\n'
        '[[reservations]]\nmac = "02:00:00:00:00:10"\nip = "192.168.1.10"\nname = "server1"\n'
        '[[port_forwards]]\nname = "vpn-sstp"\nexternal_ports = ["443"]\ninternal_ip = "192.168.1.160"\n'
        '[[static_routes]]\ndestination = "10.99.0.0/24"\ngateway = "192.168.1.11"\n'
        '[upnp]\nenabled = false\n')
    check = await server.check_desired_state(str(desired))
    assert len(check["data"]) == 5 and not check["in_sync"]
    plan = await server.apply_desired_state(str(desired))
    assert plan["preview"] and router.actions == []
    applied = await server.apply_desired_state(str(desired), confirm=True)
    assert applied["ok"], applied
    assert (await server.check_desired_state(str(desired)))["in_sync"]
    diff = (await server.diff_config(snap["snapshot_id"]))["data"]
    assert set(diff) == {"dns", "reservations", "port_forwards", "static_routes", "upnp"}


async def test_tool_catalogue():
    tools = await server.mcp.list_tools()
    names = {t.name for t in tools}
    assert len(tools) == 41
    tplink_names = {"router_status", "router_firmware", "router_diagnostics", "list_connected_devices",
                    "list_port_forwarding", "add_port_forwarding", "delete_port_forwarding",
                    "list_dhcp_reservations", "add_dhcp_reservation", "delete_dhcp_reservation", "reboot_router"}
    assert tplink_names <= names
    for t in tools:
        if t.name.startswith(("list_", "get_", "router_")):
            assert t.annotations and t.annotations.read_only_hint, t.name


# -- Wi-Fi -------------------------------------------------------------------------------

async def test_wifi_summary_has_radios_and_no_keys(router):
    out = await server.get_wifi_summary()
    assert out["ok"] and out["data"]["radios"] == {"2.4GHz": True, "5GHz": True, "6GHz": True}
    assert "wifi-secret" not in json.dumps(out)


async def test_wifi_radio_off_and_on(router):
    pre = await server.set_wifi_radio("all", False)
    assert pre["preview"] and any("mesh" in w for w in pre["warnings"])
    out = await two_phase(server.set_wifi_radio, band="all", enabled=False)
    assert out["ok"] and out["verified"] and router.cfg["Wireless_enable6G"] == "0"
    assert router.actions[-1] == ("ui_wireless_single", "")
    assert (await server.set_wifi_radio("all", False))["result"] == "no_change"
    assert (await two_phase(server.set_wifi_radio, band="6GHz", enabled=True))["verified"]
    assert router.cfg["Wireless_enable6G"] == "1" and router.cfg["Wireless_enable24G"] == "0"


async def test_wifi_network_change_verifies_key_without_returning_it(router):
    out = await two_phase(server.set_wifi_network, network="primary", band="2.4GHz", ssid="new-net",
                          password="a-new-wifi-key")
    assert out["ok"] and out["verified"], out
    assert any("mesh (SON)" in w for w in out["warnings"])
    assert router.cfg["wl_ssid5G_H"] == "new-net"  # mirrored by mesh, like the real router
    assert "a-new-wifi-key" not in json.dumps(out)
    bad = await server.set_wifi_network("primary", password="short")
    assert not bad["ok"] and "8-63" in bad["errors"][0]
    guest = await two_phase(server.set_wifi_network, network="guest", enabled=True)
    assert guest["verified"] and router.actions[-1] == ("ui_wireless_singleradio", "1")


async def test_wifi_policy(router):
    server.rt.service.policy.allow_wifi = False
    out = await server.set_wifi_radio("2.4GHz", False)
    assert not out["ok"] and "allow_wifi" in out["errors"][0]


# -- LAN ------------------------------------------------------------------------------

async def test_lan_change_refused_by_default(router):
    out = await server.set_lan_settings("192.168.0.1")
    assert not out["ok"] and "allow_lan_change" in out["errors"][0]


async def test_lan_move_preview_lists_stranded_entries(router):
    server.rt.service.policy.allow_lan_change = True
    await two_phase(server.add_dhcp_reservation, mac="02:00:00:00:00:10", ip="192.168.1.60", name="nas")
    await two_phase(server.add_static_route, destination="10.99.0.0/24", gateway="192.168.1.11")
    pre = await server.set_lan_settings("192.168.0.1")
    assert pre["preview"]
    text = " ".join(pre["warnings"])
    assert "https://192.168.0.1/" in text and "02:00:00:00:00:10" in text and "10.99.0.0/24" in text
    out = await server.set_lan_settings("192.168.0.1", confirm=True, expected_etag=pre["state_etag"])
    assert out["ok"] and out["moved_to"] == "https://192.168.0.1"
    assert router.cfg["lan_ip"] == "192.168.0.1" and router.cfg["dhcp_start_ip"] == "192.168.0.2"
    assert (router.cfg["dhcp_opt60_src_0_0"], router.cfg["dhcp_opt60_dst_0_0"]) == ("192.168.0.100",
                                                                                   "192.168.0.150")
    assert router.actions[-1] == ("ui_verizon_network_settings", "010")


async def test_lan_validation(router):
    server.rt.service.policy.allow_lan_change = True
    out = await server.set_lan_settings("192.168.1.50", dhcp_start="192.168.1.2", dhcp_end="192.168.1.254")
    assert not out["ok"] and "outside the DHCP pool" in " ".join(out["errors"])
    out = await server.set_lan_settings("192.168.1.1", dhcp_start="192.168.1.100", dhcp_end="192.168.1.150")
    assert not out["ok"] and ".100-.150" in " ".join(out["errors"])
    out = await two_phase(server.set_lan_settings, ip="192.168.1.1", dhcp_start="192.168.1.2",
                          dhcp_end="192.168.1.99")
    assert out["ok"] and out["verified"] and router.cfg["dhcp_end_ip"] == "192.168.1.99"
