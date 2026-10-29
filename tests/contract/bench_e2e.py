"""Exercise every tool over stdio MCP against a REAL CR1000A. Writes to the router.

Use an isolated bench router (WAN unplugged, not your live network). It only
creates entries named/addressed `mcptest-*` / 02:00:00:00:00:4x, removes them,
and restores DNS and UPnP to how it found them. Does not reboot.

    FIOS_ROUTER_PASSWORD_FILE=~/router.pw FIOS_MCP_CONTRACT_WRITES=1 \
        python tests/contract/bench_e2e.py

Optional: FIOS_ROUTER_URL (default https://192.168.1.1),
FIOS_MCP_BENCH_DNS (default "1.1.1.1,1.0.0.1"). The router's certificate must
already be pinned (`fios-mcp trust`). Run this before adding a firmware
version to VERIFIED_FIRMWARE.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

FAKE1, FAKE2 = "02:00:00:00:00:41", "02:00:00:00:00:42"
results: list[tuple[str, bool]] = []


def check(label: str, cond: object, detail: object = "") -> None:
    results.append((label, bool(cond)))
    print(("PASS " if cond else "FAIL ") + label + ("" if cond else f"  [{detail}]"))


async def call(s: ClientSession, tool: str, **args):
    r = await s.call_tool(tool, args)
    data = getattr(r, "structuredContent", None) or (json.loads(r.content[0].text) if r.content else {})
    return data.get("result", data) if isinstance(data, dict) and set(data) == {"result"} else data


async def two_phase(s: ClientSession, tool: str, **args):
    pre = await call(s, tool, **args)
    if not pre.get("ok") or not pre.get("preview"):
        return pre
    return await call(s, tool, confirm=True, expected_etag=pre["state_etag"], **args)


async def main(tmp: Path) -> int:
    dns = os.environ.get("FIOS_MCP_BENCH_DNS", "1.1.1.1,1.0.0.1").split(",")
    policy = tmp / "policy.toml"
    policy.write_text(f"[dns]\nallowed_servers = {json.dumps(dns)}\n[features]\nallow_dmz = false\n")
    policy.chmod(0o600)
    env = {**os.environ, "FIOS_MCP_POLICY": str(policy), "XDG_STATE_HOME": str(tmp / "state")}
    exe = shutil.which("fios-mcp") or sys.exit("fios-mcp not on PATH (pip install -e .)")
    async with stdio_client(StdioServerParameters(command=exe, args=["serve"], env=env)) as (r, w), \
            ClientSession(r, w) as s:
        await s.initialize()
        fw = await call(s, "router_firmware")
        check("firmware readable", fw.get("ok"), fw)
        print("firmware:", fw.get("data", {}).get("version"), "warnings:", fw.get("warnings"))
        lan = (await call(s, "get_lan_settings"))["data"]
        net = ipaddress.IPv4Interface(f"{lan['ip']}/{lan['mask']}").network
        host = lambda n: str(net.network_address + n)
        gw, target, res_ip = host(11), host(160), host(61)

        check("status", (await call(s, "router_status"))["ok"])
        wifi = await call(s, "get_wifi_summary")
        check("wifi summary has no key fields", wifi["ok"] and "sharedkey" not in json.dumps(wifi))
        home = (await call(s, "read_router_page", page="home"))["data"]["config"]
        check("raw page redacts the Wi-Fi key", home.get("sharedkey24G") in ("***REDACTED***", ""), home.get("sharedkey24G"))
        pre = await call(s, "add_static_route", destination="10.99.0.0/24", gateway=gw)
        stale = await call(s, "add_static_route", destination="10.99.0.0/24", gateway=gw, confirm=True,
                           expected_etag="stale")
        check("stale etag refused", not stale["ok"] and "conflict" in stale["errors"][0])
        ok = await call(s, "add_static_route", destination="10.99.0.0/24", gateway=gw, confirm=True,
                        expected_etag=pre.get("state_etag"))
        check("route add verified", ok.get("verified"), ok)
        check("route delete verified", (await two_phase(s, "delete_static_route",
                                                        destination="10.99.0.0/24")).get("verified"))
        out = await two_phase(s, "add_port_forwarding", name="mcptest-443", external_ports=["443"],
                              internal_ip=target)
        check("forward add verified", out.get("verified"), out)
        out = await two_phase(s, "set_port_forwarding_enabled", name="mcptest-443", enabled=False)
        check("forward update verified", out.get("verified"), out)
        check("forward delete verified", (await two_phase(s, "delete_port_forwarding",
                                                          name="mcptest-443")).get("verified"))
        refused = await call(s, "add_dhcp_reservation", mac=FAKE1, ip=host(122), name="mcptest-r")
        check(".100-.150 refused", not refused["ok"])
        out = await two_phase(s, "add_dhcp_reservation", mac=FAKE1, ip=res_ip, name="mcptest-r")
        check("reservation add verified", out.get("verified"), out)
        check("reservation delete verified", (await two_phase(s, "delete_dhcp_reservation",
                                                              mac=FAKE1)).get("verified"))
        orig = (await call(s, "get_dns_settings"))["data"]
        out = await two_phase(s, "set_dns_settings", mode="manual", servers=dns)
        check("dns manual verified", out.get("verified"), out)
        restore = {"mode": orig["mode"], "servers": orig["servers"]} if orig["mode"] == "manual" else {"mode": "auto"}
        if orig["mode"] == "manual" and not set(orig["servers"]) <= set(dns):
            print("NOTE: original manual DNS not in the bench allowlist; set it back by hand:", orig["servers"])
        else:
            check("dns restored", (await two_phase(s, "set_dns_settings", **restore)).get("ok"))
        up = (await call(s, "get_upnp_settings"))["data"]["enabled"]
        check("upnp toggled", (await two_phase(s, "set_upnp", enabled=not up)).get("verified"))
        check("upnp restored", (await two_phase(s, "set_upnp", enabled=up)).get("verified"))
        check("block verified", (await two_phase(s, "block_device", mac=FAKE2)).get("verified"))
        check("unblock verified", (await two_phase(s, "unblock_device", mac=FAKE2)).get("verified"))
        check("dmz refused by policy", not (await call(s, "set_dmz", enabled=True, ip=host(200)))["ok"])
        p = await call(s, "ping", target=lan["ip"], count=2)
        check("ping", p.get("ok"), p)
        snap = await call(s, "snapshot_config")
        check("snapshot + empty diff", (await call(s, "diff_config", snapshot_a=snap["snapshot_id"]))["data"] == {})
        check("reboot only previews", (await call(s, "reboot_router")).get("preview"))
        diag = await call(s, "router_diagnostics")
        print("router logins used:", diag["server"]["logins_this_process"])
    passed = sum(ok for _, ok in results)
    print(f"\n{passed}/{len(results)} passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    if os.environ.get("FIOS_MCP_CONTRACT_WRITES") != "1":
        sys.exit("refusing: this writes to the router. Set FIOS_MCP_CONTRACT_WRITES=1 on a bench router.")
    with tempfile.TemporaryDirectory() as d:
        sys.exit(asyncio.run(main(Path(d))))
