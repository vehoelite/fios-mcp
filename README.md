# fios-mcp

An [MCP](https://modelcontextprotocol.io) server that lets an AI assistant
manage a **Verizon Fios CR1000A** router — port forwards, DHCP reservations,
static routes, DNS, DMZ, UPnP, device blocking and more — through the router's
own local web interface. No cloud, no Verizon account, nothing leaves your LAN.

> **Not affiliated with or endorsed by Verizon.** This drives the router's web
> UI the same way your browser does. A bad change can cut off your network; try
> it on an isolated bench router first, keep the policy file strict, and read
> every preview before confirming.

## Why it is safe to point an AI at your router

- **Every change is two-phase.** A write tool first returns a *preview* of
  exactly what will change plus a `state_etag`. Only a second call with
  `confirm=true` and that etag applies it. If anything changed in between — say
  you edited the same setting in the web UI — it refuses with `conflict`.
- **Every change is verified.** After writing, the tool reads the router back
  and reports `verified: true|false`.
- **Your policy wins.** `policy.toml` holds a DNS allowlist, entries that may
  never be deleted, and whether DMZ is allowed at all (it isn't, by default).
- **Secrets never leave.** Wi-Fi keys, guest/IoT passwords and the admin
  password the router returns in clear text are redacted from every response.
- **Fail-closed on unknown firmware.** Writes are refused on firmware versions
  this tool has not been verified against.
- **Dangerous operations don't exist.** No tools for factory reset, firmware
  upgrade, the admin password or remote administration. Moving the LAN is
  off unless `policy.toml` allows it.
- **TLS is pinned**, not disabled, and the router's admin sessions are used
  sparingly (one per process, logged out on exit).

## Tools

| Area | Tools |
|---|---|
| Status | `router_status`, `router_firmware`, `router_diagnostics`, `ping`, `read_router_page` (redacted raw view of any page), `get_policy` |
| Devices | `list_connected_devices`, `list_dhcp_leases`, `list_arp_table`, `list_blocked_devices`, `block_device`, `unblock_device` |
| Wi-Fi | `get_wifi_summary`, `set_wifi_radio`, `set_wifi_network` (primary / guest / IoT: on/off, SSID, password, security) |
| Port forwarding | `list_port_forwarding`, `add_port_forwarding`, `delete_port_forwarding`, `set_port_forwarding_enabled` |
| DHCP | `get_lan_settings`, `list_dhcp_reservations`, `add_dhcp_reservation`, `delete_dhcp_reservation` |
| Routing & DNS | `list_static_routes`, `add_static_route`, `delete_static_route`, `get_dns_settings`, `set_dns_settings` |
| Security | `get_firewall_settings`, `get_remote_admin_settings`, `get_dmz_settings`, `set_dmz`, `get_upnp_settings`, `set_upnp` |
| System | `reboot_router`, `set_lan_settings` (router address, mask, DHCP pool) |
| Migration | `snapshot_config`, `list_snapshots`, `diff_config`, `check_desired_state`, `apply_desired_state` |

Where a tool also exists in common TP-Link router MCP servers it has the same
name, so moving settings from one router to the other is a side-by-side job.

## Things the CR1000A does that you should know

- **DHCP reservations in `.100`–`.150` are silently ignored.** That block is
  reserved for Verizon-managed devices: the router stores such a reservation but
  never hands the address out. This tool refuses them up front.
- **At most 10 admin sessions** at a time by default (`session_max`), expiring
  after 10 idle minutes. Clients that never log out lock you out of the web UI
  for a while; this one logs out.
- **Every CR1000A presents the same certificate** (`mynetworksettings.com`,
  issued by "Verizon Fios CA", valid to 2068). Pinning it blocks other
  certificates but does not identify your particular router.
- **LAN clients use the router as their DNS server**, so the WAN DNS setting is
  what every device ultimately resolves through.
- **IPv6 DNS is a separate setting, automatic by default.** With IPv6 on the
  WAN, the router can forward lookups to the ISP's IPv6 resolvers even when
  IPv4 DNS is set manually. The DNS tools warn about this (`ipv6_dns_auto`);
  changing IPv6 DNS is not supported yet, so set it in the web UI or turn IPv6
  off on the WAN if every lookup must go through your chosen resolver.
- **The LAN's `.100`–`.150` is handed to Verizon set-top boxes** (DHCP option
  60) and moves with the subnet; the DHCP pool cannot sit entirely inside it.
- **Wi-Fi saves take about 80 seconds**: the router holds the request open
  until Wi-Fi has restarted. With mesh (SON) on — the default — the 2.4 GHz and
  5 GHz networks share one SSID and password.
- **Moving the LAN ends the session.** `set_lan_settings` previews every
  reservation, forward, route or DMZ entry the new subnet would strand, then
  reports the new address to point `FIOS_ROUTER_URL` at.
- 20 static-route slots, 127 DHCP reservation slots, 128 port forwards.

## Install

Python 3.11+.

```sh
pip install "git+https://github.com/vehoelite/fios-mcp"
```

## Set up

1. Put the router's admin password in a file only you can read:

   ```sh
   mkdir -p -m 700 ~/.config/fios-mcp
   printf '%s' 'your-admin-password' > ~/.config/fios-mcp/password && chmod 600 ~/.config/fios-mcp/password
   ```

2. Pin the router's certificate (shows it and asks first):

   ```sh
   fios-mcp trust            # or: fios-mcp trust --url https://192.168.1.1
   ```

3. Write `~/.config/fios-mcp/policy.toml` (`chmod 600`) — see
   [`examples/policy.example.toml`](examples/policy.example.toml). Without one, DNS changes and
   DMZ are refused.

4. Check that it can log in:

   ```sh
   FIOS_ROUTER_PASSWORD_FILE=~/.config/fios-mcp/password fios-mcp check
   ```

### Claude Code

```sh
claude mcp add fios -e FIOS_ROUTER_PASSWORD_FILE=$HOME/.config/fios-mcp/password -- fios-mcp serve
```

### Other MCP clients

```json
{
  "mcpServers": {
    "fios": {
      "command": "fios-mcp",
      "args": ["serve"],
      "env": { "FIOS_ROUTER_PASSWORD_FILE": "/home/you/.config/fios-mcp/password" }
    }
  }
}
```

| Variable | Default |
|---|---|
| `FIOS_ROUTER_URL` | `https://192.168.1.1` |
| `FIOS_ROUTER_PASSWORD_FILE` / `FIOS_ROUTER_PASSWORD` | — (file preferred; must be `chmod 600`) |
| `FIOS_ROUTER_PIN` | `~/.config/fios-mcp/router.pem` |
| `FIOS_MCP_POLICY` | `~/.config/fios-mcp/policy.toml` |
| `FIOS_MCP_ALLOW_UNVERIFIED_FIRMWARE` | unset (writes refused on unverified firmware) |

The same keys (`url`, `password_file`, `pin_file`, `policy_file`) can go in
`~/.config/fios-mcp/config.toml`.

## Migrating to (or between) routers

Describe what the router should hold in a TOML file
([`examples/desired.toml`](examples/desired.toml)), then ask the assistant to
`check_desired_state` and `apply_desired_state`. It adds or fixes what is
missing — each item through the same validation and read-back as the
individual tools — and never removes anything extra. `snapshot_config` before
and `diff_config` after show exactly what changed.

## Tested firmware

| Firmware | Build date | Verified | Notes |
|---|---|---|---|
| 3.3.1.2 | 2024-12-19 | 2026-10-29 | every tool, on a bench router, with read-back (LAN moved away and back) |

Running another version? Reads work; writes are refused until the contract
test passes on it — please open an issue with the result.

## Development

```sh
pip install -e ".[dev]"
pytest                     # mock router, no hardware needed
ruff check fios_mcp tests
```

- `tests/mock_router.py` imitates the router (rotating field ids, CSRF tokens,
  session cap, JavaScript responses) so the whole tool suite runs in CI.
- `tests/contract/bench_e2e.py` runs every tool over stdio MCP against a real
  router — on an isolated bench only:
  `FIOS_ROUTER_PASSWORD_FILE=… FIOS_MCP_CONTRACT_WRITES=1 python tests/contract/bench_e2e.py`
- `tests/test_no_leaks.py` fails on real-looking MACs and public IPs. Put your
  own MACs, WAN IP, SSIDs and domain in a gitignored `.scrub-denylist` (one per
  line) and it checks those too.
- How the router's API works is documented in
  [`spec/DISCOVERY.md`](spec/DISCOVERY.md); the architecture in
  [`docs/DESIGN.md`](docs/DESIGN.md).

## Credits

**Written by Claude Opus 5.5** (Anthropic's AI model), with hardware setup,
bench testing and direction by [vehoelite](https://github.com/vehoelite).
Everything in this repository — the protocol notes in `spec/`, the client, the
safety layer and the tests — came out of that collaboration, with every write
path checked on a real CR1000A before it shipped.

**Thank you to [Brishen](https://github.com/Brishen)**, whose
[`verizon_router_client`](https://github.com/Brishen/verizon_router_client)
(MIT) was the first public Python client for the CR1000A. It showed that this
router's web API could be scripted at all, and that was the starting point for
this project. Thanks also to
[`skircr115/ha-verizonFiOS`](https://github.com/skircr115/ha-verizonFiOS) for
its Home Assistant work on the same router. No code from either project is
included here: the client was written from the router's own web UI code and
verified on hardware.

## License

MIT — see [LICENSE](LICENSE).
