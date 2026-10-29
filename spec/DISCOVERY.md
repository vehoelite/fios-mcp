# CR1000A web API — discovery notes

Everything here was read from the router's own web UI JavaScript and confirmed
against a bench CR1000A (WAN unplugged) on 2026-10-29. Values below are
placeholders; no real configuration is recorded in this repository.

## Web UI

- Single-page Vue app served from `/`: `js/chunk-vendors.<hash>.js`,
  `js/app.<hash>.js`, plus 85 lazily-loaded page chunks `js/<id>.<hash>.js`.
- The webpack namespace is `luci_mod_admin` — the UI is built on OpenWrt's
  LuCI, which suggests an OpenWrt-derived firmware underneath.

## TLS

- Subject `CN=mynetworksettings.com, OU=CR1000A, O=Verizon`, issuer
  `CN=Verizon Fios CA`, valid 2018-12-31 → 2068-12-18, SAN `mynetworksettings.com`.
- A 50-year certificate with a generic name is almost certainly **identical on
  every CR1000A**. Pinning it still beats disabling verification, but it does
  not identify an individual router. Say so in the README.

## Authentication

1. `GET /loginStatus.cgi` → JSON
   `{islogin: "0"|"1", wizard, token, loginToken, expires}`.
   - `loginToken`: one-time salt for the next login.
   - `token`: the **form token** (CSRF) required on every write; `expires` in
     seconds (600 observed).
2. `POST /login.cgi`, `application/x-www-form-urlencoded`:

   | field | value |
   |---|---|
   | `luci_username` | `ArcMD5(username)` |
   | `luci_password` | `SHA512hex(loginToken + ArcMD5(password))` (or `ArcMD5(password)` if `loginToken` is empty) |
   | `luci_token` | `loginToken` |
   | `luci_view` | `Desktop` or `Mobile` |
   | `luci_keep_login` | `0` / `1` |

   where `ArcMD5(x) = SHA512hex(MD5hex_lower(x))`.
   Success → 200 and a `sysauth` session cookie. Failure → 403 with a JSON body
   the UI feeds to `updateLoginInfo` (lockout state: UI disallows login when
   `flag` is -1, 2 or 7 — shapes still to be captured).
3. `POST /logout.cgi` with `token=<form token>`.

Verified: a client implementing exactly this logged in on the first attempt.

## Reading configuration

- `GET /cgi/cgi_<name>.js` returns **JavaScript**, which the UI `eval()`s. The
  body is a sequence of calls — parse them, never execute them:
  - `addCfg(name, id, value, extra?)` — one config field. `id` is an opaque
    base64-looking string; it is the key used when writing that field.
  - `addROD(name, value)` — a read-only data table (array/object literal).
- Indexed families are flattened: `static_mac_0..N`, `route_ipv4_ipaddr0..19`.

## Writing configuration

- `POST /apply_abstract.cgi` (form-encoded): `token=<form token>`, optional
  `action`, `action_params`, and **one `<id>=<value>` pair per changed field**
  (the UI sends only fields whose value differs from what it read).
- `POST /db.cgi` (form-encoded): `data=<…>`, `token=<form token>` — used for
  table-style data (port forwards are tables only; see below). Format TBD.
- Lists inside a single field are joined with a separator `CFG_SP` (value TBD).

**Field ids change on every read, even within one session** (verified). Treat
them as one-time write keys: every write = fresh `GET cgi_<page>.js` → post by
the ids from that read.

`login.cgi` answers **302 → `/`** on success (a browser follows it); confirm
with `loginStatus.cgi` (`islogin == "1"`).

### Verified write: IPv4 static route (2026-10-29)

- Add to slot `s` (the first slot whose `route_ipv4_idxen` ≠ `1`):
  `route_ipv4_idxen{s}=1`, `route_ipv4_ipaddr{s}=<network>`,
  `route_ipv4_mask{s}=<prefix length>` (the UI converts dotted masks with
  `netmaskToCIDR`), `route_ipv4_gw{s}=<gateway>`, `route_ipv4_ifname{s}=lan0`,
  `route_ipv4_metric{s}=<metric>`; `action=ui_routing`,
  `action_params=<network>,<dotted mask>,<gateway>,<metric>`. HTTP 200, empty
  body; the route appears in the live `rTable` immediately.
- Delete slot `i`: shift slots `i+1..n` down by one (slots must stay
  contiguous — the UI stops listing at the first `idxen ≠ 1`), then reset the
  last used slot to `idxen=0, ipaddr=0.0.0.0, mask=0, gw=0.0.0.0, ifname="",
  metric=1`; `action=ui_del_route`, no params. HTTP 200; the route leaves `rTable`.
- A factory-fresh empty slot can hold leftover values (seen:
  `192.168.1.0 / 255.255.255.0 / 192.168.1.1 / lan / 0` with `idxen=0`); only
  `idxen` decides whether a slot is in use.
### Verified write: port forwarding (2026-10-29)

- All changes go in one `db.cgi` call:
  `data = {"type": "edit", "to": "forwardrule", "body": [<rule>, ...]}`.
- Create: `{"type": "create", "enable": "1", "name", "privateIP",
  "forward_port": 0 | <int>, "schedule_rule_id": "0", "ports": [<port>]}`
  — `forward_port` 0 means "same as the public port"; `schedule_rule_id` "0"
  means always.
- `<port>`: `{"type": 1 tcp | 2 udp | 4 gre | 5 esp | 6 ah | 8 both,
  "source_type": 0, "source_port": "", "dest_type": 1 single | 2 range,
  "dest_port": "443" | "1000:2000"}`.
- The router stores the rule as a row
  `{id, enable, name, privateIP, port_rule_id, forward_port, schedule_rule_id,
  snat_enable, snat_id}` in `portforwardings.portforwardings` and **creates an
  unnamed service rule** (`portrules.portrules[]`, `used: 1`) holding the
  ports. Listing forwards = join on `port_rule_id`.
- Update: the row with `"type": "update"` plus `ports`; delete: the row with
  `"type": "delete"`. Delete also removes the auto-created service rule.
- UI limit: 128 rules including `reservePort` entries.

### Verified write: DHCP reservations (2026-10-29)

- 127 slots `static_mac_N` / `static_ip_N` / `static_name_N` (N = 0..126),
  **not contiguous**: add/update uses the slot already holding the MAC, else
  the first slot with an empty `static_mac_N`; delete blanks all three.
  Also set `static_enable0=1`. `apply_abstract.cgi` with **no action**;
  dnsmasq picks it up without an explicit restart.
- MACs are stored upper-case with colons.
- **Last octet 100–150 is "reserved for Verizon Managed Device".** The UI
  refuses it; the router *stores* such a reservation but **never hands the
  address out** (verified: reserved .122 → client kept its old lease even
  after `dnsmasq_restart` and a fresh DISCOVER; the same reservation at .60
  was handed out immediately). The client must refuse these up front.
- UI name rule: `^[0-9A-Za-z.\-_]+$`; duplicate names/IPs refused; not
  `.0`, `.255` or the router's own IP.

### Verified write: WAN DNS (2026-10-29)

- Read from `cgi_status` (`wan_dns_enable`, `dns_auto_enable`,
  `wan_static_dns`, live `wan_ip4_dns`); write with ids from
  `cgi_net_connections`.
- Modes: manual = `wan_dns_enable=1, dns_auto_enable=0,
  wan_static_dns="<dns1>|<dns2>"` (empty side = unset); auto =
  `wan_dns_enable=1, dns_auto_enable=1, wan_static_dns=""`; none = both `0`.
- `action=ui_verizon_broad_settings`, `action_params="<moca_wan_changed>,
  <wan_changed>,<firewall_changed>,<dns_changed>"` → `"0,0,0,1"` for a
  DNS-only change. UI waits 15 s.
- LAN clients get the router itself as their DNS server, so the WAN DNS
  setting is what every client ultimately uses.
- Not verifiable without a live WAN: that the router actually forwards to
  the configured servers. Check at cutover (e.g. Cloudflare Gateway logs).
- **IPv6 DNS is separate**: `ip6wan_DnsAuto` (`1` = automatic, the default),
  `wan_ip6_dnslist` (manual list; `0`/empty = none), `wan_ip6_auto_dnslist`
  (learned, `|`-separated), `wan6_proto` (`dhcpv6`). Write path not yet
  discovered. With IPv6 on the WAN, automatic IPv6 DNS is a second route to
  the ISP's resolvers that the IPv4 setting does not cover.

### Ping semantics

`oDiagnosticState.retry == "1"` = still running. `status`: `"1"` finished,
`"-1"` no response, `"-2"` test failed. `packets = [sent, received, loss %]`
— the third value is a **percentage**, not a count.

### Verified: other writes and actions (2026-10-29, firmware 3.3.1.2)

| Feature | Read (CGI) | Write |
|---|---|---|
| DMZ | `dmz`: `firewall_dmz_enable`, `firewall_dmz_ip`, `firewall_dmz6_enable`, `firewall_dmz6_mac` | fields + `action=ui_firewall` |
| UPnP | `upnp`: `upnp_enable`, `upnp_autoclean` | fields + `action=ui_upnp` |
| Block device | `known_devices`: `block_mac_N`, `block_enable_N` (255 slots) | no fields; `action=ui_block_dev`, `action_params=<MAC>,<slot>` (slot = first empty or disabled); unblock `action=ui_remove_block_dev`, `action_params=<slot>` |
| Ping | `diagnostics`: `oDiagnosticState = {status, packets: [sent, received, lost], round_trip_time: [min, max, avg], retry}` | `POST /diagnostics.cgi` `{token, cmd: "ping", ping_dest_ip4, ping4_number (1-999)}`; poll the CGI; `ping6` / `*_cancel` likewise |
| Reboot | — | `action=ui_reboot_reason, action_params=1`, then `action=reboot`. Down after ~6 s, **back after ~233 s**; the pinned certificate is unchanged after reboot |

### Sessions

- `login.cgi` 403 body `{flag, timeout, maxsession}`: `timeout>0` = login
  disabled for N s; `flag` 1 wrong password, **2 too many sessions**, 3/9
  expired, 7 five wrong passwords (locked for `timeout` s).
- `cgi_ui_admin`: `session_max` (default **10**, adjustable), `session_timeout`
  (600 s), `http_maxFailTimes`. A client that never logs out exhausts the
  sessions within minutes — **always `POST logout.cgi` when done.**

## Sensitive fields

Several pages return Wi-Fi credentials in clear text — e.g. `cgi_home`:
`sharedkey24G`, `sharedkey5G_H`, `sharedkey6G`, `guest_password`; also
`iot_password`, WPS PINs, and `user_userPass` in `cgi_ui_admin`. Every tool
response and every fixture must redact password/key-like fields.

## Page catalogue (50 live CGIs on the bench, firmware below)

`arp bandwith basic bh_log cellular_signal diagnostics dmz dns_server
dynamic_dns firewall_access_control firewall_general firewall_pinholes
firewall_port_forward firewall_port_trigger firewall_static_nat firmware home
ip_distribution ipv6 ipv6_distribution known_devices lan_restore log ndp
net_connections network_object ntp owl parental port_conf port_rule
router_led routing scheduler sipalg status ui_admin ui_remote_admin upnp
wan_mac_clone wifi_add_dev_modal wifi_channel wifi_channel_history
wifi_channel_settings wifi_guest wifi_iot wifi_primary wifi_qos wifi_wps
zenreach`

Some statements are real JavaScript (`addROD("wps_remain_time", parseInt(...))`);
the parser skips and records them. `cgi_cellular_signal` returns an error
page on units without a cellular modem.

- IPv6 routes are rows, not slots: `db.cgi` with
  `{"type": "create"|"update"|"delete", "to": "routes6", "body": {"id"?, "prefix6", "gw6", "metric6"}}`.

## Pages relevant to milestone 1

| CGI | What's in it |
|---|---|
| `routing` | `route_ipv4_{idxen,ipaddr,mask,gw,metric,ifname}0..19` — **20 static-route slots**; tables `rTable`, `routes6_Table`, `ipv6_active_rules` |
| `ip_distribution` | `dhcp_enable0..3`, `dhcp_start_ip`, `dhcp_end_ip`, `dhcp_lease_time`, `dhcp_wins_server`, `static_mac_N` / `static_ip_N` / `static_name_N` (DHCP reservation slots), tables `dump_dhcp_leases`, `known_device_list` |
| `firewall_port_forward` | no `addCfg`; tables `portforwardings`, `upnpportforwardings`, `readonly_portforwardings`, `portrules`, `schedulerules`, `reservePort` |
| `dns_server` (+ WAN page) | `wan_dns_enable`, `wan_static_dns` (`"dns1|dns2"`), `wan_ip4_dns` (current, space-separated), `dns_auto_enable`, `wan_ip6_dnslist` |

## Other endpoints seen in the UI

`quick_setup.cgi`, `diagnostics.cgi`, `cgi_upload.cgi`, `clearlog.cgi`,
`analysis.cgi`, `cgi/cgi_login_keep.js`, `cgi/cgi_wifi_wps_status.js`, and page
CGIs including `dmz`, `dynamic_dns`, `firewall_general`, `firewall_access_control`,
`firewall_pinholes`, `firewall_port_trigger`, `firewall_static_nat`, `ipv6`,
`ipv6_distribution`, `known_devices`, `lan_restore`, `ntp`, `routing`,
`ui_admin`, `ui_remote_admin`, `upnp`, `wan_mac_clone`.

## Still to capture (in the browser, one action per HAR)

- An add/edit/remove of a reservation, a static route and a port forward —
  confirms which of `apply_abstract.cgi` / `db.cgi` each uses and the `db.cgi`
  `data` format.
- The WAN DNS save (fields + `action`).
- The 403 login-failure body and lockout timing.
- Whether field ids change between sessions.
