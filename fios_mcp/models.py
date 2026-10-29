"""Backend-neutral data models returned by tools."""

from __future__ import annotations

import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator

Protocol = Literal["tcp", "udp", "both"]
_MAC = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")


def normalize_mac(mac: str) -> str:
    m = mac.strip().upper().replace("-", ":")
    if not _MAC.match(m):
        raise ValueError(f"not a MAC address: {mac!r}")
    return m


class PortForward(BaseModel):
    id: int | None = None
    name: str
    enabled: bool = True
    protocol: Protocol | str = "tcp"
    external_ports: list[str] = Field(description='single ports or ranges, e.g. ["443"], ["1000-2000"]')
    internal_ip: str
    internal_port: int | None = Field(None, description="None = same as the external port")
    schedule: str = "always"

    def key(self) -> tuple[str, str]:
        return (",".join(self.external_ports), str(self.protocol))


class DhcpReservation(BaseModel):
    mac: str
    ip: str
    name: str = ""
    slot: int | None = None

    @field_validator("mac")
    @classmethod
    def _mac(cls, v: str) -> str:
        return normalize_mac(v)


class StaticRoute(BaseModel):
    destination: str = Field(description="network in CIDR form, e.g. 10.99.0.0/24")
    gateway: str
    metric: int = 1
    interface: str = "lan0"
    slot: int | None = None

    @field_validator("destination")
    @classmethod
    def _cidr(cls, v: str) -> str:
        return str(ipaddress.ip_network(v, strict=True))


class DnsSettings(BaseModel):
    mode: Literal["auto", "manual", "none"]
    servers: list[str] = Field(default_factory=list, description="configured manual servers")
    active: list[str] = Field(default_factory=list, description="servers currently in use on the WAN")
    ipv6_mode: Literal["auto", "manual"] = Field(
        "auto", description="IPv6 WAN DNS; 'auto' may forward lookups to the ISP's IPv6 resolvers")
    ipv6_servers: list[str] = Field(default_factory=list, description="manual IPv6 DNS servers")
    ipv6_learned: list[str] = Field(default_factory=list, description="IPv6 DNS servers learned from the ISP")


class LanSettings(BaseModel):
    ip: str
    mask: str
    dhcp_enabled: bool
    dhcp_start: str
    dhcp_end: str
    lease_time_min: int | None = None
    reserved_range_note: str = (
        "addresses .100-.150 are reserved for Verizon-managed devices; "
        "reservations there are stored but never handed out"
    )


class Device(BaseModel):
    mac: str
    ip: str = ""
    ipv6: str = ""
    hostname: str = ""
    name: str = ""
    active: bool = False
    connection: str = ""
    os: str = ""
    device_type: str = ""
    first_seen: str = ""
    last_active: str = ""
    dhcp: bool | None = None


class Lease(BaseModel):
    hostname: str
    ip: str
    mac: str
    expires_in_s: int | None = None


class ArpEntry(BaseModel):
    ip: str
    mac: str
    state: str = ""
    interface: str = ""


class DmzSettings(BaseModel):
    enabled: bool
    ip: str = ""
    ipv6_enabled: bool = False
    ipv6_mac: str = ""


class UpnpSettings(BaseModel):
    enabled: bool
    auto_cleanup: bool


class FirewallSettings(BaseModel):
    ipv4_level: str
    ipv6_level: str
    allow_set_top_boxes: str = ""


class RemoteAdmin(BaseModel):
    enabled: bool
    https_enabled: bool
    https_port: str = ""
    wan_ping_v4: bool = False
    wan_traceroute_v4: bool = False


class SessionSettings(BaseModel):
    session_max: int | None = None
    session_timeout_s: int | None = None
    max_login_failures: int | None = None


class FirmwareInfo(BaseModel):
    version: str
    date: str = ""
    commit: str = ""
    driver: str = ""


class RouterStatus(BaseModel):
    model: str = ""
    name: str = ""
    firmware: FirmwareInfo | None = None
    wan_proto: str = ""
    wan_ip: str = ""
    wan_mask: str = ""
    wan_gateway: str = ""
    wan_mac: str = ""
    wan_dns_active: list[str] = Field(default_factory=list)
    lan_ip: str = ""
    lan_mask: str = ""


class BlockedDevice(BaseModel):
    mac: str
    slot: int


class PingResult(BaseModel):
    target: str
    outcome: Literal["ok", "packet_loss", "no_response", "failed", "timeout"] = "timeout"
    sent: int | None = None
    received: int | None = None
    loss_percent: int | None = None
    rtt_min_ms: float | None = None
    rtt_max_ms: float | None = None
    rtt_avg_ms: float | None = None
    raw: dict | None = None
