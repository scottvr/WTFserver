"""Host identity collector (Windows).

Emits exactly one ``host_identity`` observation built from four independent
sub-queries: Win32_ComputerSystem, Win32_OperatingSystem, Get-NetIPAddress,
and Get-DnsClientServerAddress. Any sub-query may fail (CollectorError,
partial observation); the collector is fatal only when every sub-query fails.
"""

from __future__ import annotations

import json
from typing import Any

from ...model import Category, Observation, parse_iso, to_iso
from ..base import CollectionContext, Collector, CollectorError, CollectorResult
from .powershell import PowerShellError

_PS_COMPUTER_SYSTEM = r"""
Get-CimInstance Win32_ComputerSystem -ErrorAction Stop |
    Select-Object Name, Domain, PartOfDomain, DomainRole |
    ConvertTo-Json -Compress
"""

_PS_OPERATING_SYSTEM = r"""
Get-CimInstance Win32_OperatingSystem -ErrorAction Stop |
    Select-Object Caption, Version,
        @{Name='LastBootUpTime'; Expression={ if ($_.LastBootUpTime) { $_.LastBootUpTime.ToUniversalTime().ToString('o') } else { $null } }} |
    ConvertTo-Json -Compress
"""

_PS_IP_ADDRESSES = r"""
$addrs = Get-NetIPAddress -ErrorAction Stop | Select-Object InterfaceAlias, IPAddress, AddressFamily
ConvertTo-Json -Compress -Depth 3 -InputObject @($addrs)
"""

_PS_DNS_SERVERS = r"""
$dns = Get-DnsClientServerAddress -ErrorAction Stop |
    Select-Object InterfaceAlias, @{Name='ServerAddresses'; Expression={ @($_.ServerAddresses) }}
ConvertTo-Json -Compress -Depth 3 -InputObject @($dns)
"""

# Win32_ComputerSystem.DomainRole -> normalized role string.
_DOMAIN_ROLE_MAP = {
    0: "standalone",  # standalone workstation
    1: "member",  # member workstation
    2: "standalone",  # standalone server
    3: "member",  # member server
    4: "domain_controller",  # backup DC
    5: "domain_controller",  # primary DC
}

_SUBQUERIES = (
    ("computer_system", _PS_COMPUTER_SYSTEM, "computer system query"),
    ("operating_system", _PS_OPERATING_SYSTEM, "operating system query"),
    ("ip_addresses", _PS_IP_ADDRESSES, "IP address query"),
    ("dns_servers", _PS_DNS_SERVERS, "DNS server query"),
)


def _first_dict(payload: Any) -> dict:
    """Single CIM instance expected; tolerate list wrapping and junk."""
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                return item
    return {}


def _as_list(payload: Any) -> list:
    """ConvertTo-Json collapses a single element to a bare object."""
    if payload is None:
        return []
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return payload
    return []


def _opt_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


class HostIdentityCollector(Collector):
    name = "host_identity"
    platforms = ("windows",)
    categories = (Category.HOST_IDENTITY,)

    def collect(self, ctx: CollectionContext) -> CollectorResult:
        result = CollectorResult()
        payloads: dict[str, Any] = {}
        failed = 0
        for key, script, label in _SUBQUERIES:
            try:
                payloads[key] = ctx.runner.run_json(script)
            except PowerShellError as exc:
                payloads[key] = None
                failed += 1
                result.errors.append(CollectorError(self.name, f"{label} failed: {exc}"))
        if failed == len(_SUBQUERIES):
            for err in result.errors:
                err.fatal = True
            return result

        raw_ref = ctx.add_raw(
            "host_identity.json", json.dumps(payloads, ensure_ascii=False, indent=2)
        )
        attributes = self._build_attributes(payloads)
        result.observations.append(
            Observation(
                id="",  # assigned by the bundle writer
                source=self.name,
                category=Category.HOST_IDENTITY,
                timestamp=to_iso(ctx.now),
                action="identity",
                attributes=attributes,
                raw_reference=raw_ref,
            )
        )
        result.stats["interfaces"] = len(attributes["interfaces"])
        result.stats["dns_servers"] = len(attributes["dns_servers"])
        return result

    def _build_attributes(self, payloads: dict[str, Any]) -> dict[str, Any]:
        cs = _first_dict(payloads.get("computer_system"))
        hostname = _opt_str(cs.get("Name"))
        part_of_domain = bool(cs.get("PartOfDomain"))
        domain = _opt_str(cs.get("Domain")) if part_of_domain else None
        fqdn = f"{hostname}.{domain}" if hostname and domain else None
        role_raw = cs.get("DomainRole")
        domain_role = (
            _DOMAIN_ROLE_MAP.get(role_raw) if isinstance(role_raw, int) else None
        )

        os_info = _first_dict(payloads.get("operating_system"))
        last_boot_raw = os_info.get("LastBootUpTime")
        last_boot = parse_iso(last_boot_raw) if isinstance(last_boot_raw, str) else None

        return {
            "hostname": hostname,
            "fqdn": fqdn,
            "os_name": _opt_str(os_info.get("Caption")),
            "os_version": _opt_str(os_info.get("Version")),
            "domain": domain,
            "domain_role": domain_role,
            "interfaces": self._interfaces(payloads.get("ip_addresses")),
            "dns_servers": self._dns_servers(payloads.get("dns_servers")),
            "last_boot": to_iso(last_boot) if last_boot else None,
        }

    @staticmethod
    def _interfaces(payload: Any) -> list[dict[str, Any]]:
        by_name: dict[str, list[str]] = {}
        for entry in _as_list(payload):
            if not isinstance(entry, dict):
                continue
            address = entry.get("IPAddress")
            if not isinstance(address, str) or not address:
                continue
            if address.startswith("169.254."):
                continue  # APIPA self-assigned address, not identity
            name = _opt_str(entry.get("InterfaceAlias")) or "unknown"
            addresses = by_name.setdefault(name, [])
            if address not in addresses:
                addresses.append(address)
        return [
            {"name": name, "addresses": sorted(by_name[name])}
            for name in sorted(by_name)
        ]

    @staticmethod
    def _dns_servers(payload: Any) -> list[str]:
        servers: list[str] = []
        for entry in _as_list(payload):
            if not isinstance(entry, dict):
                continue
            raw = entry.get("ServerAddresses")
            if isinstance(raw, str):
                raw = [raw]
            if not isinstance(raw, list):
                continue
            for address in raw:
                if isinstance(address, str) and address and address not in servers:
                    servers.append(address)
        return servers


COLLECTOR = HostIdentityCollector()
