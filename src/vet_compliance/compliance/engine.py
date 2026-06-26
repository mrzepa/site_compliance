from __future__ import annotations

import re
from ipaddress import ip_address, ip_network
from collections import defaultdict
from typing import Any

from vet_compliance.models import AuditReport, AuditTarget, Finding


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    if isinstance(value, str):
        return value.strip()
    return value


def _get_path(data: Any, path: str) -> Any:
    current = data
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


class ComplianceEngine:
    def __init__(self, rules: dict[str, Any]):
        self.rules = rules
        self.defaults = rules.get("defaults", {})
        self.profiles = rules.get("profiles", {})
        self.assignments = rules.get("assignments", [])
        self.reference_data: dict[str, Any] = {}

    def audit(self, targets: list[AuditTarget]) -> AuditReport:
        findings: list[Finding] = []
        noncompliant = set()
        noncompliant_sites = set()
        self.reference_data = self._build_reference_data(targets)
        site_keys_by_target = {id(target): self._physical_site_key(target) for target in targets}
        audited_sites = set(site_keys_by_target.values())
        for target in targets:
            profile_name = self.profile_for(target)
            if not profile_name:
                continue
            profile = self.profiles[profile_name]
            target_findings = self.audit_target(target, profile)
            findings.extend(target_findings)
            if target_findings:
                noncompliant.add((target.context.platform, target.context.site_name, target.context.device_name))
                noncompliant_sites.add(site_keys_by_target[id(target)])
        compliant = max(len(targets) - len(noncompliant), 0)
        compliant_sites = max(len(audited_sites) - len(noncompliant_sites), 0)
        return AuditReport(
            findings=findings,
            total_devices=len(targets),
            compliant_devices=compliant,
            total_sites=len(audited_sites),
            compliant_sites=compliant_sites,
        )

    def _physical_site_key(self, target: AuditTarget) -> str:
        if target.context.platform == "meraki":
            return f"meraki:{self._site_key(target.context.site_name)}"
        if target.context.platform == "unifi":
            site_key, _ = self._resolve_meraki_site_key(target)
            if site_key:
                return f"meraki:{site_key}"
        return f"{target.context.platform}:{self._site_key(target.context.site_name)}"

    def _build_reference_data(self, targets: list[AuditTarget]) -> dict[str, Any]:
        meraki_vlan_interfaces: dict[str, dict[str, str]] = {}
        meraki_vlan2_subnets: list[dict[str, Any]] = []
        for target in targets:
            if target.context.platform != "meraki":
                continue
            site_key = self._site_key(target.context.site_name)
            site_interfaces = meraki_vlan_interfaces.setdefault(site_key, {})
            for vlan in target.sections.get("vlans", []):
                if not isinstance(vlan, dict):
                    continue
                vlan_id = vlan.get("id")
                interface_ip = vlan.get("applianceIp") or vlan.get("interfaceIp")
                if vlan_id is not None and interface_ip:
                    site_interfaces[str(vlan_id)] = interface_ip
                if str(vlan_id) == "2" and vlan.get("subnet"):
                    try:
                        meraki_vlan2_subnets.append(
                            {
                                "site_key": site_key,
                                "site_name": target.context.site_name,
                                "network": ip_network(vlan["subnet"], strict=False),
                            }
                        )
                    except ValueError:
                        continue
        return {"meraki_vlan_interfaces": meraki_vlan_interfaces, "meraki_vlan2_subnets": meraki_vlan2_subnets}

    def profile_for(self, target: AuditTarget) -> str | None:
        ctx = target.context
        for assignment in self.assignments:
            if assignment.get("platform") and assignment["platform"] != ctx.platform:
                continue
            if not self._matches_regex(assignment.get("site_name_regex"), ctx.site_name):
                continue
            if not self._matches_regex(assignment.get("network_name_regex"), ctx.site_name):
                continue
            if not self._matches_regex(assignment.get("device_name_regex"), ctx.device_name):
                continue
            return assignment.get("profile")
        for name, profile in self.profiles.items():
            if profile.get("platform") == ctx.platform:
                return name
        return None

    @staticmethod
    def _matches_regex(pattern: str | None, value: str) -> bool:
        return pattern is None or re.search(pattern, value or "") is not None

    @staticmethod
    def _site_key(value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "", (value or "").lower())

    def audit_target(self, target: AuditTarget, profile: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for section_name, check in profile.get("checks", {}).items():
            actual = target.sections.get(section_name)
            if actual is None:
                findings.append(self._finding(target, section_name, f"Missing section {section_name}"))
                continue
            if "items" in check:
                findings.extend(self._audit_items(target, section_name, check, actual))
            if "required" in check:
                findings.extend(self._audit_required(target, section_name, check["required"], actual))
        return findings

    def _audit_items(self, target: AuditTarget, section: str, check: dict[str, Any], actual: Any) -> list[Finding]:
        key = check.get("key", "name")
        strict = check.get("strict", self.defaults.get("strict", True))
        expected_items = check.get("items", [])
        ignored_items = {str(item) for item in check.get("ignore_items", [])}
        actual_items = actual if isinstance(actual, list) else []
        expected_by_key = {str(item.get(key)): item for item in expected_items}
        actual_by_key = {str(item.get(key)): item for item in actual_items if isinstance(item, dict) and item.get(key) is not None}
        findings: list[Finding] = []
        missing_reference_sections: set[str] = set()

        for item_key, expected in expected_by_key.items():
            observed = actual_by_key.get(item_key)
            if observed is None:
                findings.append(self._finding(target, section, f"Missing expected {section} item {item_key}", expected=expected))
                continue
            for field, expected_value in expected.items():
                actual_value = self._actual_field_value(observed, field)
                if field == key:
                    valid, actual_display = str(actual_value) == str(expected_value), actual_value
                else:
                    valid, actual_display = self._matches_expected(target, observed, field, actual_value, expected_value)
                if isinstance(actual_display, dict) and actual_display.get("__missing_reference__"):
                    missing_reference_sections.add(actual_display.get("reference", "external reference data"))
                    continue
                if not valid:
                    finding_expected = expected_value
                    finding_actual = actual_display
                    if isinstance(actual_display, dict) and "expected_meraki_interface_ip" in actual_display:
                        finding_expected = {
                            "$meraki_vlan_interface_ip": actual_display.get("vlan_id") or item_key,
                            "ip": actual_display.get("expected_meraki_interface_ip"),
                        }
                        finding_actual = actual_display.get("actual")
                    findings.append(
                        self._finding(
                            target,
                            section,
                            self._item_message(section, item_key, field),
                            expected=finding_expected,
                            actual=finding_actual,
                            path=f"{section}[{item_key}].{field}",
                        )
                    )
        for reference in sorted(missing_reference_sections):
            findings.append(
                self._finding(
                    target,
                    "reference_data",
                    f"Missing {reference} for site {target.context.site_name}; skipped dependent {section} checks",
                    expected=f"Matching {reference} for site {target.context.site_name}",
                    actual="No matching site reference found",
                )
            )

        if strict:
            for item_key, observed in actual_by_key.items():
                if item_key not in expected_by_key and item_key not in ignored_items:
                    findings.append(self._finding(target, section, f"Unexpected {section} item {item_key}", actual=observed))
        return findings

    @staticmethod
    def _actual_field_value(observed: dict[str, Any], field: str) -> Any:
        actual_value = _get_path(observed, field)
        if actual_value is None and field == "dhcpguard_server":
            trusted_servers = [
                observed[key]
                for key in ("dhcpd_ip_1", "dhcpd_ip_2", "dhcpd_ip_3", "dhcpd_ip_4")
                if observed.get(key)
            ]
            if trusted_servers:
                return trusted_servers
        return actual_value

    def _audit_required(self, target: AuditTarget, section: str, required: dict[str, Any], actual: Any) -> list[Finding]:
        actual_dict = actual if isinstance(actual, dict) else {}
        findings: list[Finding] = []
        for field, expected_value in required.items():
            actual_value = actual_dict.get(field)
            valid, actual_display = self._matches_expected(target, actual_dict, field, actual_value, expected_value)
            if not valid:
                findings.append(
                    self._finding(
                        target,
                        section,
                        f"{section} has incorrect {field}",
                        expected=expected_value,
                        actual=actual_display,
                        path=f"{section}.{field}",
                    )
                )
        return findings

    def _matches_expected(
        self,
        target: AuditTarget,
        item: dict[str, Any],
        field: str,
        actual_value: Any,
        expected_value: Any,
    ) -> tuple[bool, Any]:
        if not isinstance(expected_value, dict):
            if field == "name":
                return self._case_insensitive_match(actual_value, expected_value), actual_value
            return _normalize(actual_value) == _normalize(expected_value), actual_value
        if "$one_of" in expected_value:
            allowed = expected_value["$one_of"]
            if field == "name":
                return any(self._case_insensitive_match(actual_value, item) for item in allowed), actual_value
            return actual_value in allowed, actual_value
        if "$present" in expected_value:
            return (actual_value not in (None, "", [], {})) == bool(expected_value["$present"]), actual_value
        if "$dhcp_option" in expected_value:
            return self._matches_dhcp_option(actual_value, expected_value["$dhcp_option"])
        if expected_value.get("$all_ips_in_subnet"):
            subnet = item.get(expected_value.get("subnet_field", "subnet"))
            return self._all_assignment_ips_in_subnet(actual_value, subnet)
        if "$first_host_of" in expected_value:
            subnet = item.get(expected_value["$first_host_of"])
            expected_ip = self._first_host(subnet)
            actual_ips = actual_value if isinstance(actual_value, list) else [actual_value]
            return expected_ip in actual_ips, actual_value
        if "$meraki_vlan_interface_ip" in expected_value:
            vlan_id = str(expected_value["$meraki_vlan_interface_ip"])
            site_key, reference_error = self._resolve_meraki_site_key(target)
            site_interfaces = self.reference_data.get("meraki_vlan_interfaces", {}).get(site_key) if site_key else None
            if site_interfaces is None:
                return False, {"__missing_reference__": True, "reference": reference_error or "Meraki VLAN interface data"}
            expected_ip = site_interfaces.get(vlan_id)
            actual_ips = actual_value if isinstance(actual_value, list) else [actual_value]
            return expected_ip is not None and expected_ip in actual_ips, {"expected_meraki_interface_ip": expected_ip, "actual": actual_value, "vlan_id": vlan_id}
        return _normalize(actual_value) == _normalize(expected_value), actual_value

    def _resolve_meraki_site_key(self, target: AuditTarget) -> tuple[str | None, str | None]:
        meraki_interfaces = self.reference_data.get("meraki_vlan_interfaces", {})
        exact_key = self._site_key(target.context.site_name)
        if exact_key in meraki_interfaces:
            return exact_key, None
        if target.context.platform != "unifi":
            return None, "Meraki VLAN interface data"
        management_ip = self._target_management_ip(target)
        if not management_ip:
            return None, "Meraki VLAN interface data; UniFi management IP was unavailable"
        try:
            address = ip_address(management_ip)
        except ValueError:
            return None, f"Meraki VLAN interface data; UniFi management IP {management_ip} was invalid"
        matches = [
            item
            for item in self.reference_data.get("meraki_vlan2_subnets", [])
            if address in item["network"]
        ]
        if len(matches) == 1:
            return matches[0]["site_key"], None
        if len(matches) > 1:
            names = ", ".join(item["site_name"] for item in matches[:5])
            return None, f"Meraki VLAN interface data; UniFi management IP {management_ip} matched multiple Meraki VLAN 2 subnets: {names}"
        return None, f"Meraki VLAN interface data; UniFi management IP {management_ip} did not match a Meraki VLAN 2 subnet"

    @staticmethod
    def _target_management_ip(target: AuditTarget) -> str | None:
        raw = target.context.raw_device or {}
        for key in ("ip", "last_ip", "fixed_ip", "connect_request_ip"):
            if raw.get(key):
                return raw[key]
        for entry in raw.get("network_table") or []:
            if isinstance(entry, dict) and entry.get("ip"):
                return entry["ip"]
        return None

    @staticmethod
    def _matches_dhcp_option(actual_value: Any, expected: dict[str, Any]) -> tuple[bool, Any]:
        options = actual_value if isinstance(actual_value, list) else []
        code = str(expected.get("code"))
        value = expected.get("value")
        matches = [option for option in options if str(option.get("code")) == code]
        if not matches:
            return False, []
        if any(option.get("value") != value for option in matches):
            return False, matches
        return True, matches

    @staticmethod
    def _case_insensitive_match(actual_value: Any, expected_value: Any) -> bool:
        if isinstance(actual_value, str) and isinstance(expected_value, str):
            return actual_value.strip().casefold() == expected_value.strip().casefold()
        return _normalize(actual_value) == _normalize(expected_value)

    @staticmethod
    def _all_assignment_ips_in_subnet(actual_value: Any, subnet: str | None) -> tuple[bool, Any]:
        if not subnet:
            return False, actual_value
        try:
            network = ip_network(subnet, strict=False)
        except ValueError:
            return False, {"subnet": subnet, "assignments": actual_value}
        assignments = actual_value if isinstance(actual_value, dict) else {}
        for reservation in assignments.values():
            reservation_ip = reservation.get("ip") if isinstance(reservation, dict) else reservation
            try:
                if ip_address(reservation_ip) not in network:
                    return False, assignments
            except ValueError:
                return False, assignments
        return True, assignments

    @staticmethod
    def _first_host(subnet: str | None) -> str | None:
        if not subnet:
            return None
        try:
            network = ip_network(subnet, strict=False)
        except ValueError:
            return None
        return str(next(network.hosts(), None))

    @staticmethod
    def _item_message(section: str, item_key: str, field: str) -> str:
        field_names = {
            "dhcpguard_server": "DHCP Guard trusted server",
            "dhcpguard_enabled": "DHCP Guard status",
            "dnsNameservers": "DNS servers",
            "vpnModeEnabled": "VPN mode",
            "dhcpOptions": "DHCP options",
            "fixedIpAssignments": "DHCP reservations",
        }
        item_labels = {
            "vlans": "VLAN",
            "wifi_settings": "WiFi network",
            "port_profiles": "Port profile",
            "settings": "Setting",
        }
        item_label = item_labels.get(section, section.rstrip("s").replace("_", " ").title())
        field_label = field_names.get(field, field.replace("_", " "))
        return f"{item_label} {item_key} has incorrect {field_label}"

    @staticmethod
    def _finding(
        target: AuditTarget,
        section: str,
        message: str,
        expected: Any = None,
        actual: Any = None,
        path: str | None = None,
    ) -> Finding:
        ctx = target.context
        return Finding(
            severity="noncompliant",
            platform=ctx.platform,
            site=ctx.site_name,
            device=ctx.device_name,
            section=section,
            message=message,
            expected=expected,
            actual=actual,
            path=path,
        )


def summarize_by_site(findings: list[Finding]) -> dict[str, int]:
    summary: dict[str, int] = defaultdict(int)
    for finding in findings:
        summary[finding.site] += 1
    return dict(summary)
