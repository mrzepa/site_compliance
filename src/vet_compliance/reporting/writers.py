from __future__ import annotations

import csv
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from vet_compliance.compliance.engine import summarize_by_site
from vet_compliance.models import AuditReport


def write_reports(report: AuditReport, output_dir: str | Path) -> dict[str, Path]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "compliance_report.json"
    csv_path = out / "compliance_findings.csv"
    summary_path = out / "summary.json"

    finding_rows = []
    for finding in report.findings:
        row = asdict(finding)
        row["expected_text"] = format_value(row["expected"], row.get("path"), expected=True)
        row["found_text"] = format_value(row["actual"], row.get("path"), expected=False)
        finding_rows.append(row)
    payload = {
        "total_devices": report.total_devices,
        "compliant_devices": report.compliant_devices,
        "noncompliant_devices": report.total_devices - report.compliant_devices,
        "compliance_percent": report.compliance_percent,
        "total_sites": report.total_sites,
        "compliant_sites": report.compliant_sites,
        "noncompliant_sites": report.total_sites - report.compliant_sites,
        "site_compliance_percent": report.site_compliance_percent,
        "findings": finding_rows,
    }
    json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    summary_path.write_text(
        json.dumps({"findings_by_site": summarize_by_site(report.findings), **{k: payload[k] for k in payload if k != "findings"}}, indent=2),
        encoding="utf-8",
    )
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["severity", "platform", "site", "device", "section", "message", "expected", "found", "path"])
        writer.writeheader()
        for row in finding_rows:
            row = dict(row)
            row["expected"] = format_value(row["expected"], row.get("path"), expected=True)
            row["found"] = format_value(row.pop("actual"), row.get("path"), expected=False)
            row.pop("expected_text", None)
            row.pop("found_text", None)
            writer.writerow(row)
    return {"json": json_path, "csv": csv_path, "summary": summary_path}


def format_value(value: Any, path: str | None = None, expected: bool = False) -> str:
    if value is None:
        return "Not found" if not expected else ""
    if isinstance(value, str):
        return value.strip()
    field = (path or "").split(".")[-1]
    vlan_id = _vlan_id_from_path(path)
    if isinstance(value, dict):
        if "$dhcp_option" in value:
            option = value["$dhcp_option"]
            suffix = " only" if option.get("only") else ""
            return f"DHCP option {option.get('code')}: {option.get('value')}{suffix}"
        if "$one_of" in value:
            return "One of: " + ", ".join(str(item) for item in value["$one_of"])
        if "$all_ips_in_subnet" in value:
            return "All DHCP reservation IPs must be inside the VLAN subnet"
        if "$meraki_vlan_interface_ip" in value:
            if value.get("ip"):
                return f"Meraki VLAN {value['$meraki_vlan_interface_ip']} interface IP: {value['ip']}"
            return f"Meraki VLAN {value['$meraki_vlan_interface_ip']} interface IP"
        if "expected_meraki_interface_ip" in value:
            found = _format_scalar(value.get("actual"))
            expected_ip = value.get("expected_meraki_interface_ip")
            if not expected_ip:
                return f"No matching Meraki VLAN interface IP was available; found {found}"
            return f"Expected Meraki interface IP {expected_ip}; found {found}"
        return _format_mapping(value, vlan_id)
    if isinstance(value, list):
        if not value:
            return "Not found"
        if field == "dhcpOptions":
            return "; ".join(_format_dhcp_option(item) for item in value)
        return ", ".join(_format_scalar(item) for item in value)
    if field == "dnsNameservers":
        prefix = f"VLAN {vlan_id}, DNS servers " if vlan_id else "DNS servers "
        return prefix + _format_dns(value)
    if field == "name" and vlan_id:
        return f"VLAN {vlan_id}, name {_format_scalar(value)}"
    if field == "subnet" and vlan_id:
        return f"VLAN {vlan_id}, subnet {_format_scalar(value)}"
    if field == "vpnModeEnabled" and vlan_id:
        return f"VLAN {vlan_id}, VPN mode {'enabled' if value else 'disabled'}"
    if field == "dhcpOptions" and not value:
        return "No matching DHCP option found"
    return _format_scalar(value)


def _format_mapping(value: dict[str, Any], vlan_id: str | None = None) -> str:
    parts: list[str] = []
    effective_vlan = vlan_id or value.get("id") or value.get("vlan")
    if effective_vlan is not None:
        parts.append(f"VLAN {effective_vlan}")
    if value.get("name") is not None:
        parts.append(f"name {format_value(value['name'])}")
    if value.get("subnet") is not None:
        parts.append(f"subnet {value['subnet']}")
    if value.get("dnsNameservers") is not None:
        parts.append(f"DNS servers {_format_dns(value['dnsNameservers'])}")
    if value.get("vpnModeEnabled") is not None:
        parts.append(f"VPN mode {'enabled' if value['vpnModeEnabled'] else 'disabled'}")
    if value.get("dhcpOptions") is not None:
        parts.append(f"DHCP options {format_value(value['dhcpOptions'], 'dhcpOptions')}")
    if parts:
        return ", ".join(parts)
    return "; ".join(f"{key}: {_format_scalar(item)}" for key, item in value.items())


def _format_dhcp_option(option: Any) -> str:
    if not isinstance(option, dict):
        return _format_scalar(option)
    code = option.get("code", "unknown")
    value = option.get("value", "")
    option_type = option.get("type")
    if option_type:
        return f"code {code} ({option_type}) value {value}"
    return f"code {code} value {value}"


def _format_dns(value: Any) -> str:
    if isinstance(value, str):
        return ", ".join(part.strip() for part in value.splitlines() if part.strip())
    if isinstance(value, list):
        return ", ".join(str(part).strip() for part in value if str(part).strip())
    return _format_scalar(value)


def _format_scalar(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str)
    return str(value)


def _vlan_id_from_path(path: str | None) -> str | None:
    if not path:
        return None
    start = path.find("[")
    end = path.find("]", start + 1)
    if start == -1 or end == -1:
        return None
    return path[start + 1:end]
