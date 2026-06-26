from __future__ import annotations

import logging
import re
from ipaddress import ip_address, ip_network
from typing import Any

from vet_compliance.models import AuditTarget

logger = logging.getLogger(__name__)


def apply_exceptions(targets: list[AuditTarget], config: dict[str, Any]) -> list[AuditTarget]:
    exceptions = config.get("exceptions", {})
    if not exceptions:
        return targets
    ignored_meraki_vlan2_subnets = _ignored_meraki_vlan2_subnets(targets, exceptions)
    ignored: list[AuditTarget] = []
    kept: list[AuditTarget] = []
    for target in targets:
        if _is_ignored(target, exceptions) or _matches_ignored_meraki_site(target, ignored_meraki_vlan2_subnets):
            ignored.append(target)
        else:
            kept.append(target)
    if ignored:
        logger.info("Ignored %s target(s) due to config exceptions.", len(ignored))
    return kept


def _is_ignored(target: AuditTarget, exceptions: dict[str, Any]) -> bool:
    return (
        _matches_any(target.context.site_name, target.context.platform, exceptions.get("ignored_sites", []))
        or _matches_any(target.context.device_name, target.context.platform, exceptions.get("ignored_devices", []))
    )


def _ignored_meraki_vlan2_subnets(targets: list[AuditTarget], exceptions: dict[str, Any]) -> list[dict[str, Any]]:
    subnets: list[dict[str, Any]] = []
    for target in targets:
        if target.context.platform != "meraki":
            continue
        if not _matches_any(target.context.site_name, target.context.platform, exceptions.get("ignored_sites", [])):
            continue
        for vlan in target.sections.get("vlans", []):
            if not isinstance(vlan, dict) or str(vlan.get("id")) != "2" or not vlan.get("subnet"):
                continue
            try:
                subnets.append({"site": target.context.site_name, "network": ip_network(vlan["subnet"], strict=False)})
            except ValueError:
                logger.debug("Ignoring invalid Meraki VLAN 2 subnet for exception matching", exc_info=True)
    return subnets


def _matches_ignored_meraki_site(target: AuditTarget, ignored_meraki_vlan2_subnets: list[dict[str, Any]]) -> bool:
    if target.context.platform != "unifi" or not ignored_meraki_vlan2_subnets:
        return False
    management_ip = _target_management_ip(target)
    if not management_ip:
        return False
    try:
        address = ip_address(management_ip)
    except ValueError:
        return False
    for item in ignored_meraki_vlan2_subnets:
        if address in item["network"]:
            logger.info(
                "Ignoring UniFi site %s because management IP %s belongs to ignored Meraki site %s VLAN 2 subnet %s.",
                target.context.site_name,
                management_ip,
                item["site"],
                item["network"],
            )
            return True
    return False


def _target_management_ip(target: AuditTarget) -> str | None:
    raw = target.context.raw_device or {}
    for key in ("ip", "last_ip", "fixed_ip", "connect_request_ip"):
        if raw.get(key):
            return raw[key]
    for entry in raw.get("network_table") or []:
        if isinstance(entry, dict) and entry.get("ip"):
            return entry["ip"]
    return None


def _matches_any(value: str, platform: str, rules: list[Any]) -> bool:
    for rule in rules:
        if isinstance(rule, str):
            if _same_name(value, rule):
                return True
            continue
        if not isinstance(rule, dict):
            continue
        if rule.get("platform") and rule["platform"] != platform:
            continue
        if rule.get("name") and _same_name(value, rule["name"]):
            return True
        if rule.get("regex") and re.search(rule["regex"], value or ""):
            return True
    return False


def _same_name(value: str, expected: str) -> bool:
    return (value or "").strip().casefold() == (expected or "").strip().casefold()
