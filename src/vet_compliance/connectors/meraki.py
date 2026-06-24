from __future__ import annotations

import logging
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import meraki
from meraki.exceptions import APIError

from vet_compliance.config import env_value
from vet_compliance.models import AuditTarget, DeviceContext

logger = logging.getLogger(__name__)


class MerakiCallGuard:
    def __init__(
        self,
        pause_seconds: float = 0.3,
        requests_per_second_per_org: float | None = None,
        rate_limit_wait_seconds: float = 60.0,
        max_retries: int = 5,
    ):
        self.pause_seconds = 1 / requests_per_second_per_org if requests_per_second_per_org else pause_seconds
        self.rate_limit_wait_seconds = rate_limit_wait_seconds
        self.max_retries = max_retries
        self._lock = threading.Lock()
        self._last_call_by_scope: dict[str, float] = {}

    def call(self, description: str, func, default=None, required: bool = False, scope: str = "global"):
        for attempt in range(1, self.max_retries + 1):
            self._pace(scope)
            try:
                return func()
            except APIError as exc:
                if _is_rate_limited(exc):
                    wait = self._retry_after(exc) or self.rate_limit_wait_seconds
                    logger.warning("Meraki rate limit while calling %s; sleeping %.1fs (attempt %s/%s).", description, wait, attempt, self.max_retries)
                    time.sleep(wait)
                    continue
                if required:
                    raise
                logger.debug("Meraki API call failed for %s", description, exc_info=True)
                return default
            except Exception:
                if required:
                    raise
                logger.debug("Meraki API call failed for %s", description, exc_info=True)
                return default
        if required:
            raise RuntimeError(f"Meraki API call failed after rate-limit retries: {description}")
        return default

    def _pace(self, scope: str) -> None:
        if self.pause_seconds <= 0:
            return
        with self._lock:
            last_call = self._last_call_by_scope.get(scope, 0.0)
            elapsed = time.monotonic() - last_call
            if elapsed < self.pause_seconds:
                time.sleep(self.pause_seconds - elapsed)
            self._last_call_by_scope[scope] = time.monotonic()


def collect_meraki_targets(config: dict[str, Any]) -> list[AuditTarget]:
    meraki_config = config.get("meraki", {})
    if not meraki_config.get("enabled", False):
        return []
    api_key = env_value(meraki_config.get("api_key_env", "MERAKI_DASHBOARD_API_KEY"))
    if not api_key:
        raise ValueError("Missing Meraki Dashboard API key")
    guard = MerakiCallGuard(
        pause_seconds=float(meraki_config.get("request_pause_seconds", 0.3)),
        requests_per_second_per_org=(
            float(meraki_config["requests_per_second_per_org"])
            if meraki_config.get("requests_per_second_per_org")
            else None
        ),
        rate_limit_wait_seconds=float(meraki_config.get("rate_limit_wait_seconds", 60)),
        max_retries=int(meraki_config.get("rate_limit_retries", 5)),
    )
    dashboard = meraki.DashboardAPI(
        api_key=api_key,
        suppress_logging=True,
        print_console=False,
        wait_on_rate_limit=True,
        maximum_retries=int(meraki_config.get("sdk_maximum_retries", 2)),
        retry_4xx_error=True,
        retry_4xx_error_wait_time=int(meraki_config.get("sdk_4xx_retry_wait_seconds", 5)),
        nginx_429_retry_wait_time=int(meraki_config.get("sdk_429_retry_wait_seconds", 5)),
    )
    orgs = guard.call("organizations", lambda: dashboard.organizations.getOrganizations(), required=True)
    org_filter = set(meraki_config.get("org_ids") or [])
    include = set(meraki_config.get("include_networks") or [])
    exclude = set(meraki_config.get("exclude_networks") or [])
    max_networks = meraki_config.get("max_networks")
    networks: list[dict[str, Any]] = []
    for org in orgs:
        if org_filter and org["id"] not in org_filter:
            continue
        org_id = org["id"]
        org_networks = guard.call(
            f"organization {org_id} networks",
            lambda org_id=org_id: dashboard.organizations.getOrganizationNetworks(org_id, total_pages="all"),
            default=[],
            scope=org_id,
        )
        for network in org_networks:
            if include and network.get("name") not in include and network.get("id") not in include:
                continue
            if network.get("name") in exclude or network.get("id") in exclude:
                continue
            if "appliance" not in network.get("productTypes", []):
                continue
            network["organizationId"] = org_id
            networks.append(network)
            if max_networks and len(networks) >= int(max_networks):
                break
        if max_networks and len(networks) >= int(max_networks):
            break
    max_workers = int(config.get("audit", {}).get("workers", {}).get("meraki_networks", 8))
    logger.info("Collecting Meraki data from %s appliance networks with %s worker(s).", len(networks), max_workers)
    targets: list[AuditTarget] = []
    if max_workers <= 1:
        for index, network in enumerate(networks, start=1):
            logger.info("Collecting Meraki network %s/%s: %s", index, len(networks), network.get("name") or network["id"])
            targets.extend(_collect_network(dashboard, guard, network))
        return targets
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_collect_network, dashboard, guard, network) for network in networks]
        for future in as_completed(futures):
            targets.extend(future.result())
    return targets


def _collect_network(dashboard: meraki.DashboardAPI, guard: MerakiCallGuard, network: dict[str, Any]) -> list[AuditTarget]:
    network_id = network["id"]
    org_id = str(network.get("organizationId") or "global")
    devices = guard.call(f"network {network_id} devices", lambda: dashboard.networks.getNetworkDevices(network_id), default=[], scope=org_id)
    vlans = guard.call(f"network {network_id} appliance VLANs", lambda: dashboard.appliance.getNetworkApplianceVlans(network_id), default=[], scope=org_id)
    firewall_settings = guard.call(
        f"network {network_id} appliance firewall settings",
        lambda: dashboard.appliance.getNetworkApplianceFirewallSettings(network_id),
        default={},
        scope=org_id,
    )
    vpn_settings = guard.call(
        f"network {network_id} site-to-site VPN settings",
        lambda: dashboard.appliance.getNetworkApplianceVpnSiteToSiteVpn(network_id),
        default={},
        scope=org_id,
    )
    _enrich_vlan_vpn_mode(vlans, vpn_settings)
    targets: list[AuditTarget] = []
    for device in devices:
        model = device.get("model", "")
        if not model.startswith("MX"):
            continue
        ctx = DeviceContext(
            platform="meraki",
            controller="Meraki Dashboard",
            site_id=network_id,
            site_name=network.get("name") or network_id,
            device_id=device.get("serial"),
            device_name=device.get("name") or device.get("serial") or model,
            device_type="appliance",
            raw_device=device,
        )
        dns_settings = _first_vlan_dns(vlans)
        dhcp_options = vlans[0] if vlans else {}
        targets.append(
            AuditTarget(
                context=ctx,
                sections={
                    "vlans": vlans,
                    "dns_settings": dns_settings,
                    "dhcp_options": dhcp_options,
                    "firewall_settings": firewall_settings,
                    "vpn_settings": vpn_settings,
                },
            )
        )
    return targets


def _is_rate_limited(exc: APIError) -> bool:
    return "429" in str(exc) or "rate limit" in str(exc).lower()


def _retry_after(exc: APIError) -> float | None:
    response = getattr(exc, "response", None)
    headers = getattr(response, "headers", {}) if response is not None else {}
    value = headers.get("Retry-After") or headers.get("retry-after")
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _first_vlan_dns(vlans: list[dict[str, Any]]) -> dict[str, Any]:
    for vlan in vlans:
        if "dnsNameservers" in vlan:
            return {"dnsNameservers": vlan.get("dnsNameservers")}
    return {}


def _enrich_vlan_vpn_mode(vlans: list[dict[str, Any]], vpn_settings: dict[str, Any]) -> None:
    local_subnets = vpn_settings.get("subnets") or vpn_settings.get("localSubnets") or []
    use_vpn_by_subnet = {
        item.get("localSubnet") or item.get("subnet"): item.get("useVpn")
        for item in local_subnets
        if isinstance(item, dict)
    }
    for vlan in vlans:
        subnet = vlan.get("subnet")
        if subnet in use_vpn_by_subnet:
            vlan["vpnModeEnabled"] = bool(use_vpn_by_subnet[subnet])
