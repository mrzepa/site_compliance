from __future__ import annotations

import base64
import binascii
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import pyotp
import requests
from urllib3.exceptions import InsecureRequestWarning

from vet_compliance.config import env_value
from vet_compliance.models import AuditTarget, DeviceContext

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
logger = logging.getLogger(__name__)


RESOURCE_ENDPOINTS = {
    "networkconf": ["/proxy/network/api/s/{site}/rest/networkconf", "/api/s/{site}/rest/networkconf"],
    "portconf": ["/proxy/network/api/s/{site}/rest/portconf", "/api/s/{site}/rest/portconf"],
    "radiusprofile": ["/proxy/network/api/s/{site}/rest/radiusprofile", "/api/s/{site}/rest/radiusprofile"],
    "setting": ["/proxy/network/api/s/{site}/rest/setting", "/api/s/{site}/rest/setting"],
    "wlanconf": ["/proxy/network/api/s/{site}/rest/wlanconf", "/api/s/{site}/rest/wlanconf"],
    "apgroups": ["/proxy/network/v2/api/site/{site}/apgroups"],
    "device": ["/proxy/network/api/s/{site}/stat/device", "/api/s/{site}/stat/device"],
}


class UnifiClient:
    def __init__(self, controller: dict[str, Any], timeout: int = 20, verify_tls: bool = False):
        self.name = controller.get("name") or controller["base_url"]
        self.base_url = controller["base_url"].rstrip("/")
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.api_key = env_value(controller.get("api_key_env"))
        self.username = env_value(controller.get("username_env", "UNIFI_USERNAME"))
        self.password = env_value(controller.get("password_env", "UNIFI_PASSWORD"))
        self.mfa_secret = env_value(controller.get("mfa_secret_env", "UNIFI_MFA_SECRET"))
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({"X-API-KEY": self.api_key, "Accept": "application/json"})

    def login(self) -> None:
        if self.api_key:
            return
        self.login_with_session()

    def login_with_session(self) -> None:
        if not self.username or not self.password:
            raise ValueError(f"Missing UniFi credentials for {self.name}")
        endpoints = ["/api/auth/login", "/api/login"]
        payload: dict[str, Any] = {"username": self.username, "password": self.password, "rememberMe": False}
        if self.mfa_secret:
            mfa_secret = "".join(self.mfa_secret.split())
            try:
                payload["token"] = pyotp.TOTP(mfa_secret).now()
            except binascii.Error as exc:
                raise ValueError(
                    f"UNIFI_MFA_SECRET for {self.name} must be a base32 TOTP seed, not a one-time code or recovery code."
                ) from exc
        for endpoint in endpoints:
            response = self.session.post(
                f"{self.base_url}{endpoint}",
                json=payload,
                timeout=self.timeout,
                verify=self.verify_tls,
            )
            if response.status_code == 200:
                self._set_csrf_header()
                return
        raise RuntimeError(f"Unable to authenticate to UniFi controller {self.name}")

    def _set_csrf_header(self) -> None:
        token_cookie = self.session.cookies.get("TOKEN")
        if not token_cookie:
            return
        try:
            payload = token_cookie.split(".")[1]
            payload += "=" * (4 - len(payload) % 4)
            decoded = json.loads(base64.b64decode(payload))
            csrf = decoded.get("csrfToken")
            if csrf:
                self.session.headers.update({"X-CSRF-Token": csrf})
        except Exception:
            logger.debug("Unable to decode UniFi CSRF token", exc_info=True)

    def get_json(self, endpoint: str, params: dict[str, Any] | None = None) -> Any:
        response = self.session.get(
            f"{self.base_url}{endpoint}",
            params=params,
            timeout=self.timeout,
            verify=self.verify_tls,
        )
        response.raise_for_status()
        data = response.json()
        if isinstance(data, dict) and data.get("meta", {}).get("rc") == "ok":
            return data.get("data", [])
        if isinstance(data, dict) and "data" in data:
            return data["data"]
        return data

    def sites(self) -> list[dict[str, Any]]:
        candidates = ["/proxy/network/api/self/sites", "/api/self/sites"]
        if self.api_key:
            candidates = ["/proxy/network/integration/v1/sites"]
        last_error: Exception | None = None
        for endpoint in candidates:
            try:
                if endpoint.endswith("/sites") and "integration" in endpoint:
                    return self._paginated_sites(endpoint)
                sites = self.get_json(endpoint)
                if isinstance(sites, list):
                    return sites
            except Exception as exc:
                last_error = exc
        if self.api_key:
            logger.warning("UniFi API key failed for %s; falling back to session login.", self.name)
            self.api_key = None
            self.session.headers.pop("X-API-KEY", None)
            self.login_with_session()
            return self.sites()
        raise RuntimeError(f"Unable to list UniFi sites for {self.name}: {last_error}")

    def _paginated_sites(self, endpoint: str) -> list[dict[str, Any]]:
        all_sites: list[dict[str, Any]] = []
        offset = 0
        while True:
            response = self.session.get(
                f"{self.base_url}{endpoint}",
                params={"limit": 100, "offset": offset},
                timeout=self.timeout,
                verify=self.verify_tls,
            )
            response.raise_for_status()
            payload = response.json()
            data = payload.get("data", []) if isinstance(payload, dict) else payload
            all_sites.extend(data)
            if len(data) < 100:
                return all_sites
            offset += 100

    def resource(self, resource_name: str, site: dict[str, Any]) -> list[dict[str, Any]]:
        tokens = [site.get("name"), site.get("_id"), site.get("id")]
        for token in [item for item in tokens if item]:
            for template in RESOURCE_ENDPOINTS[resource_name]:
                try:
                    data = self.get_json(template.format(site=token))
                    if isinstance(data, list):
                        return data
                except Exception:
                    logger.debug("Failed UniFi resource lookup", exc_info=True)
        return []


def collect_unifi_targets(config: dict[str, Any]) -> list[AuditTarget]:
    unifi_config = config.get("unifi", {})
    if not unifi_config.get("enabled", False):
        return []
    audit = config.get("audit", {})
    workers = audit.get("workers", {})
    timeout = int(audit.get("request_timeout_seconds", 20))
    verify_tls = bool(audit.get("verify_tls", False))
    controllers = unifi_config.get("controllers", [])
    targets: list[AuditTarget] = []
    with ThreadPoolExecutor(max_workers=int(workers.get("controllers", 4))) as executor:
        futures = [executor.submit(_collect_controller, c, timeout, verify_tls, int(workers.get("sites_per_controller", 8))) for c in controllers]
        for future in as_completed(futures):
            targets.extend(future.result())
    return sorted(targets, key=_target_sort_key)


def _collect_controller(controller: dict[str, Any], timeout: int, verify_tls: bool, site_workers: int) -> list[AuditTarget]:
    client = UnifiClient(controller, timeout=timeout, verify_tls=verify_tls)
    client.login()
    include = set(controller.get("include_sites") or [])
    exclude = set(controller.get("exclude_sites") or [])
    max_sites = controller.get("max_sites")
    sites = [
        site for site in client.sites()
        if (not include or site.get("desc") in include or site.get("name") in include)
        and site.get("desc") not in exclude
        and site.get("name") not in exclude
    ]
    sites = sorted(sites, key=_site_sort_key)
    if max_sites:
        sites = sites[: int(max_sites)]
    logger.info("Collecting UniFi data from %s sites on %s.", len(sites), client.name)
    targets: list[AuditTarget] = []
    with ThreadPoolExecutor(max_workers=site_workers) as executor:
        futures = [executor.submit(_collect_site, client, site) for site in sites]
        for future in as_completed(futures):
            targets.extend(future.result())
    return sorted(targets, key=_target_sort_key)


def _collect_site(client: UnifiClient, site: dict[str, Any]) -> list[AuditTarget]:
    devices = client.resource("device", site)
    networks = client.resource("networkconf", site)
    settings = client.resource("setting", site)
    wlan_conf = client.resource("wlanconf", site)
    port_profiles = client.resource("portconf", site)
    radius_profiles = client.resource("radiusprofile", site)
    ap_groups = client.resource("apgroups", site) if "apgroups" in RESOURCE_ENDPOINTS else []
    _normalize_unifi_networks(networks)
    _enrich_unifi_names(networks, settings, wlan_conf, port_profiles, radius_profiles, ap_groups)
    dns_settings = _dns_from_networks(networks)
    site_name = site.get("desc") or site.get("name") or "unknown"
    switch = _representative_switch(devices)
    offline_switches = _offline_switches(devices)
    if switch is None:
        return []
    ctx = DeviceContext(
        platform="unifi",
        controller=client.name,
        site_id=site.get("_id") or site.get("id"),
        site_name=site_name,
        device_id=site.get("_id") or site.get("id") or site.get("name"),
        device_name="Site settings",
        device_type="site",
        raw_device=switch,
    )
    return [
        AuditTarget(
            context=ctx,
            sections={
                "vlans": networks,
                "dns_settings": dns_settings,
                "wifi_settings": wlan_conf,
                "port_profiles": port_profiles,
                "radius_profiles": radius_profiles,
                "settings": settings,
                "offline_devices": offline_switches,
            },
        )
    ]


def collapse_unifi_site_targets(targets: list[AuditTarget]) -> list[AuditTarget]:
    collapsed: list[AuditTarget] = []
    unifi_sites: dict[tuple[str | None, str | None, str], list[AuditTarget]] = {}
    for target in sorted(targets, key=_target_sort_key):
        if target.context.platform != "unifi":
            collapsed.append(target)
            continue
        site_key = (target.context.controller, target.context.site_id, target.context.site_name)
        unifi_sites.setdefault(site_key, []).append(target)
    for site_targets in unifi_sites.values():
        target = site_targets[0]
        representative = _representative_switch([item.context.raw_device for item in site_targets if item.context.raw_device]) or target.context.raw_device
        offline_devices = _offline_switches([item.context.raw_device for item in site_targets if item.context.raw_device])
        if not offline_devices:
            offline_devices = target.sections.get("offline_devices", [])
        collapsed.append(
            AuditTarget(
                context=DeviceContext(
                    platform=target.context.platform,
                    controller=target.context.controller,
                    site_id=target.context.site_id,
                    site_name=target.context.site_name,
                    device_id=target.context.site_id or target.context.site_name,
                    device_name="Site settings",
                    device_type="site",
                    raw_device=representative,
                ),
                sections={
                    **target.sections,
                    "offline_devices": offline_devices,
                },
            )
        )
    return sorted(collapsed, key=_target_sort_key)


def _representative_switch(devices: list[dict[str, Any]]) -> dict[str, Any] | None:
    switches = [
        device
        for device in devices
        if str(device.get("type", "")).lower() in {"usw", "switch"}
    ]
    if not switches:
        return None
    switches = sorted(switches, key=_switch_sort_key)
    return next((device for device in switches if _is_online(device) and _device_management_ip(device)), None) or next(
        (device for device in switches if _is_online(device)),
        None,
    ) or next((device for device in switches if _device_management_ip(device)), switches[0])


def _offline_switches(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        _offline_device_summary(device)
        for device in sorted(devices, key=_switch_sort_key)
        if str(device.get("type", "")).lower() in {"usw", "switch"} and not _is_online(device)
    ]


def _offline_device_summary(device: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": device.get("name") or device.get("hostname") or device.get("mac") or "unknown",
        "ip": _device_management_ip(device),
        "last_seen": device.get("disconnected_at") or device.get("last_seen") or device.get("last_seen_at"),
    }


def _is_online(device: dict[str, Any]) -> bool:
    if device.get("state") is not None:
        return int(device.get("state") or 0) == 1
    if device.get("disconnected_at") or device.get("start_disconnected_millis"):
        return False
    return bool(device.get("connected_at") or device.get("ip"))


def _site_sort_key(site: dict[str, Any]) -> tuple[str, str, str]:
    return (str(site.get("desc") or ""), str(site.get("name") or ""), str(site.get("_id") or site.get("id") or ""))


def _switch_sort_key(device: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(_device_management_ip(device) or ""),
        str(device.get("name") or device.get("hostname") or ""),
        str(device.get("mac") or device.get("_id") or ""),
    )


def _target_sort_key(target: AuditTarget) -> tuple[str, str, str, str]:
    ctx = target.context
    return (ctx.platform, ctx.site_name or "", ctx.device_name or "", ctx.device_id or "")


def _device_management_ip(device: dict[str, Any]) -> str | None:
    for key in ("ip", "last_ip", "fixed_ip", "connect_request_ip"):
        if device.get(key):
            return device[key]
    for entry in device.get("network_table") or []:
        if isinstance(entry, dict) and entry.get("ip"):
            return entry["ip"]
    return None


def _enrich_unifi_names(
    networks: list[dict[str, Any]],
    settings: list[dict[str, Any]],
    wlan_conf: list[dict[str, Any]],
    port_profiles: list[dict[str, Any]],
    radius_profiles: list[dict[str, Any]],
    ap_groups: list[dict[str, Any]],
) -> None:
    network_names = {item.get("_id"): item.get("name") for item in networks if item.get("_id")}
    radius_names = {item.get("_id"): item.get("name") for item in radius_profiles if item.get("_id")}
    ap_group_names = {item.get("_id"): item.get("name") for item in ap_groups if item.get("_id")}
    for wlan in wlan_conf:
        wlan["networkconf_name"] = network_names.get(wlan.get("networkconf_id"))
        wlan["radiusprofile_name"] = radius_names.get(wlan.get("radiusprofile_id"))
        wlan["ap_group_names"] = [ap_group_names.get(group_id, group_id) for group_id in wlan.get("ap_group_ids", [])]
    for profile in port_profiles:
        profile["native_networkconf_name"] = network_names.get(profile.get("native_networkconf_id"))
        profile["voice_networkconf_name"] = network_names.get(profile.get("voice_networkconf_id"))
    for setting in settings:
        setting["radiusprofile_name"] = radius_names.get(setting.get("radiusprofile_id"))
        setting["dot1x_fallback_networkconf_name"] = network_names.get(setting.get("dot1x_fallback_networkconf_id"))


def _dns_from_networks(networks: list[dict[str, Any]]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for network in networks:
        for key in ("dhcpd_dns_1", "dhcpd_dns_2", "dhcpd_dns_3", "dhcpd_dns_4"):
            if key in network and key not in merged:
                merged[key] = network[key]
    return merged


def _normalize_unifi_networks(networks: list[dict[str, Any]]) -> None:
    for network in networks:
        trusted_servers = [
            network[key]
            for key in ("dhcpd_ip_1", "dhcpd_ip_2", "dhcpd_ip_3", "dhcpd_ip_4")
            if network.get(key)
        ]
        if trusted_servers and "dhcpguard_server" not in network:
            network["dhcpguard_server"] = trusted_servers
