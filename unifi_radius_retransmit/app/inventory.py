#!/usr/bin/env python
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.unifi_client import UnifiClient

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SiteCredential:
    site_name: str
    password: str
    username: str | None = None


def load_config(path: str | Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}
    return _apply_secret_config(config)


def _apply_secret_config(config: dict[str, Any]) -> dict[str, Any]:
    secret_config = config.get("secrets", {})
    secret_path = secret_config.get("vault_file") or secret_config.get("vault_yaml")
    if not secret_path:
        return config
    secrets = yaml.safe_load(_read_vault_or_plaintext(Path(secret_path))) or {}
    controller_secrets = secrets.get("unifi", {}).get("controllers", {})
    if not isinstance(controller_secrets, dict):
        raise ValueError("Secret file field unifi.controllers must be a mapping keyed by controller name.")
    for controller in config.get("unifi", {}).get("controllers", []):
        name = controller.get("name")
        if not name:
            continue
        secret_values = controller_secrets.get(name, {})
        if not isinstance(secret_values, dict):
            raise ValueError(f"Secret values for UniFi controller {name} must be a mapping.")
        for key in ("username", "password", "mfa_secret", "api_key"):
            if secret_values.get(key) not in (None, ""):
                controller[key] = secret_values[key]
    return config


def load_site_credentials(config: dict[str, Any]) -> list[SiteCredential]:
    sites_config = config["sites"]
    csv_path = Path(sites_config.get("vault_file") or sites_config["vault_csv"])
    content = _read_vault_or_plaintext(csv_path)
    rows = csv.DictReader(content.splitlines())
    credentials: list[SiteCredential] = []
    for index, row in enumerate(rows, start=2):
        site_name = (row.get("site_name") or "").strip()
        password = row.get("password") or ""
        username = (row.get("username") or "").strip() or None
        if not site_name or not password:
            raise ValueError(f"Missing site_name or password in {csv_path} line {index}")
        credentials.append(SiteCredential(site_name=site_name, password=password, username=username))
    return credentials


def _read_vault_or_plaintext(path: Path) -> str:
    raw = path.read_text(encoding="utf-8")
    if not raw.startswith("$ANSIBLE_VAULT;"):
        logger.warning("%s is not ansible-vault encrypted; encrypt it before production use.", path)
        return raw
    result = subprocess.run(
        ["ansible-vault", "view", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def build_inventory(config: dict[str, Any]) -> dict[str, Any]:
    credentials = load_site_credentials(config)
    wanted_by_name = {credential.site_name: credential for credential in credentials}
    matched_sites: set[str] = set()
    hostvars: dict[str, dict[str, Any]] = {}
    children: dict[str, Any] = {}

    unifi = config.get("unifi", {})
    timeout = int(unifi.get("request_timeout_seconds", 20))
    verify_tls = bool(unifi.get("verify_tls", False))
    ssh = config.get("ssh", {})
    ansible = config.get("ansible", {})
    ansible_connection = str(ansible.get("connection", "paramiko"))
    controllers = unifi.get("controllers", [])

    for controller_config in controllers:
        client = UnifiClient(controller_config, timeout=timeout, verify_tls=verify_tls)
        client.login()
        for site in client.sites():
            site_display_name = site.get("desc") or site.get("name") or site.get("_id") or site.get("id")
            credential = wanted_by_name.get(str(site_display_name))
            if not credential:
                continue
            matched_sites.add(credential.site_name)
            site_group = _safe_group_name(credential.site_name)
            children.setdefault(site_group, {"hosts": []})
            for device in client.devices(site):
                if not _is_switch(device):
                    continue
                address = device.get("ip")
                if not address:
                    logger.warning("Skipping switch without IP in site %s: %s", credential.site_name, device.get("name") or device.get("mac"))
                    continue
                host_key = _host_key(credential.site_name, device)
                children[site_group]["hosts"].append(host_key)
                hostvars[host_key] = {
                    "ansible_host": address,
                    "ansible_user": credential.username or ssh.get("username", "admin"),
                    "ansible_password": credential.password,
                    "ansible_port": int(ssh.get("port", 22)),
                    "ansible_connection": ansible_connection,
                    "ansible_ssh_common_args": "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
                    if ansible_connection == "ssh" and not ssh.get("host_key_checking", False)
                    else "",
                    "ansible_ssh_timeout": int(ssh.get("connect_timeout_seconds", 15)),
                    "ansible_timeout": int(ssh.get("connect_timeout_seconds", 15)),
                    "command_timeout_seconds": int(ssh.get("command_timeout_seconds", 60)),
                    "unifi_controller": client.name,
                    "unifi_site": credential.site_name,
                    "unifi_device_name": device.get("name") or device.get("hostname") or device.get("mac") or host_key,
                    "unifi_device_mac": device.get("mac"),
                }

    missing = sorted(set(wanted_by_name) - matched_sites)
    for site_name in missing:
        logger.error("No matching UniFi site found for configured site: %s", site_name)

    inventory = {
        "all": {"children": ["unifi_switches"]},
        "unifi_switches": {"children": sorted(children)},
        **children,
        "_meta": {"hostvars": hostvars},
    }
    return inventory


def _is_switch(device: dict[str, Any]) -> bool:
    device_type = str(device.get("type") or "").lower()
    model = str(device.get("model") or "").lower()
    return device_type == "usw" or model.startswith(("usw", "us-", "usl", "usw-"))


def _safe_group_name(value: str) -> str:
    safe = "".join(ch.lower() if ch.isalnum() else "_" for ch in value).strip("_")
    return f"site_{safe or 'unknown'}"


def _host_key(site_name: str, device: dict[str, Any]) -> str:
    raw = device.get("mac") or device.get("_id") or device.get("ip") or device.get("name") or "switch"
    safe = "".join(ch.lower() if ch.isalnum() else "_" for ch in f"{site_name}_{raw}").strip("_")
    return safe or "unifi_switch"


def main() -> None:
    parser = argparse.ArgumentParser(description="Build Ansible inventory from UniFi sites and an ansible-vault CSV.")
    parser.add_argument("--config", default=os.getenv("CONFIG_PATH", "config/config.yaml"))
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--host")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if args.host:
        print("{}")
        return
    try:
        inventory = build_inventory(load_config(args.config))
    except Exception as exc:
        logger.exception("Inventory generation failed")
        print(json.dumps({"_meta": {"hostvars": {}}, "all": {"hosts": []}, "error": str(exc)}))
        sys.exit(1)
    print(json.dumps(inventory, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
