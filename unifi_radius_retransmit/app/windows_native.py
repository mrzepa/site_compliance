from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import paramiko
from apscheduler.schedulers.blocking import BlockingScheduler
from prometheus_client import Gauge, start_http_server

from app.unifi_client import UnifiClient

logger = logging.getLogger(__name__)
COMMAND = "radius default-config retransmit 10 timeout 30"

LAST_RUN_TIMESTAMP = Gauge("radius_last_run_timestamp", "Unix timestamp of the last completed run.")
RUN_SUCCESS = Gauge("radius_last_run_success", "1 when the last run completed without switch failures.")
RUN_DURATION = Gauge("radius_last_run_duration_seconds", "Duration of the last run in seconds.")
SWITCH_TOTAL = Gauge("radius_switches_total", "Total switches targeted in the last run.")
SWITCH_FAILED = Gauge("radius_switches_failed", "Switches that failed in the last run.")
SITES_MISSING = Gauge("radius_sites_missing", "Configured sites not found in UniFi during the last discovery.")
SITE_SWITCH_TOTAL = Gauge("radius_site_switches_total", "Total switches targeted in the last run by site.", ["site"])
SITE_SWITCH_FAILED = Gauge("radius_site_switches_failed", "Switches that failed in the last run by site.", ["site"])
SITE_SWITCH_SUCCESS = Gauge("radius_site_switches_success", "Switches that succeeded in the last run by site.", ["site"])
SWITCH_STATUS = Gauge("radius_switch_status", "Per-switch status from the last run. 1 means success, 0 means failed.", ["site", "switch", "host"])


@dataclass(frozen=True)
class SiteSecret:
    site_name: str
    password: str
    username: str | None = None


@dataclass(frozen=True)
class SwitchTarget:
    site: str
    name: str
    host: str
    username: str
    password: str
    port: int


def load_env(path: str | Path = ".env") -> dict[str, str]:
    values = dict(os.environ)
    env_path = Path(path)
    if not env_path.exists():
        return values
    for line_number, raw_line in enumerate(env_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"Invalid .env line {line_number}: expected KEY=VALUE")
        key, value = line.split("=", 1)
        values[key.strip()] = _strip_env_quotes(value.strip())
    return values


def _strip_env_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def load_config(env_path: str | Path) -> dict[str, Any]:
    env = load_env(env_path)
    controllers = _load_controllers(env)
    sites = _load_sites(env)
    default_username = env.get("RADIUS_DEFAULT_USERNAME", "").strip()
    if not default_username and any(site.username is None for site in sites):
        raise ValueError("Set RADIUS_DEFAULT_USERNAME in .env or provide username for every RADIUS_SITES_JSON entry.")
    return {
        "controllers": controllers,
        "sites": sites,
        "default_username": default_username,
        "ssh_port": int(env.get("RADIUS_SSH_PORT", "22")),
        "connect_timeout": int(env.get("RADIUS_CONNECT_TIMEOUT_SECONDS", "15")),
        "command_timeout": int(env.get("RADIUS_COMMAND_TIMEOUT_SECONDS", "60")),
        "workers": int(env.get("RADIUS_WORKERS", "50")),
        "verify_tls": _env_bool(env.get("RADIUS_VERIFY_TLS", "false")),
        "request_timeout": int(env.get("RADIUS_REQUEST_TIMEOUT_SECONDS", "20")),
        "timezone": env.get("RADIUS_TIMEZONE", "UTC"),
        "run_on_start": _env_bool(env.get("RADIUS_RUN_ON_START", "true")),
        "daily_at": env.get("RADIUS_DAILY_AT", "03:00"),
        "metrics_port": int(env.get("RADIUS_METRICS_PORT", "9108")),
        "output_dir": Path(env.get("RADIUS_OUTPUT_DIR", "data")),
    }


def _load_controllers(env: dict[str, str]) -> list[dict[str, Any]]:
    if env.get("UNIFI_CONTROLLERS_JSON"):
        controllers = json.loads(env["UNIFI_CONTROLLERS_JSON"])
        if not isinstance(controllers, list):
            raise ValueError("UNIFI_CONTROLLERS_JSON must be a JSON list.")
        return controllers
    base_url = env.get("UNIFI_CONTROLLER_URL")
    if not base_url:
        raise ValueError("Set UNIFI_CONTROLLERS_JSON or UNIFI_CONTROLLER_URL in .env.")
    return [
        {
            "name": env.get("UNIFI_CONTROLLER_NAME") or base_url,
            "base_url": base_url,
            "username": env.get("UNIFI_USERNAME"),
            "password": env.get("UNIFI_PASSWORD"),
            "mfa_secret": env.get("UNIFI_MFA_SECRET"),
            "api_key": env.get("UNIFI_API_KEY"),
        }
    ]


def _load_sites(env: dict[str, str]) -> list[SiteSecret]:
    raw = env.get("RADIUS_SITES_JSON")
    if not raw:
        raise ValueError("Set RADIUS_SITES_JSON in .env.")
    rows = json.loads(raw)
    if not isinstance(rows, list):
        raise ValueError("RADIUS_SITES_JSON must be a JSON list.")
    sites: list[SiteSecret] = []
    for index, row in enumerate(rows, start=1):
        site_name = str(row.get("site_name") or "").strip()
        password = str(row.get("password") or "")
        username = str(row.get("username") or "").strip() or None
        if not site_name or not password:
            raise ValueError(f"RADIUS_SITES_JSON entry {index} is missing site_name or password.")
        sites.append(SiteSecret(site_name=site_name, password=password, username=username))
    return sites


def _env_bool(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "y", "on")


def discover_targets(config: dict[str, Any]) -> list[SwitchTarget]:
    wanted = {site.site_name: site for site in config["sites"]}
    targets: list[SwitchTarget] = []
    matched_sites: set[str] = set()
    for controller in config["controllers"]:
        client = UnifiClient(controller, timeout=config["request_timeout"], verify_tls=config["verify_tls"])
        client.login()
        for site in client.sites():
            site_name = str(site.get("desc") or site.get("name") or site.get("_id") or site.get("id"))
            secret = wanted.get(site_name)
            if not secret:
                continue
            matched_sites.add(site_name)
            for device in client.devices(site):
                if not _is_switch(device):
                    continue
                host = device.get("ip")
                if not host:
                    continue
                targets.append(
                    SwitchTarget(
                        site=site_name,
                        name=str(device.get("name") or device.get("hostname") or device.get("mac") or host),
                        host=str(host),
                        username=secret.username or config["default_username"],
                        password=secret.password,
                        port=config["ssh_port"],
                    )
                )
    missing_sites = sorted(set(wanted) - matched_sites)
    config["_missing_sites_count"] = len(missing_sites)
    for missing in missing_sites:
        logger.error("No matching UniFi site found for configured site: %s", missing)
    return targets


def _is_switch(device: dict[str, Any]) -> bool:
    device_type = str(device.get("type") or "").lower()
    model = str(device.get("model") or "").lower()
    return device_type == "usw" or model.startswith(("usw", "us-", "usl", "usw-"))


def run_job(config: dict[str, Any]) -> dict[str, Any]:
    started = time.time()
    config["output_dir"].mkdir(parents=True, exist_ok=True)
    targets = discover_targets(config)
    logger.info("Starting native RADIUS remediation against %s switches.", len(targets))
    results = []
    with ThreadPoolExecutor(max_workers=config["workers"]) as executor:
        futures = {executor.submit(run_switch, target, config): target for target in targets}
        for future in as_completed(futures):
            results.append(future.result())
    duration = time.time() - started
    failed = sum(1 for result in results if not result["success"])
    summary = {
        "completed_at": _format_completed_at(started + duration, config["timezone"]),
        "success": failed == 0,
        "returncode": 0 if failed == 0 else 1,
        "duration_seconds": round(duration, 3),
        "switches_total": len(targets),
        "switches_failed": failed,
        "results": results,
    }
    (config["output_dir"] / "last_run.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    _set_metrics(started + duration, duration, results)
    SITES_MISSING.set(config.get("_missing_sites_count", 0))
    return summary


def run_switch(target: SwitchTarget, config: dict[str, Any]) -> dict[str, Any]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            target.host,
            port=target.port,
            username=target.username,
            password=target.password,
            timeout=config["connect_timeout"],
            banner_timeout=config["connect_timeout"],
            auth_timeout=config["connect_timeout"],
            look_for_keys=False,
            allow_agent=False,
        )
        _, stdout, stderr = client.exec_command(COMMAND, timeout=config["command_timeout"])
        exit_status = stdout.channel.recv_exit_status()
        return {
            "site": target.site,
            "switch": target.name,
            "host": target.host,
            "success": exit_status == 0,
            "exit_status": exit_status,
            "stdout": stdout.read().decode(errors="replace")[-2000:],
            "stderr": stderr.read().decode(errors="replace")[-2000:],
        }
    except (paramiko.SSHException, socket.timeout, OSError) as exc:
        return {"site": target.site, "switch": target.name, "host": target.host, "success": False, "error": str(exc)}
    finally:
        client.close()


def _format_completed_at(timestamp: float, timezone_name: str) -> str:
    try:
        tzinfo = ZoneInfo(timezone_name) if timezone_name else None
    except ZoneInfoNotFoundError:
        tzinfo = None
    completed = datetime.fromtimestamp(timestamp, tzinfo) if tzinfo else datetime.fromtimestamp(timestamp).astimezone()
    return completed.strftime("%Y-%m-%d %H:%M:%S %Z")


def _set_metrics(completed_at: float, duration: float, results: list[dict[str, Any]]) -> None:
    failed = sum(1 for result in results if not result["success"])
    LAST_RUN_TIMESTAMP.set(completed_at)
    RUN_SUCCESS.set(1 if failed == 0 else 0)
    RUN_DURATION.set(duration)
    SWITCH_TOTAL.set(len(results))
    SWITCH_FAILED.set(failed)
    by_site: dict[str, dict[str, int]] = {}
    for result in results:
        site = result["site"]
        item = by_site.setdefault(site, {"total": 0, "failed": 0, "success": 0})
        item["total"] += 1
        item["success"] += 1 if result["success"] else 0
        item["failed"] += 0 if result["success"] else 1
        SWITCH_STATUS.labels(site=site, switch=result["switch"], host=result["host"]).set(1 if result["success"] else 0)
    for site, counts in by_site.items():
        SITE_SWITCH_TOTAL.labels(site=site).set(counts["total"])
        SITE_SWITCH_SUCCESS.labels(site=site).set(counts["success"])
        SITE_SWITCH_FAILED.labels(site=site).set(counts["failed"])


def main() -> None:
    parser = argparse.ArgumentParser(description="Windows-native UniFi RADIUS remediation without Ansible.")
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--once", action="store_true", help="Run once and exit instead of starting the scheduler.")
    parser.add_argument("--no-metrics", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
    config = load_config(args.env_file)
    if not args.no_metrics:
        start_http_server(config["metrics_port"])
    if args.once:
        summary = run_job(config)
        print(json.dumps({key: summary[key] for key in ("completed_at", "success", "returncode", "switches_total", "switches_failed", "duration_seconds")}, indent=2))
        sys.exit(0 if summary["success"] else 1)
    scheduler = BlockingScheduler(timezone=config["timezone"])
    hour, minute = [int(part) for part in str(config["daily_at"]).split(":", 1)]
    scheduler.add_job(run_job, "cron", hour=hour, minute=minute, args=[config], id="daily_radius_windows_native", max_instances=1)
    if config["run_on_start"]:
        run_job(config)
    logger.info("Windows-native scheduler started. Daily run time: %02d:%02d.", hour, minute)
    scheduler.start()


if __name__ == "__main__":
    main()
