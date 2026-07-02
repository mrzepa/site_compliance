from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from apscheduler.schedulers.blocking import BlockingScheduler
from prometheus_client import Gauge, start_http_server

from app.inventory import build_inventory, load_config

logger = logging.getLogger(__name__)

RUN_SUCCESS = Gauge("radius_last_run_success", "1 when the last run completed without switch failures.")
LAST_RUN_TIMESTAMP = Gauge("radius_last_run_timestamp", "Unix timestamp of the last completed run.")
RUN_DURATION = Gauge("radius_last_run_duration_seconds", "Duration of the last run in seconds.")
SWITCH_TOTAL = Gauge("radius_switches_total", "Total switches targeted in the last run.")
SWITCH_FAILED = Gauge("radius_switches_failed", "Switches that failed in the last run.")
SITE_MISSING = Gauge("radius_sites_missing", "Configured sites not found on the UniFi controller in the last run.")
SITE_SWITCH_TOTAL = Gauge("radius_site_switches_total", "Total switches targeted in the last run by site.", ["site"])
SITE_SWITCH_FAILED = Gauge("radius_site_switches_failed", "Switches that failed in the last run by site.", ["site"])
SITE_SWITCH_SUCCESS = Gauge("radius_site_switches_success", "Switches that succeeded in the last run by site.", ["site"])
SWITCH_STATUS = Gauge(
    "radius_switch_status",
    "Per-switch status from the last run. 1 means success, 0 means failed or unreachable.",
    ["site", "switch", "host"],
)
_SITE_LABELS: set[str] = set()
_SWITCH_LABELS: set[tuple[str, str, str]] = set()


def run_job(config_path: str) -> None:
    started = time.time()
    config = load_config(config_path)
    timezone_name = str(config.get("scheduler", {}).get("timezone", "") or "")
    output_dir = Path(config.get("metrics", {}).get("output_dir", "data"))
    output_dir.mkdir(parents=True, exist_ok=True)
    result_path = output_dir / "last_run.json"

    try:
        inventory = build_inventory(config)
    except Exception as exc:
        logger.exception("Inventory generation failed")
        _record_failure(result_path, started, f"inventory failed: {exc}", timezone_name)
        return

    target_count = _target_count(inventory)
    ansible_env = os.environ.copy()
    ansible_env["ANSIBLE_FORKS"] = str(config.get("ansible", {}).get("forks", 50))
    ansible_env["CONFIG_PATH"] = config_path
    ansible_env["PYTHONPATH"] = str(Path.cwd())
    if not config.get("ssh", {}).get("host_key_checking", False):
        ansible_env["ANSIBLE_HOST_KEY_CHECKING"] = "False"

    playbook = ["ansible-playbook", "-i", "app/inventory.py", "playbooks/radius_default_config.yml"]
    logger.info("Starting RADIUS retransmit remediation against %s switches.", target_count)
    completed = subprocess.run(playbook, capture_output=True, text=True, env=ansible_env)
    duration = time.time() - started
    recap = _recap_by_host(completed.stdout)
    site_metrics = _site_counts(inventory, recap)
    ansible_inventory_failed = _ansible_inventory_failed(completed.stdout, completed.stderr)
    failed = target_count if ansible_inventory_failed else sum(item["failed"] for item in site_metrics[0].values())
    success = completed.returncode == 0 and failed == 0 and not ansible_inventory_failed
    result = {
        "completed_at": _format_completed_at(started + duration, timezone_name),
        "success": success,
        "returncode": completed.returncode,
        "duration_seconds": round(duration, 3),
        "switches_total": target_count,
        "switches_failed": failed,
        "stdout_tail": completed.stdout[-8000:],
        "stderr_tail": completed.stderr[-8000:],
    }
    result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    _set_metrics(success, started + duration, duration, target_count, failed, _missing_site_count(completed.stderr), site_metrics)
    if success:
        logger.info("RADIUS retransmit remediation completed successfully.")
    else:
        logger.error("RADIUS retransmit remediation completed with failures. See %s.", result_path)


def _record_failure(result_path: Path, started: float, error: str, timezone_name: str) -> None:
    duration = time.time() - started
    result_path.write_text(
        json.dumps(
            {
                "completed_at": _format_completed_at(started + duration, timezone_name),
                "success": False,
                "returncode": 1,
                "duration_seconds": round(duration, 3),
                "switches_total": 0,
                "switches_failed": 0,
                "error": error[-8000:],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    _set_metrics(False, time.time(), duration, 0, 0, _missing_site_count(error), ({}, set()))


def _format_completed_at(timestamp: float, timezone_name: str) -> str:
    try:
        tzinfo = ZoneInfo(timezone_name) if timezone_name else None
    except ZoneInfoNotFoundError:
        logger.warning("Unknown scheduler timezone %s; using container local timezone for completed_at.", timezone_name)
        tzinfo = None
    if tzinfo:
        completed = datetime.fromtimestamp(timestamp, tzinfo)
    else:
        completed = datetime.fromtimestamp(timestamp).astimezone()
    return completed.strftime("%Y-%m-%d %H:%M:%S %Z")


def _target_count(inventory: dict) -> int:
    return len(inventory.get("_meta", {}).get("hostvars", {}))


def _recap_by_host(stdout: str) -> dict[str, dict[str, int]]:
    recap: dict[str, dict[str, int]] = {}
    for line in stdout.splitlines():
        if line.startswith("PLAY RECAP"):
            recap = {}
        if ": " in line and "failed=" in line:
            host = line.split(":", 1)[0].strip()
            values: dict[str, int] = {}
            for part in line.split():
                if "=" in part:
                    key, value = part.split("=", 1)
                    if value.isdigit():
                        values[key] = int(value)
            if host:
                recap[host] = values
    return recap


def _site_counts(inventory: dict, recap: dict[str, dict[str, int]]) -> tuple[dict[str, dict[str, int]], set[tuple[str, str, str, int]]]:
    counts: dict[str, dict[str, int]] = {}
    switch_statuses: set[tuple[str, str, str, int]] = set()
    hostvars = inventory.get("_meta", {}).get("hostvars", {})
    for host, vars_ in hostvars.items():
        site = str(vars_.get("unifi_site") or "unknown")
        switch = str(vars_.get("unifi_device_name") or host)
        address = str(vars_.get("ansible_host") or host)
        values = recap.get(host, {})
        failed = int(values.get("failed", 0)) + int(values.get("unreachable", 0))
        ok = int(values.get("ok", 0))
        status = 1 if failed == 0 and ok > 0 else 0
        item = counts.setdefault(site, {"total": 0, "failed": 0, "success": 0})
        item["total"] += 1
        item["failed"] += 0 if status else 1
        item["success"] += status
        switch_statuses.add((site, switch, address, status))
    return counts, switch_statuses


def _missing_site_count(text: str) -> int:
    return sum(1 for line in text.splitlines() if "No matching UniFi site found for configured site:" in line)


def _ansible_inventory_failed(stdout: str, stderr: str) -> bool:
    text = f"{stdout}\n{stderr}"
    markers = (
        "Unable to parse",
        "No inventory was parsed",
        "provided hosts list is empty",
        "skipping: no hosts matched",
    )
    return any(marker in text for marker in markers)


def _set_metrics(
    success: bool,
    completed_at: float,
    duration: float,
    total: int,
    failed: int,
    missing: int,
    site_counts: tuple[dict[str, dict[str, int]], set[tuple[str, str, str, int]]],
) -> None:
    RUN_SUCCESS.set(1 if success else 0)
    LAST_RUN_TIMESTAMP.set(completed_at)
    RUN_DURATION.set(duration)
    SWITCH_TOTAL.set(total)
    SWITCH_FAILED.set(failed)
    SITE_MISSING.set(missing)
    counts_by_site, switch_statuses = site_counts
    _remove_stale_site_labels(set(counts_by_site))
    _remove_stale_switch_labels({(site, switch, host) for site, switch, host, _ in switch_statuses})
    for site, counts in counts_by_site.items():
        SITE_SWITCH_TOTAL.labels(site=site).set(counts["total"])
        SITE_SWITCH_FAILED.labels(site=site).set(counts["failed"])
        SITE_SWITCH_SUCCESS.labels(site=site).set(counts["success"])
    for site, switch, host, status in switch_statuses:
        SWITCH_STATUS.labels(site=site, switch=switch, host=host).set(status)


def _remove_stale_site_labels(current_sites: set[str]) -> None:
    global _SITE_LABELS
    for site in _SITE_LABELS - current_sites:
        SITE_SWITCH_TOTAL.remove(site)
        SITE_SWITCH_FAILED.remove(site)
        SITE_SWITCH_SUCCESS.remove(site)
    _SITE_LABELS = current_sites


def _remove_stale_switch_labels(current_switches: set[tuple[str, str, str]]) -> None:
    global _SWITCH_LABELS
    for site, switch, host in _SWITCH_LABELS - current_switches:
        SWITCH_STATUS.remove(site, switch, host)
    _SWITCH_LABELS = current_switches


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
    config_path = os.getenv("CONFIG_PATH", "config/config.yaml")
    config = load_config(config_path)
    metrics_port = int(config.get("metrics", {}).get("listen_port", 9108))
    start_http_server(metrics_port)
    scheduler_config = config.get("scheduler", {})
    scheduler = BlockingScheduler(timezone=scheduler_config.get("timezone", "UTC"))
    hour, minute = [int(part) for part in str(scheduler_config.get("daily_at", "03:00")).split(":", 1)]
    scheduler.add_job(run_job, "cron", hour=hour, minute=minute, args=[config_path], id="daily_radius_retransmit", max_instances=1)
    if scheduler_config.get("run_on_start", True):
        run_job(config_path)
    logger.info("Scheduler started. Daily run time: %02d:%02d.", hour, minute)
    scheduler.start()


if __name__ == "__main__":
    main()
