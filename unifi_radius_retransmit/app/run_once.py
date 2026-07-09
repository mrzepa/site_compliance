from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from prometheus_client import start_http_server

from app.inventory import load_config
from app.scheduler import run_job


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the UniFi RADIUS remediation once without starting the scheduler.")
    parser.add_argument("--config", default=os.getenv("CONFIG_PATH", "config/config.yaml"))
    parser.add_argument("--metrics", action="store_true", help="Expose Prometheus metrics during the one-shot run.")
    args = parser.parse_args()

    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
    config = load_config(args.config)
    if args.metrics:
        start_http_server(int(config.get("metrics", {}).get("listen_port", 9108)))

    run_job(args.config)
    result = _load_result(config)
    if result:
        print(json.dumps(_summary(result), indent=2))
        sys.exit(0 if result.get("success") else 1)


def _load_result(config: dict) -> dict | None:
    result_path = Path(config.get("metrics", {}).get("output_dir", "data")) / "last_run.json"
    if not result_path.exists():
        return None
    return json.loads(result_path.read_text(encoding="utf-8"))


def _summary(result: dict) -> dict:
    return {
        "completed_at": result.get("completed_at"),
        "success": result.get("success"),
        "returncode": result.get("returncode"),
        "switches_total": result.get("switches_total"),
        "switches_failed": result.get("switches_failed"),
        "duration_seconds": result.get("duration_seconds"),
    }


if __name__ == "__main__":
    main()
