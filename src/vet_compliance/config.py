from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv


def load_yaml(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def load_app_config(path: str | Path, env_path: str | Path = ".env") -> dict[str, Any]:
    load_dotenv(env_path)
    config = load_yaml(path)
    config.setdefault("audit", {})
    config["audit"].setdefault("output_dir", "reports")
    config["audit"].setdefault("workers", {})
    config["audit"]["workers"].setdefault("controllers", 4)
    config["audit"]["workers"].setdefault("sites_per_controller", 8)
    config["audit"]["workers"].setdefault("meraki_networks", 1)
    config["audit"].setdefault("request_timeout_seconds", 20)
    config["audit"].setdefault("verify_tls", False)
    return config


def env_value(name: str | None, default: str | None = None) -> str | None:
    if not name:
        return default
    return os.getenv(name, default)
