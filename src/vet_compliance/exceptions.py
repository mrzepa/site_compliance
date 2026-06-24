from __future__ import annotations

import logging
import re
from typing import Any

from vet_compliance.models import AuditTarget

logger = logging.getLogger(__name__)


def apply_exceptions(targets: list[AuditTarget], config: dict[str, Any]) -> list[AuditTarget]:
    exceptions = config.get("exceptions", {})
    if not exceptions:
        return targets
    ignored: list[AuditTarget] = []
    kept: list[AuditTarget] = []
    for target in targets:
        if _is_ignored(target, exceptions):
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


def _matches_any(value: str, platform: str, rules: list[Any]) -> bool:
    for rule in rules:
        if isinstance(rule, str):
            if value == rule:
                return True
            continue
        if not isinstance(rule, dict):
            continue
        if rule.get("platform") and rule["platform"] != platform:
            continue
        if rule.get("name") and value == rule["name"]:
            return True
        if rule.get("regex") and re.search(rule["regex"], value or ""):
            return True
    return False

