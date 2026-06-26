from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from vet_compliance.models import AuditTarget, DeviceContext


def load_targets_cache(path: str | Path) -> list[AuditTarget] | None:
    cache_path = Path(path)
    if not cache_path.exists():
        return None
    payload = json.loads(cache_path.read_text(encoding="utf-8"))
    return [_target_from_dict(item) for item in payload.get("targets", [])]


def write_targets_cache(path: str | Path, targets: list[AuditTarget]) -> None:
    cache_path = Path(path)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"targets": [_target_to_dict(target) for target in sorted(targets, key=_target_sort_key)]}
    tmp_path = cache_path.with_suffix(cache_path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    tmp_path.replace(cache_path)


def _target_to_dict(target: AuditTarget) -> dict[str, Any]:
    return {
        "context": asdict(target.context),
        "sections": target.sections,
    }


def _target_from_dict(data: dict[str, Any]) -> AuditTarget:
    context = DeviceContext(**data["context"])
    return AuditTarget(context=context, sections=data.get("sections", {}))


def _target_sort_key(target: AuditTarget) -> tuple[str, str, str, str]:
    ctx = target.context
    return (ctx.platform, ctx.site_name or "", ctx.device_name or "", ctx.device_id or "")
