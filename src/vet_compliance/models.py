from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class DeviceContext:
    platform: str
    controller: str | None
    site_id: str | None
    site_name: str
    device_id: str | None
    device_name: str
    device_type: str
    raw_device: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Finding:
    severity: str
    platform: str
    site: str
    device: str
    section: str
    message: str
    expected: Any = None
    actual: Any = None
    path: str | None = None


@dataclass
class AuditTarget:
    context: DeviceContext
    sections: dict[str, Any]


@dataclass
class AuditReport:
    findings: list[Finding]
    total_devices: int
    compliant_devices: int
    total_sites: int = 0
    compliant_sites: int = 0

    @property
    def compliance_percent(self) -> float:
        if self.total_devices == 0:
            return 100.0
        return round((self.compliant_devices / self.total_devices) * 100, 2)

    @property
    def site_compliance_percent(self) -> float:
        if self.total_sites == 0:
            return 100.0
        return round((self.compliant_sites / self.total_sites) * 100, 2)
