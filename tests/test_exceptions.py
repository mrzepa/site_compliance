from vet_compliance.exceptions import apply_exceptions
from vet_compliance.models import AuditTarget, DeviceContext


def _target(platform: str, site: str, device: str) -> AuditTarget:
    return AuditTarget(
        context=DeviceContext(platform, "controller", "site-id", site, "device-id", device, "switch"),
        sections={},
    )


def test_ignored_device_by_exact_name():
    targets = [_target("meraki", "Lab", "LAB-SWITCH-01"), _target("meraki", "Prod", "MX1")]
    kept = apply_exceptions(targets, {"exceptions": {"ignored_devices": ["LAB-SWITCH-01"]}})
    assert [target.context.device_name for target in kept] == ["MX1"]


def test_ignored_site_by_regex_and_platform():
    targets = [_target("unifi", "Toronto LAB", "Switch1"), _target("meraki", "Toronto LAB", "MX1")]
    kept = apply_exceptions(targets, {"exceptions": {"ignored_sites": [{"platform": "unifi", "regex": "LAB"}]}})
    assert [target.context.platform for target in kept] == ["meraki"]
