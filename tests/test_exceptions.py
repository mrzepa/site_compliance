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


def test_ignored_site_exact_name_is_case_insensitive():
    targets = [_target("meraki", "BC - Coastland Veterinary Hospital", "MX1")]
    kept = apply_exceptions(targets, {"exceptions": {"ignored_sites": ["bc - coastland veterinary hospital"]}})
    assert kept == []


def test_ignored_meraki_site_also_ignores_matching_unifi_site_by_vlan2_subnet():
    meraki = AuditTarget(
        context=DeviceContext("meraki", "dashboard", "n1", "BC - Coastland Veterinary Hospital", "mx", "MX", "appliance"),
        sections={"vlans": [{"id": "2", "subnet": "172.16.48.0/26"}]},
    )
    unifi = AuditTarget(
        context=DeviceContext("unifi", "controller", "site-id", "Coastland VH (BCCVH)", "site", "Site settings", "site", {"ip": "172.16.48.10"}),
        sections={"vlans": []},
    )
    unrelated = AuditTarget(
        context=DeviceContext("unifi", "controller", "site-2", "Other Site", "site", "Site settings", "site", {"ip": "172.16.49.10"}),
        sections={"vlans": []},
    )

    kept = apply_exceptions(
        [meraki, unifi, unrelated],
        {"exceptions": {"ignored_sites": ["BC - Coastland Veterinary Hospital"]}},
    )

    assert kept == [unrelated]
