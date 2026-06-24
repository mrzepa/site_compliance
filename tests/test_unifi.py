from vet_compliance.connectors.unifi import _collect_site, _normalize_unifi_networks, collapse_unifi_site_targets
from vet_compliance.models import AuditTarget, DeviceContext


def test_normalize_unifi_networks_maps_dhcp_guard_servers():
    networks = [
        {
            "vlan": 100,
            "dhcpguard_enabled": True,
            "dhcpd_ip_1": "10.30.1.1",
            "dhcpd_ip_2": "",
            "dhcpd_ip_3": None,
            "dhcpd_ip_4": "10.30.1.2",
        }
    ]

    _normalize_unifi_networks(networks)

    assert networks[0]["dhcpguard_server"] == ["10.30.1.1", "10.30.1.2"]


def test_collect_site_returns_one_site_target_for_switch_settings():
    class Client:
        name = "controller-a"

        def resource(self, resource_name, site):
            resources = {
                "device": [
                    {"type": "uap", "name": "AP"},
                    {"type": "usw", "name": "Switch A", "ip": "10.30.2.10"},
                    {"type": "usw", "name": "Switch B", "ip": "10.30.2.11"},
                ],
                "networkconf": [{"vlan": 100, "name": "Secure"}],
                "setting": [],
                "wlanconf": [],
                "portconf": [],
                "radiusprofile": [],
                "apgroups": [],
            }
            return resources[resource_name]

    targets = _collect_site(Client(), {"_id": "site-1", "desc": "Example Site"})

    assert len(targets) == 1
    assert targets[0].context.device_name == "Site settings"
    assert targets[0].context.device_type == "site"
    assert targets[0].context.raw_device["ip"] == "10.30.2.10"


def test_collapse_unifi_site_targets_deduplicates_cached_switch_targets():
    first = AuditTarget(
        context=DeviceContext("unifi", "controller-a", "site-1", "Example Site", "switch-a", "Switch A", "switch", {"ip": "10.30.2.10"}),
        sections={"vlans": [{"vlan": 100, "name": "Secure"}]},
    )
    second = AuditTarget(
        context=DeviceContext("unifi", "controller-a", "site-1", "Example Site", "switch-b", "Switch B", "switch", {"ip": "10.30.2.11"}),
        sections={"vlans": [{"vlan": 100, "name": "Secure"}]},
    )

    targets = collapse_unifi_site_targets([first, second])

    assert len(targets) == 1
    assert targets[0].context.device_name == "Site settings"
