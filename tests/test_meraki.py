from vet_compliance.connectors.meraki import _collect_network, _representative_appliance, filter_meraki_mx_targets
from vet_compliance.models import AuditTarget, DeviceContext


class Guard:
    def call(self, description, func, default=None, required=False, scope="global"):
        return func()


class Dashboard:
    class Networks:
        def getNetworkDevices(self, network_id):
            if network_id == "non-mx":
                return [{"model": "MS120", "serial": "Q2XX-SWITCH"}]
            return [{"model": "MX95", "serial": "Q2XX-EXAMPLE"}]

    class Appliance:
        def getNetworkApplianceVlans(self, network_id):
            return [
                {"id": "2", "name": "Management", "subnet": "172.16.48.0/26", "applianceIp": "172.16.48.1"},
            ]

        def getNetworkApplianceFirewallSettings(self, network_id):
            return {}

        def getNetworkApplianceVpnSiteToSiteVpn(self, network_id):
            return {}

    def __init__(self):
        self.networks = self.Networks()
        self.appliance = self.Appliance()


def test_collect_network_keeps_vlan_reference_for_mx_network():
    targets = _collect_network(Dashboard(), Guard(), {"id": "n1", "organizationId": "o1", "name": "Example Network"})

    assert len(targets) == 1
    assert targets[0].context.site_name == "Example Network"
    assert targets[0].sections["vlans"][0]["subnet"] == "172.16.48.0/26"
    assert targets[0].context.raw_device["model"] == "MX95"


def test_collect_network_skips_appliance_network_without_mx_device():
    targets = _collect_network(Dashboard(), Guard(), {"id": "non-mx", "organizationId": "o1", "name": "Switch Only"})

    assert targets == []


def test_representative_appliance_is_independent_of_input_order():
    mx = {"model": "MX95", "name": "MX", "serial": "Q2XX-0002"}
    switch = {"model": "MS120", "name": "Switch", "serial": "Q2XX-0001"}

    assert _representative_appliance([switch, mx]) == mx
    assert _representative_appliance([mx, switch]) == mx
    assert _representative_appliance([switch]) is None


def test_filter_meraki_mx_targets_removes_cached_non_mx_targets():
    mx = AuditTarget(
        context=DeviceContext("meraki", "dashboard", "mx", "MX Site", "mx", "MX", "appliance", {"model": "MX75"}),
        sections={},
    )
    switch_only = AuditTarget(
        context=DeviceContext("meraki", "dashboard", "sw", "Switch Site", "sw", "Switch", "appliance", {"model": "MS120"}),
        sections={},
    )
    unifi = AuditTarget(
        context=DeviceContext("unifi", "controller", "u", "UniFi Site", "u", "Site settings", "site", {"model": "USW"}),
        sections={},
    )

    assert filter_meraki_mx_targets([mx, switch_only, unifi]) == [mx, unifi]
