from vet_compliance.reporting.writers import format_value


def test_meraki_interface_reference_formats_expected_and_found_separately():
    path = "vlans[100].dhcpguard_server"
    expected = {"$meraki_vlan_interface_ip": "100", "ip": "10.30.1.1"}

    assert format_value(expected, path, expected=True) == "Meraki VLAN 100 interface IP: 10.30.1.1"
    assert format_value(None, path, expected=False) == "Not found"
