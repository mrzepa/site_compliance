from ipaddress import ip_network

from vet_compliance.compliance.engine import ComplianceEngine
from vet_compliance.models import AuditTarget, DeviceContext


def test_strict_items_flag_unexpected_vlan():
    rules = {
        "defaults": {"strict": True},
        "profiles": {
            "p": {
                "platform": "unifi",
                "checks": {"vlans": {"key": "vlan", "items": [{"vlan": 2, "name": "Management"}]}},
            }
        },
    }
    target = AuditTarget(
        context=DeviceContext("unifi", "c", "s1", "Site", "d1", "Switch", "switch"),
        sections={"vlans": [{"vlan": 2, "name": "Management"}, {"vlan": 5, "name": "Extra"}]},
    )
    report = ComplianceEngine(rules).audit([target])
    assert report.findings[0].message == "Unexpected vlans item 5"


def test_strict_items_can_ignore_known_extra_vlan():
    rules = {
        "defaults": {"strict": True},
        "profiles": {
            "p": {
                "platform": "unifi",
                "checks": {
                    "vlans": {
                        "key": "vlan",
                        "ignore_items": [1],
                        "items": [{"vlan": 2, "name": "Management"}],
                    }
                },
            }
        },
    }
    target = AuditTarget(
        context=DeviceContext("unifi", "c", "s1", "Site", "d1", "Switch", "switch"),
        sections={"vlans": [{"vlan": 1, "name": "Default"}, {"vlan": 2, "name": "Management"}]},
    )
    report = ComplianceEngine(rules).audit([target])
    assert report.findings == []


def test_vlan_name_comparison_is_case_insensitive():
    rules = {
        "profiles": {
            "p": {
                "platform": "unifi",
                "checks": {"vlans": {"key": "vlan", "items": [{"vlan": 2, "name": "Management"}]}},
            }
        },
    }
    target = AuditTarget(
        context=DeviceContext("unifi", "c", "s1", "Site", "d1", "Switch", "switch"),
        sections={"vlans": [{"vlan": 2, "name": "management"}]},
    )
    report = ComplianceEngine(rules).audit([target])
    assert report.findings == []


def test_vlan_name_one_of_comparison_is_case_insensitive():
    rules = {
        "profiles": {
            "p": {
                "platform": "unifi",
                "checks": {
                    "vlans": {
                        "key": "vlan",
                        "items": [
                            {
                                "vlan": 99,
                                "name": {"$one_of": ["Trunk Native", "Trunk_Native"]},
                            }
                        ],
                    }
                },
            }
        },
    }
    target = AuditTarget(
        context=DeviceContext("unifi", "c", "s1", "Site", "d1", "Switch", "switch"),
        sections={"vlans": [{"vlan": 99, "name": "trunk_native"}]},
    )
    report = ComplianceEngine(rules).audit([target])
    assert report.findings == []


def test_wifi_settings_name_comparison_is_case_insensitive():
    rules = {
        "profiles": {
            "p": {
                "platform": "unifi",
                "checks": {
                    "wifi_settings": {
                        "key": "name",
                        "items": [
                            {
                                "name": "VS_Guest",
                                "networkconf_name": "Guest",
                            }
                        ],
                    }
                },
            }
        },
    }
    target = AuditTarget(
        context=DeviceContext("unifi", "c", "s1", "Site", "d1", "Site settings", "site"),
        sections={"wifi_settings": [{"name": "vs_guest", "networkconf_name": "Guest"}]},
    )
    report = ComplianceEngine(rules).audit([target])
    assert report.findings == []


def test_wifi_settings_ignore_items_are_case_insensitive():
    rules = {
        "profiles": {
            "p": {
                "platform": "unifi",
                "checks": {
                    "wifi_settings": {
                        "strict": True,
                        "key": "name",
                        "ignore_items": ["VS_IOT"],
                        "items": [{"name": "VS_Guest"}],
                    }
                },
            }
        },
    }
    target = AuditTarget(
        context=DeviceContext("unifi", "c", "s1", "Site", "d1", "Site settings", "site"),
        sections={"wifi_settings": [{"name": "VS_Guest"}, {"name": "vs_iot"}]},
    )
    report = ComplianceEngine(rules).audit([target])
    assert report.findings == []


def test_offline_unifi_devices_create_site_finding():
    rules = {"profiles": {"p": {"platform": "unifi", "checks": {}}}}
    target = AuditTarget(
        context=DeviceContext("unifi", "c", "s1", "Site", "d1", "Site settings", "site"),
        sections={"offline_devices": [{"name": "Offline Switch", "ip": "10.30.2.50", "last_seen": 123}]},
    )

    report = ComplianceEngine(rules).audit([target])

    assert len(report.findings) == 1
    assert report.compliant_devices == 1
    assert report.compliant_sites == 1
    assert report.findings[0].severity == "info"
    assert report.findings[0].section == "offline_devices"
    assert report.findings[0].message == "Device Offline Switch is offline; last reported IP 10.30.2.50; cannot validate against Meraki VLAN 2"


def test_offline_unifi_representative_does_not_create_reference_data_failure():
    rules = {
        "profiles": {
            "unifi": {
                "platform": "unifi",
                "checks": {
                    "vlans": {
                        "key": "vlan",
                        "items": [{"vlan": 2, "dhcpguard_server": {"$meraki_vlan_interface_ip": 2}}],
                    }
                },
            }
        }
    }
    target = AuditTarget(
        context=DeviceContext("unifi", "c", "s1", "Site", "d1", "Site settings", "site", {"ip": "10.20.76.6", "state": 0}),
        sections={
            "vlans": [{"vlan": 2, "dhcpguard_server": ["10.20.76.1"]}],
            "offline_devices": [{"name": "Offline Switch", "ip": "10.20.76.6", "last_seen": 123}],
        },
    )

    report = ComplianceEngine(rules).audit([target])

    assert len(report.findings) == 1
    assert report.findings[0].section == "offline_devices"
    assert report.findings[0].severity == "info"
    assert report.compliant_devices == 1


def test_offline_unifi_reference_with_stale_ip_does_not_create_reference_data_failure():
    rules = {"profiles": {"unifi": {"platform": "unifi", "checks": {}}}}
    target = AuditTarget(
        context=DeviceContext("unifi", "c", "s1", "Big Rock AC (ABBRAC)", "d1", "Site settings", "site"),
        sections={"offline_devices": [{"name": "Offline Switch", "ip": "10.20.76.6", "last_seen": 123}]},
    )
    engine = ComplianceEngine(rules)

    skip = engine._reference_skip_is_explained_by_offline_device(
        target,
        "Meraki VLAN interface data; UniFi management IP 10.20.76.6 did not match a Meraki VLAN 2 subnet",
    )

    assert skip is True


def test_unifi_state_one_is_online_even_with_disconnect_timestamps():
    target = AuditTarget(
        context=DeviceContext(
            "unifi",
            "c",
            "s1",
            "Site",
            "d1",
            "Site settings",
            "site",
            {"ip": "172.23.27.2", "state": 1, "disconnected_at": 1782404866, "start_disconnected_millis": 1782490721308},
        ),
        sections={},
    )

    assert ComplianceEngine._raw_device_is_offline(target.context.raw_device) is False
    assert ComplianceEngine._target_management_ip(target) == "172.23.27.2"


def test_dhcp_option_operator_matches_option_15():
    rules = {
        "profiles": {
            "p": {
                "platform": "meraki",
                "checks": {
                    "vlans": {
                        "key": "id",
                        "items": [
                            {
                                "id": "2",
                                "dhcpOptions": {"$dhcp_option": {"code": "15", "value": "vs.local", "only": True}},
                            }
                        ],
                    }
                },
            }
        }
    }
    target = AuditTarget(
        context=DeviceContext("meraki", "dashboard", "n1", "Site", "d1", "MX", "appliance"),
        sections={"vlans": [{"id": 2, "dhcpOptions": [{"code": "15", "value": "vs.local"}]}]},
    )
    report = ComplianceEngine(rules).audit([target])
    assert report.findings == []


def test_dhcp_option_operator_allows_other_option_codes():
    rules = {
        "profiles": {
            "p": {
                "platform": "meraki",
                "checks": {
                    "vlans": {
                        "key": "id",
                        "items": [
                            {
                                "id": "2",
                                "dhcpOptions": {"$dhcp_option": {"code": "15", "value": "vs.local"}},
                            }
                        ],
                    }
                },
            }
        }
    }
    target = AuditTarget(
        context=DeviceContext("meraki", "dashboard", "n1", "Site", "d1", "MX", "appliance"),
        sections={
            "vlans": [
                {
                    "id": 2,
                    "dhcpOptions": [
                        {"code": "15", "value": "vs.local"},
                        {"code": "42", "value": "10.1.2.3"},
                    ],
                }
            ]
        },
    )
    report = ComplianceEngine(rules).audit([target])
    assert report.findings == []


def test_dhcp_option_operator_rejects_wrong_option_15_value():
    rules = {
        "profiles": {
            "p": {
                "platform": "meraki",
                "checks": {
                    "vlans": {
                        "key": "id",
                        "items": [
                            {
                                "id": "2",
                                "dhcpOptions": {"$dhcp_option": {"code": "15", "value": "vs.local"}},
                            }
                        ],
                    }
                },
            }
        }
    }
    target = AuditTarget(
        context=DeviceContext("meraki", "dashboard", "n1", "Site", "d1", "MX", "appliance"),
        sections={
            "vlans": [
                {
                    "id": 2,
                    "dhcpOptions": [
                        {"code": "15", "value": "wrong.local"},
                        {"code": "42", "value": "10.1.2.3"},
                    ],
                }
            ]
        },
    )
    report = ComplianceEngine(rules).audit([target])
    assert len(report.findings) == 1
    assert report.findings[0].path == "vlans[2].dhcpOptions"


def test_dhcp_option_operator_ignores_other_codes_when_option_15_is_missing():
    rules = {
        "profiles": {
            "p": {
                "platform": "meraki",
                "checks": {
                    "vlans": {
                        "key": "id",
                        "items": [
                            {
                                "id": "2",
                                "dhcpOptions": {"$dhcp_option": {"code": "15", "value": "vs.local"}},
                            }
                        ],
                    }
                },
            }
        }
    }
    target = AuditTarget(
        context=DeviceContext("meraki", "dashboard", "n1", "Site", "d1", "MX", "appliance"),
        sections={
            "vlans": [
                {
                    "id": 2,
                    "dhcpOptions": [
                        {"code": "66", "type": "text", "value": "https://pbx.example.test/provisioning/example"},
                    ],
                }
            ]
        },
    )
    report = ComplianceEngine(rules).audit([target])
    assert len(report.findings) == 1
    assert report.findings[0].actual == []


def test_fixed_ip_assignments_must_be_in_vlan_subnet():
    rules = {
        "profiles": {
            "p": {
                "platform": "meraki",
                "checks": {
                    "vlans": {
                        "key": "id",
                        "items": [
                            {
                                "id": "100",
                                "fixedIpAssignments": {"$all_ips_in_subnet": True, "subnet_field": "subnet"},
                            }
                        ],
                    }
                },
            }
        }
    }
    target = AuditTarget(
        context=DeviceContext("meraki", "dashboard", "n1", "Site", "d1", "MX", "appliance"),
        sections={"vlans": [{"id": "100", "subnet": "10.30.1.0/24", "fixedIpAssignments": {"aa:bb": {"ip": "10.30.2.25"}}}]},
    )
    report = ComplianceEngine(rules).audit([target])
    assert len(report.findings) == 1


def test_unifi_dhcp_guard_can_reference_meraki_vlan_interface_ip():
    rules = {
        "profiles": {
            "meraki": {"platform": "meraki", "checks": {}},
            "unifi": {
                "platform": "unifi",
                "checks": {
                    "vlans": {
                        "key": "vlan",
                        "items": [
                            {
                                "vlan": 100,
                                "dhcpguard_server": {"$meraki_vlan_interface_ip": 100},
                            }
                        ],
                    }
                },
            },
        },
        "assignments": [
            {"profile": "meraki", "platform": "meraki"},
            {"profile": "unifi", "platform": "unifi"},
        ],
    }
    meraki = AuditTarget(
        context=DeviceContext("meraki", "dashboard", "n1", "Clinic A", "d1", "MX", "appliance"),
        sections={"vlans": [{"id": "100", "applianceIp": "10.30.1.1"}]},
    )
    unifi = AuditTarget(
        context=DeviceContext("unifi", "controller", "s1", "Clinic A", "d2", "Switch", "switch"),
        sections={"vlans": [{"vlan": 100, "dhcpguard_server": ["10.30.1.1"]}]},
    )
    report = ComplianceEngine(rules).audit([unifi, meraki])
    assert report.findings == []


def test_unifi_dhcp_guard_can_use_unifi_dhcpd_ip_fields():
    rules = {
        "profiles": {
            "meraki": {"platform": "meraki", "checks": {}},
            "unifi": {
                "platform": "unifi",
                "checks": {
                    "vlans": {
                        "key": "vlan",
                        "items": [
                            {
                                "vlan": 100,
                                "dhcpguard_server": {"$meraki_vlan_interface_ip": 100},
                            }
                        ],
                    }
                },
            },
        },
        "assignments": [
            {"profile": "meraki", "platform": "meraki"},
            {"profile": "unifi", "platform": "unifi"},
        ],
    }
    meraki = AuditTarget(
        context=DeviceContext("meraki", "dashboard", "n1", "Clinic A", "d1", "MX", "appliance"),
        sections={"vlans": [{"id": "100", "applianceIp": "10.30.1.1"}]},
    )
    unifi = AuditTarget(
        context=DeviceContext("unifi", "controller", "s1", "Clinic A", "d2", "Switch", "switch"),
        sections={"vlans": [{"vlan": 100, "dhcpd_ip_1": "10.30.1.1"}]},
    )
    report = ComplianceEngine(rules).audit([unifi, meraki])
    assert report.findings == []


def test_meraki_interface_reference_finding_splits_expected_and_actual():
    rules = {
        "profiles": {
            "meraki": {"platform": "meraki", "checks": {}},
            "unifi": {
                "platform": "unifi",
                "checks": {
                    "vlans": {
                        "key": "vlan",
                        "items": [
                            {
                                "vlan": 100,
                                "dhcpguard_server": {"$meraki_vlan_interface_ip": 100},
                            }
                        ],
                    }
                },
            },
        },
        "assignments": [
            {"profile": "meraki", "platform": "meraki"},
            {"profile": "unifi", "platform": "unifi"},
        ],
    }
    meraki = AuditTarget(
        context=DeviceContext("meraki", "dashboard", "n1", "Clinic A", "d1", "MX", "appliance"),
        sections={"vlans": [{"id": "100", "applianceIp": "10.30.1.1"}]},
    )
    unifi = AuditTarget(
        context=DeviceContext("unifi", "controller", "s1", "Clinic A", "d2", "Switch", "switch"),
        sections={"vlans": [{"vlan": 100, "dhcpguard_server": None}]},
    )
    report = ComplianceEngine(rules).audit([unifi, meraki])
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.message == "VLAN 100 has incorrect DHCP Guard trusted server"
    assert finding.expected == {"$meraki_vlan_interface_ip": "100", "ip": "10.30.1.1"}
    assert finding.actual is None


def test_missing_meraki_site_reference_is_single_reference_finding():
    rules = {
        "profiles": {
            "unifi": {
                "platform": "unifi",
                "checks": {
                    "vlans": {
                        "key": "vlan",
                        "items": [
                            {"vlan": 2, "dhcpguard_server": {"$meraki_vlan_interface_ip": 2}},
                            {"vlan": 10, "dhcpguard_server": {"$meraki_vlan_interface_ip": 10}},
                        ],
                    }
                },
            }
        },
    }
    unifi = AuditTarget(
        context=DeviceContext("unifi", "controller", "s1", "Clinic Without Meraki", "d2", "Switch", "switch"),
        sections={"vlans": [{"vlan": 2, "dhcpguard_server": []}, {"vlan": 10, "dhcpguard_server": []}]},
    )
    report = ComplianceEngine(rules).audit([unifi])
    assert len(report.findings) == 1
    assert report.findings[0].section == "reference_data"


def test_unifi_meraki_reference_can_match_by_vlan2_management_subnet():
    rules = {
        "profiles": {
            "meraki": {"platform": "meraki", "checks": {}},
            "unifi": {
                "platform": "unifi",
                "checks": {
                    "vlans": {
                        "key": "vlan",
                        "items": [
                            {"vlan": 100, "dhcpguard_server": {"$meraki_vlan_interface_ip": 100}},
                        ],
                    }
                },
            },
        },
        "assignments": [
            {"profile": "meraki", "platform": "meraki"},
            {"profile": "unifi", "platform": "unifi"},
        ],
    }
    meraki = AuditTarget(
        context=DeviceContext("meraki", "dashboard", "n1", "Example Clinic - EX001", "d1", "MX", "appliance"),
        sections={"vlans": [{"id": "2", "subnet": "10.50.2.0/24", "applianceIp": "10.50.2.1"}, {"id": "100", "applianceIp": "10.50.100.1"}]},
    )
    unifi = AuditTarget(
        context=DeviceContext("unifi", "controller", "s1", "Example Short Name (EX001)", "d2", "Switch", "switch", {"ip": "10.50.2.25"}),
        sections={"vlans": [{"vlan": 100, "dhcpguard_server": ["10.50.100.1"]}]},
    )
    report = ComplianceEngine(rules).audit([unifi, meraki])
    assert report.findings == []


def test_site_counts_merge_meraki_and_unifi_by_vlan2_management_subnet():
    rules = {
        "profiles": {
            "meraki": {"platform": "meraki", "checks": {}},
            "unifi": {
                "platform": "unifi",
                "checks": {
                    "vlans": {
                        "key": "vlan",
                        "items": [
                            {"vlan": 100, "dhcpguard_server": {"$meraki_vlan_interface_ip": 100}},
                        ],
                    }
                },
            },
        },
        "assignments": [
            {"profile": "meraki", "platform": "meraki"},
            {"profile": "unifi", "platform": "unifi"},
        ],
    }
    meraki = AuditTarget(
        context=DeviceContext("meraki", "dashboard", "n1", "Example Veterinary Hospital - EXVH", "d1", "MX", "appliance"),
        sections={"vlans": [{"id": "2", "subnet": "10.50.2.0/24", "applianceIp": "10.50.2.1"}, {"id": "100", "applianceIp": "10.50.100.1"}]},
    )
    unifi = AuditTarget(
        context=DeviceContext("unifi", "controller", "s1", "Example VH (EXVH)", "d2", "Switch", "switch", {"ip": "10.50.2.25"}),
        sections={"vlans": [{"vlan": 100, "dhcpguard_server": ["10.50.100.1"]}]},
    )
    report = ComplianceEngine(rules).audit([unifi, meraki])
    assert report.total_sites == 1
    assert report.compliant_sites == 1


def test_duplicate_meraki_vlan2_subnet_records_do_not_create_ambiguous_unifi_match():
    rules = {
        "profiles": {
            "meraki": {"platform": "meraki", "checks": {}},
            "unifi": {
                "platform": "unifi",
                "checks": {
                    "vlans": {
                        "key": "vlan",
                        "items": [
                            {"vlan": 100, "dhcpguard_server": {"$meraki_vlan_interface_ip": 100}},
                        ],
                    }
                },
            },
        },
        "assignments": [
            {"profile": "meraki", "platform": "meraki"},
            {"profile": "unifi", "platform": "unifi"},
        ],
    }
    meraki_a = AuditTarget(
        context=DeviceContext("meraki", "dashboard", "n1", "Example Hospital", "mx-a", "MX-A", "appliance"),
        sections={"vlans": [{"id": "2", "subnet": "172.20.149.0/24", "applianceIp": "172.20.149.1"}, {"id": "100", "applianceIp": "10.50.100.1"}]},
    )
    meraki_b = AuditTarget(
        context=DeviceContext("meraki", "dashboard", "n1", "Example Hospital", "mx-b", "MX-B", "appliance"),
        sections={"vlans": [{"id": "2", "subnet": "172.20.149.0/24", "applianceIp": "172.20.149.1"}, {"id": "100", "applianceIp": "10.50.100.1"}]},
    )
    unifi = AuditTarget(
        context=DeviceContext("unifi", "controller", "s1", "Example Short Name", "site", "Site settings", "site", {"ip": "172.20.149.12"}),
        sections={"vlans": [{"vlan": 100, "dhcpguard_server": ["10.50.100.1"]}]},
    )
    report = ComplianceEngine(rules).audit([unifi, meraki_a, meraki_b])
    assert report.findings == []


def test_resolver_deduplicates_duplicate_meraki_vlan2_matches():
    engine = ComplianceEngine({})
    engine.reference_data = {
        "meraki_vlan_interfaces": {"examplehospital": {"100": "10.50.100.1"}},
        "meraki_vlan2_subnets": [
            {"site_key": "examplehospital", "site_name": "Example Hospital", "network": ip_network("172.20.149.0/24")},
            {"site_key": "examplehospital", "site_name": "Example Hospital", "network": ip_network("172.20.149.0/24")},
        ],
    }
    target = AuditTarget(
        context=DeviceContext("unifi", "controller", "s1", "Example Short Name", "site", "Site settings", "site", {"ip": "172.20.149.12"}),
        sections={},
    )

    site_key, error = engine._resolve_meraki_site_key(target)

    assert site_key == "examplehospital"
    assert error is None


def test_resolver_matches_unifi_management_ip_inside_meraki_vlan2_subnet():
    engine = ComplianceEngine({})
    engine.reference_data = {
        "meraki_vlan_interfaces": {"examplecoastland": {"2": "172.16.48.1"}},
        "meraki_vlan2_subnets": [
            {"site_key": "examplecoastland", "site_name": "Example Coastland", "network": ip_network("172.16.48.0/26")},
        ],
    }
    target = AuditTarget(
        context=DeviceContext("unifi", "controller", "s1", "Coastland Short Name", "site", "Site settings", "site", {"ip": "172.16.48.10"}),
        sections={},
    )

    site_key, error = engine._resolve_meraki_site_key(target)

    assert site_key == "examplecoastland"
    assert error is None


def test_audit_can_use_reference_targets_not_in_audited_targets():
    rules = {
        "profiles": {
            "unifi": {
                "platform": "unifi",
                "checks": {
                    "vlans": {
                        "key": "vlan",
                        "items": [
                            {"vlan": 2, "dhcpguard_server": {"$meraki_vlan_interface_ip": 2}},
                        ],
                    }
                },
            }
        },
    }
    meraki_reference = AuditTarget(
        context=DeviceContext("meraki", "dashboard", "n1", "BC - Coastland Veterinary Hospital", "mx", "MX", "appliance"),
        sections={"vlans": [{"id": "2", "subnet": "172.16.48.0/26", "applianceIp": "172.16.48.1"}]},
    )
    unifi = AuditTarget(
        context=DeviceContext("unifi", "controller", "s1", "Coastland VH (BCCVH)", "site", "Site settings", "site", {"ip": "172.16.48.10"}),
        sections={"vlans": [{"vlan": 2, "dhcpguard_server": ["172.16.48.1"]}]},
    )

    report = ComplianceEngine(rules).audit([unifi], reference_targets=[unifi, meraki_reference])

    assert report.findings == []
