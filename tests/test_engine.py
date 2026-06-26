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
