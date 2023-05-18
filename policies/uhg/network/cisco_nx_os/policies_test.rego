package uhg.network.cisco_nx_os

import future.keywords
import data.uhg.helpers.count_violations

test_UHG_NTWK_NXOS_00001_no_violation_if_device_has_two_management_peers if {
    test_input := {"devices":[{"wgsin710leaf01":{"total_peers":2}}]}
    count_violations(UHG_NTWK_NXOS_00001_id, policy_violations) == 0 with input as test_input
}

test_UHG_NTWK_NXOS_00001_has_violation_if_device_has_less_than_two_management_peers if {
    test_input := {"devices":[{"wgsin710leaf01":{"total_peers":1}}]}
    count_violations(UHG_NTWK_NXOS_00001_id, policy_violations) == 1 with input as test_input
}

test_UHG_NTWK_NXOS_00001_has_violation_if_device_has_more_than_two_management_peers if {
    test_input := {"devices":[{"wgsin710leaf01":{"total_peers":3}}]}
    count_violations(UHG_NTWK_NXOS_00001_id, policy_violations) == 1 with input as test_input
}

test_UHG_NTWK_NXOS_00002_has_violation_if_device_doesnt_have_synchronized_peer_two_in_list if {
    test_input := {"devices":[{"wgsin710leaf01":{"vrf":{"management":{"peer":{"10.90.40.105":{"mode":"client"},"10.7.136.103":{"mode":"client"}}}}}}]}
    count_violations(UHG_NTWK_NXOS_00002_id, policy_violations) == 1 with input as test_input
}

test_UHG_NTWK_NXOS_00002_has_violation_if_device_doesnt_have_synchronized_peer_none_in_list if {
    test_input := {"devices":[{"wgsin710leaf01":{"vrf":{"management":{"peer":{}}}}}]}
    count_violations(UHG_NTWK_NXOS_00002_id, policy_violations) == 1 with input as test_input
}

test_UHG_NTWK_NXOS_00002_no_violation_if_device_has_synchronized_peer if {
    test_input := {"devices":[{"wgsin710leaf01":{"vrf":{"management":{"peer":{"10.90.40.105":{"mode":"client"},"10.7.136.103":{"mode":"synchronized"}}}}}}]}
    count_violations(UHG_NTWK_NXOS_00002_id, policy_violations) == 0 with input as test_input
}

test_UHG_NTWK_NXOS_00003_has_violation_if_not_only_using_management_vrf if {
    test_input := {"devices":[{"wgsin710leaf01":{"vrf":{"management":{}, "vrf2":{}}}}]}
    count_violations(UHG_NTWK_NXOS_00003_id, policy_violations) == 1 with input as test_input
}

test_UHG_NTWK_NXOS_00003_no_violation_if_only_using_management_vrf if {
    test_input := {"devices":[{"wgsin710leaf01":{"vrf":{"management":{"peer":{}}}}}]}
    count_violations(UHG_NTWK_NXOS_00003_id, policy_violations) == 0 with input as test_input
}

test_UHG_NTWK_NXOS_00004_has_violation_if_not_using_correct_peers_one_missing if {
    test_input := {"devices":[{"wgsin710leaf01":{"vrf":{"management":{"peer":{"10.90.40.105":{}}}}}}]}
    count_violations(UHG_NTWK_NXOS_00004_id, policy_violations) == 1 with input as test_input
}

test_UHG_NTWK_NXOS_00004_has_violation_if_not_using_correct_peers_both_missing if {
    test_input := {"devices":[{"wgsin710leaf01":{"vrf":{"management":{"peer":{}}}}}]}
    count_violations(UHG_NTWK_NXOS_00004_id, policy_violations) == 1 with input as test_input
}

test_UHG_NTWK_NXOS_00004_has_violation_if_not_using_correct_peers_extra_present if {
    test_input := {"devices":[{"wgsin710leaf01":{"vrf":{"management":{"peer":{"10.90.40.105":{},"10.7.136.103":{},"127.0.0.1":{}}}}}}]}
    count_violations(UHG_NTWK_NXOS_00004_id, policy_violations) == 1 with input as test_input
}

test_UHG_NTWK_NXOS_00004_no_violation_if_only_approved_management_peers_present if {
    test_input := {"devices":[{"wgsin710leaf01":{"vrf":{"management":{"peer":{"10.90.40.105":{},"10.7.136.103":{}}}}}}]}
    count_violations(UHG_NTWK_NXOS_00004_id, policy_violations) == 0 with input as test_input
}