package uhg.network.cisco_ios

import future.keywords
import data.uhg.helpers.count_violations

test_UHG_NTWK_IOS_00001_no_violation_if_device_has_two_management_peers if {
    test_input := {"devices":[{"stkal047a01a01":{"peer":{"10.90.40.105":{},"10.7.136.103":{}}}}]}
    count_violations(UHG_NTWK_IOS_00001_id, policy_violations) == 0 with input as test_input
}

test_UHG_NTWK_IOS_00001_has_violation_if_only_one_ntp_peer if {
    test_input := {"devices":[{"stkal047a01a01":{"peer":{"10.90.40.105":{}}}}]}
    count_violations(UHG_NTWK_IOS_00001_id, policy_violations) == 1 with input as test_input
}

test_UHG_NTWK_IOS_00001_has_violation_if_neither_peer_present if {
    test_input := {"devices":[{"stkal047a01a01":{"peer":{}}}]}
    count_violations(UHG_NTWK_IOS_00001_id, policy_violations) == 1 with input as test_input
}

test_UHG_NTWK_IOS_00002_has_violation_no_peers_in_synchronized_state if {
    test_input := {"devices":[{"stkal047a01a01":{"peer":{}}}]}
    count_violations(UHG_NTWK_IOS_00002_id, policy_violations) == 1 with input as test_input
}

test_UHG_NTWK_IOS_00002_has_no_violation_if_one_peer_in_synchonized_state if {
    test_input := {"devices":[{"stkal047a01a01":{"peer":{"10.90.40.105":{"local_mode":{"client":{"mode":"synchronized"}}},"10.7.136.103":{"local_mode":{"client":{"mode":"unsynchronized"}}}}}}]}
    count_violations(UHG_NTWK_IOS_00002_id, policy_violations) == 0 with input as test_input
}

test_UHG_NTWK_IOS_00002_has_no_violation_if_two_peers_in_synchonized_state if {
    test_input := {"devices":[{"stkal047a01a01":{"peer":{"10.90.40.105":{"local_mode":{"client":{"mode":"synchronized"}}},"10.7.136.103":{"local_mode":{"client":{"mode":"synchronized"}}}}}}]}
    count_violations(UHG_NTWK_IOS_00002_id, policy_violations) == 0 with input as test_input
}

test_UHG_NTWK_IOS_00002_has_violation_if_three_peers_in_unsynchonized_state if {
    test_input := {"devices":[{"stkal047a01a01":{"peer":{"10.90.40.105":{"local_mode":{"client":{"mode":"unsynchronized"}}},"10.7.136.103":{"local_mode":{"client":{"mode":"unsynchronized"}}},"127.0.0.1":{"local_mode":{"client":{"mode":"unsynchronized"}}}}}}]}
    count_violations(UHG_NTWK_IOS_00002_id, policy_violations) == 1 with input as test_input
}

test_UHG_NTWK_IOS_00003_has_violation_if_no_ntp_peers_present if {
    test_input := {"devices":[{"stkal047a01a01":{"peer":{}}}]}
    count_violations(UHG_NTWK_IOS_00003_id, policy_violations) == 1 with input as test_input
}

test_UHG_NTWK_IOS_00003_has_violation_if_three_ntp_peers_present if {
    test_input := {"devices":[{"stkal047a01a01":{"peer":{"10.90.40.105":{},"10.7.136.103":{},"127.0.0.1":{}}}}]}
    count_violations(UHG_NTWK_IOS_00003_id, policy_violations) == 1 with input as test_input
}

test_UHG_NTWK_IOS_00003_has_no_violation_if_expected_ntp_peers_present if {
    test_input := {"devices":[{"stkal047a01a01":{"peer":{"10.7.136.103":{},"10.90.40.105":{}}}}]}
    count_violations(UHG_NTWK_IOS_00003_id, policy_violations) == 0 with input as test_input
}