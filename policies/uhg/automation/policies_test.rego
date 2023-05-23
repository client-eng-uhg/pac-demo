package uhg.automation

import future.keywords
import data.uhg.helpers.count_violations

test_UHG_ATMN_00001_has_violation_if_other_device_present if {
    test_input := {"devices":[{"wgsin710leaf05":{},"wgsin710leaf03":{},"wgsin710leaf04":{}}]}
    count_violations(UHG_ATMN_00001_id, policy_violations) > 0 with input as test_input
}

test_UHG_ATMN_00001_has_no_violation_if_approved_device_present if {
    test_input := {"devices":[{"wgsin710leaf01":{}}]}
    count_violations(UHG_ATMN_00001_id, policy_violations) == 0 with input as test_input
}


test_UHG_ATMN_00002_has_violation_if_prevented_device_present if {
    test_input := {"devices":[{"wgsin710leaf05":{},"wgsin710leaf06":{},"wgsin710leaf04":{}}]}
    count_violations(UHG_ATMN_00002_id, policy_violations) > 0 with input as test_input
}

test_UHG_ATMN_00002_has_no_violation_if_no_prevented_device_present if {
    test_input := {"devices":[{"wgsin710leaf01":{}, "wgsin710leaf02":{}, "wgsin710leaf03":{}}]}
    count_violations(UHG_ATMN_00002_id, policy_violations) == 0 with input as test_input
}