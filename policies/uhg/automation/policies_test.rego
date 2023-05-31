package uhg.automation

import future.keywords
import future.keywords.contains
import future.keywords.if
import future.keywords.in
import data.uhg.helpers.count_violations

test_UHG_ATMN_00001_has_violation_if_other_device_present if {
    test_input := {"devices":[{"wgsin710leaf05":{},"wgsin710leaf03":{},"wgsin710leaf04":{}}]}
    count_violations(UHG_ATMN_00001_id, policy_violations) > 0 with input as test_input
}

test_UHG_ATMN_00001_has_no_violation_if_approved_device_present if {
    test_input := {"devices":[{"wgsin710leaf01":{}, "wgsin710leaf01":{}}]}
    count_violations(UHG_ATMN_00001_id, policy_violations) == 0 with input as test_input
}


test_UHG_ATMN_00002_has_violation_if_prevented_device_present if {
    test_input := {"devices":[{"wgsin710leaf05":{},"wgsin710leaf06":{},"wgsin710leaf04":{}}]}
    count_violations(UHG_ATMN_00002_id, policy_violations) == 2 with input as test_input
}

test_UHG_ATMN_00002_has_no_violation_if_no_prevented_device_present if {
    test_input := {"devices":[{"wgsin710leaf01":{}, "wgsin710leaf02":{}, "wgsin710leaf03":{}}]}
    count_violations(UHG_ATMN_00002_id, policy_violations) == 0 with input as test_input
}


test_UHG_ATMN_00003_has_violation_if_blocked_commands_present if {
    test_input := {"playbooks":[{"hello-world.yaml":{"connection":"local","hosts":"localhost","tasks":[{"ansible.netcommon.cli_command":{"command":"clear ip nat translation * write erase"},"name":"Clear NAT table","register":"remediation"},{"ansible.netcommon.cli_command":{"command":"clear ip nat translation * read w e"},"name":"Clear NAT table","register":"remediation"}],"vars":{"policy_as_code_plan_validation_url":"http://localhost:8181/v1/data/policies"}}}]}
    print("count violations 3 :", count_violations(UHG_ATMN_00003_id, policy_violations)) with input as test_input
    count_violations(UHG_ATMN_00003_id, policy_violations) == 1 with input as test_input
}

test_UHG_ATMN_00003_has_no_violation_if_blocked_commands__not_present if {
    test_input := {"playbooks":[{"hello-world.yaml":{"connection":"local","hosts":"localhost","tasks":[{"ansible.netcommon.cli_command":{"command":"clear ip nat translation * write"},"name":"Clear NAT table","register":"remediation"},{"ansible.netcommon.cli_command":{"command":"clear ip nat translation * read e"},"name":"Clear NAT table","register":"remediation"}],"vars":{"policy_as_code_plan_validation_url":"http://localhost:8181/v1/data/policies"}}}]}
    count_violations(UHG_ATMN_00003_id, policy_violations) == 0 with input as test_input
}
