package uhg.automation

import data.uhg.helpers.LEVEL
import data.uhg.helpers.new_violation

# METADATA
# title: UHG-ATMN-00001 - Runtime check for Specific Devices
# description: >-
#   The device is not listed to run this automation. Please change the permission for this device
# custom:
#   level: FAIL
UHG_ATMN_00001_id := "UHG-ATMN-00001"
UHG_ATMN_00001_message := "The device is not listed to run this automation. Please this device in the approved list"
UHG_ATMN_00001_playbook := "NOT_IMPLEMENTED"
UHG_ATMN_00001_playbook_variables(device_attributes) := playbook_vars {
    playbook_vars := {}
}

# add UHG_ATMN_00001 policy to policy set
policies[policy_id] := policy {
    policy_id := UHG_ATMN_00001_id
    policy := {
        "reason": UHG_ATMN_00001_message,
        "level": LEVEL.FAIL,
        "playbook": UHG_ATMN_00001_playbook
    }
}

# add UHG_ATMN_00001 violations to violations list if any exist
policy_violations[UHG_ATMN_00001_violation] {

    #Approved Device Name
    APPROVED_DEVICE_NAME := {"wgsin710leaf02":{}, "wgsin710leaf01":{}}

    # loop through each device
    some device_index, device_name
    device_attributes := input.devices[device_index][device_name]


    # get the set of approved devices and check against the approved device set
    approved_devices := { device_index |
        approved_list := device_attributes[device_index]
    }
    # device_attributes[device_name]
    approved_devices != APPROVED_DEVICE_NAME

    # create a violation if device does not have listed in the approved device
    UHG_ATMN_00001_violation := new_violation(
        policies,
        UHG_ATMN_00001_id,
        device_name,
        UHG_ATMN_00001_playbook_variables(device_attributes)
    )

}