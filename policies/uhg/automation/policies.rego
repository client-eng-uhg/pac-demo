package uhg.automation

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.uhg.helpers.LEVEL
import data.uhg.helpers.new_violation
import data.uhg.helpers.count_violations



######################################################################################################
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
    
    # check if the device_name is not in the set of approved devices
    not APPROVED_DEVICE_NAME[device_name]

    # create a violation if device does not have listed in the approved device
    UHG_ATMN_00001_violation := new_violation(
        policies,
        UHG_ATMN_00001_id,
        device_name,
        UHG_ATMN_00001_playbook_variables(device_attributes)
    )

}


######################################################################################################
# METADATA
# title: UHG-ATMN-00002 - Prevent Device with specific name from running
# description: >-
#   The device is prevented from running this automation. Please change with approved device.
# custom:
#   level: FAIL
UHG_ATMN_00002_id := "UHG-ATMN-00002"
UHG_ATMN_00002_message := "The device is prevented from running this automation. Please change with approved device."
UHG_ATMN_00002_playbook := "NOT_IMPLEMENTED"
UHG_ATMN_00002_playbook_variables(device_attributes) := playbook_vars {
    playbook_vars := {}
}

# add UHG_ATMN_00002 policy to policy set
policies[policy_id] := policy {
    policy_id := UHG_ATMN_00002_id
    policy := {
        "reason": UHG_ATMN_00002_message,
        "level": LEVEL.FAIL,
        "playbook": UHG_ATMN_00002_playbook
    }
}

# add UHG_ATMN_00002 violations to violations list if any exist
policy_violations[UHG_ATMN_00002_violation] {

    #Approved Device Name
    PREVENTED_DEVICE_NAME := {"wgsin710leaf05":{}, "wgsin710leaf06":{}}

    # loop through each device
    some device_index, device_name
    device_attributes := input.devices[device_index][device_name]
    
    # check if the device_name is in the set of prevented devices
    PREVENTED_DEVICE_NAME[device_name]

    # create a violation if device does not have listed in the prevented device
    UHG_ATMN_00002_violation := new_violation(
        policies,
        UHG_ATMN_00002_id,
        device_name,
        UHG_ATMN_00002_playbook_variables(device_attributes)
    )

}


######################################################################################################
# METADATA
# title: UHG-ATMN-00003 - Runtime check for Block commands from the Ansible playbook
# description: >-
#   This command is not allowed, please use different command.
# custom:
#   level: FAIL
UHG_ATMN_00003_id := "UHG-ATMN-00003"
UHG_ATMN_00003_message := "The device is prevented from running this automation. Please change with approved device."
UHG_ATMN_00003_playbook := "NOT_IMPLEMENTED"
UHG_ATMN_00003_playbook_variables(device_attributes) := playbook_vars {
    playbook_vars := {}
}

# add UHG_ATMN_00002 policy to policy set
policies[policy_id] := policy {
    policy_id := UHG_ATMN_00003_id
    policy := {
        "reason": UHG_ATMN_00003_message,
        "level": LEVEL.FAIL,
        "playbook": UHG_ATMN_00003_playbook
    }
}

policy_violations[UHG_ATMN_00003_violation] {

    BLOCKED_COMMANDS := {"write erase", "w e"}
    # [
    # "write erase",
    # "w e"
    # ]

    some playbook_index, playbook_name
    playbook_attributes := input.playbooks[playbook_index][playbook_name]

  # fetches the command string from ansible playbook under mentioned task
    task := playbook_attributes.tasks[_]
    command_name := task["ansible.netcommon.cli_command"].command

     # checks the command string with listed blocked commands
    blocked_command := BLOCKED_COMMANDS[_]
    contains(command_name, blocked_command) = true

    # create a violation if runtime check finds the blocked commands
    UHG_ATMN_00003_violation := new_violation(
        policies,
        UHG_ATMN_00003_id,
        playbook_name,
        UHG_ATMN_00002_playbook_variables(playbook_attributes)
    )
    print("violation: ", UHG_ATMN_00003_violation)

}