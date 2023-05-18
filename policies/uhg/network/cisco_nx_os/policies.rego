package uhg.network.cisco_nx_os

import data.uhg.helpers.LEVEL
import data.uhg.helpers.new_violation

# METADATA
# title: UHG-NTWK-NXOS-00001 - VRF's: Management Peer Count
# description: >-
#   Nexus devices should have exactly 2 management peers
# custom:
#   level: FAIL
UHG_NTWK_NXOS_00001_id := "UHG-NTWK-NXOS-00001"
UHG_NTWK_NXOS_00001_message := "Nexus devices should have exactly 2 management peers"
UHG_NTWK_NXOS_00001_playbook := "NOT_IMPLEMENTED"
UHG_NTWK_NXOS_00001_playbook_variables(device_attributes) := playbook_vars {
    playbook_vars := {}
}

# add UHG_NTWK_NXOS_00001 policy to policy set
policies[policy_id] := policy {
    policy_id := UHG_NTWK_NXOS_00001_id
    policy := {
        "reason": UHG_NTWK_NXOS_00001_message,
        "level": LEVEL.FAIL,
        "playbook": UHG_NTWK_NXOS_00001_playbook
    }
}

# add UHG_NTWK_NXOS_00001 violations to violations list if any exist
policy_violations[UHG_NTWK_NXOS_00001_violation] {

    # loop through each device
    some device_index, device_name
    device_attributes := input.devices[device_index][device_name]

    # check if peer count is not exactly 2
    device_attributes.total_peers != 2

    # create a violation if device does not have exactly 2 management peers
    UHG_NTWK_NXOS_00001_violation := new_violation(
        policies,
        UHG_NTWK_NXOS_00001_id,
        device_name,
        UHG_NTWK_NXOS_00001_playbook_variables(device_attributes)
    )

}

# METADATA
# title: UHG-NTWK-NXOS-00002 - VRF's: Peer Synchornization
# description: >-
#   Nexus devices should have at least 1 management peer in synchronized state
# custom:
#   level: FAIL
UHG_NTWK_NXOS_00002_id := "UHG-NTWK-NXOS-00002"
UHG_NTWK_NXOS_00002_message := "Nexus devices should have at least 1 management peer in synchronized state"
UHG_NTWK_NXOS_00002_playbook := "NOT_IMPLEMENTED"
UHG_NTWK_NXOS_00002_playbook_variables(device_attributes) := playbook_vars {
    playbook_vars := {}
}

# add UHG_NTWK_NXOS_00002 policy to policy set
policies[policy_id] := policy {
    policy_id := UHG_NTWK_NXOS_00002_id
    policy := {
        "reason": UHG_NTWK_NXOS_00002_message,
        "level": LEVEL.FAIL,
        "playbook": UHG_NTWK_NXOS_00002_playbook
    }
}

# add UHG_NTWK_NXOS_00002 violations to violations list if any exist
policy_violations[UHG_NTWK_NXOS_00002_violation] {

    # loop through each device
    some device_index, device_name
    device_attributes := input.devices[device_index][device_name]
    
    # count number of synchronized peers and proceed if less than 1
    synchronized_peers := { peer |
        peer := device_attributes.vrf.management.peer[_]
        peer.mode == "synchronized"
    }
    count(synchronized_peers) < 1

    # create a violation if less than 1 synchronized peers
    UHG_NTWK_NXOS_00002_violation := new_violation(
        policies,
        UHG_NTWK_NXOS_00002_id,
        device_name,
        UHG_NTWK_NXOS_00002_playbook_variables(device_attributes)
    )

}

# METADATA
# title: UHG-NTWK-NXOS-00003 - VRF's: Only Management VRF
# description: >-
#   Nexus devices shouldn't use any VRF's other than management
# custom:
#   level: WARN
UHG_NTWK_NXOS_00003_id := "UHG-NTWK-NXOS-00003"
UHG_NTWK_NXOS_00003_message := "Nexus devices shouldn't use any VRF's other than management"
UHG_NTWK_NXOS_00003_playbook := "NOT_IMPLEMENTED"
UHG_NTWK_NXOS_00003_playbook_variables(device_attributes) := playbook_vars {
    playbook_vars := {}
}

# add UHG_NTWK_NXOS_00003 policy to policy set
policies[policy_id] := policy {
    policy_id := UHG_NTWK_NXOS_00003_id
    policy := {
        "reason": UHG_NTWK_NXOS_00003_message,
        "level": LEVEL.FAIL,
        "playbook": UHG_NTWK_NXOS_00003_playbook
    }
}

# add UHG_NTWK_NXOS_00003 violations to violations list if any exist
policy_violations[UHG_NTWK_NXOS_00003_violation] {

    # loop through each device
    some device_index, device_name
    device_attributes := input.devices[device_index][device_name]
    
    # count number of vrf's that aren't "management" and proceed if greater than 0
    non_management_vrf_list := { vrf_name |
        vrf := device_attributes.vrf[vrf_name]
        vrf_name != "management"
    }
    count(non_management_vrf_list) > 0

    # create a violation if any peers not using management vrf
    UHG_NTWK_NXOS_00003_violation := new_violation(
        policies,
        UHG_NTWK_NXOS_00003_id,
        device_name,
        UHG_NTWK_NXOS_00003_playbook_variables(device_attributes)
    )

}

# METADATA
# title: UHG-NTWK-NXOS-00004 - VRF's: Only Approved Management Peers
# description: >-
#   Nexus devices shouldn't use any other VRF management peers other than the two
#   approved peers: 10.90.40.105 and 10.7.136.103
# custom:
#   level: WARN
UHG_NTWK_NXOS_00004_id := "UHG-NTWK-NXOS-00004"
UHG_NTWK_NXOS_00004_message := "Nexus devices shouldn't use any other VRF management peers other than the two approved peers: 10.90.40.105 and 10.7.136.103"
UHG_NTWK_NXOS_00004_playbook := "NOT_IMPLEMENTED"
UHG_NTWK_NXOS_00004_playbook_variables(device_attributes) := playbook_vars {
    playbook_vars := {}
}

# add UHG_NTWK_NXOS_00004 policy to policy set
policies[policy_id] := policy {
    policy_id := UHG_NTWK_NXOS_00004_id
    policy := {
        "reason": UHG_NTWK_NXOS_00004_message,
        "level": LEVEL.WARN,
        "playbook": UHG_NTWK_NXOS_00004_playbook
    }
}

# add UHG_NTWK_NXOS_00004 violations to violations list if any exist
policy_violations[UHG_NTWK_NXOS_00004_violation] {

    # constants
    APPROVED_MANAGEMENT_PEERS := {"10.90.40.105", "10.7.136.103"}

    # loop through each device
    some device_index, device_name
    device_attributes := input.devices[device_index][device_name]
    
    # get the set of management peers and check against the approved peers set
    device_management_peers := { peer_name |
        peer := device_attributes.vrf.management.peer[peer_name]
    }
    device_management_peers != APPROVED_MANAGEMENT_PEERS

    # create a violation if device peers do not match approved set
    UHG_NTWK_NXOS_00004_violation := new_violation(
        policies,
        UHG_NTWK_NXOS_00004_id,
        device_name,
        UHG_NTWK_NXOS_00004_playbook_variables(device_attributes)
    )

}
