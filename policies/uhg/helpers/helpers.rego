package uhg.helpers

# Constants for policy levels
LEVEL := {
    "FAIL": "FAIL",
    "WARN": "WARN"
}

# Function to create policy violations
new_violation(policies, policy_id, name, playbook_variables) = v {
  v := {
    "name": name,
    "policy_id": policy_id,
    "reason": policies[policy_id].reason,
    "level": policies[policy_id].level,
    "playbook": policies[policy_id].playbook,
    "playbook_variables": playbook_variables
  }
}

# Function to count policy violations
count_violations(policy_id, policy_violations) = violations_count {
  violations_count := count([ v | v := policy_violations[_]; v.policy_id == policy_id ])
}