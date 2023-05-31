package uhg.checkin

import future.keywords.contains
import future.keywords.if
import future.keywords.in
import data.uhg.helpers.LEVEL
import data.uhg.helpers.new_violation
import data.tasks

# List of Blocked commands during check-in
BLOCKED_COMMANDS = [
  "write erase",
  "w e"
]

deny_unapproved_commands contains msg if {
  some task in input.tasks

  # fetches the command string from ansible playbook under mentioned task
    command_name := task["ansible.netcommon.cli_command"].command

  # checks the command string with listed blocked commands
  contains(command_name, BLOCKED_COMMANDS[i]) = true
  denied_command := BLOCKED_COMMANDS[i]

  # displays error message if the blocked commands are mentioned in the command string for the playbook execution
  msg := sprintf(" '%v' command is not allowed, please use different command", [denied_command])
}