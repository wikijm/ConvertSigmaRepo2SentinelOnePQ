```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.cmdline contains "/var/log/syslog" and ((tgt.process.image.path contains "/rm" and (tgt.process.cmdline contains " -r " or tgt.process.cmdline contains " -f " or tgt.process.cmdline contains " -rf " or tgt.process.cmdline contains "/var/log/syslog")) or tgt.process.image.path contains "/unlink" or tgt.process.image.path contains "/mv" or (tgt.process.image.path contains "/truncate" and (tgt.process.cmdline contains "0 " and tgt.process.cmdline contains "/var/log/syslog") and (tgt.process.cmdline contains "-s " or tgt.process.cmdline contains "-c " or tgt.process.cmdline contains "--size")) or (tgt.process.image.path contains "/ln" and (tgt.process.cmdline contains "/dev/null " and tgt.process.cmdline contains "/var/log/syslog") and (tgt.process.cmdline contains "-sf " or tgt.process.cmdline contains "-sfn " or tgt.process.cmdline contains "-sfT ")) or (tgt.process.image.path contains "/cp" and tgt.process.cmdline contains "/dev/null") or (tgt.process.image.path contains "/shred" and tgt.process.cmdline contains "-u "))) or ((tgt.process.cmdline contains " > /var/log/syslog" or tgt.process.cmdline contains " >/var/log/syslog" or tgt.process.cmdline contains " >| /var/log/syslog" or tgt.process.cmdline contains ": > /var/log/syslog" or tgt.process.cmdline contains ":> /var/log/syslog" or tgt.process.cmdline contains ":>/var/log/syslog" or tgt.process.cmdline contains ">|/var/log/syslog") or (tgt.process.cmdline contains "journalctl --vacuum" or tgt.process.cmdline contains "journalctl --rotate"))))
```


# Original Sigma Rule:
```yaml
title: Syslog Clearing or Removal Via System Utilities
id: 3fcc9b35-39e4-44c0-a2ad-9e82b6902b31
status: test
description: |
    Detects specific commands commonly used to remove or empty the syslog. Which is a technique often used by attacker as a method to hide their tracks
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.002/T1070.002.md
    - https://www.virustotal.com/gui/file/54d60fd58d7fa3475fa123985bfc1594df26da25c1f5fbc7dfdba15876dd8ac5/behavior
author: Max Altgelt (Nextron Systems), Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
date: 2021-10-15
modified: 2025-10-15
tags:
    - attack.defense-evasion
    - attack.t1070.002
logsource:
    product: linux
    category: process_creation
detection:
    selection_file:
        CommandLine|contains: '/var/log/syslog'
    selection_command_rm:
        # Examples:
        #   rm -f /var/log/syslog
        Image|endswith: '/rm'
        CommandLine|contains:
            - ' -r '
            - ' -f '
            - ' -rf '
            - '/var/log/syslog' # We use this to avoid re-writing a separate selection
    selection_command_unlink:
        # Examples:
        #   unlink /var/log/syslog
        Image|endswith: '/unlink'
    selection_command_mv:
        # Examples:
        #   mv /var/log/syslog
        Image|endswith: '/mv'
    selection_command_truncate:
        # Examples:
        #   truncate --size 0 /var/log/syslog
        Image|endswith: '/truncate'
        CommandLine|contains|all:
            - '0 '
            - '/var/log/syslog' # We use this to avoid re-writing a separate selection
        CommandLine|contains:
            - '-s '
            - '-c '
            - '--size'
    selection_command_ln:
        # Examples:
        #   ln -sfn /dev/null /var/log/syslog
        Image|endswith: '/ln'
        CommandLine|contains|all:
            - '/dev/null '
            - '/var/log/syslog' # We use this to avoid re-writing a separate selection
        CommandLine|contains:
            - '-sf '
            - '-sfn '
            - '-sfT '
    selection_command_cp:
        # Examples:
        #   cp /dev/null /var/log/syslog
        Image|endswith: '/cp'
        CommandLine|contains: '/dev/null'
    selection_command_shred:
        # Examples:
        #   shred -u /var/log/syslog
        Image|endswith: '/shred'
        CommandLine|contains: '-u '
    selection_unique_other:
        CommandLine|contains:
            - ' > /var/log/syslog'
            - ' >/var/log/syslog'
            - ' >| /var/log/syslog'  # redirection empties w spacing, noclobber
            - ': > /var/log/syslog'
            - ':> /var/log/syslog'
            - ':>/var/log/syslog'
            - '>|/var/log/syslog'
    selection_unique_journalctl:
        CommandLine|contains:
            - 'journalctl --vacuum'
            - 'journalctl --rotate' # archives current journal files and creates new empty ones
    condition: (selection_file and 1 of selection_command_*) or 1 of selection_unique_*
falsepositives:
    - Log rotation.
    - Maintenance.
level: high
```
