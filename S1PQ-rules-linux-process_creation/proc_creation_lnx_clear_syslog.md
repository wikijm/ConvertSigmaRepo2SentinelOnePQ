```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.cmdline contains "rm /var/log/syslog" or tgt.process.cmdline contains "rm -r /var/log/syslog" or tgt.process.cmdline contains "rm -f /var/log/syslog" or tgt.process.cmdline contains "rm -rf /var/log/syslog" or tgt.process.cmdline contains "unlink /var/log/syslog" or tgt.process.cmdline contains "unlink -r /var/log/syslog" or tgt.process.cmdline contains "unlink -f /var/log/syslog" or tgt.process.cmdline contains "unlink -rf /var/log/syslog" or tgt.process.cmdline contains "mv /var/log/syslog" or tgt.process.cmdline contains " >/var/log/syslog" or tgt.process.cmdline contains " > /var/log/syslog" or tgt.process.cmdline contains "journalctl --vacuum"))
```


# Original Sigma Rule:
```yaml
title: Commands to Clear or Remove the Syslog
id: 3fcc9b35-39e4-44c0-a2ad-9e82b6902b31
status: test
description: Detects specific commands commonly used to remove or empty the syslog. Which is often used by attacker as a method to hide their tracks
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.002/T1070.002.md
    - https://www.virustotal.com/gui/file/54d60fd58d7fa3475fa123985bfc1594df26da25c1f5fbc7dfdba15876dd8ac5/behavior
author: Max Altgelt (Nextron Systems), Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
date: 2021-10-15
modified: 2024-10-14
tags:
    - attack.defense-evasion
    - attack.t1070.002
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'rm /var/log/syslog'
            - 'rm -r /var/log/syslog'
            - 'rm -f /var/log/syslog'
            - 'rm -rf /var/log/syslog'
            - 'unlink /var/log/syslog'
            - 'unlink -r /var/log/syslog'
            - 'unlink -f /var/log/syslog'
            - 'unlink -rf /var/log/syslog'
            - 'mv /var/log/syslog'
            - ' >/var/log/syslog'
            - ' > /var/log/syslog'
            - 'journalctl --vacuum'
    condition: selection
falsepositives:
    - Log rotation.
level: high
```
