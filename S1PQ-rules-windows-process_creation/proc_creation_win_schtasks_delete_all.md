```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\schtasks.exe" and (tgt.process.cmdline contains " /delete " and tgt.process.cmdline contains "/tn \*" and tgt.process.cmdline contains " /f")))
```


# Original Sigma Rule:
```yaml
title: Delete All Scheduled Tasks
id: 220457c1-1c9f-4c2e-afe6-9598926222c1
status: test
description: Detects the usage of schtasks with the delete flag and the asterisk symbol to delete all tasks from the schedule of the local computer, including tasks scheduled by other users.
references:
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-delete
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-09
tags:
    - attack.impact
    - attack.t1489
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - ' /delete '
            - '/tn \*'
            - ' /f'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
