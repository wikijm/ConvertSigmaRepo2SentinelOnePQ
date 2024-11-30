```sql
// Translated content (automatically translated on 30-11-2024 01:23:06):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\schtasks.exe" and tgt.process.cmdline contains " /create ") and (not (tgt.process.user contains "AUTHORI" or tgt.process.user contains "AUTORI"))))
```


# Original Sigma Rule:
```yaml
title: Scheduled Task Creation Via Schtasks.EXE
id: 92626ddd-662c-49e3-ac59-f6535f12d189
status: test
description: Detects the creation of scheduled tasks by user accounts via the "schtasks" utility.
references:
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create
author: Florian Roth (Nextron Systems)
date: 2019-01-16
modified: 2024-01-18
tags:
    - attack.execution
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1053.005
    - attack.s0111
    - car.2013-08-001
    - stp.1u
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: ' /create '
    filter_main_system_user:
        User|contains: # covers many language settings
            - 'AUTHORI'
            - 'AUTORI'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Administrative activity
    - Software installation
level: low
```
