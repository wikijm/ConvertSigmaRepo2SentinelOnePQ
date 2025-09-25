```sql
// Translated content (automatically translated on 25-09-2025 01:54:36):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\powershell.exe" or src.process.image.path contains "\\pwsh.exe") and tgt.process.image.path contains "\\schtasks.exe" and (tgt.process.cmdline contains "/Create" and tgt.process.cmdline contains "powershell.exe -NonI" and tgt.process.cmdline contains "/TN Updater /TR") and (tgt.process.cmdline contains "/SC ONLOGON" or tgt.process.cmdline contains "/SC DAILY /ST" or tgt.process.cmdline contains "/SC ONIDLE" or tgt.process.cmdline contains "/SC HOURLY")))
```


# Original Sigma Rule:
```yaml
title: HackTool - Default PowerSploit/Empire Scheduled Task Creation
id: 56c217c3-2de2-479b-990f-5c109ba8458f
status: test
description: Detects the creation of a schtask via PowerSploit or Empire Default Configuration.
references:
    - https://github.com/0xdeadbeefJERKY/PowerSploit/blob/8690399ef70d2cad10213575ac67e8fa90ddf7c3/Persistence/Persistence.psm1
    - https://github.com/EmpireProject/Empire/blob/08cbd274bef78243d7a8ed6443b8364acd1fc48b/lib/modules/powershell/persistence/userland/schtasks.py
author: Markus Neis, @Karneades
date: 2018-03-06
modified: 2023-03-03
tags:
    - attack.execution
    - attack.persistence
    - attack.privilege-escalation
    - attack.s0111
    - attack.g0022
    - attack.g0060
    - car.2013-08-001
    - attack.t1053.005
    - attack.t1059.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - '/Create'
            - 'powershell.exe -NonI'
            - '/TN Updater /TR'
        CommandLine|contains:
            - '/SC ONLOGON'
            - '/SC DAILY /ST'
            - '/SC ONIDLE'
            - '/SC HOURLY'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
