```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.image.path contains "\\HollowReaper.exe")
```


# Original Sigma Rule:
```yaml
title: HackTool - HollowReaper Execution
id: 85d23b42-9a9d-4f8f-b3d7-d2733c1d58f5
status: experimental
description: |
    Detects usage of HollowReaper, a process hollowing shellcode launcher used for stealth payload execution through process hollowing.
    It replaces the memory of a legitimate process with custom shellcode, allowing the attacker to execute payloads under the guise of trusted binaries.
references:
    - https://github.com/vari-sh/RedTeamGrimoire/tree/b5e7635d34db6e1f0398d8847e8f293186e947c5/HollowReaper
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2025-07-01
tags:
    - attack.privilege-escalation
    - attack.defense-evasion
    - attack.t1055.012
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\HollowReaper.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
```
