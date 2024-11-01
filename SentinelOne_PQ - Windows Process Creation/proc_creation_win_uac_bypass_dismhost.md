```sql
// Translated content (automatically translated on 02-11-2024 01:18:28):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "C:\Users\" and src.process.image.path contains "\AppData\Local\Temp\" and src.process.image.path contains "\DismHost.exe") and (tgt.process.integrityLevel in ("High","System"))))
```


# Original Sigma Rule:
```yaml
title: UAC Bypass Using DismHost
id: 853e74f9-9392-4935-ad3b-2e8c040dae86
status: test
description: Detects the pattern of UAC Bypass using DismHost DLL hijacking (UACMe 63)
references:
    - https://github.com/hfiref0x/UACME
author: Christian Burkard (Nextron Systems)
date: 2021-08-30
modified: 2022-10-09
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|contains|all:
            - 'C:\Users\'
            - '\AppData\Local\Temp\'
            - '\DismHost.exe'
        IntegrityLevel:
            - 'High'
            - 'System'
    condition: selection
falsepositives:
    - Unknown
level: high
```
