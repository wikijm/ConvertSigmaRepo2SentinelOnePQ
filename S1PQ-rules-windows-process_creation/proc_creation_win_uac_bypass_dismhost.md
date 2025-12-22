```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "C:\\Users\\" and src.process.image.path contains "\\AppData\\Local\\Temp\\" and src.process.image.path contains "\\DismHost.exe") and (tgt.process.integrityLevel in ("High","System","S-1-16-16384","S-1-16-12288"))))
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
modified: 2024-12-01
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
            - 'S-1-16-16384' # System
            - 'S-1-16-12288' # High
    condition: selection
falsepositives:
    - Unknown
level: high
```
