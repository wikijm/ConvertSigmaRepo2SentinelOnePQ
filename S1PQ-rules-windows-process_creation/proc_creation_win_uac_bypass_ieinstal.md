```sql
// Translated content (automatically translated on 04-09-2025 01:50:53):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.integrityLevel in ("High","System","S-1-16-16384","S-1-16-12288")) and src.process.image.path contains "\\ieinstal.exe" and tgt.process.image.path contains "\\AppData\\Local\\Temp\\" and tgt.process.image.path contains "consent.exe"))
```


# Original Sigma Rule:
```yaml
title: UAC Bypass Using IEInstal - Process
id: 80fc36aa-945e-4181-89f2-2f907ab6775d
status: test
description: Detects the pattern of UAC Bypass using IEInstal.exe (UACMe 64)
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
        IntegrityLevel:
            - 'High'
            - 'System'
            - 'S-1-16-16384' # System
            - 'S-1-16-12288' # High
        ParentImage|endswith: '\ieinstal.exe'
        Image|contains: '\AppData\Local\Temp\'
        Image|endswith: 'consent.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
```
