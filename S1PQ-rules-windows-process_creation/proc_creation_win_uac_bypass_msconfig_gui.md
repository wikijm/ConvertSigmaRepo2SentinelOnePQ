```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.integrityLevel in ("High","System","S-1-16-16384","S-1-16-12288")) and src.process.image.path contains "\\AppData\\Local\\Temp\\pkgmgr.exe" and tgt.process.cmdline="\"C:\\Windows\\system32\\msconfig.exe\" -5"))
```


# Original Sigma Rule:
```yaml
title: UAC Bypass Using MSConfig Token Modification - Process
id: ad92e3f9-7eb6-460e-96b1-582b0ccbb980
status: test
description: Detects the pattern of UAC Bypass using a msconfig GUI hack (UACMe 55)
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
        ParentImage|endswith: '\AppData\Local\Temp\pkgmgr.exe'
        CommandLine: '"C:\Windows\system32\msconfig.exe" -5'
    condition: selection
falsepositives:
    - Unknown
level: high
```
