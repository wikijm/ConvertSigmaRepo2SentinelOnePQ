```sql
// Translated content (automatically translated on 02-11-2024 01:18:28):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.integrityLevel in ("High","System")) and src.process.image.path contains "\AppData\Local\Temp\system32\winsat.exe" and src.process.cmdline contains "C:\Windows \system32\winsat.exe"))
```


# Original Sigma Rule:
```yaml
title: UAC Bypass Abusing Winsat Path Parsing - Process
id: 7a01183d-71a2-46ad-ad5c-acd989ac1793
status: test
description: Detects the pattern of UAC Bypass using a path parsing issue in winsat.exe (UACMe 52)
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
        IntegrityLevel:
            - 'High'
            - 'System'
        ParentImage|endswith: '\AppData\Local\Temp\system32\winsat.exe'
        ParentCommandLine|contains: 'C:\Windows \system32\winsat.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
```
