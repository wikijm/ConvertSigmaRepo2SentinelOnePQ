```sql
// Translated content (automatically translated on 24-10-2024 01:19:12):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\consent.exe" and tgt.process.image.path contains "\werfault.exe" and (tgt.process.integrityLevel in ("High","System"))))
```


# Original Sigma Rule:
```yaml
title: UAC Bypass Using Consent and Comctl32 - Process
id: 1ca6bd18-0ba0-44ca-851c-92ed89a61085
status: test
description: Detects the pattern of UAC Bypass using consent.exe and comctl32.dll (UACMe 22)
references:
    - https://github.com/hfiref0x/UACME
author: Christian Burkard (Nextron Systems)
date: 2021-08-23
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
        ParentImage|endswith: '\consent.exe'
        Image|endswith: '\werfault.exe'
        IntegrityLevel:
            - 'High'
            - 'System'
    condition: selection
falsepositives:
    - Unknown
level: high
```
