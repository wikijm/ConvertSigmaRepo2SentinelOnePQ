```sql
// Translated content (automatically translated on 02-11-2024 01:18:28):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\pkgmgr.exe" and tgt.process.image.path contains "\dism.exe" and (tgt.process.integrityLevel in ("High","System"))))
```


# Original Sigma Rule:
```yaml
title: UAC Bypass Using PkgMgr and DISM
id: a743ceba-c771-4d75-97eb-8a90f7f4844c
status: test
description: Detects the pattern of UAC Bypass using pkgmgr.exe and dism.exe (UACMe 23)
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
        ParentImage|endswith: '\pkgmgr.exe'
        Image|endswith: '\dism.exe'
        IntegrityLevel:
            - 'High'
            - 'System'
    condition: selection
falsepositives:
    - Unknown
level: high
```
