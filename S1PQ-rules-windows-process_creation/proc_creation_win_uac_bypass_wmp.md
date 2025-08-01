```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path="C:\Program Files\Windows Media Player\osk.exe" or (tgt.process.image.path="C:\Windows\System32\cmd.exe" and src.process.cmdline="\"C:\Windows\system32\mmc.exe\" \"C:\Windows\system32\eventvwr.msc\" /s")) and (tgt.process.integrityLevel in ("High","System","S-1-16-16384","S-1-16-12288"))))
```


# Original Sigma Rule:
```yaml
title: UAC Bypass Using Windows Media Player - Process
id: 0058b9e5-bcd7-40d4-9205-95ca5a16d7b2
status: test
description: Detects the pattern of UAC Bypass using Windows Media Player osksupport.dll (UACMe 32)
references:
    - https://github.com/hfiref0x/UACME
author: Christian Burkard (Nextron Systems)
date: 2021-08-23
modified: 2024-12-01
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_img_1:
        Image: 'C:\Program Files\Windows Media Player\osk.exe'
    selection_img_2:
        Image: 'C:\Windows\System32\cmd.exe'
        ParentCommandLine: '"C:\Windows\system32\mmc.exe" "C:\Windows\system32\eventvwr.msc" /s'
    selection_integrity:
        IntegrityLevel:
            - 'High'
            - 'System'
            - 'S-1-16-16384' # System
            - 'S-1-16-12288' # High
    condition: 1 of selection_img_* and selection_integrity
falsepositives:
    - Unknown
level: high
```
