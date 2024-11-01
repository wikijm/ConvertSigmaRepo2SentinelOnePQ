```sql
// Translated content (automatically translated on 02-11-2024 01:18:28):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path="C:\Program Files\Windows Media Player\osk.exe" and (tgt.process.integrityLevel in ("High","System"))) or (tgt.process.image.path="C:\Windows\System32\cmd.exe" and src.process.cmdline="\"C:\Windows\system32\mmc.exe\" \"C:\Windows\system32\eventvwr.msc\" /s" and (tgt.process.integrityLevel in ("High","System")))))
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
modified: 2022-10-09
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image: 'C:\Program Files\Windows Media Player\osk.exe'
        IntegrityLevel:
            - 'High'
            - 'System'
    selection2:
        Image: 'C:\Windows\System32\cmd.exe'
        ParentCommandLine: '"C:\Windows\system32\mmc.exe" "C:\Windows\system32\eventvwr.msc" /s'
        IntegrityLevel:
            - 'High'
            - 'System'
    condition: 1 of selection*
falsepositives:
    - Unknown
level: high
```
