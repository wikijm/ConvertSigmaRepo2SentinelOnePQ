```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\changepk.exe" and src.process.image.path contains "\\slui.exe" and (tgt.process.integrityLevel in ("High","System","S-1-16-16384","S-1-16-12288"))))
```


# Original Sigma Rule:
```yaml
title: UAC Bypass Using ChangePK and SLUI
id: 503d581c-7df0-4bbe-b9be-5840c0ecc1fc
status: test
description: Detects an UAC bypass that uses changepk.exe and slui.exe (UACMe 61)
references:
    - https://mattharr0ey.medium.com/privilege-escalation-uac-bypass-in-changepk-c40b92818d1b
    - https://github.com/hfiref0x/UACME
    - https://medium.com/falconforce/falconfriday-detecting-uac-bypasses-0xff16-86c2a9107abf
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
    selection:
        Image|endswith: '\changepk.exe'
        ParentImage|endswith: '\slui.exe'
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
