```sql
// Translated content (automatically translated on 06-10-2024 07:02:16):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\wsreset.exe" and (tgt.process.integrityLevel in ("High","System"))))
```


# Original Sigma Rule:
```yaml
title: UAC Bypass WSReset
id: 89a9a0e0-f61a-42e5-8957-b1479565a658
status: test
description: Detects the pattern of UAC Bypass via WSReset usable by default sysmon-config
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Wsreset/
    - https://github.com/hfiref0x/UACME
    - https://medium.com/falconforce/falconfriday-detecting-uac-bypasses-0xff16-86c2a9107abf
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
        Image|endswith: '\wsreset.exe'
        IntegrityLevel:
            - 'High'
            - 'System'
    condition: selection
falsepositives:
    - Unknown
level: high
```