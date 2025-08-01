```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.user contains "AUTHORI" or tgt.process.user contains "AUTORI") and tgt.process.image.path contains "\tscon.exe"))
```


# Original Sigma Rule:
```yaml
title: Suspicious TSCON Start as SYSTEM
id: 9847f263-4a81-424f-970c-875dab15b79b
status: test
description: Detects a tscon.exe start as LOCAL SYSTEM
references:
    - http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html
    - https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6
    - https://www.ired.team/offensive-security/lateral-movement/t1076-rdp-hijacking-for-lateral-movement
author: Florian Roth (Nextron Systems)
date: 2018-03-17
modified: 2022-05-27
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        User|contains: # covers many language settings
            - 'AUTHORI'
            - 'AUTORI'
        Image|endswith: '\tscon.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
```
