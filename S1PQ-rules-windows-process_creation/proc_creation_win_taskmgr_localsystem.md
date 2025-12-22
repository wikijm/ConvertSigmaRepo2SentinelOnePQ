```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.user contains "AUTHORI" or tgt.process.user contains "AUTORI") and tgt.process.image.path contains "\\taskmgr.exe"))
```


# Original Sigma Rule:
```yaml
title: Taskmgr as LOCAL_SYSTEM
id: 9fff585c-c33e-4a86-b3cd-39312079a65f
status: test
description: Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM
references:
    - Internal Research
author: Florian Roth (Nextron Systems)
date: 2018-03-18
modified: 2022-05-27
tags:
    - attack.defense-evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        User|contains: # covers many language settings
            - 'AUTHORI'
            - 'AUTORI'
        Image|endswith: '\taskmgr.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
```
