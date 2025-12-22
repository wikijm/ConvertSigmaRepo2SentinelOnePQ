```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\procdump.exe" or tgt.process.image.path contains "\\procdump64.exe"))
```


# Original Sigma Rule:
```yaml
title: Procdump Execution
id: 2e65275c-8288-4ab4-aeb7-6274f58b6b20
status: test
description: Detects usage of the SysInternals Procdump utility
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
author: Florian Roth (Nextron Systems)
date: 2021-08-16
modified: 2023-02-28
tags:
    - attack.defense-evasion
    - attack.t1036
    - attack.t1003.001
    - attack.credential-access
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\procdump.exe'
            - '\procdump64.exe'
    condition: selection
falsepositives:
    - Legitimate use of procdump by a developer or administrator
level: medium
```
