```sql
// Translated content (automatically translated on 23-07-2025 02:22:13):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "noconsentprompt" and tgt.process.cmdline contains "shadow:"))
```


# Original Sigma Rule:
```yaml
title: Potential MSTSC Shadowing Activity
id: 6ba5a05f-b095-4f0a-8654-b825f4f16334
status: test
description: Detects RDP session hijacking by using MSTSC shadowing
references:
    - https://twitter.com/kmkz_security/status/1220694202301976576
    - https://github.com/kmkz/Pentesting/blob/47592e5e160d3b86c2024f09ef04ceb87d204995/Post-Exploitation-Cheat-Sheet
author: Florian Roth (Nextron Systems)
date: 2020-01-24
modified: 2023-02-05
tags:
    - attack.lateral-movement
    - attack.t1563.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'noconsentprompt'
            - 'shadow:'
    condition: selection
falsepositives:
    - Unknown
level: high
```
