```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "dcagentservice.exe" or src.process.image.path contains "dcagentregister.exe") or (tgt.process.image.path contains "dcagentservice.exe" or tgt.process.image.path contains "dcagentregister.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Manage Engine (Desktop Central) RMM Tool Process Activity
id: c02588b6-85d8-472c-b291-634f7c6a2f0d
status: experimental
description: |
    Detects potential processes activity of Manage Engine (Desktop Central) RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - dcagentservice.exe
            - dcagentregister.exe
    selection_image:
        Image|endswith:
            - dcagentservice.exe
            - dcagentregister.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Manage Engine (Desktop Central)
level: medium
```
