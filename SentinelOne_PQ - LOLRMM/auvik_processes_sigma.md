```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "auvik.engine.exe" or src.process.image.path contains "auvik.agent.exe") or (tgt.process.image.path contains "auvik.engine.exe" or tgt.process.image.path contains "auvik.agent.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Auvik RMM Tool Process Activity
id: 5e122c70-c7cd-4f0d-ab0b-c5d0ba91ffab
status: experimental
description: |
    Detects potential processes activity of Auvik RMM tool
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
            - auvik.engine.exe
            - auvik.agent.exe
    selection_image:
        Image|endswith:
            - auvik.engine.exe
            - auvik.agent.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Auvik
level: medium
```
