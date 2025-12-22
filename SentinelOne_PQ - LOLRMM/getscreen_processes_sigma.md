```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "GetScreen.exe" or src.process.image.path contains "getscreen.exe") or (tgt.process.image.path contains "GetScreen.exe" or tgt.process.image.path contains "getscreen.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential GetScreen RMM Tool Process Activity
id: 5fa801a1-fb76-4bf1-a42a-b017406c11c4
status: experimental
description: |
    Detects potential processes activity of GetScreen RMM tool
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
            - GetScreen.exe
            - getscreen.exe
    selection_image:
        Image|endswith:
            - GetScreen.exe
            - getscreen.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of GetScreen
level: medium
```
