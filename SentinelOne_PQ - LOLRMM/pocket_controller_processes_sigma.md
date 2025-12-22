```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "pocketcontroller.exe" or src.process.image.path contains "pocketcloudservice.exe" or src.process.image.path contains "wysebrowser.exe") or (tgt.process.image.path contains "pocketcontroller.exe" or tgt.process.image.path contains "pocketcloudservice.exe" or tgt.process.image.path contains "wysebrowser.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Pocket Controller RMM Tool Process Activity
id: 39f8cf4e-8f16-4c78-9d57-e25d9da82f28
status: experimental
description: |
    Detects potential processes activity of Pocket Controller RMM tool
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
            - pocketcontroller.exe
            - pocketcloudservice.exe
            - wysebrowser.exe
    selection_image:
        Image|endswith:
            - pocketcontroller.exe
            - pocketcloudservice.exe
            - wysebrowser.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Pocket Controller
level: medium
```
