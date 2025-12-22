```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path="*pocketcloud*.exe" or src.process.image.path contains "pocketcloudservice.exe") or (tgt.process.image.path="*pocketcloud*.exe" or tgt.process.image.path contains "pocketcloudservice.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Pocket Cloud (Wyse) RMM Tool Process Activity
id: f29c2462-148d-488f-9e29-6e3c7d4661b7
status: experimental
description: |
    Detects potential processes activity of Pocket Cloud (Wyse) RMM tool
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
            - pocketcloud*.exe
            - pocketcloudservice.exe
    selection_image:
        Image|endswith:
            - pocketcloud*.exe
            - pocketcloudservice.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Pocket Cloud (Wyse)
level: medium
```
