```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "nvClient.exe" or src.process.image.path contains "netviewer.exe") or (tgt.process.image.path contains "nvClient.exe" or tgt.process.image.path contains "netviewer.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Netviewer (GoToMeet) RMM Tool Process Activity
id: a6346afe-86d5-4f01-aada-e9b2f19cba58
status: experimental
description: |
    Detects potential processes activity of Netviewer (GoToMeet) RMM tool
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
            - nvClient.exe
            - netviewer.exe
    selection_image:
        Image|endswith:
            - nvClient.exe
            - netviewer.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Netviewer (GoToMeet)
level: medium
```
