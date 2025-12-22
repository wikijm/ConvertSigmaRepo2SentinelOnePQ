```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path="*netviewer*.exe" or src.process.image.path contains "netviewer.exe") or (tgt.process.image.path="*netviewer*.exe" or tgt.process.image.path contains "netviewer.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Netviewer RMM Tool Process Activity
id: c79e9209-c485-45bf-af98-777c7b1040a2
status: experimental
description: |
    Detects potential processes activity of Netviewer RMM tool
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
            - netviewer*.exe
            - netviewer.exe
    selection_image:
        Image|endswith:
            - netviewer*.exe
            - netviewer.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Netviewer
level: medium
```
