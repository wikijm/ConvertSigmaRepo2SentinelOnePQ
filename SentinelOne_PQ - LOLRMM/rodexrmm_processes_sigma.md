```sql
// Translated content (automatically translated on 07-09-2026 01:44:50):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "RodexAgent.exe" or tgt.process.image.path contains "RodexAgent.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Rodex RMM Tool Process Activity
description: |
    Detects potential processes activity of Rodex RMM tool
author: johnk3r
date: 2026-04-03
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith: RodexAgent.exe
    selection_image:
        Image|endswith: RodexAgent.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Rodex RMM
level: medium
```
