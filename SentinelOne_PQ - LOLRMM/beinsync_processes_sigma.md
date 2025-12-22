```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*Beinsync*.exe" or tgt.process.image.path="*Beinsync*.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential BeInSync RMM Tool Process Activity
id: 608f00ea-10b2-49c6-8b5f-7a0ca2c31d4f
status: experimental
description: |
    Detects potential processes activity of BeInSync RMM tool
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
        ParentImage|endswith: Beinsync*.exe
    selection_image:
        Image|endswith: Beinsync*.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of BeInSync
level: medium
```
