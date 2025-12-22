```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "royalts.exe" or tgt.process.image.path contains "royalts.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Royal TS RMM Tool Process Activity
id: 55dd0a0f-5654-4796-8917-35e281b63137
status: experimental
description: |
    Detects potential processes activity of Royal TS RMM tool
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
        ParentImage|endswith: royalts.exe
    selection_image:
        Image|endswith: royalts.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Royal TS
level: medium
```
