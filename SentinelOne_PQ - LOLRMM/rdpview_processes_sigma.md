```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "dwrcs.exe" or tgt.process.image.path contains "dwrcs.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential RDPView RMM Tool Process Activity
id: 77fcb82b-5173-44b0-bab4-472eb1a09be8
status: experimental
description: |
    Detects potential processes activity of RDPView RMM tool
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
        ParentImage|endswith: dwrcs.exe
    selection_image:
        Image|endswith: dwrcs.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of RDPView
level: medium
```
