```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "ctiserv.exe" or tgt.process.image.path contains "ctiserv.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Centurion RMM Tool Process Activity
id: 497ba66f-fb7d-4cc7-97aa-97fc6e4ea9ca
status: experimental
description: |
    Detects potential processes activity of Centurion RMM tool
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
        ParentImage|endswith: ctiserv.exe
    selection_image:
        Image|endswith: ctiserv.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Centurion
level: medium
```
