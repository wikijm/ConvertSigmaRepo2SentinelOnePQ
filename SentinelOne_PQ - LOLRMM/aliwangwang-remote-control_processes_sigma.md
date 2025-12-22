```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "alitask.exe" or tgt.process.image.path contains "alitask.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential AliWangWang-remote-control RMM Tool Process Activity
id: ba1c6242-0f04-4913-bc23-5ad3cd2964da
status: experimental
description: |
    Detects potential processes activity of AliWangWang-remote-control RMM tool
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
        ParentImage|endswith: alitask.exe
    selection_image:
        Image|endswith: alitask.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of AliWangWang-remote-control
level: medium
```
