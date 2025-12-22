```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "ManualLauncher.exe" or tgt.process.image.path contains "ManualLauncher.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Any Support RMM Tool Process Activity
id: 7799e615-745e-4cd7-948c-b21d032345d2
status: experimental
description: |
    Detects potential processes activity of Any Support RMM tool
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
        ParentImage|endswith: ManualLauncher.exe
    selection_image:
        Image|endswith: ManualLauncher.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Any Support
level: medium
```
