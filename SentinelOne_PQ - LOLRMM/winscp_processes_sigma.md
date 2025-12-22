```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "WinSCP.exe" or tgt.process.image.path contains "WinSCP.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential WinSCP RMM Tool Process Activity
id: 4c69afec-1230-4cb8-b9ab-7464b64395e8
status: experimental
description: |
    Detects potential processes activity of WinSCP RMM tool
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
        ParentImage|endswith: WinSCP.exe
    selection_image:
        Image|endswith: WinSCP.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of WinSCP
level: medium
```
