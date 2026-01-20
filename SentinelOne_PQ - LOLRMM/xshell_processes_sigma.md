```sql
// Translated content (automatically translated on 20-01-2026 00:56:32):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "xShell.exe" or tgt.process.image.path contains "xShell.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Xshell RMM Tool Process Activity
id: 0ee932d7-49d1-47f8-83ef-a4845e8f4031
status: experimental
description: |
    Detects potential processes activity of Xshell RMM tool
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
        ParentImage|endswith: xShell.exe
    selection_image:
        Image|endswith: xShell.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Xshell
level: medium
```
