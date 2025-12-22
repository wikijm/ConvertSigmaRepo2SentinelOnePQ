```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "ddsystem.exe" or src.process.image.path contains "dd.exe" or src.process.image.path contains "distant-desktop.exe") or (tgt.process.image.path contains "ddsystem.exe" or tgt.process.image.path contains "dd.exe" or tgt.process.image.path contains "distant-desktop.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Distant Desktop RMM Tool Process Activity
id: 9184b9f8-a983-4e99-a729-8a3b0c4d8b17
status: experimental
description: |
    Detects potential processes activity of Distant Desktop RMM tool
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
            - ddsystem.exe
            - dd.exe
            - distant-desktop.exe
    selection_image:
        Image|endswith:
            - ddsystem.exe
            - dd.exe
            - distant-desktop.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Distant Desktop
level: medium
```
