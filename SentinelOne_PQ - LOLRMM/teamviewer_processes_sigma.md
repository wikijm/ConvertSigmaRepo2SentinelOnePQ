```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "teamviewer_desktop.exe" or src.process.image.path contains "teamviewer_service.exe") or (tgt.process.image.path contains "teamviewer_desktop.exe" or tgt.process.image.path contains "teamviewer_service.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential TeamViewer RMM Tool Process Activity
id: 42c7fcb9-0379-4b81-b03e-1bcfe16f27af
status: experimental
description: |
    Detects potential processes activity of TeamViewer RMM tool
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
            - teamviewer_desktop.exe
            - teamviewer_service.exe
    selection_image:
        Image|endswith:
            - teamviewer_desktop.exe
            - teamviewer_service.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of TeamViewer
level: medium
```
