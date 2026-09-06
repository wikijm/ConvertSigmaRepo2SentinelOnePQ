```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\UltraViewer_Service.exe" or src.process.image.path contains "\\UltraViewer_Desktop.exe" or src.process.image.path contains "\\ultraviewer.exe") or (tgt.process.image.path contains "\\UltraViewer_Service.exe" or tgt.process.image.path contains "\\UltraViewer_Desktop.exe" or tgt.process.image.path contains "\\ultraviewer.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential UltraViewer RMM Tool Process Activity
id: 28310552-4d99-4da6-96cd-f9ac9258f564
status: experimental
description: |
    Detects potential processes activity of UltraViewer RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\UltraViewer_Service.exe'
            - '\\UltraViewer_Desktop.exe'
            - '\\ultraviewer.exe'
    selection_image:
        Image|endswith:
            - '\\UltraViewer_Service.exe'
            - '\\UltraViewer_Desktop.exe'
            - '\\ultraviewer.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of UltraViewer
level: medium
```
