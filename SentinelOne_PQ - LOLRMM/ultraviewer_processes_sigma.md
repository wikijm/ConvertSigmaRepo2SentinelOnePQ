```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "UltraViewer_Service.exe" or src.process.image.path contains "UltraViewer_Desktop.exe" or src.process.image.path contains "ultraviewer.exe" or src.process.image.path contains "UltraViewer_Desktop.exe" or src.process.image.path contains "UltraViewer_Desktop.exe" or src.process.image.path contains "ultraviewer_desktop.exe" or src.process.image.path contains "ultraviewer_service.exe" or src.process.image.path contains "UltraViewer_Desktop.exe" or src.process.image.path contains "UltraViewer_Service.exe") or (tgt.process.image.path contains "UltraViewer_Service.exe" or tgt.process.image.path contains "UltraViewer_Desktop.exe" or tgt.process.image.path contains "ultraviewer.exe" or tgt.process.image.path contains "UltraViewer_Desktop.exe" or tgt.process.image.path contains "UltraViewer_Desktop.exe" or tgt.process.image.path contains "ultraviewer_desktop.exe" or tgt.process.image.path contains "ultraviewer_service.exe" or tgt.process.image.path contains "UltraViewer_Desktop.exe" or tgt.process.image.path contains "UltraViewer_Service.exe")))
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
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - UltraViewer_Service.exe
            - UltraViewer_Desktop.exe
            - ultraviewer.exe
            - UltraViewer_Desktop.exe
            - UltraViewer_Desktop.exe
            - ultraviewer_desktop.exe
            - ultraviewer_service.exe
            - UltraViewer_Desktop.exe
            - UltraViewer_Service.exe
    selection_image:
        Image|endswith:
            - UltraViewer_Service.exe
            - UltraViewer_Desktop.exe
            - ultraviewer.exe
            - UltraViewer_Desktop.exe
            - UltraViewer_Desktop.exe
            - ultraviewer_desktop.exe
            - ultraviewer_service.exe
            - UltraViewer_Desktop.exe
            - UltraViewer_Service.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of UltraViewer
level: medium
```
