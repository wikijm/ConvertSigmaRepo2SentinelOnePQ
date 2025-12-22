```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "UltraViewer_Service.exe" or src.process.image.path contains "UltraViewer_Desktop.exe" or src.process.image.path contains "ultraviewer.exe" or src.process.image.path contains "C:\\Program Files (x86)\\UltraViewer\\UltraViewer_Desktop.exe" or src.process.image.path contains "\\UltraViewer_Desktop.exe" or src.process.image.path contains "ultraviewer_desktop.exe" or src.process.image.path contains "ultraviewer_service.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential UltraViewer RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - UltraViewer_Service.exe
    - UltraViewer_Desktop.exe
    - ultraviewer.exe
    - C:\Program Files (x86)\UltraViewer\UltraViewer_Desktop.exe
    - '*\UltraViewer_Desktop.exe'
    - ultraviewer_desktop.exe
    - ultraviewer_service.exe
  condition: selection
id: 71b5a484-76c9-4341-9267-f4b7eb8fd8a3
status: experimental
description: Detects potential processes activity of UltraViewer RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of UltraViewer
level: medium
```
