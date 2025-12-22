```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "fastclient.exe" or src.process.image.path contains "fastmaster.exe" or src.process.image.path contains "FastViewer.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential FastViewer RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - fastclient.exe
    - fastmaster.exe
    - FastViewer.exe
  condition: selection
id: 820782ac-3ab0-4d83-8ba2-0f5349a56a99
status: experimental
description: Detects potential processes activity of FastViewer RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of FastViewer
level: medium
```
