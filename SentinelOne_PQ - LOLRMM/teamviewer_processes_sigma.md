```sql
// Translated content (automatically translated on 02-08-2025 00:55:07):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "teamviewer_desktop.exe" or src.process.image.path contains "teamviewer_service.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential TeamViewer RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - teamviewer_desktop.exe
    - teamviewer_service.exe
  condition: selection
id: 6da6259d-68f3-4da4-aa39-7d1b75496e67
status: experimental
description: Detects potential processes activity of TeamViewer RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of TeamViewer
level: medium
```
