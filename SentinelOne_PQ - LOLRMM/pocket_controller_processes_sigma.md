```sql
// Translated content (automatically translated on 02-08-2025 00:55:07):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "pocketcontroller.exe" or src.process.image.path contains "pocketcloudservice.exe" or src.process.image.path contains "wysebrowser.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Pocket Controller RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - pocketcontroller.exe
    - pocketcloudservice.exe
    - wysebrowser.exe
  condition: selection
id: b942a1b1-e907-4817-b13c-56b43f741606
status: experimental
description: Detects potential processes activity of Pocket Controller RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Pocket Controller
level: medium
```
