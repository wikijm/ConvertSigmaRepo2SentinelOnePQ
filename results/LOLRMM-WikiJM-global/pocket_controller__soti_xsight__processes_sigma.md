```sql
// Translated content (automatically translated on 02-08-2025 01:45:23):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "pocketcontroller.exe" or src.process.image.path contains "wysebrowser.exe" or src.process.image.path contains "XSightService.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Pocket Controller (Soti Xsight) RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - pocketcontroller.exe
    - wysebrowser.exe
    - XSightService.exe
  condition: selection
id: 7e666c30-2204-4f07-8ba0-8e46e054c24b
status: experimental
description: Detects potential processes activity of Pocket Controller (Soti Xsight)
  RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Pocket Controller (Soti Xsight)
level: medium
```
