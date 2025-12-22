```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "C:\*\\puttytray.exe" or src.process.image.path contains "\\puttytray.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential PuTTY Tray RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - C:\*\puttytray.exe
    - '*\puttytray.exe'
  condition: selection
id: c66fd994-a408-4c47-aa4f-23cb9355f9c4
status: experimental
description: Detects potential processes activity of PuTTY Tray RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of PuTTY Tray
level: medium
```
