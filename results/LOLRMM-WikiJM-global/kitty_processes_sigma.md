```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "C:\*\\kitty.exe" or src.process.image.path contains "\\kitty.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential KiTTY RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - C:\*\kitty.exe
    - '*\kitty.exe'
  condition: selection
id: 3fad837e-9c84-4098-a411-d0accba8543d
status: experimental
description: Detects potential processes activity of KiTTY RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of KiTTY
level: medium
```
