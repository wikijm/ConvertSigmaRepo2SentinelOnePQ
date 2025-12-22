```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "superopsticket.exe" or src.process.image.path contains "superops.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential SuperOps RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - superopsticket.exe
    - superops.exe
  condition: selection
id: b40a28b6-6003-4142-a64e-e084556270b7
status: experimental
description: Detects potential processes activity of SuperOps RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of SuperOps
level: medium
```
