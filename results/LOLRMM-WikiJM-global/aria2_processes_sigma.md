```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\aria2c.exe")
```


# Original Sigma Rule:
```yaml
title: Potential aria2 RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\aria2c.exe'
  condition: selection
id: 6c235ccb-9731-4e38-9fe2-b16ae844528b
status: experimental
description: Detects potential processes activity of aria2 RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of aria2
level: medium
```
