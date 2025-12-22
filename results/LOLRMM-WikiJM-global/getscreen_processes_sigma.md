```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "GetScreen.exe" or src.process.image.path contains "getscreen.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential GetScreen RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - GetScreen.exe
    - getscreen.exe
  condition: selection
id: 0c38030b-b6a5-4df0-8c3e-bbe6c56c1bb7
status: experimental
description: Detects potential processes activity of GetScreen RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of GetScreen
level: medium
```
