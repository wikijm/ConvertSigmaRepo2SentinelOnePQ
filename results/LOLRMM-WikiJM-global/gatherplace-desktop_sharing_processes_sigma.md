```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "gp3.exe" or src.process.image.path contains "gp4.exe" or src.process.image.path contains "gp5.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential GatherPlace-desktop sharing RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - gp3.exe
    - gp4.exe
    - gp5.exe
  condition: selection
id: 5c52fe62-88f8-4156-b9b6-a53ec478bb98
status: experimental
description: Detects potential processes activity of GatherPlace-desktop sharing RMM
  tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of GatherPlace-desktop sharing
level: medium
```
