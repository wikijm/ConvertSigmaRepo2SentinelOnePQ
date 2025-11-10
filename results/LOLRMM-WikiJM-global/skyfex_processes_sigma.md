```sql
// Translated content (automatically translated on 10-11-2025 01:42:17):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "Deskroll.exe" or src.process.image.path contains "DeskRollUA.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential SkyFex RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - Deskroll.exe
    - DeskRollUA.exe
  condition: selection
id: 6a2573e2-7550-4caf-927b-ed8f490a68b7
status: experimental
description: Detects potential processes activity of SkyFex RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of SkyFex
level: medium
```
