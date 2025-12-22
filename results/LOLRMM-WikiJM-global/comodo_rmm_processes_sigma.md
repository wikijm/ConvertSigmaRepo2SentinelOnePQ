```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "itsmagent.exe" or src.process.image.path contains "rviewer.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Comodo RMM RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - itsmagent.exe
    - rviewer.exe
  condition: selection
id: 1f2d2541-f3b7-488a-b553-aebd29c01eaa
status: experimental
description: Detects potential processes activity of Comodo RMM RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Comodo RMM
level: medium
```
