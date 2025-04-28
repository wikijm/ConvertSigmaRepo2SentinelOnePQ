```sql
// Translated content (automatically translated on 28-04-2025 00:52:14):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "tdp2tcp.exe")
```


# Original Sigma Rule:
```yaml
title: Potential rdp2tcp RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - tdp2tcp.exe
  condition: selection
id: a4f71aeb-9561-4483-b35b-267093abd3a0
status: experimental
description: Detects potential processes activity of rdp2tcp RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of rdp2tcp
level: medium
```
