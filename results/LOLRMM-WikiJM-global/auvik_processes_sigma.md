```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "auvik.engine.exe" or src.process.image.path contains "auvik.agent.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Auvik RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - auvik.engine.exe
    - auvik.agent.exe
  condition: selection
id: 0ab4238c-6f77-4b2f-bf04-413ebf61dae1
status: experimental
description: Detects potential processes activity of Auvik RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Auvik
level: medium
```
